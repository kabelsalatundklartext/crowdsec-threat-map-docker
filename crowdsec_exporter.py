#!/usr/bin/env python3
# CrowdSec → Prometheus Exporter
# Liest direkt aus der CrowdSec SQLite-DB + MaxMind GeoLite2-City.mmdb
# Keine externen pip-Pakete nötig – nur Python3 stdlib + mmdb pure-python reader
# Version: 2.1 | 2026-04-22
# Port: 9456

import subprocess
import os

CROWDSEC_CONTAINER = os.environ.get("CROWDSEC_CONTAINER_NAME", "crowdsec")

def run_unban(ip):
    """IP aus CrowdSec-Bans entfernen via docker exec"""
    global _cache_time
    try:
        result = subprocess.run(
            ["docker", "exec", CROWDSEC_CONTAINER, "cscli", "decisions", "delete", "--ip", ip],
            capture_output=True, text=True, timeout=10
        )
        # Auch Alerts löschen
        subprocess.run(
            ["docker", "exec", CROWDSEC_CONTAINER, "cscli", "alerts", "delete", "--ip", ip],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            log(f"✅ Unban erfolgreich: {ip}")
            # IP merken damit sie nicht mehr im Feed erscheint
            with _cache_lock:
                _unbanned_ips.add(ip)
                _cache_time = 0  # Cache invalidieren → sofort neu laden
            return True, f"IP {ip} erfolgreich entsperrt"
        else:
            log(f"❌ Unban fehlgeschlagen: {ip} — {result.stderr}")
            return False, result.stderr.strip()
    except Exception as e:
        log(f"❌ Unban Fehler: {e}")
        return False, str(e)

import sqlite3
import struct
import socket
import json
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime, timezone
import sys

### ====================================================
### ⚙️  KONFIGURATION
### Werte werden aus Umgebungsvariablen gelesen (Docker).
### Fallback-Pfade fuer Direktbetrieb ohne Docker.
### ====================================================
DB_PATH      = os.environ.get("CROWDSEC_DB_PATH",    "/crowdsec/data/crowdsec.db")
MMDB_PATH    = os.environ.get("CROWDSEC_MMDB_PATH",  "/crowdsec/data/GeoLite2-City.mmdb")
LISTEN_PORT  = int(os.environ.get("LISTEN_PORT",     "9456"))
LISTEN_HOST  = "0.0.0.0"
CACHE_TTL    = int(os.environ.get("CACHE_TTL",       "60"))
DAYS_BACK    = int(os.environ.get("DAYS_BACK",       "365"))

# Dynamic Whitelist
WHITELIST_ENABLED   = os.environ.get("WHITELIST_ENABLED",  "true").lower() == "true"
WHITELIST_FILE      = os.environ.get("WHITELIST_FILE",     "/crowdsec/postoverflows/s01-whitelist/my-whitelist.yaml")
WHITELIST_INTERVAL  = int(os.environ.get("WHITELIST_INTERVAL", "900"))
CROWDSEC_RESTART_WAIT = int(os.environ.get("CROWDSEC_RESTART_WAIT", "15"))  # Sekunden warten nach docker restart

SERVER_LAT   = float(os.environ.get("SERVER_LAT",  "0.0"))
SERVER_LON   = float(os.environ.get("SERVER_LON",  "0.0"))
SERVER_NAME  = os.environ.get("SERVER_NAME",        "MeinServer")

### ---- Logging ----
def log(msg):
    print(f"[{datetime.now().strftime('%F %T')}] {msg}", flush=True)

# ---------------------------------------------------------------------------
# Minimaler MaxMind MMDB Reader (pure Python, keine pip-Pakete)
# ---------------------------------------------------------------------------
class MMDBReader:
    def __init__(self, path):
        with open(path, "rb") as f:
            self.data = f.read()
        self._parse_metadata()

    def _parse_metadata(self):
        marker = b"\xab\xcd\xefMaxMind.com"
        idx = self.data.rfind(marker)
        if idx == -1:
            raise ValueError("Keine MMDB-Metadaten gefunden")
        meta_raw = self.data[idx + len(marker):]
        self.metadata = self._decode(meta_raw, 0)[0]
        self.node_count     = self.metadata["node_count"]
        self.record_size    = self.metadata["record_size"]
        self.ip_version     = self.metadata["ip_version"]
        self.node_byte_size = (self.record_size * 2) // 8
        self.search_tree_size = self.node_count * self.node_byte_size
        self.data_offset = self.search_tree_size + 16

    def _read_node(self, node, bit):
        record_size = self.record_size
        offset = node * self.node_byte_size
        if record_size == 28:
            b = self.data[offset:offset+4]
            if bit == 0:
                return ((b[3] & 0xF0) << 20) | struct.unpack(">I", b'\x00' + b[:3])[0]
            else:
                return ((b[3] & 0x0F) << 24) | struct.unpack(">I", b'\x00' + b[4:7])[0] if len(b) > 6 else \
                       ((b[3] & 0x0F) << 24) | (b[4] << 16 | b[5] << 8 | b[6]) if len(self.data[offset:offset+7]) == 7 else \
                       struct.unpack(">I", self.data[offset+3:offset+7])[0] & 0x0FFFFFFF
        elif record_size == 24:
            if bit == 0:
                return struct.unpack(">I", b'\x00' + self.data[offset:offset+3])[0]
            else:
                return struct.unpack(">I", b'\x00' + self.data[offset+3:offset+6])[0]
        elif record_size == 32:
            if bit == 0:
                return struct.unpack(">I", self.data[offset:offset+4])[0]
            else:
                return struct.unpack(">I", self.data[offset+4:offset+8])[0]
        raise ValueError(f"Unbekannte record_size: {record_size}")

    def _ip_to_bits(self, ip_str):
        try:
            packed = socket.inet_aton(ip_str)
            num = struct.unpack(">I", packed)[0]
            return [(num >> (31 - i)) & 1 for i in range(32)]
        except OSError:
            packed = socket.inet_pton(socket.AF_INET6, ip_str)
            bits = []
            for byte in packed:
                for i in range(7, -1, -1):
                    bits.append((byte >> i) & 1)
            return bits

    def _search(self, ip_str):
        bits = self._ip_to_bits(ip_str)
        if self.ip_version == 6 and "." in ip_str:
            bits = [0]*96 + bits
        node = 0
        for bit in bits:
            if node >= self.node_count:
                break
            node = self._read_node(node, bit)
        if node == self.node_count:
            return None
        if node <= self.node_count:
            return None
        return node

    def _decode(self, data, offset):
        if offset >= len(data):
            return None, offset
        ctrl = data[offset]
        offset += 1
        type_num = (ctrl >> 5) & 0x7
        if type_num == 0:
            type_num = data[offset] + 7
            offset += 1
        size = ctrl & 0x1F
        if size == 29:
            size = data[offset] + 29; offset += 1
        elif size == 30:
            size = struct.unpack(">H", data[offset:offset+2])[0] + 285; offset += 2
        elif size == 31:
            size = struct.unpack(">I", b'\x00' + data[offset:offset+3])[0] + 65821; offset += 3

        if type_num == 1:
            ptr_size = ((ctrl >> 3) & 0x3)
            if ptr_size == 0:
                ptr = ((ctrl & 0x7) << 8) | data[offset]; offset += 1
            elif ptr_size == 1:
                ptr = ((ctrl & 0x7) << 16) | (data[offset] << 8) | data[offset+1] + 2048; offset += 2
            elif ptr_size == 2:
                ptr = ((ctrl & 0x7) << 24) | struct.unpack(">I", b'\x00' + data[offset:offset+3])[0] + 526336; offset += 3
            else:
                ptr = struct.unpack(">I", data[offset:offset+4])[0]; offset += 4
            val, _ = self._decode(data, ptr)
            return val, offset
        elif type_num == 2:
            return data[offset:offset+size].decode("utf-8", errors="replace"), offset+size
        elif type_num == 3:
            return struct.unpack(">d", data[offset:offset+8])[0], offset+8
        elif type_num == 4:
            return data[offset:offset+size], offset+size
        elif type_num == 5:
            val = 0
            for b in data[offset:offset+size]: val = (val << 8) | b
            return val, offset+size
        elif type_num == 6:
            val = 0
            for b in data[offset:offset+size]: val = (val << 8) | b
            return val, offset+size
        elif type_num == 7:
            result = {}
            for _ in range(size):
                key, offset = self._decode(data, offset)
                val, offset = self._decode(data, offset)
                result[key] = val
            return result, offset
        elif type_num == 8:
            val = struct.unpack(">i", data[offset:offset+size].rjust(4, b'\x00'))[0]
            return val, offset+size
        elif type_num == 9:
            val = 0
            for b in data[offset:offset+size]: val = (val << 8) | b
            return val, offset+size
        elif type_num == 11:
            result = []
            for _ in range(size):
                val, offset = self._decode(data, offset)
                result.append(val)
            return result, offset
        elif type_num == 14:
            return size != 0, offset
        elif type_num == 15:
            return struct.unpack(">f", data[offset:offset+4])[0], offset+4
        return None, offset+size

    def get(self, ip_str):
        try:
            node = self._search(ip_str)
            if node is None:
                return None
            data_record_offset = node - self.node_count - 16
            record, _ = self._decode(self.data, self.data_offset + data_record_offset)
            if not isinstance(record, dict):
                return None
            result = {}
            loc = record.get("location", {})
            result["lat"] = loc.get("latitude", 0.0)
            result["lon"] = loc.get("longitude", 0.0)
            country = record.get("country", {})
            result["country_iso"]  = country.get("iso_code", "??")
            en = country.get("names", {})
            result["country_name"] = en.get("en", "Unknown") if isinstance(en, dict) else "Unknown"
            city = record.get("city", {})
            city_names = city.get("names", {})
            result["city"] = city_names.get("en", "") if isinstance(city_names, dict) else ""
            return result
        except Exception:
            return None


# ---------------------------------------------------------------------------
# Geo-Fallback (Ländermittelpunkte)
# ---------------------------------------------------------------------------
GEO_FALLBACK = {
    "AF":"33.9391,67.7100","AL":"41.1533,20.1683","DZ":"28.0339,1.6596",
    "AR":"-38.4161,-63.6167","AM":"40.0691,45.0382","AU":"-25.2744,133.7751",
    "AT":"47.5162,14.5501","AZ":"40.1431,47.5769","BD":"23.6850,90.3563",
    "BY":"53.7098,27.9534","BE":"50.5039,4.4699","BR":"-14.2350,-51.9253",
    "BG":"42.7339,25.4858","CA":"56.1304,-106.3468","CL":"-35.6751,-71.5430",
    "CN":"35.8617,104.1954","CO":"4.5709,-74.2973","HR":"45.1000,15.2000",
    "CZ":"49.8175,15.4730","DK":"56.2639,9.5018","EG":"26.8206,30.8025",
    "EE":"58.5953,25.0136","FI":"61.9241,25.7482","FR":"46.6034,1.8883",
    "DE":"51.1657,10.4515","GR":"39.0742,21.8243","HK":"22.3193,114.1694",
    "HU":"47.1625,19.5033","IN":"20.5937,78.9629","ID":"-0.7893,113.9213",
    "IR":"32.4279,53.6880","IQ":"33.2232,43.6793","IE":"53.4129,-8.2439",
    "IL":"31.0461,34.8516","IT":"41.8719,12.5674","JP":"36.2048,138.2529",
    "KZ":"48.0196,66.9237","KR":"35.9078,127.7669","LV":"56.8796,24.6032",
    "LT":"55.1694,23.8813","MY":"4.2105,101.9758","MX":"23.6345,-102.5528",
    "MD":"47.4116,28.3699","NL":"52.1326,5.2913","NZ":"-40.9006,174.8860",
    "NG":"9.0820,8.6753","NO":"60.4720,8.4689","PK":"30.3753,69.3451",
    "PL":"51.9194,19.1451","PT":"39.3999,-8.2245","RO":"45.9432,24.9668",
    "RU":"61.5240,105.3188","SA":"23.8859,45.0792","RS":"44.0165,21.0059",
    "SG":"1.3521,103.8198","SK":"48.6690,19.6990","ZA":"-30.5595,22.9375",
    "ES":"40.4637,-3.7492","SE":"60.1282,18.6435","CH":"46.8182,8.2275",
    "TW":"23.6978,120.9605","TH":"15.8700,100.9925","TR":"38.9637,35.2433",
    "UA":"48.3794,31.1656","AE":"23.4241,53.8478","GB":"55.3781,-3.4360",
    "US":"37.0902,-95.7129","UZ":"41.3775,64.5853","VN":"14.0583,108.2772",
}

def geo_fallback(country_iso):
    coords = GEO_FALLBACK.get(country_iso, "0,0")
    lat, lon = coords.split(",")
    return float(lat), float(lon)


# ---------------------------------------------------------------------------
# Daten-Cache
# ---------------------------------------------------------------------------
_cache_lock    = threading.Lock()
_cache_metrics = ""
_cache_time    = 0
_unbanned_ips  = set()  # IPs die manuell entsperrt wurden
_mmdb          = None

# Whitelist-Status (für Dashboard-Badge)
_whitelist_status = {
    "ip":        "",
    "last_check": "",
    "last_change": "",
    "status":    "unbekannt",  # "ok", "aktualisiert", "fehler", "unbekannt"
}


# ---------------------------------------------------------------------------
# Dynamische Whitelist — eigene IP alle 15 Min aktualisieren
# ---------------------------------------------------------------------------
import urllib.request

def _get_public_ip():
    """Öffentliche IP holen — mehrere Dienste als Fallback"""
    for url in ["https://ifconfig.me", "https://api.ipify.org", "https://checkip.amazonaws.com"]:
        try:
            with urllib.request.urlopen(url, timeout=8) as r:
                ip = r.read().decode().strip()
                if ip:
                    return ip
        except Exception:
            continue
    return None

def _run_whitelist_update():
    """Whitelist-Update-Logik — analog zu deinem Shell-Script"""
    global _whitelist_status
    now_str = datetime.now().strftime("%d.%m.%Y %H:%M:%S")

    log("🔎 [Whitelist] Hole aktuelle öffentliche IP...")
    ip = _get_public_ip()
    if not ip:
        log("❌ [Whitelist] Keine IP gefunden!")
        _whitelist_status.update({"status": "fehler", "last_check": now_str})
        return

    log(f"🌍 [Whitelist] Aktuelle IP: {ip}")
    _whitelist_status["last_check"] = now_str
    _whitelist_status["ip"] = ip

    # Prüfen ob IP sich geändert hat
    current_ip = ""
    if os.path.exists(WHITELIST_FILE):
        try:
            with open(WHITELIST_FILE, "r") as f:
                content = f.read()
            import re
            m = re.search(r'(\d+\.\d+\.\d+\.\d+)', content)
            if m:
                current_ip = m.group(1)
        except Exception:
            pass

    if current_ip == ip:
        log(f"✅ [Whitelist] IP unverändert ({ip}) — entferne ggf. aktiven Ban")
        # Trotzdem sicherstellen dass kein Ban existiert
        try:
            subprocess.run(
                ["docker", "exec", CROWDSEC_CONTAINER, "cscli", "decisions", "delete", "--ip", ip],
                capture_output=True, timeout=15
            )
        except subprocess.TimeoutExpired:
            log("⚠️  [Whitelist] Timeout bei Ban-Prüfung — CrowdSec beschäftigt?")
        _whitelist_status["status"] = "ok"
        return

    log(f"♻️  [Whitelist] IP geändert: {current_ip or 'neu'} → {ip}")

    # YAML neu schreiben
    try:
        os.makedirs(os.path.dirname(WHITELIST_FILE), exist_ok=True)
        yaml_content = (
            f"name: my-whitelist\n"
            f"description: dynamic whitelist\n"
            f"whitelist:\n"
            f"  reason: dynamic\n"
            f"  ip:\n"
            f'    - "{ip}"\n'
        )
        with open(WHITELIST_FILE, "w") as f:
            f.write(yaml_content)
        log(f"📝 [Whitelist] Datei geschrieben: {WHITELIST_FILE}")
    except Exception as e:
        log(f"❌ [Whitelist] Schreiben fehlgeschlagen: {e}")
        _whitelist_status["status"] = "fehler"
        return

    # CrowdSec neustarten
    log("🔄 [Whitelist] Starte CrowdSec neu...")
    subprocess.run(["docker", "restart", CROWDSEC_CONTAINER], capture_output=True, timeout=90)

    # Warten bis CrowdSec wieder läuft
    # Erst 15s initial warten (CrowdSec braucht Zeit zum Hochfahren)
    log(f"⏳ [Whitelist] Warte auf CrowdSec (initial {CROWDSEC_RESTART_WAIT}s)...")
    time.sleep(CROWDSEC_RESTART_WAIT)
    for attempt in range(15):
        time.sleep(5)
        try:
            r = subprocess.run(
                ["docker", "exec", CROWDSEC_CONTAINER, "cscli", "version"],
                capture_output=True, timeout=15
            )
            if r.returncode == 0:
                log(f"✅ [Whitelist] CrowdSec online (Versuch {attempt+1})")
                break
        except subprocess.TimeoutExpired:
            log(f"⏳ [Whitelist] Noch nicht bereit (Versuch {attempt+1}/15)...")
            continue
    else:
        log("❌ [Whitelist] CrowdSec kommt nicht hoch — Ban-Entfernung übersprungen")
        _whitelist_status["status"] = "fehler"
        return

    # Kurz noch extra warten damit LAPI vollständig initialisiert ist
    time.sleep(5)

    # Alten Ban entfernen (Fehler ignorieren — existiert vielleicht nicht)
    try:
        subprocess.run(
            ["docker", "exec", CROWDSEC_CONTAINER, "cscli", "decisions", "delete", "--ip", ip],
            capture_output=True, timeout=15
        )
    except subprocess.TimeoutExpired:
        log("⚠️  [Whitelist] Ban-Entfernung Timeout — wird beim nächsten Lauf wiederholt")

    change_str = datetime.now().strftime("%d.%m.%Y %H:%M:%S")
    _whitelist_status.update({"status": "aktualisiert", "last_change": change_str})
    log(f"🎉 [Whitelist] Fertig — IP {ip} gewhitelistet")


def _whitelist_loop():
    """Background-Thread: läuft alle WHITELIST_INTERVAL Sekunden"""
    log(f"🛡️  [Whitelist] Hintergrund-Loop gestartet (Intervall: {WHITELIST_INTERVAL}s)")
    while True:
        try:
            _run_whitelist_update()
        except Exception as e:
            log(f"❌ [Whitelist] Unerwarteter Fehler: {e}")
        time.sleep(WHITELIST_INTERVAL)


def init_mmdb():
    global _mmdb
    if os.path.exists(MMDB_PATH):
        try:
            _mmdb = MMDBReader(MMDB_PATH)
            log(f"✅ MaxMind MMDB geladen: {MMDB_PATH}")
        except Exception as e:
            log(f"⚠️  MMDB laden fehlgeschlagen: {e} – nutze Länder-Fallback")
    else:
        log(f"⚠️  MMDB nicht gefunden unter {MMDB_PATH} – nutze Länder-Fallback")
        log(f"    → GeoLite2-City.mmdb herunterladen: https://www.maxmind.com/en/geolite2/signup")

def geo_lookup(ip, country_iso):
    if _mmdb:
        result = _mmdb.get(ip)
        if result:
            lat  = result["lat"]
            lon  = result["lon"]
            city = result.get("city", "")
            # Wenn MMDB keine Stadt hat → nächste Stadt aus Koordinaten bestimmen
            if not city and lat and lon:
                city = nearest_city(lat, lon)
            return lat, lon, city
    lat, lon = geo_fallback(country_iso)
    city = nearest_city(lat, lon) if (lat and lon) else ""
    return lat, lon, city


# ---------------------------------------------------------------------------
# Nearest-City Fallback — nächste bekannte Stadt aus lat/lon
# Format: (lat, lon, "Stadtname")
# ---------------------------------------------------------------------------
_CITIES = [
    # Europa
    (51.507,-0.128,"London"),(53.48,-2.242,"Manchester"),(53.801,-1.549,"Leeds"),
    (52.486,-1.89,"Birmingham"),(51.454,-2.588,"Bristol"),(55.953,-3.189,"Edinburgh"),
    (55.864,-4.252,"Glasgow"),(53.544,-113.491,"Edmonton"),(51.899,-8.474,"Cork"),
    (53.349,-6.26,"Dublin"),(54.607,-5.926,"Belfast"),(48.853,2.35,"Paris"),
    (45.764,4.836,"Lyon"),(43.297,5.381,"Marseille"),(43.61,3.877,"Montpellier"),
    (44.837,-0.58,"Bordeaux"),(47.218,-1.554,"Nantes"),(50.629,3.057,"Lille"),
    (48.574,7.752,"Strasbourg"),(45.188,5.724,"Grenoble"),(43.125,5.931,"Toulon"),
    (52.52,13.405,"Berlin"),(53.551,9.994,"Hamburg"),(48.135,11.582,"Munich"),
    (50.938,6.96,"Cologne"),(50.11,8.682,"Frankfurt"),(48.783,9.182,"Stuttgart"),
    (51.228,6.773,"Dusseldorf"),(51.514,7.468,"Dortmund"),(53.075,8.808,"Bremen"),(53.219,6.566,"Groningen"),(52.374,4.89,"Amsterdam"),(52.3716,4.8883,"Amsterdam"),(52.3759,4.8975,"Amsterdam"),(52.352,4.9392,"Amsterdam"),
    (51.34,12.375,"Leipzig"),(51.221,4.4,"Antwerp"),(51.05,13.738,"Dresden"),
    (49.452,11.077,"Nuremberg"),(52.268,10.526,"Braunschweig"),(54.323,10.123,"Kiel"),
    (54.093,12.14,"Rostock"),(53.866,10.686,"Lubeck"),(47.067,15.433,"Graz"),
    (48.21,16.37,"Vienna"),(47.81,13.055,"Salzburg"),(47.376,8.548,"Zurich"),(45.4722,9.1922,"Milan"),
    (46.948,7.448,"Bern"),(46.204,6.143,"Geneva"),(47.559,7.588,"Basel"),
    (40.417,-3.704,"Madrid"),(41.385,2.173,"Barcelona"),(39.47,-0.376,"Valencia"),
    (37.389,-5.984,"Seville"),(36.721,-4.422,"Malaga"),(43.263,-2.935,"Bilbao"),
    (41.649,0.874,"Lleida"),(37.997,-1.13,"Murcia"),(43.362,-5.85,"Oviedo"),
    (36.527,-6.294,"Cadiz"),(37.177,-3.599,"Granada"),(38.345,-0.483,"Alicante"),
    (38.914,-6.341,"Badajoz"),(42.349,-7.866,"Ourense"),(43.547,-5.922,"Gijon"),
    (41.878,-87.63,"Chicago"),(40.714,-74.006,"New York"),(34.052,-118.244,"Los Angeles"),
    (29.76,-95.37,"Houston"),(33.448,-112.074,"Phoenix"),(29.424,-98.494,"San Antonio"),
    (32.776,-96.797,"Dallas"),(28.538,-81.379,"Orlando"),(32.715,-117.157,"San Diego"),
    (30.267,-97.743,"Austin"),(30.332,-81.656,"Jacksonville"),(37.774,-122.419,"San Francisco"),
    (39.739,-104.984,"Denver"),(36.175,-115.137,"Las Vegas"),(47.606,-122.332,"Seattle"),
    (42.36,-71.059,"Boston"),(25.775,-80.209,"Miami"),(38.907,-77.037,"Washington DC"),
    (39.952,-75.164,"Philadelphia"),(33.749,-84.39,"Atlanta"),(35.467,-97.517,"Oklahoma City"),
    (36.162,-86.782,"Nashville"),(35.149,-90.049,"Memphis"),(29.951,-90.071,"New Orleans"),
    (43.048,-76.147,"Syracuse"),(41.499,-81.695,"Cleveland"),(43.047,-88.0,"Milwaukee"),
    (44.98,-93.265,"Minneapolis"),(41.259,-95.938,"Omaha"),(39.099,-94.578,"Kansas City"),
    (39.768,-86.158,"Indianapolis"),(42.332,-83.046,"Detroit"),(43.049,-76.147,"Buffalo"),
    (45.523,-122.676,"Portland"),(35.227,-80.843,"Charlotte"),(36.851,-76.289,"Norfolk"),
    (37.337,-121.89,"San Jose"),(37.687,-122.47,"Oakland"),(33.749,-84.389,"Atlanta"),
    (41.6015,-93.6127,"Des Moines"),(40.760,-111.891,"Salt Lake City"),(41.221,-111.974,"Ogden"),(43.049,-76.147,"Buffalo"),(35.779,-78.638,"Raleigh"),
    (30.438,-84.281,"Tallahassee"),(32.361,-86.279,"Montgomery"),(38.252,-85.759,"Louisville"),
    (43.653,-79.383,"Toronto"),(45.508,-73.554,"Montreal"),(49.246,-123.116,"Vancouver"),
    (51.045,-114.057,"Calgary"),(53.544,-113.491,"Edmonton"),(45.422,-75.697,"Ottawa"),
    (43.255,-79.843,"Hamilton"),(49.895,-97.138,"Winnipeg"),(46.812,-71.215,"Quebec City"),
    (44.649,-63.599,"Halifax"),(53.544,-113.491,"Edmonton"),(45.4995,-73.5848,"Laval"),
    (55.755,37.617,"Moscow"),(59.939,30.315,"Saint Petersburg"),(56.838,60.597,"Yekaterinburg"),
    (56.326,44.006,"Nizhny Novgorod"),(55.03,82.92,"Novosibirsk"),(55.796,49.106,"Kazan"),
    (53.195,50.148,"Samara"),(47.222,39.72,"Rostov-on-Don"),(54.732,55.958,"Ufa"),
    (45.045,38.976,"Krasnodar"),(48.693,44.512,"Volgograd"),(52.29,104.297,"Irkutsk"),
    (56.01,92.852,"Krasnoyarsk"),(43.115,131.885,"Vladivostok"),(57.626,39.885,"Yaroslavl"),
    (54.993,73.368,"Omsk"),(56.484,84.948,"Tomsk"),(52.033,113.501,"Chita"),
    (50.45,30.523,"Kyiv"),(49.84,24.03,"Lviv"),(46.948,31.992,"Mykolaiv"),
    (46.482,30.723,"Odessa"),(49.993,36.23,"Kharkiv"),(48.459,35.046,"Dnipro"),
    (47.837,35.139,"Zaporizhzhia"),(50.262,28.652,"Zhytomyr"),(49.234,28.468,"Vinnytsia"),
    (50.45,30.523,"Kyiv"),(52.23,21.01,"Warsaw"),(50.065,19.945,"Krakow"),
    (51.107,17.038,"Wroclaw"),(53.13,18.009,"Bydgoszcz"),(54.352,18.646,"Gdansk"),
    (53.428,14.553,"Szczecin"),(51.771,19.454,"Lodz"),(50.259,19.021,"Katowice"),
    (51.246,22.568,"Lublin"),(50.676,17.921,"Opole"),(50.088,14.42,"Prague"),
    (49.195,16.608,"Brno"),(49.737,13.373,"Plzen"),(50.231,12.871,"Cheb"),
    (47.498,19.04,"Budapest"),(47.526,21.637,"Debrecen"),(46.253,20.149,"Szeged"),
    (44.432,26.104,"Bucharest"),(46.77,23.59,"Cluj-Napoca"),(45.797,24.152,"Sibiu"),(45.655,25.611,"Brasov"),
    (45.749,21.23,"Timisoara"),(44.316,23.796,"Craiova"),(47.162,27.59,"Iasi"),
    (42.698,23.322,"Sofia"),(42.137,24.747,"Plovdiv"),(43.849,25.953,"Varna"),
    (44.804,20.465,"Belgrade"),(45.267,19.833,"Novi Sad"),(43.32,21.896,"Nis"),
    (50.85,4.352,"Brussels"),(51.221,4.4,"Antwerp"),(51.057,3.721,"Ghent"),
    (50.668,4.612,"Namur"),(50.633,5.567,"Liege"),(55.676,12.568,"Copenhagen"),
    (56.163,10.203,"Aarhus"),(55.404,10.402,"Odense"),(57.048,9.921,"Aalborg"),
    (59.913,10.752,"Oslo"),(60.391,5.322,"Bergen"),(63.431,10.395,"Trondheim"),
    (69.649,18.957,"Tromso"),(58.97,5.733,"Stavanger"),(59.334,18.063,"Stockholm"),
    (57.708,11.975,"Gothenburg"),(55.605,13.003,"Malmo"),(59.858,17.645,"Uppsala"),
    (60.605,15.626,"Falun"),(57.782,14.162,"Jonkoping"),(56.879,14.809,"Vaxjo"),
    (60.169,24.938,"Helsinki"),(61.498,23.76,"Tampere"),(60.453,22.27,"Turku"),
    (65.012,25.472,"Oulu"),(62.892,27.678,"Kuopio"),(62.601,29.763,"Joensuu"),
    (64.135,-21.895,"Reykjavik"),(53.35,-6.26,"Dublin"),(54.607,-5.926,"Belfast"),
    (35.69,139.692,"Tokyo"),(34.693,135.502,"Osaka"),(35.181,136.907,"Nagoya"),
    (43.062,141.354,"Sapporo"),(33.59,130.402,"Fukuoka"),(34.386,132.455,"Hiroshima"),
    (35.016,135.768,"Kyoto"),(35.605,140.106,"Chiba"),(35.447,139.642,"Kawasaki"),
    (31.596,130.557,"Kagoshima"),(26.212,127.679,"Naha"),(38.269,140.872,"Sendai"),
    (37.566,126.978,"Seoul"),(35.166,129.056,"Busan"),(35.838,128.756,"Daegu"),
    (37.458,126.705,"Incheon"),(35.534,129.314,"Ulsan"),(36.351,127.385,"Daejeon"),
    (35.157,126.851,"Gwangju"),(39.92,32.854,"Ankara"),(41.015,28.979,"Istanbul"),
    (38.423,27.143,"Izmir"),(36.9,30.7,"Antalya"),(40.183,27.92,"Bursa"),
    (37.874,32.485,"Konya"),(39.919,32.854,"Ankara"),(36.886,30.705,"Antalya"),
    (39.905,116.391,"Beijing"),(31.224,121.469,"Shanghai"),(22.543,114.058,"Shenzhen"),
    (23.13,113.26,"Guangzhou"),(30.658,104.066,"Chengdu"),(31.861,117.283,"Hefei"),
    (36.651,117.12,"Jinan"),(30.267,120.153,"Hangzhou"),(32.059,118.796,"Nanjing"),
    (28.228,112.939,"Changsha"),(22.816,108.315,"Nanning"),(29.563,106.551,"Chongqing"),
    (25.048,102.718,"Kunming"),(26.578,106.707,"Guiyang"),(39.125,117.19,"Tianjin"),
    (34.341,108.94,"Xi'an"),(43.825,125.324,"Changchun"),(45.803,126.535,"Harbin"),
    (41.796,123.429,"Shenyang"),(38.042,114.515,"Shijiazhuang"),(24.481,118.157,"Xiamen"),
    (37.871,112.549,"Taiyuan"),(47.827,130.316,"Jixi"),(25.047,121.519,"Taipei"),
    (22.397,114.109,"Hong Kong"),(22.194,113.543,"Macau"),(22.3,114.2,"Kowloon"),
    (28.613,77.209,"New Delhi"),(19.076,72.878,"Mumbai"),(12.972,77.594,"Bangalore"),
    (22.572,88.364,"Kolkata"),(13.083,80.27,"Chennai"),(17.385,78.487,"Hyderabad"),
    (23.023,72.572,"Ahmedabad"),(18.52,73.856,"Pune"),(26.912,75.787,"Jaipur"),
    (21.146,79.082,"Nagpur"),(22.719,75.857,"Indore"),(13.0,-80.0,"Coimbatore"),
    (12.295,76.642,"Mysore"),(11.664,78.146,"Salem"),(15.828,78.037,"Kurnool"),
    (18.5211,73.8502,"Pune"),(27.153,78.058,"Agra"),(25.447,81.846,"Allahabad"),
    (24.861,67.01,"Karachi"),(31.549,74.343,"Lahore"),(33.688,73.058,"Islamabad"),
    (25.396,68.361,"Hyderabad-PK"),(34.009,71.579,"Peshawar"),(30.184,67.007,"Quetta"),
    (23.81,90.412,"Dhaka"),(22.329,91.834,"Chittagong"),(24.905,91.861,"Sylhet"),
    (6.914,79.973,"Colombo"),(3.148,101.686,"Kuala Lumpur"),(1.352,103.82,"Singapore"),
    (-6.208,106.846,"Jakarta"),(-6.914,107.609,"Bandung"),(-7.25,112.75,"Surabaya"),
    (-0.505,117.153,"Samarinda"),(-8.65,115.216,"Denpasar"),(3.597,98.672,"Medan"),
    (-7.801,110.365,"Yogyakarta"),(13.756,100.502,"Bangkok"),(16.468,107.591,"Hue"),
    (10.823,106.63,"Ho Chi Minh City"),(21.028,105.834,"Hanoi"),(16.048,108.243,"Da Nang"),
    (14.064,108.268,"Pleiku"),(14.093,108.268,"Pleiku"),(10.0,105.0,"Can Tho"),
    (11.562,104.916,"Phnom Penh"),(17.967,102.6,"Vientiane"),(16.871,96.199,"Yangon"),
    (21.978,96.083,"Mandalay"),(1.553,110.359,"Kuching"),(5.979,116.073,"Kota Kinabalu"),
    (33.749,-84.39,"Atlanta"),(35.693,-105.944,"Santa Fe"),(32.221,-110.969,"Tucson"),
    (44.052,-123.086,"Eugene"),(47.252,-122.444,"Tacoma"),(47.658,-117.426,"Spokane"),
    (46.877,-96.789,"Fargo"),(44.986,-93.258,"Saint Paul"),(38.627,-90.198,"St. Louis"),
    (39.961,-82.999,"Columbus"),(36.116,-115.175,"Henderson"),(35.384,-94.399,"Fort Smith"),
    (30.696,-88.043,"Mobile"),(32.783,-96.817,"Dallas"),(31.428,-100.451,"San Angelo"),
    (19.429,-99.128,"Mexico City"),(20.659,-103.349,"Guadalajara"),(25.686,-100.316,"Monterrey"),
    (31.746,-106.439,"Ciudad Juarez"),(19.042,-98.198,"Puebla"),(20.967,-89.623,"Merida"),
    (23.634,-102.553,"Aguascalientes"),(25.793,-108.985,"Los Mochis"),(29.072,-110.977,"Hermosillo"),
    (-34.612,-58.37,"Buenos Aires"),(-31.42,-64.183,"Cordoba-AR"),(-32.889,-68.845,"Mendoza"),
    (-26.816,-65.223,"San Miguel de Tucuman"),(-24.782,-65.423,"Salta"),
    (-23.549,-46.633,"Sao Paulo"),(-22.903,-43.172,"Rio de Janeiro"),(-15.78,-47.929,"Brasilia"),
    (-12.971,-38.501,"Salvador"),(-3.119,-60.022,"Manaus"),(-3.717,-38.543,"Fortaleza"),
    (-8.05,-34.9,"Recife"),(-25.435,-49.271,"Curitiba"),(-30.033,-51.23,"Porto Alegre"),
    (-19.921,-43.94,"Belo Horizonte"),(-10.913,-37.073,"Aracaju"),(-7.115,-34.861,"Joao Pessoa"),
    (4.711,-74.073,"Bogota"),(10.48,-66.904,"Caracas"),(10.654,-71.661,"Maracaibo"),
    (-0.229,-78.524,"Quito"),(-2.19,-79.888,"Guayaquil"),(-33.457,-70.648,"Santiago"),
    (-16.5,-68.15,"La Paz"),(-17.39,-66.157,"Cochabamba"),(-25.286,-57.647,"Asuncion"),
    (-34.901,-56.165,"Montevideo"),(9.928,-84.091,"San Jose CR"),(-12.046,-77.043,"Lima"),
    (11.866,-15.598,"Bissau"),(5.56,-0.207,"Accra"),(6.367,2.426,"Cotonou"),
    (6.455,3.384,"Lagos"),(4.061,9.742,"Douala"),(3.848,11.502,"Yaounde"),
    (-4.325,15.322,"Kinshasa"),(9.076,7.399,"Abuja"),(11.105,4.42,"Birnin Kebbi"),
    (15.552,32.532,"Khartoum"),(9.024,38.747,"Addis Ababa"),(-1.286,36.82,"Nairobi"),
    (-0.316,36.07,"Nakuru"),(-4.043,39.668,"Mombasa"),(-6.173,35.739,"Dodoma"),
    (-6.8,39.283,"Dar es Salaam"),(-13.967,33.787,"Lilongwe"),(-15.416,28.283,"Lusaka"),
    (-17.825,31.053,"Harare"),(-25.891,32.605,"Maputo"),(-26.204,28.047,"Johannesburg"),
    (-33.926,18.424,"Cape Town"),(-29.858,31.029,"Durban"),(-25.747,28.188,"Pretoria"),
    (33.59,-7.619,"Casablanca"),(34.02,-6.83,"Rabat"),(31.956,35.945,"Amman"),
    (33.511,36.291,"Damascus"),(33.887,35.495,"Beirut"),(32.109,34.855,"Tel Aviv"),
    (31.771,35.217,"Jerusalem"),(30.048,31.244,"Cairo"),(25.204,55.271,"Dubai"),
    (24.466,54.367,"Abu Dhabi"),(26.217,50.196,"Manama"),(25.285,51.531,"Doha"),
    (21.543,39.173,"Jeddah"),(24.688,46.722,"Riyadh"),(23.614,58.593,"Muscat"),
    (15.369,44.191,"Sanaa"),(38.56,68.774,"Dushanbe"),(41.299,69.24,"Tashkent"),
    (42.87,74.59,"Bishkek"),(37.948,58.381,"Ashgabat"),(51.18,71.446,"Astana"),
    (40.409,49.867,"Baku"),(41.694,44.834,"Tbilisi"),(40.183,44.515,"Yerevan"),
    (27.717,85.318,"Kathmandu"),(23.761,90.389,"Dhaka"),(6.914,79.973,"Colombo"),
    (-33.8672,151.1997,"Sydney"),(-37.814,144.963,"Melbourne"),(-27.468,153.028,"Brisbane"),
    (-31.952,115.861,"Perth"),(-34.929,138.601,"Adelaide"),(-33.869,151.209,"Sydney North"),
    (-36.848,174.763,"Auckland"),(-41.286,174.776,"Wellington"),(-43.532,172.637,"Christchurch"),
    (-36.866,174.77,"Auckland North"),(-45.878,170.502,"Dunedin"),
    (14.093,-87.206,"Tegucigalpa"),(12.136,-86.313,"Managua"),(13.699,-89.191,"San Salvador"),
    (15.499,-88.025,"San Pedro Sula"),(8.994,-79.519,"Panama City"),
    (18.074,-76.808,"Kingston"),(18.466,-66.106,"San Juan PR"),(19.451,-99.127,"Tlalnepantla"),
    (23.132,-82.378,"Havana"),(18.476,-69.895,"Santo Domingo"),(19.451,-72.337,"Port-au-Prince"),
    (-33.45,-70.673,"Santiago CL"),(-16.5,-68.15,"La Paz BO"),
    (59.3247,18.056,"Stockholm"),(58.97,5.733,"Stavanger"),
    (46.0551,14.5051,"Ljubljana"),(45.815,15.982,"Zagreb"),
    (43.842,18.428,"Sarajevo"),(41.996,21.431,"Skopje"),(42.441,19.263,"Podgorica"),
    (41.33,19.82,"Tirana"),(55.87,9.837,"Silkeborg"),(57.046,9.92,"Aalborg"),
    (47.162,27.59,"Iasi"),(46.567,26.914,"Bacau"),(44.0,28.658,"Constanta"),
    (46.074,23.58,"Alba Iulia"),(45.648,25.606,"Brasov"),(47.658,23.568,"Baia Mare"),
]

def nearest_city(lat, lon):
    """Gibt den Namen der nächstgelegenen Stadt aus _CITIES zurück."""
    best_name = ""
    best_dist = float("inf")
    for clat, clon, name in _CITIES:
        # Schnelle euklidische Näherung (reicht für unsere Zwecke)
        d = (lat - clat) ** 2 + (lon - clon) ** 2
        if d < best_dist:
            best_dist = d
            best_name = name
    # Nur zurückgeben wenn innerhalb ~500km (ca. 25 Grad²)
    return best_name if best_dist < 25.0 else ""

def sanitize_label(val):
    if val is None:
        return ""
    return str(val).replace('"', "'").replace('\\', '/').replace('\n', ' ')

def clean_scenario(scenario):
    if "/" in scenario:
        return scenario.split("/", 1)[1]
    return scenario

def load_metrics():
    if not os.path.exists(DB_PATH):
        return f"# ERROR: DB nicht gefunden: {DB_PATH}\n"

    cutoff    = int(time.time()) - (DAYS_BACK * 86400)
    lines     = []
    seen      = set()
    flow_data = {}  # flow_key -> {src_lat, src_lon, country, scenario, ip, count}

    try:
        conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True, timeout=5)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        cur.execute("""
            SELECT
                a.id,
                a.created_at,
                a.scenario,
                a.source_value     AS ip,
                a.source_country   AS country,
                a.source_as_name   AS as_name,
                a.source_as_number AS as_number,
                a.source_range     AS ip_range,
                a.source_latitude  AS latitude,
                a.source_longitude AS longitude,
                COALESCE(d.type, 'ban') AS decision_type,
                CASE WHEN d.id IS NOT NULL THEN 1 ELSE 0 END AS active_ban
            FROM alerts a
            LEFT JOIN decisions d ON d.alert_decisions = a.id
            WHERE a.created_at >= ?
            ORDER BY a.created_at DESC
        """, (cutoff,))

        rows = cur.fetchall()
        conn.close()

        lines.append("# HELP cs_lapi_realtime CrowdSec realtime alerts")
        lines.append("# TYPE cs_lapi_realtime gauge")

        country_counts  = {}
        scenario_counts = {}
        total = 0

        for row in rows:
            ip         = row["ip"] or ""
            country    = row["country"] or "??"
            as_name    = row["as_name"] or "unknown"
            as_number  = str(row["as_number"] or "0")
            ip_range   = row["ip_range"] or "-"
            decision   = row["decision_type"] or "ban"
            active_ban = int(row["active_ban"] or 0)
            scenario   = row["scenario"] or "unknown"
            created_at = row["created_at"]
            db_lat     = row["latitude"]
            db_lon     = row["longitude"]

            # Grundfilter
            if not ip or scenario == "unknown":
                continue
            if ip in _unbanned_ips:
                continue  # manuell entsperrt — nicht mehr anzeigen
            if as_number == "0" and ip_range in ("-", "ban", ""):
                continue

            # Timestamp validieren
            try:
                if isinstance(created_at, str):
                    created_at = created_at.replace("Z", "").replace("T", " ").split(".")[0]
                    dt = datetime.strptime(created_at, "%Y-%m-%d %H:%M:%S")
                    dt = dt.replace(tzinfo=timezone.utc)
                else:
                    dt = datetime.fromtimestamp(created_at, tz=timezone.utc)
                unix_ts = int(dt.timestamp())
                if unix_ts < 1000000000:
                    continue
            except Exception:
                continue

            attack_time_de  = dt.strftime("%d.%m.%Y %H:%M:%S")
            attack_time_iso = dt.strftime("%Y-%m-%d %H:%M:%S")

            # Geo
            if db_lat and db_lon and (db_lat != 0.0 or db_lon != 0.0):
                lat, lon = db_lat, db_lon
                city = ""
                if _mmdb:
                    r = _mmdb.get(ip)
                    if r:
                        city = r.get("city", "")
                # Fallback: nächste Stadt aus Koordinaten
                if not city:
                    city = nearest_city(lat, lon)
            else:
                lat, lon, city = geo_lookup(ip, country)

            # Szenario bereinigen
            scenario_clean = clean_scenario(scenario)

            # Flow-Daten für Vaduga MapGL sammeln
            flow_key = f"{round(lat, 2)},{round(lon, 2)}"
            if flow_key not in flow_data:
                flow_data[flow_key] = {
                    "src_lat":  lat,
                    "src_lon":  lon,
                    "country":  country,
                    "city":     city,
                    "scenario": scenario_clean,
                    "ip":       ip,
                    "count":    0,
                }
            flow_data[flow_key]["count"] += 1

            # cs_lapi_realtime Metrik schreiben
            labels = {
                "instance":        sanitize_label(socket.gethostbyname(socket.gethostname())),
                "country":         sanitize_label(country),
                "city":            sanitize_label(city),
                "asname":          sanitize_label(as_name),
                "asnumber":        sanitize_label(as_number),
                "iprange":         sanitize_label(ip_range),
                "ip":              sanitize_label(ip),
                "type":            sanitize_label(decision),
                "scenario":        sanitize_label(scenario_clean),
                "latitude":        str(round(lat, 4)),
                "longitude":       str(round(lon, 4)),
                "attack_time":     sanitize_label(attack_time_de),
                "attack_time_iso": sanitize_label(attack_time_iso),
                "active_ban":      str(active_ban),
            }
            label_str = ",".join(f'{k}="{v}"' for k, v in labels.items())
            lines.append(f"cs_lapi_realtime{{{label_str}}} 1")

            total += 1
            country_counts[country]         = country_counts.get(country, 0) + 1
            scenario_counts[scenario_clean] = scenario_counts.get(scenario_clean, 0) + 1

        # Aggregiert pro Land
        lines.append("# HELP cs_attacks_by_country Total attacks per country")
        lines.append("# TYPE cs_attacks_by_country gauge")
        for cc, count in sorted(country_counts.items(), key=lambda x: -x[1]):
            lat, lon = geo_fallback(cc)
            lines.append(f'cs_attacks_by_country{{country="{cc}",latitude="{lat}",longitude="{lon}"}} {count}')

        # Aggregiert pro Szenario
        lines.append("# HELP cs_attacks_by_scenario Total attacks per scenario")
        lines.append("# TYPE cs_attacks_by_scenario gauge")
        for sc, count in sorted(scenario_counts.items(), key=lambda x: -x[1]):
            lines.append(f'cs_attacks_by_scenario{{scenario="{sc}"}} {count}')

        # Flow-Metriken (Angriffspfeile zum Server)
        lines.append("# HELP cs_attack_flow Attack flows from attacker to server")
        lines.append("# TYPE cs_attack_flow gauge")
        for fkey, fd in flow_data.items():
            lines.append(
                f'cs_attack_flow{{'
                f'src_lat="{round(fd["src_lat"], 4)}",'
                f'src_lon="{round(fd["src_lon"], 4)}",'
                f'dst_lat="{SERVER_LAT}",'
                f'dst_lon="{SERVER_LON}",'
                f'country="{sanitize_label(fd["country"])}",'
                f'city="{sanitize_label(fd.get("city",""))}",'
                f'scenario="{sanitize_label(fd["scenario"])}",'
                f'ip="{sanitize_label(fd["ip"])}",'
                f'server="{SERVER_NAME}"'
                f'}} {fd["count"]}'
            )

        # Scrape-Info
        lines.append("# HELP cs_exporter_last_scrape Unix timestamp of last successful scrape")
        lines.append("# TYPE cs_exporter_last_scrape gauge")
        lines.append(f"cs_exporter_last_scrape {int(time.time())}")
        lines.append(f"cs_exporter_total_alerts {total}")

        # Whitelist-Status
        ws = _whitelist_status
        lines.append("# HELP cs_whitelist_status Dynamic whitelist status")
        lines.append("# TYPE cs_whitelist_status gauge")
        lines.append(
            f'cs_whitelist_status{{ip="{ws["ip"]}",'
            f'status="{ws["status"]}",'
            f'last_check="{ws["last_check"]}",'
            f'last_change="{ws["last_change"]}"}} 1'
        )

        log(f"✅ Metriken geladen: {total} Alerts, {len(country_counts)} Länder, "
            f"{len(scenario_counts)} Szenarien, {len(flow_data)} Flow-Quellen")

    except Exception as e:
        log(f"❌ DB-Fehler: {e}")
        return f"# ERROR: {e}\n"

    return "\n".join(lines) + "\n"


def get_metrics():
    global _cache_metrics, _cache_time
    with _cache_lock:
        if time.time() - _cache_time > CACHE_TTL:
            log("🔄 Lade Metriken neu...")
            _cache_metrics = load_metrics()
            _cache_time = time.time()
        return _cache_metrics


# ---------------------------------------------------------------------------
# HTTP Server
# ---------------------------------------------------------------------------
class MetricsHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        import json as _json
        if self.path == "/unban":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            try:
                data = _json.loads(body)
                ip = data.get("ip", "").strip()
                if not ip:
                    self._json_response(400, {"success": False, "message": "IP fehlt"})
                    return
                ok, msg = run_unban(ip)
                self._json_response(200, {"success": ok, "message": msg, "ip": ip})
            except Exception as e:
                self._json_response(400, {"success": False, "message": str(e)})
        else:
            self._json_response(404, {"error": "Not found"})

    def _json_response(self, code, data):
        import json as _json
        body = _json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        """CORS Preflight"""
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.end_headers()

    def do_GET(self):
        if self.path in ("/metrics", "/"):
            body = get_metrics().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/whitelist-status":
            import json as _json
            body = _json.dumps(_whitelist_status).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)
        else:
            self._json_response(404, {"error": "Not found"})

    def log_message(self, format, *args):
        try:
            if args and isinstance(args[0], str) and "/metrics" in args[0]:
                log(f"📡 Scrape von {self.client_address[0]}: {args[1] if len(args)>1 else ''}")
        except Exception:
            pass

    def handle_error(self, request, client_address):
        """Harmlose Verbindungsfehler (Browser schließt Tab etc.) unterdrücken"""
        import sys
        exc_type = sys.exc_info()[0]
        if exc_type in (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
            return  # still
        # Alle anderen Fehler normal loggen
        super().handle_error(request, client_address)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    log("=" * 60)
    log("🚀 CrowdSec Prometheus Exporter startet")
    log(f"   DB:     {DB_PATH}")
    log(f"   MMDB:   {MMDB_PATH}")
    log(f"   Port:   {LISTEN_PORT}")
    log(f"   TTL:    {CACHE_TTL}s")
    log(f"   Server: {SERVER_NAME} ({SERVER_LAT}, {SERVER_LON})")
    log("=" * 60)

    init_mmdb()

    # Whitelist-Hintergrund-Loop starten
    if WHITELIST_ENABLED:
        wl_thread = threading.Thread(target=_whitelist_loop, daemon=True, name="whitelist-loop")
        wl_thread.start()
        log(f"🛡️  Whitelist-Loop aktiv — Intervall: {WHITELIST_INTERVAL}s, Datei: {WHITELIST_FILE}")
    else:
        log("ℹ️  Whitelist-Loop deaktiviert (WHITELIST_ENABLED=False)")

    log("📊 Initialer Metrik-Load...")
    get_metrics()

    server = HTTPServer((LISTEN_HOST, LISTEN_PORT), MetricsHandler)
    log(f"✅ Exporter läuft auf http://{LISTEN_HOST}:{LISTEN_PORT}/metrics")
    log("   Drücke CTRL+C zum Beenden")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log("👋 Exporter gestoppt.")
        server.server_close()
