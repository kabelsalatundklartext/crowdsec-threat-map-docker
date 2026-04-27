# 🛡️ CrowdSec Threat Map

**Real-time attack map — directly from your local CrowdSec database**

![Version](https://img.shields.io/badge/version-v1.4.2-00ffe0?style=flat-square)
![License](https://img.shields.io/badge/license-GPL--3.0-00ff88?style=flat-square)
![Platform](https://img.shields.io/badge/platform-Docker%20%7C%20Unraid-orange?style=flat-square)
![Python](https://img.shields.io/badge/python-3.12-blue?style=flat-square)
![Docker](https://img.shields.io/badge/docker-ghcr.io-2496ED?style=flat-square&logo=docker)

---

# 🇬🇧 English

## 📸 Preview

> Interactive world map · Animated attack lines · Live feed · Mobile-ready

![CrowdSec Threat Map](preview.png)

---

## ✨ Features

- 🌍 **Interactive world map** with animated attack lines (D3.js)
- 🎯 **Auto-fit zoom** — automatically keeps all attack points visible
- 🔍 **Real-time search** by IP, country, city, scenario, ASN
- 🚫📋 **Ban status indicator** — 🚫 active ban / 📋 alert-history only
- 🔓 **IP unban** directly from the dashboard — removes Decision AND Alert
- 📊 **Sparkline** — attacks per hour at a glance
- 🎨 **4 color themes** — Cyan, Alarm Red, Matrix Green, Amber
- 📥 **CSV export** — directly next to the feed pagination
- 📱 **Fully responsive** — desktop and mobile
- 〰️ **Line toggle** — enable/disable attack lines & radar rings
- 🛡️ **Dynamic IP whitelist** — automatically whitelists your current IP every 15 min
- 🟢 **Whitelist badge** — shows current IP + live status in dashboard
- 🌐 **Language via variable** — `LANGUAGE=de` or `LANGUAGE=en` in docker-compose
- 🏙️ **Localized city names** — Nuremberg instead of Nürnberg, Munich instead of München, etc.
- 📍 **Corrected GeoIP** — Vogtland/Plauen shown correctly instead of wrong border region

---

## 🚀 Installation — Unraid (App Store)

### 1. Open App Store

Unraid → **Apps** → Search: `crowdsec-threat-map` → Install

### 2. Fill required fields

| Unraid | Example | Description |
|------|---------|-------------|
| **Server Latitude** | `52.5200` | ⚠️ Required — your server latitude |
| **Server Longitude** | `13.4050` | ⚠️ Required — your server longitude |
| Path `/crowdsec/data` | `/mnt/user/Docker/crowdsec/data` | ⚠️ Required — path to your CrowdSec data |
| Path `/crowdsec/postoverflows` | `/mnt/user/Docker/crowdsec/postoverflows` | Required for dynamic whitelist |
| Port `8080` | `8080` | Dashboard port (freely selectable) |

> **Find coordinates:** Right click on [Google Maps](https://maps.google.com) → “What’s here?”

> **Find CrowdSec path:**
> ```bash
> docker inspect crowdsec | grep -A5 "Mounts"
> # → "Source": "/mnt/user/Docker/crowdsec/data"
> ```

### 3. Optional settings

| Field | Default | Description |
|------|----------|-------------|
| Variable `SERVER_NAME` | `MyServer` | Display name on the map |
| Variable `CROWDSEC_CONTAINER` | `crowdsec` | Name of the CrowdSec container |
| Variable `WHITELIST_ENABLED` | `true` | Prevents self-ban on IP changes |
| Variable `LANGUAGE` | `en` | Language: `de` or `en` |

### 4. Start

Click **Apply** → container starts automatically.

Dashboard: **http://YOUR-UNRAID-IP:8080**

---

## 🚀 Installation — Docker

```bash
docker run -d \
  --name crowdsec-monitor \
  --restart unless-stopped \
  -p 8080:8080 \
  -v /path/to/crowdsec/data:/crowdsec/data:ro \
  -v /path/to/crowdsec/postoverflows:/crowdsec/postoverflows \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  --group-add 999 \
  -e SERVER_LAT=52.5200 \
  -e SERVER_LON=13.4050 \
  -e SERVER_NAME=Berlin \
  -e LANGUAGE=en \
  ghcr.io/kabelsalatundklartext/crowdsec-threat-map-docker:latest
```

Or with `docker-compose.yml` — the latest version is available in the repository under `docker/docker-compose.yml`.

---

## ⚙️ All Variables

| Variable | Default | Description |
|----------|----------|-------------|
| `SERVER_LAT` | `0.0` | ⚠️ Server latitude |
| `SERVER_LON` | `0.0` | ⚠️ Server longitude |
| `SERVER_NAME` | `MyServer` | Display name on the map |
| `LANGUAGE` | `en` | UI language: `de` or `en` |
| `CROWDSEC_CONTAINER` | `crowdsec` | Name of the CrowdSec Docker container |
| `CROWDSEC_DB_PATH` | `/crowdsec/data/crowdsec.db` | Path to CrowdSec SQLite DB |
| `CROWDSEC_MMDB_PATH` | `/crowdsec/data/GeoLite2-City.mmdb` | Path to GeoIP database |
| `CACHE_TTL` | `60` | Cache time in seconds |
| `DAYS_BACK` | `365` | Number of days to display |
| `WHITELIST_ENABLED` | `true` | Enable dynamic whitelist |
| `WHITELIST_FILE` | `/crowdsec/postoverflows/`<br>`s01-whitelist/my-whitelist.yaml` | Path to whitelist YAML |
| `WHITELIST_INTERVAL` | `900` | Check interval in seconds (15 min) |
| `CROWDSEC_RESTART_WAIT` | `15` | Wait time after CrowdSec restart (sec.) |

---

## 📦 Volumes

| Host Path | Container Path | Description | Required? |
|-----------|---------------|-------------|---------|
| `/path/to/crowdsec/data` | `/crowdsec/data:ro` | CrowdSec DB + GeoIP MMDB | ✅ Yes |
| `/path/to/crowdsec/postoverflows` | `/crowdsec/postoverflows` | For dynamic whitelist | Only if `WHITELIST_ENABLED=true` |
| `/var/run/docker.sock` | `/var/run/docker.sock:ro` | For IP unban + whitelist restart | Only for unban button |

---

## 🛡️ Dynamic IP Whitelist

Most home internet connections get a new public IP regularly. Without a whitelist, CrowdSec may ban your own connection.  
The built-in background thread checks your current public IP every 15 minutes and updates the whitelist YAML automatically.

**Requirements:**
- `WHITELIST_ENABLED=true` (default)
- Volume `/crowdsec/postoverflows` mounted
- `/var/run/docker.sock` mounted
- Correct Docker GID set (`--group-add 999` or `group_add` in Unraid)

**How it works:**
1. Exporter detects your current public IP
2. Compares it with the current whitelist YAML
3. If changed: YAML gets updated, CrowdSec restarts
4. Restart wait time configurable via `CROWDSEC_RESTART_WAIT`

**Dashboard badge:**

| Color | Meaning |
|-------|---------|
| 🟢 Green | IP whitelisted, all good |
| 🔵 Cyan | IP was just updated |
| 🔴 Red | Update error |

---

## 🔓 IP Unban

Each feed entry shows the ban status directly:

| Icon | Meaning | Click |
|------|---------|-------|
| 🚫 (glowing) | Active ban exists | Remove Decision + Alert |
| 📋 (glowing) | Alert/history only | Remove Alert only |

---

## 🗺️ GeoIP & City Display

Without a GeoIP database, only country markers are shown — no city data.

**Setup GeoLite2-City.mmdb:**
1. Register for free: [MaxMind GeoLite2](https://www.maxmind.com/en/geolite2/signup)
2. Download `GeoLite2-City.mmdb`
3. Place it in your CrowdSec data folder (same folder as `crowdsec.db`)
4. Restart container

---

## 🛠️ Troubleshooting

**Dashboard empty / no data:**
```bash
docker logs crowdsec-monitor
curl http://YOUR-IP:8080/metrics | head -10
```

**Wrong CrowdSec path:**
```bash
docker inspect crowdsec | grep -A5 "Mounts"
```

**Unban does not work:**
```bash
# Check Docker GID
getent group docker | cut -d: -f3
# → Add in Unraid under "Extra Parameters" as --group-add
```

**Whitelist error:**
```bash
curl http://YOUR-IP:8080/whitelist-status
```

**Dashboard shows connection error:**
```bash
# Check whether entrypoint.sh set the correct URL
docker exec crowdsec-monitor grep "EXPORTER_URL" /var/www/html/index.html
# → Should show '/metrics'
```

---

## 📋 Changelog

Full version history → [CHANGELOG.md](CHANGELOG.md)

---

## 🔗 Links

- [MaxMind GeoLite2](https://www.maxmind.com/en/geolite2/signup) — free GeoIP database
- [CrowdSec Docker Hub](https://hub.docker.com/r/crowdsecurity/crowdsec)
- [CrowdSec Docs](https://docs.crowdsec.net)

---

## 📄 License

**GNU General Public License v3.0 (GPL-3.0)**

| | |
|--|--|
| ✅ Private & homelab use | ✅ Modify & customize |
| ✅ Redistribute & share | ✅ Publish own versions |
| ✅ Commercial use allowed | ❌ No closed-source forks |
| ✅ Forks must remain GPL-3.0 | ✅ Source code must stay open |

When redistributing or publishing: keep attribution + GPL-3.0 license.
> *"CrowdSec Threat Map" by kabelsalatundklartext — [GitHub](https://github.com/kabelsalatundklartext/crowdsec-threat-map-docker)*

---

# 🇩🇪 Deutsch

## 📸 Vorschau

> Interaktive Weltkarte · Animierte Angriffspfeile · Live-Feed · Mobile-ready

![CrowdSec Threat Map](preview.png)

---

## ✨ Features

- 🌍 **Interaktive Weltkarte** mit animierten Angriffspfeilen (D3.js)
- 🎯 **Auto-Fit Zoom** — alle Angriffspunkte automatisch sichtbar
- 🔍 **Echtzeit-Suche** nach IP, Land, Stadt, Szenario, ASN
- 🚫📋 **Ban-Status-Anzeige** — 🚫 aktiver Ban / 📋 nur Alert/Historie
- 🔓 **IP-Unban** direkt aus dem Dashboard — löscht Decision UND Alert
- 📊 **Sparkline** — Angriffe/Stunde auf einen Blick
- 🎨 **4 Farbthemen** — Cyan, Alarm-Rot, Matrix-Grün, Amber
- 📥 **CSV-Export** — direkt neben den Feed-Seitenzahlen
- 📱 **Vollständig responsive** — Desktop und Mobile
- 〰️ **Linien-Toggle** — Angriffspfeile & Radar-Ringe ein-/ausblenden
- 🛡️ **Dynamische IP-Whitelist** — eigene IP automatisch alle 15 Min whitelisten
- 🟢 **Whitelist-Badge** — zeigt aktuelle IP + Status live im Dashboard
- 🌐 **Sprache per Variable** — `LANGUAGE=de` oder `LANGUAGE=en` in docker-compose
- 🏙️ **Lokalisierte Stadtnamen** — Nürnberg statt Nuremberg, München statt Munich etc.
- 📍 **Korrigierte GeoIP** — Vogtland/Plauen korrekt statt falscher Grenzregion

---

## 🚀 Installation — Unraid (App Store)

### 1. App Store öffnen

Unraid → **Apps** → Suchfeld: `crowdsec-threat-map` → Installieren

### 2. Pflichtfelder ausfüllen

| Unraid | Beispiel | Beschreibung |
|------|---------|-------------|
| **Server Breitengrad** | `52.5200` | ⚠️ Pflicht — euer Breitengrad |
| **Server Längengrad** | `13.4050` | ⚠️ Pflicht — euer Längengrad |
| Pfad `/crowdsec/data` | `/mnt/user/Docker/crowdsec/data` | ⚠️ Pflicht — Pfad zu euren CrowdSec-Daten |
| Pfad `/crowdsec/postoverflows` | `/mnt/user/Docker/crowdsec/postoverflows` | Für dynamische Whitelist |
| Port `8080` | `8080` | Port für das Dashboard (frei wählbar) |

> **Koordinaten finden:** Rechtsklick auf [Google Maps](https://maps.google.com) → „Was ist hier?"

> **CrowdSec-Pfad finden:**
> ```bash
> docker inspect crowdsec | grep -A5 "Mounts"
> # → "Source": "/mnt/user/Docker/crowdsec/data"
> ```

### 3. Optionale Einstellungen

| Feld | Standard | Beschreibung |
|------|----------|-------------|
| Variable `SERVER_NAME` | `MeinServer` | Anzeigename auf der Karte |
| Variable `CROWDSEC_CONTAINER` | `crowdsec` | Name des CrowdSec-Containers |
| Variable `WHITELIST_ENABLED` | `true` | Schützt vor Selbst-Ban bei IP-Wechsel |
| Variable `LANGUAGE` | `de` | Sprache: `de` oder `en` |

### 4. Starten

Auf **Anwenden** klicken → Container startet automatisch.

Dashboard: **http://EURE-UNRAID-IP:8080**

---

## 🚀 Installation — Docker

```bash
docker run -d \
  --name crowdsec-monitor \
  --restart unless-stopped \
  -p 8080:8080 \
  -v /pfad/zu/crowdsec/data:/crowdsec/data:ro \
  -v /pfad/zu/crowdsec/postoverflows:/crowdsec/postoverflows \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  --group-add 999 \
  -e SERVER_LAT=52.5200 \
  -e SERVER_LON=13.4050 \
  -e SERVER_NAME=Berlin \
  -e LANGUAGE=de \
  ghcr.io/kabelsalatundklartext/crowdsec-threat-map-docker:latest
```

Oder mit `docker-compose.yml` — die aktuelle Version findet ihr im Repository unter `docker/docker-compose.yml`.

---

## ⚙️ Alle Variablen

| Variable | Standard | Beschreibung |
|----------|----------|-------------|
| `SERVER_LAT` | `0.0` | ⚠️ Breitengrad des Servers |
| `SERVER_LON` | `0.0` | ⚠️ Längengrad des Servers |
| `SERVER_NAME` | `MeinServer` | Anzeigename auf der Karte |
| `LANGUAGE` | `de` | Sprache der Oberfläche: `de` oder `en` |
| `CROWDSEC_CONTAINER` | `crowdsec` | Name des CrowdSec-Docker-Containers |
| `CROWDSEC_DB_PATH` | `/crowdsec/data/crowdsec.db` | Pfad zur CrowdSec SQLite-DB |
| `CROWDSEC_MMDB_PATH` | `/crowdsec/data/GeoLite2-City.mmdb` | Pfad zur GeoIP-Datenbank |
| `CACHE_TTL` | `60` | Cache-Zeit in Sekunden |
| `DAYS_BACK` | `365` | Anzahl Tage für die Anzeige |
| `WHITELIST_ENABLED` | `true` | Dynamische Whitelist aktivieren |
| `WHITELIST_FILE` | `/crowdsec/postoverflows/`<br>`s01-whitelist/my-whitelist.yaml` | Pfad zur Whitelist-YAML |
| `WHITELIST_INTERVAL` | `900` | Prüfintervall in Sekunden (15 min) |
| `CROWDSEC_RESTART_WAIT` | `15` | Wartezeit nach CrowdSec-Neustart (Sek.) |

---

## 📦 Volumes

| Host-Pfad | Container-Pfad | Beschreibung | Pflicht? |
|-----------|---------------|-------------|---------|
| `/pfad/zu/crowdsec/data` | `/crowdsec/data:ro` | CrowdSec DB + GeoIP-MMDB | ✅ Ja |
| `/pfad/zu/crowdsec/postoverflows` | `/crowdsec/postoverflows` | Für dynamische Whitelist | Nur wenn `WHITELIST_ENABLED=true` |
| `/var/run/docker.sock` | `/var/run/docker.sock:ro` | Für IP-Unban + Whitelist-Neustart | Nur für Unban-Button |

---

## 🛡️ Dynamische IP-Whitelist

Heimanschlüsse bekommen meist täglich eine neue IP. Ohne Whitelist kann CrowdSec euch selbst bannen. Der eingebaute Hintergrund-Thread prüft alle 15 Minuten eure aktuelle öffentliche IP und aktualisiert die Whitelist-YAML automatisch.

**Voraussetzungen:**
- `WHITELIST_ENABLED=true` (Standard)
- Volume `/crowdsec/postoverflows` eingebunden
- `/var/run/docker.sock` eingebunden
- Docker-GID korrekt gesetzt (`--group-add 999` bzw. in Unraid über `group_add`)

**Wie es funktioniert:**
1. Exporter ermittelt eure aktuelle öffentliche IP
2. Vergleich mit der aktuellen Whitelist-YAML
3. Bei Änderung: YAML wird aktualisiert, CrowdSec wird neu gestartet
4. Wartezeit nach Neustart konfigurierbar via `CROWDSEC_RESTART_WAIT`

**Dashboard-Badge:**

| Farbe | Bedeutung |
|-------|-----------|
| 🟢 Grün | IP gewhitelistet, alles ok |
| 🔵 Cyan | IP wurde gerade aktualisiert |
| 🔴 Rot | Fehler beim Update |

---

## 🔓 IP-Unban

Jeder Feed-Eintrag zeigt den Ban-Status direkt an:

| Icon | Bedeutung | Klick |
|------|-----------|-------|
| 🚫 (leuchtend) | Aktiver Ban vorhanden | Decision + Alert löschen |
| 📋 (leuchtend) | Nur Alert/Historie | Nur Alert löschen |

---

## 🗺️ GeoIP & Stadtanzeige

Ohne GeoIP-Datenbank werden keine Städte angezeigt, nur Länderpunkte.

**GeoLite2-City.mmdb einrichten:**
1. Kostenlos registrieren: [MaxMind GeoLite2](https://www.maxmind.com/en/geolite2/signup)
2. `GeoLite2-City.mmdb` herunterladen
3. In euren CrowdSec-Datenordner legen (gleicher Ordner wie `crowdsec.db`)
4. Container neu starten

---

## 🛠️ Fehlerbehebung

**Dashboard leer / keine Daten:**
```bash
docker logs crowdsec-monitor
curl http://EURE-IP:8080/metrics | head -10
```

**Falscher CrowdSec-Pfad:**
```bash
docker inspect crowdsec | grep -A5 "Mounts"
```

**Unban funktioniert nicht:**
```bash
# Docker-GID prüfen
getent group docker | cut -d: -f3
# → In Unraid unter "Extra Parameters" als --group-add eintragen
```

**Whitelist-Fehler:**
```bash
curl http://EURE-IP:8080/whitelist-status
```

**Dashboard zeigt Verbindungsfehler:**
```bash
# Prüfen ob entrypoint.sh die URL korrekt gesetzt hat
docker exec crowdsec-monitor grep "EXPORTER_URL" /var/www/html/index.html
# → Sollte '/metrics' zeigen
```

---

## 📋 Changelog

Vollständige Versionshistorie → [CHANGELOG.md](CHANGELOG.md)

---

## 🔗 Links

- [MaxMind GeoLite2](https://www.maxmind.com/en/geolite2/signup) — kostenlose GeoIP-Datenbank
- [CrowdSec Docker Hub](https://hub.docker.com/r/crowdsecurity/crowdsec)
- [CrowdSec Docs](https://docs.crowdsec.net)

---

## 📄 Lizenz

**GNU General Public License v3.0 (GPL-3.0)**

| | |
|--|--|
| ✅ Privat & Homelab nutzen | ✅ Verändern & anpassen |
| ✅ Weitergeben & teilen | ✅ Eigene Versionen veröffentlichen |
| ✅ Kommerzieller Einsatz erlaubt | ❌ Closed-Source-Abwandlungen verboten |
| ✅ Forks müssen GPL-3.0 bleiben | ✅ Quellcode muss immer offen bleiben |

Bei Weitergabe oder Veröffentlichung: Namensnennung + GPL-3.0-Lizenz beibehalten.
> *"CrowdSec Threat Map" von kabelsalatundklartext — [GitHub](https://github.com/kabelsalatundklartext/crowdsec-threat-map-docker)*
