# 🛡️ CrowdSec Threat Map

**Echtzeit-Angriffskarte — direkt aus eurer lokalen CrowdSec-Datenbank**

![Version](https://img.shields.io/badge/version-v1.4.1-00ffe0?style=flat-square)
![License](https://img.shields.io/badge/license-GPL--3.0-00ff88?style=flat-square)
![Platform](https://img.shields.io/badge/platform-Docker%20%7C%20Unraid-orange?style=flat-square)
![Python](https://img.shields.io/badge/python-3.12-blue?style=flat-square)
![Docker](https://img.shields.io/badge/docker-ghcr.io-2496ED?style=flat-square&logo=docker)

---

## 📸 Preview

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
- 🔊 **Sound-Alarm** bei neuen Hochrisiko-Angriffen
- 📥 **CSV-Export** des kompletten Feeds
- 📱 **Vollständig responsive** — Desktop und Mobile
- 〰️ **Linien-Toggle** — Angriffspfeile & Radar-Ringe ein-/ausblenden
- 🛡️ **Dynamische IP-Whitelist** — eigene IP automatisch alle 15 Min whitelisten
- 🟢 **Whitelist-Badge** — zeigt aktuelle IP + Status live an
- 📐 **Responsive Controls** — Buttons passen sich der Fenstergröße an

---

## 🚀 Docker-Installation (empfohlen)

### 1. docker-compose.yml anlegen

```bash
mkdir crowdsec-monitor && cd crowdsec-monitor
curl -o docker-compose.yml \
  https://raw.githubusercontent.com/kabelsalatundklartext/crowdsec-threat-map-docker/main/docker/docker-compose.yml
```

### 2. Konfigurieren

`docker-compose.yml` öffnen und anpassen:

```yaml
volumes:
  - /EUER-PFAD/data:/crowdsec/data:ro          # ⚠️ Pflicht
  - /EUER-PFAD/postoverflows:/crowdsec/postoverflows  # für Whitelist

environment:
  - SERVER_LAT=53.5753   # ⚠️ Pflicht — euer Breitengrad
  - SERVER_LON=10.0153   # ⚠️ Pflicht — euer Längengrad
  - SERVER_NAME=Hamburg  # euer Servername
```

**CrowdSec-Datenpfad herausfinden:**
```bash
docker inspect crowdsec | grep -A5 "Mounts"
# → "Source": "/euer/pfad/data"
```

**Koordinaten:** Rechtsklick auf [Google Maps](https://maps.google.com) → „Was ist hier?"

### 3. Starten

```bash
docker compose up -d
```

Dashboard: **http://EURE-IP:8080**

---

## ⚙️ Umgebungsvariablen

| Variable | Standard | Beschreibung |
|----------|----------|-------------|
| `SERVER_LAT` | `0.0` | ⚠️ Breitengrad des Servers |
| `SERVER_LON` | `0.0` | ⚠️ Längengrad des Servers |
| `SERVER_NAME` | `MeinServer` | Anzeigename im Dashboard |
| `CROWDSEC_CONTAINER` | `crowdsec` | Name des CrowdSec-Docker-Containers |
| `CACHE_TTL` | `60` | Cache-Zeit in Sekunden |
| `DAYS_BACK` | `365` | Anzahl Tage für die Anzeige |
| `WHITELIST_ENABLED` | `true` | Dynamische Whitelist aktivieren |
| `WHITELIST_FILE` | *(siehe unten)* | Pfad zur Whitelist-YAML |
| `WHITELIST_INTERVAL` | `900` | Prüfintervall in Sekunden (15 min) |

Standard-Whitelist-Pfad im Container:
`/crowdsec/postoverflows/s01-whitelist/my-whitelist.yaml`

---

## 📦 Volumes

| Container-Pfad | Beschreibung | Pflicht? |
|---------------|-------------|---------|
| `/crowdsec/data` | CrowdSec-Datenpfad (DB + optional MMDB) | ✅ Ja |
| `/crowdsec/postoverflows` | Für dynamische Whitelist | Nur wenn `WHITELIST_ENABLED=true` |
| `/var/run/docker.sock` | Für IP-Unban via `docker exec` | Nur für Unban-Button |

---

## 🛡️ Dynamische IP-Whitelist

Heimanschlüsse in Deutschland bekommen meist täglich eine neue IP. Ohne Whitelist kann CrowdSec euch selbst bannen. Der eingebaute Hintergrund-Thread prüft alle 15 Minuten eure aktuelle IP und aktualisiert die Whitelist-YAML automatisch.

**Dashboard-Badge:**

| Farbe | Bedeutung |
|-------|-----------|
| 🟢 Grün | IP gewhitelistet, alles ok |
| 🔵 Cyan | IP wurde gerade aktualisiert |
| 🔴 Rot | Fehler beim Update |

---

## 🔓 IP-Unban

Jeder Feed-Eintrag zeigt:

| Icon | Bedeutung | Klick |
|------|-----------|-------|
| 🚫 (leuchtend) | Aktiver Ban | Decision + Alert löschen |
| 📋 (leuchtend) | Nur Alert/Historie | Nur Alert löschen |

---


Für direkte Installation ohne Docker-Image:

1. `crowdsec_exporter.py` herunterladen
2. Pfade oben in der Datei anpassen (`DB_PATH`, `MMDB_PATH`, etc.)
3. Unraid → **Settings → User Scripts** → neues Script
5. `EXPORTER_PATH` anpassen → **At Startup of Array**

---

## 🛠️ Fehlerbehebung

**Dashboard leer / keine Daten:**
```bash
# Exporter-Logs prüfen
docker logs crowdsec-monitor

# API direkt testen
curl http://EURE-IP:8080/metrics | head -5
```

**Unban funktioniert nicht:**
```bash
# Container-Namen prüfen
docker ps | grep crowdsec
# → In CROWDSEC_CONTAINER eintragen

# Docker-Socket prüfen
ls -la /var/run/docker.sock
```

**Whitelist-Fehler:**
```bash
# Status abrufen
curl http://EURE-IP:8080/whitelist-status

# Häufige Ursache: postoverflows-Volume nicht eingebunden
# → docker-compose.yml prüfen
```

**Keine Stadtanzeige:**
→ `GeoLite2-City.mmdb` ins CrowdSec-Datenverzeichnis legen
→ [MaxMind kostenlos herunterladen](https://www.maxmind.com/en/geolite2/signup)

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
