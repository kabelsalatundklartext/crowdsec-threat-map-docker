# Unraid Community Applications Template

## Für Nutzer — manuell hinzufügen

Falls das Template noch nicht in CA gelistet ist:

1. Unraid → **Apps** → oben rechts **"..." → "Add"**
2. URL eintragen:
   ```
   https://raw.githubusercontent.com/kabelsalatundklartext/crowdsec-threat-map/main/unraid/crowdsec-threat-map.xml
   ```
3. Speichern → in CA nach "CrowdSec" suchen

---

## Icon

Das `icon.png` wird von CA als App-Icon angezeigt.
Empfohlene Größe: **128×128px PNG**, freigestelltes Shield-Icon in Cyan (#00ffe0).

Falls kein Icon vorhanden, fällt CA auf das Docker-Image-Label zurück.

---

## Offiziell in CA eintragen (für Maintainer)

Um das Template offiziell in Community Applications zu listen:

1. Fork von [Squidly271/CA_AutoUpdate_Apps](https://github.com/Squidly271/CA_AutoUpdate_Apps) erstellen
2. Repo-URL zu `data/plugins.json` hinzufügen
3. Pull Request stellen

Alternativ: im [Unraid Forum](https://forums.unraid.net/forum/35-docker-containers/) einen Thread erstellen und CA-Maintainer (@Squid) taggen.

---

## Template-Felder Übersicht

| Feld | Wert |
|------|------|
| Pflicht-Variablen | `SERVER_LAT`, `SERVER_LON`, `SERVER_NAME`, `CROWDSEC_CONTAINER` |
| Optionale Variablen | `WHITELIST_ENABLED`, `WHITELIST_INTERVAL`, `CACHE_TTL`, `DAYS_BACK`, `CROWDSEC_RESTART_WAIT` |
| Ports | `8080` (Dashboard) |
| Volumes | `/crowdsec/data` (ro), `/crowdsec/postoverflows` (rw), `/var/run/docker.sock` (ro) |
| Extra Params | `--group-add 999` (Docker-Socket-Zugriff) |
