#!/bin/sh
set -e

# ============================================================
# CrowdSec Threat Map — Container Entrypoint v1.4.2
# ============================================================

log() { echo "[$(date '+%F %T')] $*"; }

log "🛡️  CrowdSec Threat Map startet..."
log "   Version: v1.4.2"

# ── Pflichtprüfungen ──
if [ -z "$SERVER_LAT" ] || [ "$SERVER_LAT" = "0.0" ]; then
    log "⚠️  SERVER_LAT nicht gesetzt! Bitte in docker-compose.yml eintragen."
fi
if [ -z "$SERVER_LON" ] || [ "$SERVER_LON" = "0.0" ]; then
    log "⚠️  SERVER_LON nicht gesetzt! Bitte in docker-compose.yml eintragen."
fi

# ── DB-Pfad prüfen ──
DB_FILE="${CROWDSEC_DB_PATH:-/crowdsec/data/crowdsec.db}"
if [ ! -f "$DB_FILE" ]; then
    log "❌ CrowdSec-Datenbank nicht gefunden: $DB_FILE"
    log "   Bitte volumes in docker-compose.yml prüfen!"
    log "   Erwartet: /crowdsec/data/crowdsec.db"
    exit 1
fi
log "✅ Datenbank gefunden: $DB_FILE"

# ── GeoLite2 prüfen ──
MMDB_FILE="${CROWDSEC_MMDB_PATH:-/crowdsec/data/GeoLite2-City.mmdb}"
if [ -f "$MMDB_FILE" ]; then
    log "✅ GeoLite2 gefunden: $MMDB_FILE (Stadtanzeige aktiv)"
else
    log "ℹ️  GeoLite2 nicht gefunden — Stadtanzeige deaktiviert"
fi

# ── Whitelist-Info ──
WL_ENABLED="${WHITELIST_ENABLED:-true}"
if [ "$WL_ENABLED" = "true" ]; then
    log "🛡️  Dynamische Whitelist: AKTIV (Interval: ${WHITELIST_INTERVAL:-900}s)"
else
    log "ℹ️  Dynamische Whitelist: deaktiviert"
fi

# ── Umgebungsvariablen exportieren (werden vom Exporter gelesen) ──
export CROWDSEC_DB_PATH="${CROWDSEC_DB_PATH:-/crowdsec/data/crowdsec.db}"
export CROWDSEC_MMDB_PATH="${CROWDSEC_MMDB_PATH:-/crowdsec/data/GeoLite2-City.mmdb}"
export SERVER_LAT="${SERVER_LAT:-0.0}"
export SERVER_LON="${SERVER_LON:-0.0}"
export SERVER_NAME="${SERVER_NAME:-MeinServer}"
export CROWDSEC_CONTAINER_NAME="${CROWDSEC_CONTAINER:-crowdsec}"
export CACHE_TTL="${CACHE_TTL:-60}"
export DAYS_BACK="${DAYS_BACK:-365}"
export WHITELIST_ENABLED="${WHITELIST_ENABLED:-true}"
export WHITELIST_FILE="${WHITELIST_FILE:-/crowdsec/postoverflows/s01-whitelist/my-whitelist.yaml}"
export WHITELIST_INTERVAL="${WHITELIST_INTERVAL:-900}"
export CROWDSEC_RESTART_WAIT="${CROWDSEC_RESTART_WAIT:-15}"

export LANGUAGE="${LANGUAGE:-de}"

# ── index.html mit korrekter Exporter-URL patchen ──
log "🔧 Dashboard konfigurieren..."

# Relative URL /metrics — nginx proxied intern zu Port 9456
METRICS_URL="${EXPORTER_URL:-/metrics}"

sed -i "s|http://EURE-UNRAID-IP:9456/metrics|${METRICS_URL}|g" \
    /var/www/html/index.html 2>/dev/null || true
sed -i "s|const SERVER_LAT   = 0.0;|const SERVER_LAT   = ${SERVER_LAT};|g" \
    /var/www/html/index.html 2>/dev/null || true
sed -i "s|const SERVER_LON   = 0.0;|const SERVER_LON   = ${SERVER_LON};|g" \
    /var/www/html/index.html 2>/dev/null || true
sed -i "s|'MEIN-SERVER'|'${SERVER_NAME}'|g" \
    /var/www/html/index.html 2>/dev/null || true

# Sprache setzen (de oder en)
LANG_VAL="${LANGUAGE:-de}"
if [ "$LANG_VAL" != "de" ] && [ "$LANG_VAL" != "en" ]; then
    log "⚠️  LANGUAGE='${LANG_VAL}' unbekannt — Fallback auf 'de'"
    LANG_VAL="de"
fi
sed -i "s|'LANGUAGE_PLACEHOLDER'|'${LANG_VAL}'|g" \
    /var/www/html/index.html 2>/dev/null || true
log "🌐 Sprache: ${LANG_VAL}"

log "✅ Dashboard konfiguriert (Exporter-URL: ${METRICS_URL})"

# ── Nginx starten ──
log "🌐 Nginx starten (Dashboard auf Port 8080)..."
nginx -g "daemon off;" &
NGINX_PID=$!

# ── Exporter starten ──
log "📡 Exporter starten (API auf Port 9456)..."
python3 /app/crowdsec_exporter.py &
EXPORTER_PID=$!

log "✅ Alles läuft!"
log "   Dashboard: http://<EURE-IP>:8080"
log "   API direkt: http://<EURE-IP>:9456/metrics (optional)"

# ── Warten und bei Absturz neu starten ──
while true; do
    if ! kill -0 $EXPORTER_PID 2>/dev/null; then
        log "⚠️  Exporter abgestürzt — Neustart..."
        python3 /app/crowdsec_exporter.py &
        EXPORTER_PID=$!
    fi
    if ! kill -0 $NGINX_PID 2>/dev/null; then
        log "⚠️  Nginx abgestürzt — Neustart..."
        nginx -g "daemon off;" &
        NGINX_PID=$!
    fi
    sleep 10
done
