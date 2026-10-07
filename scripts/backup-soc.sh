#!/usr/bin/env bash
# =============================================================================
# backup-soc.sh — nightly backup of the SOC state on VPS2 (same shape as
# SURF's scripts/backup-db.sh on VPS1).
#
# What is saved (all small, < 20 MB together):
#   pg_<ts>.sql.gz          Postgres: incidents, hashchain, users, rules state
#   wazuh-etc_<ts>.tgz      Wazuh manager etc: ossec.conf, client.keys (agent
#                           enrolment!), shared agent.conf, local rules
#   grafana-data_<ts>.tgz   dashboards / data sources
#   minio-data_<ts>.tgz     evidence bucket
# NOT saved: OpenSearch (replayable events, ~400 MB+), Loki/Tempo/Prometheus.
#
# Usage (manual):   bash scripts/backup-soc.sh
# Cron (03:30 UTC, keep 30 days):
#   30 3 * * * /opt/soc/scripts/backup-soc.sh >> /var/log/soc-backup.log 2>&1
#
# Restore hints:
#   zcat pg_<ts>.sql.gz | docker compose ... exec -T postgres psql -U "$PG_USER" "$PG_DB"
#   docker run --rm -v surf-security-companion_wazuh-etc:/dst -v /var/backups/soc:/src alpine \
#     sh -c 'cd /dst && tar xzf /src/wazuh-etc_<ts>.tgz'   (container stopped first)
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

COMPOSE="docker compose -f docker-compose.yml -f docker-compose.prod.yml"
PROJECT="${COMPOSE_PROJECT_NAME:-surf-security-companion}"   # = `name:` in docker-compose.yml
BACKUP_DIR="${BACKUP_DIR:-/var/backups/soc}"
KEEP_DAYS="${KEEP_DAYS:-30}"
TS="$(date +%Y%m%d_%H%M%S)"
VOLUMES="wazuh-etc grafana-data minio-data"

if [[ -f .env ]]; then
  set -a
  # shellcheck source=/dev/null
  source .env
  set +a
fi
PG_USER="${PG_USER:-soc}"
PG_DB="${PG_DB:-soc}"

mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

log() { echo "[$(date -Iseconds)] $*"; }

# --- 1. Postgres -------------------------------------------------------------
PG_FILE="${BACKUP_DIR}/pg_${TS}.sql.gz"
log "pg_dump ${PG_DB} → ${PG_FILE}"
# </dev/null: `exec -T` inside cron/scripts otherwise swallows stdin (see DEPLOY_VPS2.md gotchas)
$COMPOSE exec -T postgres pg_dump -U "$PG_USER" "$PG_DB" </dev/null | gzip > "$PG_FILE"
log "✓ postgres $(du -sh "$PG_FILE" | cut -f1)"

# --- 2. Named volumes (read-only bind, no service restart needed) ---------------
for v in $VOLUMES; do
  VOL="${PROJECT}_${v}"
  if ! docker volume inspect "$VOL" >/dev/null 2>&1; then
    log "⚠ volume ${VOL} not found — skipped"
    continue
  fi
  OUT="${v}_${TS}.tgz"
  docker run --rm -v "${VOL}:/src:ro" -v "${BACKUP_DIR}:/dst" alpine:3.20 \
    tar czf "/dst/${OUT}" -C /src . </dev/null
  log "✓ ${v} $(du -sh "${BACKUP_DIR}/${OUT}" | cut -f1)"
done

# --- 3. Rotation ----------------------------------------------------------------
DELETED=$(find "$BACKUP_DIR" -maxdepth 1 -type f \( -name "pg_*.sql.gz" -o -name "*_*.tgz" \) \
  -mtime "+${KEEP_DAYS}" -print -delete | wc -l)
[[ $DELETED -gt 0 ]] && log "deleted ${DELETED} file(s) older than ${KEEP_DAYS} days"

log "done — $(ls -1 "$BACKUP_DIR" | wc -l) files, $(du -sh "$BACKUP_DIR" | cut -f1) total"
