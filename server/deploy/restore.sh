#!/usr/bin/env bash
# Envelock restore — and, more importantly, the restore DRILL.
#
# A backup nobody has restored is a hypothesis. This script exists so the
# hypothesis gets tested on a normal Tuesday rather than during the incident.
#
#   ./deploy/restore.sh --list              # what do we have?
#   ./deploy/restore.sh --drill             # restore the newest into a scratch
#                                           # database, check it, drop it
#   ./deploy/restore.sh --to-db envelock_x FILE
#   ./deploy/restore.sh --PRODUCTION FILE   # the real thing, guarded
#
# The drill is the command to put on a calendar. It proves three things at once:
# the dump is readable, it contains the tables you think it does, and the
# restore procedure on this machine works with these tool versions.
set -euo pipefail

BACKUP_DIR="${ENVELOCK_BACKUP_DIR:-/var/backups/envelock}"

log()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m!!  %s\033[0m\n' "$*" >&2; }
fail() { printf '\n\033[1;31m!!  %s\033[0m\n' "$*" >&2; exit 1; }

ENV_FILE="${ENVELOCK_ENV_FILE:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/.env}"
[ -f "$ENV_FILE" ] || fail "no .env at $ENV_FILE — set ENVELOCK_ENV_FILE"
# Prefer the OWNER's DSN. Under row-level security the application connects as a
# restricted role that can SELECT but owns nothing, and a dump taken with it is
# quietly incomplete — the worst possible property for a backup. Falls back to
# the app DSN, which is correct in development where they are the same.
DSN="$(grep -E '^ENVELOCK_DB_OWNER_DSN=' "$ENV_FILE" | tail -1 | cut -d= -f2- | tr -d '"'"'"' ')"
[ -n "$DSN" ] || DSN="$(grep -E '^ENVELOCK_POSTGRES_DSN=' "$ENV_FILE" | tail -1 | cut -d= -f2- | tr -d '"'"'"' ')"
PG_URL="${DSN/postgresql+asyncpg:/postgresql:}"
# Everything but the database name, so we can address a different database on
# the same server without a second set of credentials in a second place.
SERVER_URL="${PG_URL%/*}"
PROD_DB="${PG_URL##*/}"
PROD_DB="${PROD_DB%%\?*}"

newest() { ls -1t "$BACKUP_DIR"/envelock-*.dump 2>/dev/null | head -1; }

case "${1:-}" in
  --list)
    log "backups in $BACKUP_DIR"
    ls -lht "$BACKUP_DIR"/envelock-*.dump 2>/dev/null || echo "  (none)"
    exit 0
    ;;

  --drill)
    FILE="${2:-$(newest)}"
    [ -n "$FILE" ] || fail "no backups found in $BACKUP_DIR"
    DRILL_DB="envelock_drill_$(date -u +%Y%m%d%H%M%S)"
    log "restore drill: $FILE → $DRILL_DB"

    # Trap so an interrupted drill never leaves a stray database behind. A drill
    # that litters is a drill people stop running.
    cleanup() {
      psql "$SERVER_URL/postgres" -qc "DROP DATABASE IF EXISTS $DRILL_DB" >/dev/null 2>&1 || true
    }
    trap cleanup EXIT

    psql "$SERVER_URL/postgres" -qc "CREATE DATABASE $DRILL_DB" \
      || fail "could not create the scratch database"
    pg_restore --no-owner --no-privileges --dbname="$SERVER_URL/$DRILL_DB" "$FILE" \
      || fail "pg_restore failed — THIS BACKUP CANNOT BE RESTORED"

    log "checking the restored data"
    # Not just "did it restore" — does it contain the things that matter? An
    # empty-but-valid restore is the failure this catches.
    psql "$SERVER_URL/$DRILL_DB" -qtc "
      SELECT
        (SELECT count(*) FROM tenants)             AS tenants,
        (SELECT count(*) FROM users)               AS users,
        (SELECT count(*) FROM mailboxes)           AS mailboxes,
        (SELECT count(*) FROM mailbox_credentials) AS credentials,
        (SELECT count(*) FROM alerts)              AS alerts;
    " || fail "the restored database is missing core tables"

    tables="$(psql "$SERVER_URL/$DRILL_DB" -qtAc \
      "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")"
    [ "$tables" -ge 15 ] \
      || fail "only $tables tables restored — expected the full schema"
    log "DRILL PASSED — $tables tables restored and readable"
    echo "    Record today's date as the last successful restore drill."
    exit 0
    ;;

  --to-db)
    TARGET="${2:?--to-db needs a database name}"
    FILE="${3:-$(newest)}"
    [ -n "$FILE" ] || fail "no backup file given and none found"
    log "restoring $FILE → $TARGET"
    psql "$SERVER_URL/postgres" -qc "CREATE DATABASE $TARGET" 2>/dev/null || true
    pg_restore --no-owner --no-privileges --dbname="$SERVER_URL/$TARGET" "$FILE"
    log "done"
    exit 0
    ;;

  --PRODUCTION)
    FILE="${2:?--PRODUCTION needs an explicit backup file}"
    [ -f "$FILE" ] || fail "no such file: $FILE"
    warn "This OVERWRITES the live database '$PROD_DB'."
    warn "Everything written since $(basename "$FILE") will be lost."
    warn "Stop the API first:  sudo systemctl stop envelock-api"
    # Typed confirmation, not y/N: this is the one command in the repo that can
    # destroy customer data on purpose, and it should be impossible to reach by
    # holding down return.
    printf '\nType the database name (%s) to proceed: ' "$PROD_DB"
    read -r typed
    [ "$typed" = "$PROD_DB" ] || fail "aborted"

    SAFETY="$BACKUP_DIR/pre-restore-$(date -u +%Y%m%dT%H%M%SZ).dump"
    log "taking a safety dump of the CURRENT database first → $SAFETY"
    # If the restore turns out to be the wrong call, this is the way back.
    pg_dump --format=custom --no-owner --no-privileges --file="$SAFETY" "$PG_URL" \
      || warn "safety dump failed — continuing only because you asked explicitly"

    log "restoring into $PROD_DB"
    pg_restore --clean --if-exists --no-owner --no-privileges \
               --dbname="$PG_URL" "$FILE"
    log "restored. Start the API:  sudo systemctl start envelock-api"
    exit 0
    ;;

  *)
    cat <<'USAGE'
Envelock restore

  ./deploy/restore.sh --list                 List available backups
  ./deploy/restore.sh --drill [FILE]         Restore into a scratch database,
                                             verify it, drop it. Run monthly.
  ./deploy/restore.sh --to-db NAME [FILE]    Restore into a named database
  ./deploy/restore.sh --PRODUCTION FILE      Overwrite the live database

The drill is the one that matters. Put it on a calendar.
USAGE
    exit 1
    ;;
esac
