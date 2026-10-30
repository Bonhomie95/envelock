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
# `|| true`: under `set -e -o pipefail` a missing key failed the assignment and
# ended the script silently, before the fallbacks below could run (backup.sh
# had the same bug).
read_dsn() { grep -E "^$1=" "$ENV_FILE" | tail -1 | cut -d= -f2- | tr -d '"'"'"' ' || true; }
# The OWNER restores: it has to drop and recreate the tables. Falls back to the
# app DSN, which is correct in development where they are the same.
DSN="$(read_dsn ENVELOCK_DB_OWNER_DSN)"
[ -n "$DSN" ] || DSN="$(read_dsn ENVELOCK_POSTGRES_DSN)"
[ -n "$DSN" ] || fail "no database DSN found in $ENV_FILE"
PG_URL="${DSN/postgresql+asyncpg:/postgresql:}"
# But the owner cannot DUMP: FORCE ROW LEVEL SECURITY applies to it too, and
# pg_dump refuses rather than write a partial dump. Dumps use the backup role
# (BYPASSRLS, read-only), exactly as backup.sh does.
DUMP_DSN="$(read_dsn ENVELOCK_DB_BACKUP_DSN)"
[ -n "$DUMP_DSN" ] || DUMP_DSN="$DSN"
DUMP_URL="${DUMP_DSN/postgresql+asyncpg:/postgresql:}"
# Row counts are read as the owner, which FORCE RLS shows nothing without a
# tenant — so they opt into the platform-wide scope the policies allow
# (db_rls.GUC_SYSTEM). Without this every count read 0 and the drill passed.
SYSTEM_SCOPE="SET envelock.system = 'on';"
# Everything but the database name, so we can address a different database on
# the same server without a second set of credentials in a second place.
SERVER_URL="${PG_URL%/*}"
PROD_DB="${PG_URL##*/}"
PROD_DB="${PROD_DB%%\?*}"

newest() { ls -1t "$BACKUP_DIR"/envelock-*.dump 2>/dev/null | head -1; }

# An off-box copy is age-encrypted (backup.sh). Decrypt it with the offline
# private key — ENVELOCK_BACKUP_AGE_IDENTITY=/path/to/envelock-backup.key, copied
# in only for the restore — into a private temp file that is removed on exit.
PLAIN=""
trap 'rm -f "$PLAIN"' EXIT
decrypt_if_needed() {
  case "$FILE" in
    *.age)
      local identity="${ENVELOCK_BACKUP_AGE_IDENTITY:-}"
      [ -n "$identity" ] || fail "set ENVELOCK_BACKUP_AGE_IDENTITY to the backup private key file"
      command -v age >/dev/null 2>&1 || fail "age is not installed (sudo apt-get install age)"
      PLAIN="$(umask 077 && mktemp "${TMPDIR:-/tmp}/envelock-restore.XXXXXX")"
      age -d -i "$identity" -o "$PLAIN" "$FILE" || fail "could not decrypt $FILE with $identity"
      FILE="$PLAIN"
      ;;
  esac
}

case "${1:-}" in
  --list)
    log "backups in $BACKUP_DIR"
    ls -lht "$BACKUP_DIR"/envelock-*.dump 2>/dev/null || echo "  (none)"
    exit 0
    ;;

  --drill)
    FILE="${2:-$(newest)}"
    [ -n "$FILE" ] || fail "no backups found in $BACKUP_DIR"
    decrypt_if_needed
    DRILL_DB="envelock_drill_$(date -u +%Y%m%d%H%M%S)"
    log "restore drill: $FILE → $DRILL_DB"

    # Trap so an interrupted drill never leaves a stray database behind. A drill
    # that litters is a drill people stop running.
    cleanup() {
      psql "$SERVER_URL/postgres" -qc "DROP DATABASE IF EXISTS $DRILL_DB" >/dev/null 2>&1 || true
      rm -f "$PLAIN"
    }
    trap cleanup EXIT

    psql "$SERVER_URL/postgres" -qc "CREATE DATABASE $DRILL_DB" \
      || fail "could not create the scratch database"
    pg_restore --no-owner --no-privileges --dbname="$SERVER_URL/$DRILL_DB" "$FILE" \
      || fail "pg_restore failed — THIS BACKUP CANNOT BE RESTORED"

    log "checking the restored data"
    # Not just "did it restore" — does it contain the things that matter? An
    # empty-but-valid restore is the failure this catches.
    counts="$(psql "$SERVER_URL/$DRILL_DB" -qtA -F ' ' -c "$SYSTEM_SCOPE
      SELECT
        (SELECT count(*) FROM tenants),
        (SELECT count(*) FROM users),
        (SELECT count(*) FROM mailboxes),
        (SELECT count(*) FROM mailbox_credentials),
        (SELECT count(*) FROM alerts);
    ")" || fail "the restored database is missing core tables"
    read -r r_tenants r_users r_mailboxes r_credentials r_alerts <<<"$counts"
    echo "    tenants=$r_tenants users=$r_users mailboxes=$r_mailboxes credentials=$r_credentials alerts=$r_alerts"
    # An empty restore of a database that has customers is a backup of nothing.
    live="$(psql "$PG_URL" -qtA -c "$SYSTEM_SCOPE SELECT count(*) FROM tenants" 2>/dev/null || true)"
    if [ "${live:-0}" -gt 0 ] 2>/dev/null && [ "${r_tenants:-0}" -eq 0 ]; then
      fail "the restored copy has no tenants, while the live database has $live — THIS BACKUP IS EMPTY"
    fi

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
    decrypt_if_needed
    log "restoring $FILE → $TARGET"
    psql "$SERVER_URL/postgres" -qc "CREATE DATABASE $TARGET" 2>/dev/null || true
    pg_restore --no-owner --no-privileges --dbname="$SERVER_URL/$TARGET" "$FILE"
    log "done"
    exit 0
    ;;

  --PRODUCTION)
    FILE="${2:?--PRODUCTION needs an explicit backup file}"
    [ -f "$FILE" ] || fail "no such file: $FILE"
    # Both services write to the database — the worker more than the API: every
    # poll, every alert. Restoring under a running worker interleaves its writes
    # with the restore. Refuse rather than warn.
    if command -v systemctl >/dev/null 2>&1 \
       && systemctl is-active --quiet envelock-api envelock-worker; then
      fail "envelock-api or envelock-worker is running. Stop both first:
    sudo systemctl stop envelock-api envelock-worker envelock-backup.timer"
    fi
    decrypt_if_needed
    warn "This OVERWRITES the live database '$PROD_DB'."
    warn "Everything written since $(basename "$FILE") will be lost."
    # Typed confirmation, not y/N: this is the one command in the repo that can
    # destroy customer data on purpose, and it should be impossible to reach by
    # holding down return.
    printf '\nType the database name (%s) to proceed: ' "$PROD_DB"
    read -r typed
    [ "$typed" = "$PROD_DB" ] || fail "aborted"

    SAFETY="$BACKUP_DIR/pre-restore-$(date -u +%Y%m%dT%H%M%SZ).dump"
    log "taking a safety dump of the CURRENT database first → $SAFETY"
    # If the restore turns out to be the wrong call, this is the way back — so no
    # safety dump, no restore. (It used to be taken with the owner DSN, which
    # FORCE RLS always refuses, and the failure was only a warning.)
    ( umask 077 && pg_dump --format=custom --no-owner --no-privileges \
                           --file="$SAFETY" "$DUMP_URL" ) \
      || fail "safety dump failed — NOT restoring. Without it there is no way back"

    log "restoring into $PROD_DB"
    # One transaction: an error part-way leaves the database exactly as it was,
    # not half old and half restored.
    pg_restore --single-transaction --clean --if-exists --no-owner --no-privileges \
               --dbname="$PG_URL" "$FILE"
    log "restored. Start Envelock:  sudo systemctl start envelock-api envelock-worker envelock-backup.timer"
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
