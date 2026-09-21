#!/usr/bin/env bash
# Envelock database backup.
#
# This database holds every tenant's sealed mailbox credentials, their supplier
# bank records and their whole alert history. There was no backup of any kind —
# no dump, no WAL archiving, no restore path. One bad disk was the company.
#
#   ./deploy/backup.sh                     # a normal backup
#   ./deploy/backup.sh --label predeploy    # tagged, taken by deploy.sh
#   ./deploy/backup.sh --verify-only        # re-check the newest backup
#
# Design notes, because the details are what make a backup real:
#
#   * Custom format (-Fc), not plain SQL. It is compressed, and `pg_restore` can
#     restore a single table from it — which is what you actually want at 3am,
#     rather than replaying a 4 GB text file to recover one row.
#   * Every dump is VERIFIED by listing its table of contents. A dump that cannot
#     be read is not a backup, and the failure is silent until the day you need
#     it. Verification is the difference between a backup and a backup habit.
#   * A checksum is written next to each dump so bit-rot on the backup disk is
#     detectable rather than discovered during a restore.
#   * The dump is written 0600 and owned by the invoking user. It contains
#     ciphertext, not plaintext credentials — the envelope keys live elsewhere —
#     but it is still every customer's metadata in one file.
#
# Off-box copy is the part this script deliberately does NOT guess at: set
# ENVELOCK_BACKUP_REMOTE to an `rclone`/`aws s3` destination and it will push
# there. A backup that lives only on the machine it is protecting is not one.
set -euo pipefail

BACKUP_DIR="${ENVELOCK_BACKUP_DIR:-/var/backups/envelock}"
RETAIN_DAYS="${ENVELOCK_BACKUP_RETAIN_DAYS:-14}"
REMOTE="${ENVELOCK_BACKUP_REMOTE:-}"
LABEL="scheduled"
VERIFY_ONLY=0

log()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m!!  %s\033[0m\n' "$*" >&2; }
fail() { printf '\n\033[1;31m!!  %s\033[0m\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --label) LABEL="${2:?--label needs a value}"; shift 2 ;;
    --verify-only) VERIFY_ONLY=1; shift ;;
    *) fail "unknown argument: $1" ;;
  esac
done

# ---- Connection details, from the same .env the app reads ----
# Deriving them rather than duplicating them means the backup can never quietly
# be pointed at a different database than the one in production.
ENV_FILE="${ENVELOCK_ENV_FILE:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/.env}"
[ -f "$ENV_FILE" ] || fail "no .env at $ENV_FILE — set ENVELOCK_ENV_FILE"
# The nightly timer runs this without the app's environment, so a remote set
# only in .env was never seen and every scheduled backup stayed on this machine.
if [ -z "$REMOTE" ]; then
  REMOTE="$(grep -E '^ENVELOCK_BACKUP_REMOTE=' "$ENV_FILE" | tail -1 | cut -d= -f2- | tr -d '"'"'"' ' || true)"
fi
if [ -z "${ENVELOCK_BACKUP_RETAIN_DAYS:-}" ]; then
  from_file="$(grep -E '^ENVELOCK_BACKUP_RETAIN_DAYS=' "$ENV_FILE" | tail -1 | cut -d= -f2- | tr -d '"'"'"' ' || true)"
  [ -n "$from_file" ] && RETAIN_DAYS="$from_file"
fi

# Prefer the OWNER's DSN. Under row-level security the application connects as a
# restricted role that can SELECT but owns nothing, and a dump taken with it is
# quietly incomplete — the worst possible property for a backup. Falls back to
# the app DSN, which is correct in development where they are the same.
# Order matters. `pg_dump` sets row_security=off, so ANY policy that could apply
# makes it fail rather than emit a partial dump — and FORCE RLS applies to the
# table owner too. So the backup role (BYPASSRLS, read-only) is preferred, then
# the owner, then the app DSN. The last is correct only in development, where
# RLS is off and all three are the same.
read_dsn() { grep -E "^$1=" "$ENV_FILE" | tail -1 | cut -d= -f2- | tr -d '"'"'"' '; }
DSN="$(read_dsn ENVELOCK_DB_BACKUP_DSN)"
[ -n "$DSN" ] || DSN="$(read_dsn ENVELOCK_DB_OWNER_DSN)"
[ -n "$DSN" ] || DSN="$(read_dsn ENVELOCK_POSTGRES_DSN)"
[ -n "$DSN" ] || fail "no database DSN found in $ENV_FILE"

# SQLAlchemy's driver suffix is not valid for libpq.
PG_URL="${DSN/postgresql+asyncpg:/postgresql:}"

verify() {                              # $1 = dump file
  local file="$1"
  pg_restore --list "$file" >/dev/null 2>&1 \
    || fail "VERIFY FAILED: $file is not a readable dump. This is not a backup."
  local tables
  tables="$(pg_restore --list "$file" | grep -c 'TABLE DATA' || true)"
  [ "${tables:-0}" -ge 5 ] \
    || fail "VERIFY FAILED: $file contains only ${tables:-0} tables with data.
  An almost-empty dump usually means the DSN pointed somewhere unexpected."
  printf '    verified: %s table(s) with data\n' "$tables"
}

if [ "$VERIFY_ONLY" = 1 ]; then
  newest="$(ls -1t "$BACKUP_DIR"/envelock-*.dump 2>/dev/null | head -1 || true)"
  [ -n "$newest" ] || fail "no backups found in $BACKUP_DIR"
  log "verifying $newest"
  verify "$newest"
  ( cd "$BACKUP_DIR" && sha256sum -c "$(basename "$newest").sha256" ) \
    || fail "checksum mismatch — the backup file has been corrupted on disk"
  echo "OK"
  exit 0
fi

# `/var/backups` is root-owned, so a first run as `ubuntu` cannot create the
# directory beneath it. Say exactly how to fix that rather than emitting a bare
# mkdir error — this runs from deploy.sh, where an unexplained non-zero exit
# aborts the whole deploy.
if [ ! -d "$BACKUP_DIR" ]; then
  mkdir -p "$BACKUP_DIR" 2>/dev/null || fail "cannot create $BACKUP_DIR — run once:
    sudo mkdir -p $BACKUP_DIR && sudo chown $(id -un):$(id -gn) $BACKUP_DIR"
fi
[ -w "$BACKUP_DIR" ] || fail "$BACKUP_DIR is not writable by $(id -un) — run:
    sudo chown $(id -un):$(id -gn) $BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$BACKUP_DIR/envelock-$STAMP-$LABEL.dump"

log "dumping to $OUT"
# --no-owner/--no-privileges so the dump restores cleanly into a database whose
# roles differ from production's — which is exactly the situation during a
# restore drill, and the reason drills otherwise fail on unrelated errors.
umask 077
if ! pg_dump --format=custom --compress=6 --no-owner --no-privileges \
             --file="$OUT" "$PG_URL" 2> >(tee /tmp/envelock-pgdump.err >&2); then
  if grep -q "row-level security" /tmp/envelock-pgdump.err 2>/dev/null; then
    fail "pg_dump refused because row-level security applies to this role.
  That refusal is CORRECT — it will not write a partial dump — but it means the
  backup needs a role that bypasses RLS. Create one and point the backup at it:

    sudo -u postgres psql -d envelock -c \"CREATE ROLE envelock_backup LOGIN \\
      PASSWORD 'pick-one' BYPASSRLS NOSUPERUSER\"
    sudo -u postgres psql -d envelock -c \"GRANT USAGE ON SCHEMA public TO \\
      envelock_backup; GRANT SELECT ON ALL TABLES IN SCHEMA public TO envelock_backup\"

  then add to .env:
    ENVELOCK_DB_BACKUP_DSN=postgresql://envelock_backup:pick-one@localhost:5432/envelock"
  fi
  fail "pg_dump failed"
fi

log "verifying the dump can actually be read"
verify "$OUT"

( cd "$BACKUP_DIR" && sha256sum "$(basename "$OUT")" > "$(basename "$OUT").sha256" )
printf '    %s\n' "$(du -h "$OUT" | cut -f1)"

# ---- Off-box copy ----
if [ -n "$REMOTE" ]; then
  log "copying off-box to $REMOTE"
  if command -v rclone >/dev/null 2>&1 && [[ "$REMOTE" != s3://* ]]; then
    rclone copy "$OUT" "$REMOTE" && rclone copy "$OUT.sha256" "$REMOTE"
  elif command -v aws >/dev/null 2>&1; then
    aws s3 cp "$OUT" "$REMOTE/" && aws s3 cp "$OUT.sha256" "$REMOTE/"
  else
    fail "ENVELOCK_BACKUP_REMOTE is set but neither rclone nor aws is installed"
  fi
else
  warn "ENVELOCK_BACKUP_REMOTE is unset — this backup exists ONLY on the machine
  it is meant to protect. Set it to an off-box destination."
fi

# ---- Retention ----
# Local only. Off-box retention belongs to the bucket's lifecycle policy, where
# a compromised server cannot delete history.
log "pruning local backups older than $RETAIN_DAYS days"
find "$BACKUP_DIR" -name 'envelock-*.dump*' -mtime "+$RETAIN_DAYS" -print -delete || true

log "backup complete"
ls -1t "$BACKUP_DIR"/envelock-*.dump | head -5
