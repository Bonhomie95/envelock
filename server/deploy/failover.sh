#!/usr/bin/env bash
# Envelock — make this STANDBY the live server.
#
# Run as root on the standby when the live server is lost (or before planned
# maintenance on it):
#     sudo bash ~ubuntu/apps/server/deploy/failover.sh --email you@yourdomain.com
#
# In order: stops if the old server still answers (two live servers would
# poll every mailbox twice and split the data), promotes this database to
# read-write, deploys the latest code, starts the API, worker and backups,
# then tells you exactly which DNS records to change. If DNS already points
# here, it also issues the HTTPS certificates.
#
# Options:
#   --email ADDRESS   for the HTTPS certificate (as in setup-server.sh)
#   --force           promote even though the old server still answers. Only
#                     after you have stopped it:  systemctl disable --now
#                     envelock-api envelock-worker  (on the OLD server).
set -euo pipefail

APP_USER="${ENVELOCK_APP_USER:-ubuntu}"
APPS="/home/$APP_USER/apps"
EMAIL=""; FORCE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --email) EMAIL="${2:?--email needs an address}"; shift 2 ;;
    --force) FORCE=1; shift ;;
    -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
    *) echo "unknown option: $1 (try --help)" >&2; exit 2 ;;
  esac
done

log()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()   { printf '    \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!  %s\033[0m\n' "$*" >&2; }
fail() { printf '\n\033[1;31m!!  %s\033[0m\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || fail "run this as root:  sudo bash $0"
# Resumable: if a previous run promoted the database and then stopped (a failed
# deploy, a lost SSH session), running it again carries on from there.
PROMOTED=0
[ "$(sudo -u postgres psql -tAc 'SELECT pg_is_in_recovery()')" = "f" ] && PROMOTED=1

PG_VER="$(ls /etc/postgresql | sort -n | tail -1)"
PRIMARY="$(sudo -u postgres psql -tAc "SELECT substring(conninfo from 'host=([^ ]+)') FROM pg_stat_wal_receiver" | tr -d ' ')"
if [ -z "$PRIMARY" ]; then
  # After promotion the receiver is gone; the old address stays in the config.
  PRIMARY="$(grep -o "host=[^ ']*" "/var/lib/postgresql/$PG_VER/main/postgresql.auto.conf" 2>/dev/null | head -1 | cut -d= -f2)"
fi

log "is the old server still up?"
answers() { timeout 5 bash -c "</dev/tcp/$1/$2" 2>/dev/null; }
if [ -n "$PRIMARY" ] && { answers "$PRIMARY" 443 || answers "$PRIMARY" 80; }; then
  if [ "$FORCE" = 1 ]; then
    warn "$PRIMARY still answers — continuing because of --force"
  else
    fail "$PRIMARY still answers. If it's really broken, stop Envelock on it first
    (on the OLD server:  systemctl disable --now envelock-api envelock-worker)
    and re-run with --force. Two live servers would poll every mailbox twice."
  fi
else
  ok "${PRIMARY:-the old server} is not answering"
fi

if [ "$PROMOTED" = 0 ]; then
LAG="$(sudo -u postgres psql -tAc "SELECT COALESCE(EXTRACT(EPOCH FROM now() - pg_last_xact_replay_timestamp())::int, -1)")"
echo "    last change copied from the old server: ${LAG}s ago (changes made after that, if any, are lost; on a quiet system this is simply the last activity)"
read -r -p "    Type PROMOTE to make this server live: " answer
[ "$answer" = "PROMOTE" ] || fail "not promoted"

log "promoting the database"
sudo -u postgres psql -v ON_ERROR_STOP=1 -tAc "SELECT pg_promote(wait => true, wait_seconds => 60)" | grep -q t \
  || fail "Postgres did not promote — check: journalctl -u postgresql"
[ "$(sudo -u postgres psql -tAc 'SELECT pg_is_in_recovery()')" = "f" ] || fail "still read-only"
ok "read-write"
else
  ok "the database is already live (an earlier run promoted it) — carrying on"
fi

log "deploying the latest code and starting Envelock"
systemctl enable --now redis-server >/dev/null 2>&1
sudo -u "$APP_USER" -H bash -c "$APPS/server/deploy/deploy.sh" \
  || fail "deploy.sh stopped — its message above says why. The database is live; fix and re-run deploy.sh"
systemctl enable --now envelock-api envelock-worker envelock-backup.timer >/dev/null 2>&1
for i in $(seq 1 30); do
  curl -fsS --max-time 3 localhost:8010/ready >/dev/null 2>&1 && break
  [ "$i" = 30 ] && { journalctl -u envelock-api -n 40 --no-pager; fail "the API did not become ready"; }
  sleep 2
done
systemctl is-active --quiet envelock-worker || fail "the worker is not running: journalctl -u envelock-worker"
ok "API ready, worker running, nightly backups on"

IP="$(curl -4fsS --max-time 10 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')"
log "HTTPS"
if [ "$(dig +short A api.envelock.org @1.1.1.1 | tail -1)" = "$IP" ] && [ -n "$EMAIL" ]; then
  bash "$APPS/server/deploy/setup-server.sh" --tls-only --email "$EMAIL" || warn "certificate request failed; re-run later"
else
  echo "    DNS doesn't point here yet — after changing it, run:"
  echo "      sudo bash $APPS/server/deploy/setup-server.sh --tls-only --email you@yourdomain.com"
fi

cat <<EOF

────────────────────────────────────────────────────────────────────────────
 This server ($IP) is now the live Envelock.

 1. DNS: point these A records at $IP —
      envelock.org  www  app  api  admin   (and go., if you use the link edge)
    On Cloudflare with the orange cloud on, the switch is immediate.
 2. The old server, when it comes back: keep it OFF
      systemctl disable --now envelock-api envelock-worker
    then rebuild it as the new standby (LAUNCH-GUIDE, "A standby server").
────────────────────────────────────────────────────────────────────────────
EOF
