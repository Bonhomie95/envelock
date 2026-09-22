#!/usr/bin/env bash
# Envelock — let a standby server copy this database, continuously.
#
# Run as root on the LIVE server, once, before setting up the standby:
#     bash ~ubuntu/apps/server/deploy/replication-primary.sh --standby-ip 203.0.113.20
#
# Safe to re-run (e.g. with a new standby IP). It:
#   * creates a replication login, `envelock_replicator` (password saved to
#     /root/envelock-secrets as REPLICATION_PASSWORD),
#   * reserves a replication slot so the WAL the standby still needs is kept
#     even if it falls behind for a while,
#   * lets Postgres listen on this server's public address, accepting ONLY
#     that login from ONLY the standby's IP, over TLS,
#   * opens port 5432 in the firewall for the standby's IP and nobody else,
#   * restarts Postgres (a few seconds; the API reconnects by itself).
#
# Then on the standby:  bash setup-server.sh --standby-of <this server's IP>
# (see docs/LAUNCH-GUIDE.md, "A standby server").
set -euo pipefail

STANDBY_IP=""
SLOT="envelock_standby"
SECRETS="/root/envelock-secrets"
while [ $# -gt 0 ]; do
  case "$1" in
    --standby-ip) STANDBY_IP="${2:?--standby-ip needs an address}"; shift 2 ;;
    -h|--help) sed -n '2,19p' "$0"; exit 0 ;;
    *) echo "unknown option: $1 (try --help)" >&2; exit 2 ;;
  esac
done

log()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()   { printf '    \033[32m✓\033[0m %s\n' "$*"; }
fail() { printf '\n\033[1;31m!!  %s\033[0m\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || fail "run this as root:  sudo bash $0 --standby-ip X.X.X.X"
[[ "$STANDBY_IP" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || fail "--standby-ip must be the standby's IPv4 address"
[ "$(sudo -u postgres psql -tAc 'SELECT pg_is_in_recovery()')" = "f" ] \
  || fail "this Postgres is itself a standby — run this on the live (primary) server"

PG_VER="$(sudo -u postgres psql -tAc 'SHOW server_version_num' | cut -c1-2)"
CONF_DIR="/etc/postgresql/$PG_VER/main"
[ -d "$CONF_DIR" ] || fail "expected Postgres config in $CONF_DIR"

log "replication login"
touch "$SECRETS"; chmod 600 "$SECRETS"
if ! grep -q '^REPLICATION_PASSWORD=' "$SECRETS"; then
  echo "REPLICATION_PASSWORD=$(openssl rand -hex 24)" >> "$SECRETS"
fi
# shellcheck disable=SC1090
. "$SECRETS"
sudo -u postgres psql -v ON_ERROR_STOP=1 -q <<SQL
DO \$\$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'envelock_replicator') THEN
    CREATE ROLE envelock_replicator WITH REPLICATION LOGIN PASSWORD '$REPLICATION_PASSWORD';
  ELSE
    ALTER ROLE envelock_replicator WITH REPLICATION LOGIN PASSWORD '$REPLICATION_PASSWORD';
  END IF;
END \$\$;
SQL
ok "envelock_replicator (password in $SECRETS)"

log "replication slot"
sudo -u postgres psql -v ON_ERROR_STOP=1 -q -c \
  "SELECT pg_create_physical_replication_slot('$SLOT') WHERE NOT EXISTS (SELECT 1 FROM pg_replication_slots WHERE slot_name = '$SLOT')" >/dev/null
ok "$SLOT"

log "Postgres settings"
PUBLIC_IP="$(ip -4 route get 1.1.1.1 | awk '{for (i=1;i<NF;i++) if ($i=="src") print $(i+1)}')"
install -d "$CONF_DIR/conf.d"
cat > "$CONF_DIR/conf.d/envelock-replication.conf" <<CONF
# Written by replication-primary.sh — the standby streams from this server.
listen_addresses = 'localhost,$PUBLIC_IP'
wal_level = replica
max_wal_senders = 5
max_replication_slots = 5
# The slot already keeps what the standby needs; this bounds the disk a slot
# can pin if the standby is gone for good (then drop the slot).
max_slot_wal_keep_size = '20GB'
ssl = on
CONF
HBA="$CONF_DIR/pg_hba.conf"
sed -i '/# envelock-replication$/d' "$HBA"
echo "hostssl replication envelock_replicator $STANDBY_IP/32 scram-sha-256 # envelock-replication" >> "$HBA"
ok "listening on localhost and $PUBLIC_IP; replication only from $STANDBY_IP, TLS only"

log "firewall"
ufw delete allow proto tcp from any to any port 5432 >/dev/null 2>&1 || true
ufw allow proto tcp from "$STANDBY_IP" to any port 5432 >/dev/null
ok "5432 open to $STANDBY_IP only"

log "restarting Postgres"
systemctl restart postgresql
sleep 2
systemctl is-active --quiet postgresql || fail "Postgres did not come back — check: journalctl -u postgresql"
for i in $(seq 1 30); do
  curl -fsS --max-time 3 localhost:8010/ready >/dev/null 2>&1 && break
  [ "$i" = 30 ] && echo "    (the API is still reconnecting; check: curl localhost:8010/ready)"
  sleep 2
done
ok "Postgres up; API $(curl -fsS --max-time 3 localhost:8010/ready >/dev/null 2>&1 && echo ready || echo 'reconnecting')"

cat <<EOF

────────────────────────────────────────────────────────────────────────────
 This server is ready to be copied.

 On the standby (a fresh Ubuntu 24.04 server), as root:
   1. Copy these three files to it (from this server):
        scp /home/ubuntu/apps/server/deploy/setup-server.sh \\
            /home/ubuntu/apps/server/.env /home/ubuntu/apps/server/.env.worker \\
            root@$STANDBY_IP:/root/
   2. Run:
        ENVELOCK_REPLICATION_PASSWORD='$REPLICATION_PASSWORD' \\
          bash /root/setup-server.sh --standby-of $PUBLIC_IP

 Check it any time with:  bash /home/ubuntu/apps/server/deploy/replica-status.sh
────────────────────────────────────────────────────────────────────────────
EOF
