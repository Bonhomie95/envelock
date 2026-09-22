#!/usr/bin/env bash
# Envelock — build a production server from a fresh Ubuntu 24.04 VPS.
#
# Run ONCE, as root, on the new machine. Safe to re-run: every step checks
# whether it is already done. See docs/LAUNCH-GUIDE.md, Part B.
#
#   From your laptop, copy three files up:
#     scp server/deploy/setup-server.sh server/deploy/make_prod_env.py \
#         server/.env root@SERVER_IP:/root/
#   Then on the server:
#     bash /root/setup-server.sh --email you@yourdomain.com
#
# Options:
#   --email ADDRESS   for the Let's Encrypt certificate (expiry notices)
#   --skip-tls        do everything except the HTTPS certificate (DNS not ready)
#   --tls-only        only request the certificate (after DNS points here)
#   --standby-of IP   build a STANDBY: a streaming copy of the live server at IP,
#                     with the API and worker installed but off (see
#                     replication-primary.sh and failover.sh). Needs the live
#                     server's .env and .env.worker in /root, and
#                     ENVELOCK_REPLICATION_PASSWORD set.
#
# What it does, in order: a login user `ubuntu`, system packages, a firewall,
# Postgres + Redis, GitHub access, the repository, the Python
# environment, the two production settings files, the database schema,
# row-level security, the systemd services, nginx, HTTPS, and a first deploy.
# Generated passwords are kept in /root/envelock-secrets (root only).
set -euo pipefail

# ---- configuration (overridable, mainly so the script can be tested) --------
APP_USER="${ENVELOCK_APP_USER:-ubuntu}"
APP_HOME="/home/$APP_USER"
APPS="$APP_HOME/apps"
REPO_URL="${ENVELOCK_REPO_URL:-git@github.com:Bonhomie95/envelock.git}"
DEPLOY_DIR="$APP_HOME/deploy"
SOURCE_ENV="${ENVELOCK_SOURCE_ENV:-/root/.env}"
SECRETS="/root/envelock-secrets"
HOSTS=(envelock.org www.envelock.org app.envelock.org api.envelock.org admin.envelock.org)

EMAIL=""; SKIP_TLS=0; TLS_ONLY=0; PRIMARY_IP=""
while [ $# -gt 0 ]; do
  case "$1" in
    --email) EMAIL="${2:?--email needs an address}"; shift 2 ;;
    --skip-tls) SKIP_TLS=1; shift ;;
    --tls-only) TLS_ONLY=1; shift ;;
    --standby-of) PRIMARY_IP="${2:?--standby-of needs the IP of the live server}"; SKIP_TLS=1; shift 2 ;;
    -h|--help) sed -n '2,29p' "$0"; exit 0 ;;
    *) echo "unknown option: $1 (try --help)" >&2; exit 2 ;;
  esac
done

log()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()   { printf '    \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!  %s\033[0m\n' "$*" >&2; }
fail() { printf '\n\033[1;31m!!  %s\033[0m\n' "$*" >&2; exit 1; }
as_app() { sudo -u "$APP_USER" -H bash -c "$*"; }

[ "$(id -u)" = 0 ] || fail "run this as root:  sudo bash $0"
. /etc/os-release
[ "${ID:-}" = ubuntu ] || fail "this script expects Ubuntu (found ${PRETTY_NAME:-unknown})"
[ "${VERSION_ID:-}" = "24.04" ] || warn "tested on Ubuntu 24.04; this is ${PRETTY_NAME}"

public_ip() {
  if [ -n "${ENVELOCK_PUBLIC_IP:-}" ]; then echo "$ENVELOCK_PUBLIC_IP"; return; fi
  curl -4fsS --max-time 10 https://api.ipify.org 2>/dev/null \
    || curl -4fsS --max-time 10 https://ifconfig.me 2>/dev/null \
    || fail "could not work out this server's public IP; set ENVELOCK_PUBLIC_IP=x.x.x.x"
}

request_tls() {
  local ip; ip="$(public_ip)"
  log "HTTPS certificates"
  local missing=()
  for h in "${HOSTS[@]}"; do
    [ "$(dig +short A "$h" @1.1.1.1 | tail -1)" = "$ip" ] || missing+=("$h")
  done
  if [ ${#missing[@]} -gt 0 ]; then
    warn "these do not point at $ip yet: ${missing[*]}"
    warn "set their A records (Cloudflare: grey cloud / DNS only), wait a few minutes, then run:"
    warn "    bash $0 --tls-only --email you@yourdomain.com"
    return 1
  fi
  [ -n "$EMAIL" ] || fail "--email is needed for the certificate (Let's Encrypt expiry notices)"
  local args=(); for h in "${HOSTS[@]}"; do args+=(-d "$h"); done
  certbot --nginx --non-interactive --agree-tos -m "$EMAIL" --redirect "${args[@]}"
  ok "certificates issued; renewal is automatic ($(systemctl list-timers --no-pager | grep -c certbot) timer)"
}

if [ "$TLS_ONLY" = 1 ]; then
  request_tls; exit $?
fi

# ---- 1. the login user -------------------------------------------------------
log "1/13  user '$APP_USER'"
if ! id "$APP_USER" >/dev/null 2>&1; then
  adduser --disabled-password --gecos "" "$APP_USER"
  ok "created"
else
  ok "exists"
fi
usermod -aG sudo "$APP_USER"
# deploy.sh restarts services with sudo, unattended.
echo "$APP_USER ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/90-$APP_USER"
chmod 440 "/etc/sudoers.d/90-$APP_USER"
if [ -f /root/.ssh/authorized_keys ] && [ ! -f "$APP_HOME/.ssh/authorized_keys" ]; then
  install -d -m 700 -o "$APP_USER" -g "$APP_USER" "$APP_HOME/.ssh"
  install -m 600 -o "$APP_USER" -g "$APP_USER" /root/.ssh/authorized_keys "$APP_HOME/.ssh/authorized_keys"
  ok "your SSH key now also logs in as $APP_USER"
fi

# ---- 2. packages -------------------------------------------------------------
log "2/13  system packages"
export DEBIAN_FRONTEND=noninteractive
# A freshly created server runs its own security updates for the first few
# minutes and holds the package lock while it does; wait for it rather than fail.
wait_for_apt() {
  local waited=0
  while fuser /var/lib/dpkg/lock-frontend /var/lib/apt/lists/lock /var/lib/dpkg/lock >/dev/null 2>&1; do
    [ "$waited" = 0 ] && echo "    waiting for the server's automatic updates to finish…"
    sleep 5; waited=$((waited + 5))
    [ "$waited" -ge 900 ] && fail "the package manager has been busy for 15 minutes — reboot and re-run"
  done
}
APT=(apt-get -o DPkg::Lock::Timeout=600)
wait_for_apt
"${APT[@]}" update -qq
wait_for_apt
"${APT[@]}" install -y -qq python3 python3-venv python3-dev build-essential \
  postgresql postgresql-contrib redis-server nginx certbot python3-certbot-nginx \
  git curl dnsutils ufw tesseract-ocr libzbar0 libpq-dev >/dev/null
if ! command -v node >/dev/null || [ "$(node -p 'process.versions.node.split(".")[0]')" -lt 22 ]; then
  wait_for_apt
  curl -fsSL https://deb.nodesource.com/setup_22.x | bash - >/dev/null
  wait_for_apt
  "${APT[@]}" install -y -qq nodejs >/dev/null
fi
ok "python $(python3 -c 'import platform;print(platform.python_version())'), node $(node --version), $(psql --version | awk '{print "postgres "$3}')"
if ! swapon --show | grep -q .; then
  fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile >/dev/null && swapon /swapfile
  grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
  ok "2 GB swap added (keeps a web build from exhausting memory)"
fi

# ---- 3. firewall -------------------------------------------------------------
log "3/13  firewall"
ufw allow OpenSSH >/dev/null
ufw allow 80/tcp >/dev/null
ufw allow 443/tcp >/dev/null
ufw --force enable >/dev/null
ok "open: 22 (SSH), 80, 443 — everything else closed (database, Redis, API stay local)"

# ---- 4. database -------------------------------------------------------------
log "4/13  Postgres and Redis"
systemctl enable --now postgresql redis-server >/dev/null 2>&1
if [ -n "$PRIMARY_IP" ]; then
  # A standby's database is a byte-for-byte copy of the live one, kept current by
  # streaming replication — roles, passwords and data included. Nothing is
  # created here; it is copied.
  : "${ENVELOCK_REPLICATION_PASSWORD:?set ENVELOCK_REPLICATION_PASSWORD (printed by replication-primary.sh)}"
  PG_VER="$(ls /etc/postgresql | sort -n | tail -1)"
  PGDATA="/var/lib/postgresql/$PG_VER/main"
  if [ "$(sudo -u postgres psql -tAc 'SELECT pg_is_in_recovery()' 2>/dev/null)" = "t" ]; then
    ok "already a standby"
  else
    systemctl stop postgresql
    rm -rf "$PGDATA"
    sudo -u postgres env PGPASSWORD="$ENVELOCK_REPLICATION_PASSWORD" pg_basebackup \
      -h "$PRIMARY_IP" -U envelock_replicator -D "$PGDATA" \
      -X stream -S envelock_standby -R -d "sslmode=require" \
      || fail "could not copy the database from $PRIMARY_IP — did replication-primary.sh run there with --standby-ip $(public_ip)?"
    systemctl start postgresql
    ok "copied from $PRIMARY_IP; streaming"
  fi
  [ "$(sudo -u postgres psql -tAc 'SELECT pg_is_in_recovery()')" = "t" ] \
    || fail "Postgres is not running as a standby"
elif [ ! -f "$SECRETS" ]; then
  (
    umask 077
    {
      echo "OWNER_PASSWORD=$(openssl rand -hex 24)"
      echo "APP_PASSWORD=$(openssl rand -hex 24)"
      echo "BACKUP_PASSWORD=$(openssl rand -hex 24)"
    } > "$SECRETS"
  )
  ok "passwords generated → $SECRETS"
fi
if [ -z "$PRIMARY_IP" ]; then
# shellcheck disable=SC1090
. "$SECRETS"
sudo -u postgres psql -v ON_ERROR_STOP=1 -q <<SQL
DO \$\$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'envelock') THEN
    CREATE ROLE envelock LOGIN PASSWORD '$OWNER_PASSWORD' CREATEROLE CREATEDB;
  ELSE
    ALTER ROLE envelock LOGIN PASSWORD '$OWNER_PASSWORD' CREATEROLE CREATEDB;
  END IF;
END \$\$;
SQL
if ! sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='envelock'" | grep -q 1; then
  sudo -u postgres createdb -O envelock envelock
fi
ok "database 'envelock' owned by role 'envelock'"
fi

# ---- 5. GitHub access --------------------------------------------------------
log "5/13  GitHub access"
if [[ "$REPO_URL" == git@github.com:* ]]; then
  if [ ! -f "$APP_HOME/.ssh/id_ed25519" ]; then
    as_app "mkdir -p ~/.ssh && chmod 700 ~/.ssh && ssh-keygen -q -t ed25519 -C envelock-server -N '' -f ~/.ssh/id_ed25519"
  fi
  as_app "ssh-keyscan -t ed25519 github.com >> ~/.ssh/known_hosts 2>/dev/null; sort -u -o ~/.ssh/known_hosts ~/.ssh/known_hosts"
  until as_app "ssh -o BatchMode=yes -T git@github.com 2>&1 | grep -q 'successfully authenticated'"; do
    echo
    echo "    This server needs read access to your GitHub repository."
    echo "    Copy the line below, then on github.com: Settings → SSH and GPG keys → New SSH key."
    echo
    cat "$APP_HOME/.ssh/id_ed25519.pub"
    echo
    read -r -p "    Press Enter once it is added (Ctrl-C to stop)… " _
  done
  ok "GitHub accepts this server's key"
else
  ok "using $REPO_URL"
fi

# ---- 6. code -----------------------------------------------------------------
log "6/13  code"
# One repository, cloned straight into ~/apps, so server/, client/ and admin/
# sit where the services, nginx and backups expect them.
if [ ! -d "$APPS/.git" ]; then
  [ -z "$(ls -A "$APPS" 2>/dev/null)" ] || fail "$APPS exists and is not a clone of the repository — move it aside first"
  as_app "git clone -q '$REPO_URL' '$APPS'"
  ok "cloned the repository into $APPS"
else
  ok "repository already present"
fi
for app in server client admin; do
  [ -d "$APPS/$app" ] || fail "$APPS/$app is missing — is $REPO_URL the right repository?"
done
as_app "mkdir -p $DEPLOY_DIR && cp $APPS/server/deploy/deploy.sh $DEPLOY_DIR/deploy.sh && chmod +x $DEPLOY_DIR/deploy.sh"
as_app "cd $APPS/server && [ -x .venv/bin/python ] || python3 -m venv .venv"
as_app "cd $APPS/server && ./.venv/bin/pip install -q --upgrade pip && ./.venv/bin/pip install -q -e ."
ok "python environment ready"

# ---- 7. settings -------------------------------------------------------------
log "7/13  production settings"
if [ -n "$PRIMARY_IP" ]; then
  # The standby must be the same deployment: same database passwords (they came
  # over with the data), same app secret, same credential keys.
  for f in .env .env.worker; do
    if [ ! -f "$APPS/server/$f" ]; then
      [ -f "/root/$f" ] || fail "copy the live server's server/$f to /root/$f first (see replication-primary.sh's output)"
      install -m 600 -o "$APP_USER" -g "$APP_USER" "/root/$f" "$APPS/server/$f"
    fi
  done
  ok ".env and .env.worker copied from the live server"
elif [ -f "$APPS/server/.env.worker" ]; then
  ok ".env and .env.worker already exist — left untouched"
else
  [ -f "$SOURCE_ENV" ] || fail "copy your laptop's server/.env to $SOURCE_ENV first (see the top of this script)"
  IP="$(public_ip)"
  as_app "true"  # ensure the user can read what we hand it
  install -m 600 -o "$APP_USER" -g "$APP_USER" "$SOURCE_ENV" "$APP_HOME/.laptop.env"
  as_app "cd $APPS/server && ./.venv/bin/python deploy/make_prod_env.py --source ~/.laptop.env \
    --ip '$IP' --owner-password '$OWNER_PASSWORD' --app-password '$APP_PASSWORD' \
    --backup-password '$BACKUP_PASSWORD'"
  rm -f "$APP_HOME/.laptop.env"
  ok "API settings → .env (cannot decrypt), worker settings → .env.worker (holds the private key)"
fi
PRIVATE="$(grep -E '^ENVELOCK_CREDENTIAL_PRIVATE_KEY=' "$APPS/server/.env.worker" | cut -d= -f2-)"

# ---- 8. schema + row-level security -----------------------------------------
if [ -n "$PRIMARY_IP" ]; then
  log "8-9/13 schema and row-level security — copied with the database (standby)"
else
log "8/13  database tables"
# Development mode for these two commands only: production refuses to load at
# all until row-level security is in place, which is what step 9 sets up.
as_app "cd $APPS/server && ENVELOCK_ENV=development ./.venv/bin/alembic upgrade head" >/dev/null
ok "schema at head"

log "9/13  row-level security"
# Its output repeats the passwords and suggests manual commands this script
# runs itself below, so it is only shown if something went wrong.
provision_log="$(as_app "cd $APPS/server && ENVELOCK_ENV=development ./.venv/bin/python -m envelock.security.provision_rls \
  --password '$APP_PASSWORD' --backup-password '$BACKUP_PASSWORD' \
  --dsn 'postgresql+asyncpg://envelock:$OWNER_PASSWORD@localhost:5432/envelock'" 2>&1)" \
  || { echo "$provision_log"; fail "provisioning the restricted database role failed (output above)"; }
sudo -u postgres psql -v ON_ERROR_STOP=1 -q -d envelock <<SQL
DO \$\$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'envelock_app') THEN
    RAISE EXCEPTION 'provision_rls did not create envelock_app';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'envelock_backup') THEN
    CREATE ROLE envelock_backup LOGIN PASSWORD '$BACKUP_PASSWORD' BYPASSRLS NOSUPERUSER;
  ELSE
    ALTER ROLE envelock_backup LOGIN PASSWORD '$BACKUP_PASSWORD' BYPASSRLS NOSUPERUSER;
  END IF;
END \$\$;
GRANT CONNECT ON DATABASE envelock TO envelock_backup;
GRANT USAGE ON SCHEMA public TO envelock_backup;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO envelock_backup;
ALTER DEFAULT PRIVILEGES FOR ROLE envelock IN SCHEMA public GRANT SELECT ON TABLES TO envelock_backup;
SQL
ok "app role (restricted) and backup role (read-only, bypasses RLS) ready"
fi

# ---- 10. services ------------------------------------------------------------
log "10/13 services"
for unit in envelock-api.service envelock-worker.service envelock-backup.service envelock-backup.timer; do
  sed "s#/home/ubuntu#$APP_HOME#g; s#^User=ubuntu#User=$APP_USER#" \
    "$APPS/server/deploy/$unit" > "/etc/systemd/system/$unit"
done
install -d -o "$APP_USER" -g "$APP_USER" /var/backups/envelock
systemctl daemon-reload
if [ -n "$PRIMARY_IP" ]; then
  # Installed, deliberately OFF: a second API/worker would poll every mailbox
  # twice and write to a read-only database. failover.sh turns them on.
  systemctl disable --now envelock-api envelock-worker envelock-backup.timer >/dev/null 2>&1 || true
  ok "API, worker and backups installed but off until failover"
else
systemctl enable envelock-api envelock-worker envelock-backup.timer >/dev/null 2>&1
systemctl restart envelock-api envelock-worker
systemctl start envelock-backup.timer
for i in $(seq 1 30); do
  curl -fsS --max-time 3 localhost:8010/ready >/dev/null 2>&1 && break
  [ "$i" = 30 ] && { journalctl -u envelock-api -n 40 --no-pager; fail "the API did not become ready — its log is above"; }
  sleep 2
done
ok "API ready: $(curl -fsS localhost:8010/ready)"
sleep 3
# Read the log once, then search it. Piping journalctl straight into `grep -q`
# under `pipefail` reports failure whenever grep finds its match before the
# journal has finished writing — a false alarm that appears only once the log
# is long, i.e. on every run after the first.
api_log="$(journalctl -u envelock-api -n 300 --no-pager -o cat)"
if grep -q "row-level security is enforced" <<<"$api_log"; then
  ok "API: row-level security enforced"
else
  warn "API log does not confirm RLS — check: journalctl -u envelock-api | grep -i rls"
fi
if grep -q "seal-only" <<<"$api_log"; then
  ok "API: seal-only (cannot decrypt mailbox passwords)"
else
  warn "API log does not confirm seal-only custody"
fi
systemctl is-active --quiet envelock-worker && ok "worker running" \
  || { journalctl -u envelock-worker -n 40 --no-pager; fail "the worker is not running — its log is above"; }
fi

# ---- 11. nginx ---------------------------------------------------------------
log "11/13 nginx"
install -d /etc/nginx/snippets
cp "$APPS/server/deploy/nginx/cloudflare-realip.conf" "$APPS"/server/deploy/nginx/headers-*.conf /etc/nginx/snippets/
for s in app api admin root; do
  # certbot adds its TLS lines to these files; do not overwrite a site it has already edited.
  if ! grep -q "managed by Certbot" "/etc/nginx/sites-available/envelock-$s.conf" 2>/dev/null; then
    sed "s#/home/ubuntu#$APP_HOME#g" "$APPS/server/deploy/nginx/envelock-$s.conf" \
      > "/etc/nginx/sites-available/envelock-$s.conf"
  fi
  ln -sf "/etc/nginx/sites-available/envelock-$s.conf" /etc/nginx/sites-enabled/
done
rm -f /etc/nginx/sites-enabled/default
chmod o+x "$APP_HOME" "$APPS"
nginx -t 2>&1 | tail -1
systemctl reload nginx
ok "nginx serving app., api., admin. and the root redirect"

# ---- 12. HTTPS ---------------------------------------------------------------
if [ "$SKIP_TLS" = 1 ]; then
  log "12/13 HTTPS — skipped (--skip-tls). Later:  bash $0 --tls-only --email you@yourdomain.com"
else
  request_tls || warn "continuing without HTTPS for now"
fi

# ---- 13. first deploy --------------------------------------------------------
if [ -n "$PRIMARY_IP" ]; then
  log "13/13 building the web app and admin console (no deploy: the database is read-only)"
  as_app "cd $APPS/client && { npm ci || npm install; } >/dev/null && npm run build >/dev/null"
  as_app "cd $APPS/admin && { npm ci || npm install; } >/dev/null && npm run build >/dev/null"
  chmod -R a+rX "$APPS/client/dist" "$APPS/admin/dist"
  ok "built"
  printf '%s\n' \
    "" \
    "────────────────────────────────────────────────────────────────────────────" \
    " Standby ready: a live copy of $PRIMARY_IP, everything installed and off." \
    "" \
    " Check replication:   bash $APPS/server/deploy/replica-status.sh" \
    " If the live server is lost:" \
    "   sudo bash $APPS/server/deploy/failover.sh --email you@yourdomain.com" \
    " then point DNS at this server (docs/LAUNCH-GUIDE.md, \"A standby server\")." \
    "────────────────────────────────────────────────────────────────────────────"
  exit 0
fi
log "13/13 first deploy (builds the web app and admin console)"
as_app "$DEPLOY_DIR/deploy.sh" || fail "deploy.sh stopped — its message above says why"

cat <<EOF

────────────────────────────────────────────────────────────────────────────
 Envelock is installed.

 Save these in your password manager NOW, then delete $SECRETS:
   • the three database passwords in $SECRETS
   • the credential PRIVATE key (in $APPS/server/.env.worker):
       ${PRIVATE:0:6}…  — losing it means every customer reconnects every mailbox

 Next (docs/LAUNCH-GUIDE.md, step 14): create your operator account:
   sudo -u $APP_USER -H bash -c 'cd $APPS/server && ./.venv/bin/python -m \\
     envelock.security.bootstrap_staff --email you@envelock.org --name "Your Name" --department leadership'

 From now on, log in as $APP_USER, and deploy with:  ~/deploy/deploy.sh
────────────────────────────────────────────────────────────────────────────
EOF
