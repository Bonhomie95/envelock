#!/usr/bin/env bash
# Envelock deploy: pull the repository from GitHub, rebuild, restart, verify.
#
# One repository (Bonhomie95/envelock) holds all three apps, cloned straight
# into ~/apps so every path the services, nginx and backups use stays put:
#
#     /home/ubuntu/
#     ├── apps/            <- the repository
#     │   ├── server/
#     │   ├── client/
#     │   └── admin/
#     └── deploy/          <- this script, and client.env (outside the repo)
#
# Being outside the repo means a bad deploy cannot leave the deploy tool itself
# in a half-updated state, and it keeps working even if the clone is wiped and
# re-made. `git pull` cannot update this file, so right after pulling it compares
# itself with the copy in the repo and, if that one is newer, swaps it in and
# re-runs it — every deploy runs the deploy tool of the release it deploys.
#
# The important part is the PREFLIGHT: the new server code is imported and its
# settings constructed *before* the running API is touched. A config error — the
# class of bug that takes the API down for every customer at once — is caught
# while the old process is still serving. And because `pip install` has already
# put the new code in the live venv by then, a failed preflight (or build, or
# backup, or migration) ROLLS BACK: the checkout and the venv go back to the
# commit that is running, so the next crash or reboot does not boot the build
# that just failed. Nothing customer-facing changes until the new API is ready:
# the web builds go to dist.next and are swapped in only after that.
set -euo pipefail

# Override with ENVELOCK_APPS=/somewhere ./deploy.sh if your layout differs.
APPS="${ENVELOCK_APPS:-/home/ubuntu/apps}"
API_BASE="${ENVELOCK_API_BASE:-https://api.envelock.org}"   # baked into the client build
API_UNIT="envelock-api"
WORKER_UNIT="envelock-worker"         # only exists once key custody is split
# Where the installed copies live. Overridable so the script can be tested.
NGINX_SNIPPETS="${ENVELOCK_NGINX_SNIPPETS:-/etc/nginx/snippets}"
SYSTEMD_DIR="${ENVELOCK_SYSTEMD_DIR:-/etc/systemd/system}"
API_READY="${ENVELOCK_API_READY_URL:-http://localhost:8010/ready}"
WORKER_READY="${ENVELOCK_WORKER_READY_URL:-http://localhost:8011/ready}"
READY_SLEEP="${ENVELOCK_READY_SLEEP:-2}"

SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
DEPLOY_DIR="$(dirname "$SELF")"

log()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m!!  %s\033[0m\n' "$*" >&2; }
fail() { printf '\n\033[1;31m!!  %s\033[0m\n' "$*" >&2; exit 1; }

# ---- 0. Sanity: is the clone where we think, with all three apps in it? ----
[ -d "$APPS/.git" ] || fail "$APPS is not a git clone of the Envelock repository.
  Set ENVELOCK_APPS=/path/to/the/clone if yours lives elsewhere."
for app in server client admin; do
  [ -d "$APPS/$app" ] || fail "$APPS/$app is missing — is $APPS the right repository?"
done

pull() {                              # $1 = repo dir
  local dir="$1" br before after
  br="$(git -C "$dir" rev-parse --abbrev-ref HEAD)"
  before="$(git -C "$dir" rev-parse HEAD)"
  log "$(basename "$dir"): pulling origin/$br"
  # Refuse to deploy on top of uncommitted work: it is either someone debugging
  # on the box (whose changes this would blow away) or a half-finished edit.
  git -C "$dir" diff --quiet || fail "$(basename "$dir") has uncommitted changes — commit or stash first"
  # Fetch first, then decide. `git pull --ff-only` fails with a bare "not
  # possible to fast-forward", which does not distinguish the two cases that
  # produce it — and they need opposite responses.
  git -C "$dir" fetch --quiet origin "$br"
  if ! git -C "$dir" merge-base --is-ancestor HEAD "origin/$br" 2>/dev/null; then
    # Diverged. Whether that is safe to fix automatically comes down to one
    # question: would resetting lose any content?
    #
    # After a history rewrite (an amended message, a dropped trailer) this box
    # sits on a commit that no longer exists upstream — which *counts* as a
    # local commit, so counting commits says "you have work here" when the
    # files are byte-identical. Comparing trees answers the real question:
    # identical content means a reset provably loses nothing.
    if git -C "$dir" diff --quiet "origin/$br" HEAD 2>/dev/null; then
      log "$(basename "$dir"): upstream history was rewritten (same content); resetting"
      git -C "$dir" reset --hard "origin/$br"
      echo "   now at $(git -C "$dir" rev-parse --short HEAD)"
      return
    fi
    local ahead
    ahead="$(git -C "$dir" rev-list --count "origin/$br"..HEAD 2>/dev/null || echo "?")"
    fail "$(basename "$dir") has diverged from origin/$br ($ahead local commit(s), and the
  content differs). Look before discarding anything:
      cd $dir && git log --oneline origin/$br..HEAD && git diff origin/$br
  If none of it is wanted:
      cd $dir && git fetch origin && git reset --hard origin/$br"
  fi
  git -C "$dir" merge --ff-only "origin/$br"
  after="$(git -C "$dir" rev-parse HEAD)"
  [ "$before" = "$after" ] && echo "   (already up to date)" || echo "   ${before:0:7} → ${after:0:7}"
}

# The commit the services are running, so a failed deploy can put the checkout
# and the venv back to it. Exported so it survives the re-exec below.
export ENVELOCK_DEPLOY_BEFORE="${ENVELOCK_DEPLOY_BEFORE:-$(git -C "$APPS" rev-parse HEAD)}"
SNIPPET_BACKUP=""

restore_snippets() {
  [ -n "$SNIPPET_BACKUP" ] || return 0
  if ! { sudo cp -a "$SNIPPET_BACKUP/." "$NGINX_SNIPPETS/" \
         && sudo nginx -t -q && sudo systemctl reload nginx; }; then
    warn "could not restore the previous nginx snippets — check: sudo nginx -t"
  fi
  SNIPPET_BACKUP=""
}

# Only for failures BEFORE the migration and the restart: then the running
# services are still the previous release, and the files on disk must match them
# again. After a migration the schema has moved on; rolling the code back then
# would be the wrong direction, so later failures stop and say so instead.
rollback() {                          # $1 = what failed
  warn "$1 — rolling back to ${ENVELOCK_DEPLOY_BEFORE:0:7}"
  restore_snippets
  rm -rf "$APPS/client/dist.next" "$APPS/admin/dist.next"
  if git -C "$APPS" reset -q --hard "$ENVELOCK_DEPLOY_BEFORE" \
     && ( cd "$APPS/server" && ./.venv/bin/pip install -q . ); then
    fail "$1. Rolled back to ${ENVELOCK_DEPLOY_BEFORE:0:7}: the checkout and the venv match
  the release that is still serving, so a restart or reboot brings back that one."
  fi
  fail "$1 — AND the rollback failed, so the venv may hold the new build. Fix that
  before anything restarts the services:
      cd $APPS && git reset --hard ${ENVELOCK_DEPLOY_BEFORE:0:7} && cd server && ./.venv/bin/pip install ."
}

# ---- 1. Pull ----
pull "$APPS"

# ---- 1a. Run the deploy tool of the release being deployed ----
# A rename, not a copy over the top: bash reads a running script as it goes, so
# overwriting it in place corrupts this very run. The new file is a new inode;
# this process keeps reading the old one until exec replaces it.
CANON="$APPS/server/deploy/deploy.sh"
if [ -z "${ENVELOCK_DEPLOY_REEXEC:-}" ] && [ -f "$CANON" ] && [ "$CANON" != "$SELF" ] \
   && ! cmp -s "$CANON" "$SELF"; then
  if install -m 755 "$CANON" "$SELF.new" && mv -f "$SELF.new" "$SELF"; then
    log "deploy.sh: the repository has a newer version — re-running that one"
    ENVELOCK_DEPLOY_REEXEC=1 exec "$SELF" "$@"
  fi
  warn "could not replace $SELF with the repository's newer copy — continuing with this one"
fi

# ---- 2. The server: install, then prove it boots ----
log "server: installing deps"
# Not -q: a dependency floor raised for a security fix (e.g. pypdf, cryptography)
# upgrades here, and you want to see that happen rather than wonder later.
( cd "$APPS/server" && ./.venv/bin/pip install . ) || rollback "pip install failed"

log "server: preflight (import + settings + routes)"
# Run it from the same working directory systemd uses, so `.env` is found the
# same way and a missing or malformed setting fails here rather than after the
# restart.
#
# Deliberately NOT `set -a; . ./.env`. Sourcing the env file with bash was both
# unnecessary and actively harmful: pydantic-settings already reads `.env` from
# this directory — it is the same loader the running app uses, so it is a
# *truer* preflight than bash — while bash applies shell syntax to values it has
# no business interpreting. A perfectly good SMTP password containing `)`, `(`
# or `|` aborted the preflight with a shell syntax error, which is to say the
# deploy tool broke on exactly the passwords you want people to use.
(
  cd "$APPS/server"
  ./.venv/bin/python - <<'PY'
import sys

try:
    from envelock.config import get_settings

    settings = get_settings()          # the production validator runs here
    from envelock.main import app      # every router imports here

    from envelock.security.keys import custody_summary

    custody = custody_summary()
    routes = len(app.openapi()["paths"])
except RecursionError:
    sys.exit("preflight: settings recursed — a validator is re-entering Settings()")
except Exception as exc:
    sys.exit(f"preflight: {type(exc).__name__}: {exc}")

if not custody["ok"]:
    sys.exit(f"preflight: credential key custody unusable — {custody.get('error')}")

print(f"    env={settings.env}  routes={routes}  key custody={custody['key_id']}")
if custody["mode"] == "local" and settings.env == "production":
    print("    WARNING: mailbox passwords are wrapped with a key in an environment")
    print("             variable, readable by this web process. See server/docs/LAUNCH-GUIDE.md, Part B.")
PY
) || rollback "server preflight failed — NOT restarting; the old build is still serving"

# The worker boots from its own file, which the check above never read: a key
# the worker cannot use, or a setting only it gets wrong, crash-looped it while
# the deploy reported success. Same loader, run from a directory with no `.env`
# so only the worker's values count. Read through sudo when it is root-only.
WORKER_ENV="$APPS/server/.env.worker"
if [ -f "$WORKER_ENV" ]; then
  log "worker: preflight (its own settings + key custody)"
  WORKER_PREFLIGHT="$(cat <<'PY'
import os
import sys

from dotenv import dotenv_values

for key in [k for k in os.environ if k.startswith("ENVELOCK_")]:
    del os.environ[key]
os.environ.update({k: v for k, v in dotenv_values(stream=sys.stdin).items() if v is not None})
try:
    from envelock.config import get_settings
    from envelock.security.keys import custody_summary

    settings = get_settings()
    custody = custody_summary()
except RecursionError:
    sys.exit("worker preflight: settings recursed")
except Exception as exc:
    sys.exit(f"worker preflight: {type(exc).__name__}: {exc}")
if not custody["ok"]:
    sys.exit(f"worker preflight: credential key custody unusable — {custody.get('error')}")
if not custody.get("can_decrypt"):
    sys.exit("worker preflight: .env.worker cannot decrypt stored credentials, so the worker would read no mail")
print(f"    worker env={settings.env}  key custody={custody['key_id']} (can decrypt)")
PY
)"
  read_worker_env() { if [ -r "$WORKER_ENV" ]; then cat "$WORKER_ENV"; else sudo -n cat "$WORKER_ENV"; fi; }
  read_worker_env | ( cd / && "$APPS/server/.venv/bin/python" -c "$WORKER_PREFLIGHT" ) \
    || rollback "worker preflight failed — NOT restarting; the old build is still serving"
fi

# ---- 3. Web builds, into dist.next ----
# Built now, so a broken build stops the deploy while it can still roll back, and
# into dist.next, so nginx keeps serving the current build until the API that
# matches the new one is up (step 7).
#
# The client has no hardcoded API host: an absent env file means same-origin,
# which would 404 against the static host. Write it before every build.
#
# Anything else the build needs (the sensor's store links, VITE_SENSOR_*_URL)
# lives in client.env next to this script, outside the repo, and is appended.
# Writing only the API line used to erase those links on every deploy.
{
  printf 'VITE_API_BASE_URL=%s\n' "$API_BASE"
  if [ -f "$DEPLOY_DIR/client.env" ]; then
    grep -v '^VITE_API_BASE_URL=' "$DEPLOY_DIR/client.env" || true
  fi
} > "$APPS/client/.env.production"
log "client: building"
( cd "$APPS/client" && { npm ci || npm install; } && npm run build -- --outDir dist.next ) \
  || rollback "client build failed"
[ -f "$APPS/client/dist.next/index.html" ] || rollback "client build produced no index.html"
grep -q "$API_BASE" "$APPS/client"/dist.next/assets/*.js \
  || rollback "client bundle does not reference $API_BASE — the env file was not picked up"

log "admin: building"
( cd "$APPS/admin" && { npm ci || npm install; } && npm run build -- --outDir dist.next ) \
  || rollback "admin build failed"
[ -f "$APPS/admin/dist.next/index.html" ] || rollback "admin build produced no index.html"

# ---- 3a. nginx security headers ----
# setup-server.sh copied these snippets once; nothing ever updated them, so a CSP
# change (Turnstile's challenges.cloudflare.com, 29 Oct) stayed in the repo while
# production kept the old policy and blocked the widget. They are installed
# verbatim, so they can be synced safely — unlike the site files, which certbot
# edits. Checked with `nginx -t` and put back if nginx refuses them.
sync_snippets() {
  local src="$APPS/server/deploy/nginx" f changed=0
  for f in "$src"/headers-*.conf "$src"/cloudflare-realip.conf; do
    cmp -s "$f" "$NGINX_SNIPPETS/$(basename "$f")" || changed=1
  done
  if [ "$changed" = 0 ]; then
    echo "    nginx snippets: unchanged"
    return 0
  fi
  log "nginx: installing changed security-header snippets"
  SNIPPET_BACKUP="$(mktemp -d)"
  sudo cp -a "$NGINX_SNIPPETS/." "$SNIPPET_BACKUP/"
  sudo install -m 644 "$src"/headers-*.conf "$src"/cloudflare-realip.conf "$NGINX_SNIPPETS/"
  if ! sudo nginx -t -q; then
    rollback "nginx rejected the new snippets (the previous ones are back in place)"
  fi
  sudo systemctl reload nginx || rollback "nginx did not reload with the new snippets"
}
sync_snippets

# ---- 4. Database: back up, then migrate ----
# Order is not negotiable. A migration is the most likely thing in a deploy to
# damage data, so the backup that would let you undo it has to exist BEFORE it
# runs, not on tonight's timer.
log "database: pre-deploy backup"
if [ -x "$APPS/server/deploy/backup.sh" ]; then
  ( cd "$APPS/server" && ./deploy/backup.sh --label "predeploy" ) \
    || rollback "pre-deploy backup failed — NOT migrating. Fix the backup first: a
  migration you cannot roll back is not a migration, it is a gamble"
else
  warn "deploy/backup.sh missing — skipping the pre-deploy backup. Install it."
fi

# Migrations were written, tested by tests/test_migrations.py, and never run:
# this script had no `alembic upgrade head`, so the schema came from create_all
# plus the runtime reconciler. That reconciler adds missing columns and widens
# undersized ones — it CANNOT add an index, add a constraint, change a type or
# migrate data. Every index written since launch therefore never reached
# production. This is where that stops.
log "database: alembic upgrade head"
# A failed upgrade is rolled back by Postgres (transactional DDL), so the old
# code still matches the schema and rolling the files back is safe.
( cd "$APPS/server" && ./.venv/bin/alembic upgrade head ) \
  || rollback "migration failed — NOT restarting; the old build is still serving.
  The pre-deploy backup above is your restore point: ./deploy/restore.sh --list"
# Past the migration there is no rolling back, so the old snippets are not needed.
if [ -n "$SNIPPET_BACKUP" ]; then
  sudo rm -rf "$SNIPPET_BACKUP"
  SNIPPET_BACKUP=""
fi

# ---- 5. Restart ----
log "restarting the API"
sudo systemctl restart "$API_UNIT"
# The worker only exists on a split-custody deployment; restart it if it is there.
# `systemctl cat`, not a fixed file path: the unit can live under /lib, /run, a
# drop-in, or an enablement symlink, and a bare `[ -f /etc/systemd/system/... ]`
# then tests false even though systemd knows the unit — which silently left the
# worker running the PREVIOUS release on every deploy (it 403'd on stale Graph
# URLs for a full release cycle before this was caught). `systemctl cat` exits 0
# iff the unit is known, wherever its file is, and needs no pipe under pipefail.
HAS_WORKER=0
if systemctl cat "$WORKER_UNIT" >/dev/null 2>&1; then
  HAS_WORKER=1
  sudo systemctl restart "$WORKER_UNIT"
  log "restarted $WORKER_UNIT"
else
  log "no $WORKER_UNIT unit found — skipping (single-process deployment)"
fi

# ---- 6. Verify ----
# /ready, not /health. /health is liveness: it answers 200 as soon as the event
# loop is up and deliberately touches no dependency, so gating a deploy on it
# reported "deployed successfully" for a release that could not reach Postgres.
# /ready runs the actual dependency checks and 503s when the database is gone.
# The worker serves the same app on its own loopback port, and answers only once
# its start-up — settings, schema, key custody — has finished.
wait_ready() {                        # $1 = url, $2 = unit
  local attempt
  for attempt in 1 2 3 4 5 6 7 8 9 10; do
    if curl -fsS --max-time 5 "$1" >/dev/null 2>&1; then
      echo "    $2: $(curl -fsS --max-time 5 "$1")"
      return 0
    fi
    [ "$attempt" = 10 ] || sleep "$READY_SLEEP"
  done
  # Show what actually failed rather than only the exit status: the body names
  # the failing dependency.
  curl -sS --max-time 5 "$1" || true
  echo
  fail "$2 did not become ready — sudo journalctl -u $2 -n 50 --no-pager
  The database IS migrated, so fix forward; the pre-deploy backup is the way back."
}
log "readiness check"
wait_ready "$API_READY" "$API_UNIT"
if [ "$HAS_WORKER" = 1 ]; then
  wait_ready "$WORKER_READY" "$WORKER_UNIT"
fi

# ---- 7. Publish the web builds ----
# Two renames: the window with no dist/ is a few microseconds, and the previous
# build stays in dist.prev until the next deploy in case it has to come back.
publish() {                           # $1 = app dir
  [ -d "$1/dist.next" ] || return 0
  rm -rf "$1/dist.prev"
  if [ -d "$1/dist" ]; then mv "$1/dist" "$1/dist.prev"; fi
  mv "$1/dist.next" "$1/dist"
}
log "publishing the web builds + making them readable by nginx"
publish "$APPS/client"
publish "$APPS/admin"
# Readable files are not enough: nginx (www-data) must be able to walk EVERY
# directory on the way down. Ubuntu creates /home/<user> as 750, so without the
# execute bit here nginx cannot enter the path at all and answers 403 for a
# perfectly good build. `o+x` grants traversal only — not listing, which would
# need `o+r` — so nothing becomes browsable.
chmod o+x "$HOME" "$APPS" "$APPS/client" "$APPS/admin"
chmod -R a+rX "$APPS/client/dist" "$APPS/admin/dist"

# The static sites are served by nginx, not the API, so check them separately —
# a perfectly healthy API with a broken vhost is still an outage for customers.
for host in app.envelock.org admin.envelock.org; do
  # No -f here: it makes curl exit nonzero on an HTTP error while -w still
  # prints the status, so a fallback would concatenate onto the real code.
  code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 "https://$host/" 2>/dev/null)" || true
  code="${code:-000}"
  case "$code" in
    200) echo "    $host  ok" ;;
    403) echo "    $host  403  <-- nginx cannot read the build. Run:" ;
         echo "                    chmod o+x $HOME $APPS $APPS/client $APPS/admin" ;;
    404) echo "    $host  404  <-- build missing; check $APPS/*/dist/index.html" ;;
    502|503) echo "    $host  $code  <-- API down: journalctl -u $API_UNIT -n 50" ;;
    521|000) echo "    $host  $code  <-- origin unreachable; is TLS set up on :443?" ;;
    *)   echo "    $host  $code  <-- check nginx" ;;
  esac
done
# And the one thing that is easy to get wrong: the admin console calls /api on
# its OWN origin, so this proxy has to work or the console is dead on arrival.
code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 https://admin.envelock.org/api/v1/admin/whoami 2>/dev/null)" || true
code="${code:-000}"
# 404 is the CORRECT unauthenticated answer here, not a miss: the console
# deliberately does not advertise that a super-admin surface exists (auth/deps.py).
if [ "$code" = 404 ] || [ "$code" = 401 ]; then
  echo "    admin /api proxy  ok (auth gate answered $code)"
else
  echo "    admin /api proxy  $code  <-- nginx is not proxying /api to the API"
fi

# ---- 8. Are the installed systemd units the repository's? ----
# Like the nginx snippets, setup-server.sh installed these once. They are not
# synced automatically — a sandboxing change to a running service deserves a
# person watching it restart — but drift is reported every time, with the fix.
drift=""
for unit in envelock-api.service envelock-worker.service envelock-backup.service \
            envelock-backup.timer envelock-notify@.service; do
  src="$APPS/server/deploy/$unit"
  [ -f "$src" ] || continue
  [ -f "$SYSTEMD_DIR/$unit" ] || [ "$unit" = envelock-notify@.service ] || continue
  if ! sed "s#/home/ubuntu#$HOME#g; s#^User=ubuntu#User=$(id -un)#" "$src" \
       | cmp -s - "$SYSTEMD_DIR/$unit"; then
    drift="$drift $unit"
  fi
done
if [ -n "$drift" ]; then
  warn "these systemd units differ from the repository's:$drift
  Review the change, then install them (docs/LAUNCH-GUIDE.md, \"Updating the systemd units\"):
      cd $APPS/server/deploy && for u in$drift; do
        sed \"s#/home/ubuntu#\$HOME#g; s#^User=ubuntu#User=\$(id -un)#\" \"\$u\" | sudo tee $SYSTEMD_DIR/\"\$u\" >/dev/null
      done && sudo systemctl daemon-reload && sudo systemctl restart $API_UNIT $WORKER_UNIT"
fi

log "deploy complete."
