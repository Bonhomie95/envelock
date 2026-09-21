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
# re-made. The cost is that `git pull` does not update this file, so the tail
# end compares it against the copy in the repo and tells you when yours has
# fallen behind.
#
# The important part is the PREFLIGHT: the new server code is imported and its
# settings constructed *before* the running API is touched. A config error — the
# class of bug that takes the API down for every customer at once — is caught
# while the old process is still serving.
set -euo pipefail

# Override with ENVELOCK_APPS=/somewhere ./deploy.sh if your layout differs.
APPS="${ENVELOCK_APPS:-/home/ubuntu/apps}"
API_BASE="${ENVELOCK_API_BASE:-https://api.envelock.org}"   # baked into the client build
API_UNIT="envelock-api"
WORKER_UNIT="envelock-worker"         # only exists once key custody is split

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

# ---- 1. Pull, then the server (API) ----
pull "$APPS"
log "server: installing deps"
# Not -q: a dependency floor raised for a security fix (e.g. pypdf, cryptography)
# upgrades here, and you want to see that happen rather than wonder later.
( cd "$APPS/server" && ./.venv/bin/pip install . )

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
) || fail "server preflight failed — NOT restarting; the old build is still serving"

# ---- 2. Client ----
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
( cd "$APPS/client" && { npm ci || npm install; } && npm run build )
[ -f "$APPS/client/dist/index.html" ] || fail "client build produced no index.html"
grep -q "$API_BASE" "$APPS/client"/dist/assets/*.js \
  || fail "client bundle does not reference $API_BASE — the env file was not picked up"

# ---- 3. Admin ----
log "admin: building"
( cd "$APPS/admin" && { npm ci || npm install; } && npm run build )
[ -f "$APPS/admin/dist/index.html" ] || fail "admin build produced no index.html"

# ---- 3b. Database: back up, then migrate ----
# Order is not negotiable. A migration is the most likely thing in a deploy to
# damage data, so the backup that would let you undo it has to exist BEFORE it
# runs, not on tonight's timer.
log "database: pre-deploy backup"
if [ -x "$APPS/server/deploy/backup.sh" ]; then
  ( cd "$APPS/server" && ./deploy/backup.sh --label "predeploy" ) \
    || fail "pre-deploy backup failed — NOT migrating. Fix the backup first: a
  migration you cannot roll back is not a migration, it is a gamble."
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
( cd "$APPS/server" && ./.venv/bin/alembic upgrade head ) \
  || fail "migration failed — NOT restarting; the old build is still serving.
  The pre-deploy backup above is your restore point:
    ./deploy/restore.sh --list"

# ---- 4. Publish + restart ----
log "making builds readable by nginx + restarting the API"
# Readable files are not enough: nginx (www-data) must be able to walk EVERY
# directory on the way down. Ubuntu creates /home/<user> as 750, so without the
# execute bit here nginx cannot enter the path at all and answers 403 for a
# perfectly good build. `o+x` grants traversal only — not listing, which would
# need `o+r` — so nothing becomes browsable.
chmod o+x "$HOME" "$APPS" "$APPS/client" "$APPS/admin"
chmod -R a+rX "$APPS/client/dist" "$APPS/admin/dist"
sudo systemctl restart "$API_UNIT"
# The worker only exists on a split-custody deployment; restart it if it is there.
# A file test, not `systemctl list-unit-files | grep -q`: under pipefail that
# pipeline fails whenever grep exits before the (long) listing is written, and
# the worker would then silently keep running the previous release.
if [ -f "/etc/systemd/system/${WORKER_UNIT}.service" ]; then
  sudo systemctl restart "$WORKER_UNIT"
fi

# ---- 5. Verify ----
# /ready, not /health. /health is liveness: it answers 200 as soon as the event
# loop is up and deliberately touches no dependency, so gating a deploy on it
# reported "deployed successfully" for a release that could not reach Postgres.
# /ready runs the actual dependency checks and 503s when the database is gone.
log "readiness check"
for attempt in 1 2 3 4 5 6 7 8 9 10; do
  if curl -fsS --max-time 5 localhost:8010/ready >/dev/null 2>&1; then
    curl -fsS localhost:8010/ready && echo
    break
  fi
  if [ "$attempt" = 10 ]; then
    # Show what actually failed rather than only the exit status: the body
    # names the failing dependency.
    curl -sS --max-time 5 localhost:8010/ready || true
    echo
    fail "API did not become ready — sudo journalctl -u $API_UNIT -n 50 --no-pager"
  fi
  sleep 2
done

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

# ---- 6. Is this script itself out of date? ----
# Living outside the repos is what makes this tool independent, and also what
# stops `git pull` from ever updating it. The repo keeps the canonical copy, so
# compare against it rather than letting yours quietly rot.
CANON="$APPS/server/deploy/deploy.sh"
if [ -f "$CANON" ] && ! cmp -s "$CANON" "$SELF"; then
  warn "a newer deploy.sh is in the server repo. To adopt it:"
  warn "    cp $CANON $SELF"
fi

log "deploy complete."
