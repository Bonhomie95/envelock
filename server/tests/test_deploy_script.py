"""`deploy/deploy.sh`, run for real against a stubbed machine.

The script is the one thing every release passes through, and its failure modes
were all of the quiet kind: a failed preflight left the new build installed in
the live venv (so the next crash booted it), the web builds went live before the
migration, the worker was never preflighted or checked, the nginx security
headers were never updated after setup, and the script never updated itself.

Each test builds a throwaway "server": a git origin with two commits, a clone of
the first one where the box keeps its checkout, and stubs on PATH for every
command that would touch the real system (sudo, systemctl, nginx, npm, curl, and
the venv's pip/python/alembic). The stubs append to a call log, so the tests can
assert on order as well as outcome.
"""

from __future__ import annotations

import os
import pwd
import shutil
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

SERVER = Path(__file__).resolve().parents[1]
DEPLOY = SERVER / "deploy"

BASH = shutil.which("bash")
GIT = shutil.which("git")
if BASH is None or GIT is None:  # pragma: no cover
    pytest.skip("needs bash and git", allow_module_level=True)

_STUBS = {
    "sudo": """
[ "$1" = "-n" ] && shift
exec "$@"
""",
    "systemctl": """
echo "systemctl $*" >> "$CALLS"
case "$1" in
  cat) [ -n "${HAS_WORKER_UNIT:-}" ] && exit 0; exit 1 ;;
esac
exit 0
""",
    "nginx": """
echo "nginx $*" >> "$CALLS"
if [ "$1" = "-t" ] && grep -q BROKEN "$ENVELOCK_NGINX_SNIPPETS"/headers-*.conf 2>/dev/null; then
  echo "nginx: [emerg] unexpected end of file" >&2
  exit 1
fi
exit 0
""",
    "npm": """
echo "npm $* ($(basename "$PWD"))" >> "$CALLS"
[ "$1" = run ] || exit 0
[ -n "${NPM_BUILD_FAIL:-}" ] && exit 1
out=dist
while [ $# -gt 0 ]; do
  if [ "$1" = --outDir ]; then out="$2"; fi
  shift
done
mkdir -p "$out/assets"
echo "fetch('$ENVELOCK_API_BASE') // new" > "$out/assets/index.js"
echo "new $(basename "$PWD")" > "$out/index.html"
""",
    "curl": """
echo "curl $*" >> "$CALLS"
url=""
for a in "$@"; do case "$a" in http*) url="$a" ;; esac; done
for arg in "$@"; do
  if [ "$arg" = "-w" ]; then printf 200; exit 0; fi
done
if [ -n "${CURL_FAIL:-}" ] && printf '%s' "$url" | grep -q "$CURL_FAIL"; then
  echo '{"status":"not_ready"}'
  exit 22
fi
echo '{"status":"ready"}'
""",
}

_VENV = {
    "pip": """
echo "pip $* @$(git -C "$ENVELOCK_APPS" rev-parse --short HEAD)" >> "$CALLS"
exit "${PIP_EXIT:-0}"
""",
    "python": """
if [ "$1" = "-c" ]; then
  cat > "$WORK/worker_env_seen"
  echo "python worker-preflight cwd=$PWD" >> "$CALLS"
  exit "${WORKER_PREFLIGHT_EXIT:-0}"
fi
cat > /dev/null
echo "python api-preflight" >> "$CALLS"
exit "${API_PREFLIGHT_EXIT:-0}"
""",
    "alembic": """
echo "alembic $*" >> "$CALLS"
exit "${MIGRATE_EXIT:-0}"
""",
}

_BACKUP_STUB = """#!/usr/bin/env bash
echo "backup $*" >> "$CALLS"
exit "${BACKUP_EXIT:-0}"
"""

_UNITS = (
    "envelock-api.service",
    "envelock-worker.service",
    "envelock-backup.service",
    "envelock-backup.timer",
    "envelock-notify@.service",
)


def _write_exec(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/usr/bin/env bash\n" + body.lstrip("\n"))
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(  # noqa: S603
        [GIT, "-c", "user.name=t", "-c", "user.email=t@example.test", *args],
        cwd=cwd, check=True, capture_output=True, text=True,
    ).stdout.strip()


@dataclass
class Box:
    root: Path
    home: Path
    apps: Path
    seed: Path
    snippets: Path
    systemd: Path
    calls: Path
    before: str
    after: str

    @property
    def self_copy(self) -> Path:
        return self.home / "deploy" / "deploy.sh"

    def calls_log(self) -> list[str]:
        return self.calls.read_text().splitlines() if self.calls.exists() else []

    def index(self, prefix: str) -> int:
        for i, line in enumerate(self.calls_log()):
            if line.startswith(prefix):
                return i
        raise AssertionError(f"{prefix!r} never ran: {self.calls_log()}")

    def ran(self, prefix: str) -> bool:
        return any(line.startswith(prefix) for line in self.calls_log())

    def head(self) -> str:
        return _git(self.apps, "rev-parse", "HEAD")

    def run(self, **env: str) -> subprocess.CompletedProcess:
        base = {
            "PATH": f"{self.root / 'stubs'}:{os.environ.get('PATH', '/usr/bin:/bin')}",
            "HOME": str(self.home),
            "CALLS": str(self.calls),
            "WORK": str(self.root),
            "ENVELOCK_APPS": str(self.apps),
            "ENVELOCK_API_BASE": "https://api.example.test",
            "ENVELOCK_NGINX_SNIPPETS": str(self.snippets),
            "ENVELOCK_SYSTEMD_DIR": str(self.systemd),
            "ENVELOCK_READY_SLEEP": "0",
        }
        return subprocess.run(  # noqa: S603
            [BASH, str(self.self_copy)],
            env={**base, **env}, capture_output=True, text=True, timeout=120,
        )

    def push_change(self, rel: str, text: str, message: str) -> None:
        (self.seed / rel).write_text(text)
        _git(self.seed, "add", "-A")
        _git(self.seed, "commit", "-q", "-m", message)
        _git(self.seed, "push", "-q", "origin", "main")
        self.after = _git(self.seed, "rev-parse", "HEAD")


@pytest.fixture
def box(tmp_path: Path) -> Box:
    origin = tmp_path / "origin.git"
    seed = tmp_path / "seed"
    home = tmp_path / "home"
    apps = home / "apps"
    _git(tmp_path, "init", "-q", "--bare", str(origin))
    _git(origin, "symbolic-ref", "HEAD", "refs/heads/main")
    _git(tmp_path, "init", "-q", "-b", "main", str(seed))

    (seed / "server" / "deploy" / "nginx").mkdir(parents=True)
    shutil.copy2(DEPLOY / "deploy.sh", seed / "server" / "deploy" / "deploy.sh")
    for conf in (DEPLOY / "nginx").glob("*.conf"):
        shutil.copy2(conf, seed / "server" / "deploy" / "nginx" / conf.name)
    for unit in _UNITS:
        if (DEPLOY / unit).exists():
            shutil.copy2(DEPLOY / unit, seed / "server" / "deploy" / unit)
    _write_exec(seed / "server" / "deploy" / "backup.sh", _BACKUP_STUB.split("\n", 1)[1])
    for app in ("client", "admin"):
        (seed / app).mkdir()
        (seed / app / "README").write_text(app)
    (seed / "server" / "VERSION").write_text("1\n")
    _git(seed, "add", "-A")
    _git(seed, "commit", "-q", "-m", "v1")
    _git(seed, "remote", "add", "origin", str(origin))
    _git(seed, "push", "-q", "origin", "main")
    before = _git(seed, "rev-parse", "HEAD")

    home.mkdir()
    _git(home, "clone", "-q", str(origin), str(apps))
    for name, body in _VENV.items():
        _write_exec(apps / "server" / ".venv" / "bin" / name, body)
    for app in ("client", "admin"):
        (apps / app / "dist").mkdir()
        (apps / app / "dist" / "index.html").write_text(f"old {app}")
    for name, body in _STUBS.items():
        _write_exec(tmp_path / "stubs" / name, body)

    # The box as setup-server.sh left it: snippets and units installed once.
    snippets = tmp_path / "snippets"
    snippets.mkdir()
    for conf in (DEPLOY / "nginx").glob("*.conf"):
        shutil.copy2(conf, snippets / conf.name)
    systemd = tmp_path / "systemd"
    systemd.mkdir()
    user = pwd.getpwuid(os.geteuid()).pw_name  # what `id -un` prints
    for unit in _UNITS:
        if (DEPLOY / unit).exists():
            rendered = (DEPLOY / unit).read_text().replace("/home/ubuntu", str(home))
            rendered = "\n".join(
                f"User={user}" if line == "User=ubuntu" else line
                for line in rendered.split("\n")
            )
            (systemd / unit).write_text(rendered)

    (home / "deploy").mkdir()
    shutil.copy2(DEPLOY / "deploy.sh", home / "deploy" / "deploy.sh")

    b = Box(
        root=tmp_path, home=home, apps=apps, seed=seed, snippets=snippets,
        systemd=systemd, calls=tmp_path / "calls.log", before=before, after=before,
    )
    b.push_change("server/VERSION", "2\n", "v2")
    return b


# ── The order of a good deploy ───────────────────────────────────────────────
def test_a_good_deploy_runs_in_order_and_publishes_last(box: Box) -> None:
    result = box.run()
    assert result.returncode == 0, result.stderr
    assert "deploy complete" in result.stdout
    assert box.head() == box.after

    order = [
        box.index("pip install ."),
        box.index("python api-preflight"),
        box.index("npm run build -- --outDir dist.next (client)"),
        box.index("npm run build -- --outDir dist.next (admin)"),
        box.index("backup --label predeploy"),
        box.index("alembic upgrade head"),
        box.index("systemctl restart envelock-api"),
        box.index("curl -fsS --max-time 5 http://localhost:8010/ready"),
    ]
    assert order == sorted(order), box.calls_log()
    # Published only after the API was ready, and the previous build kept.
    assert (box.apps / "client" / "dist" / "index.html").read_text().strip() == "new client"
    assert (box.apps / "client" / "dist.prev" / "index.html").read_text() == "old client"
    assert not (box.apps / "client" / "dist.next").exists()
    assert (box.apps / "admin" / "dist" / "index.html").read_text().strip() == "new admin"


# ── Failures before the restart roll the box back ────────────────────────────
@pytest.mark.parametrize(
    "env",
    [
        {"API_PREFLIGHT_EXIT": "1"},
        {"NPM_BUILD_FAIL": "1"},
        {"BACKUP_EXIT": "1"},
        {"MIGRATE_EXIT": "1"},
    ],
    ids=["preflight", "web-build", "backup", "migration"],
)
def test_a_failure_before_the_restart_rolls_the_venv_back(box: Box, env: dict) -> None:
    """`pip install` puts the new code in the live venv before the preflight. The
    script used to stop there saying "the old build is still serving" — while the
    venv held the new one, ready to boot on the next crash or reboot."""
    result = box.run(**env)
    assert result.returncode != 0
    assert "Rolled back to" in result.stderr, result.stderr
    assert box.head() == box.before
    # The last install is of the commit that is still running.
    installs = [line for line in box.calls_log() if line.startswith("pip install")]
    assert installs[-1].endswith("@" + box.before[:7]), installs
    assert not box.ran("systemctl restart")
    # Customers never saw the new web build.
    assert (box.apps / "client" / "dist" / "index.html").read_text() == "old client"
    assert not (box.apps / "client" / "dist.next").exists()


def test_the_worker_is_preflighted_with_its_own_settings(box: Box) -> None:
    (box.apps / "server" / ".env.worker").write_text("ENVELOCK_ENV=production\nX=1\n")
    result = box.run(WORKER_PREFLIGHT_EXIT="1")
    assert result.returncode != 0
    assert "worker preflight failed" in result.stderr
    assert box.head() == box.before
    # It read the worker's file, from a directory with no .env to mix in.
    assert (box.root / "worker_env_seen").read_text().startswith("ENVELOCK_ENV=production")
    assert any(line == "python worker-preflight cwd=/" for line in box.calls_log())


def test_a_crash_looping_worker_fails_the_deploy(box: Box) -> None:
    """Only :8010 was checked, so a worker that never came up still ended in
    "deploy complete" — with mail analysis stopped and the status page green."""
    result = box.run(HAS_WORKER_UNIT="1", CURL_FAIL=":8011/")
    assert result.returncode != 0
    assert "envelock-worker did not become ready" in result.stderr
    assert box.ran("systemctl restart envelock-worker")
    # Past the migration nothing is rolled back — and nothing is published.
    assert box.head() == box.after
    assert (box.apps / "client" / "dist" / "index.html").read_text() == "old client"


# ── nginx security headers ───────────────────────────────────────────────────
def test_changed_snippets_are_installed_checked_and_reloaded(box: Box) -> None:
    stale = box.snippets / "headers-app.conf"
    stale.write_text("add_header Content-Security-Policy \"script-src 'self'\" always;\n")
    result = box.run()
    assert result.returncode == 0, result.stderr
    assert stale.read_text() == (DEPLOY / "nginx" / "headers-app.conf").read_text()
    assert box.index("nginx -t -q") < box.index("systemctl reload nginx")
    assert box.index("systemctl reload nginx") < box.index("alembic upgrade head")


def test_unchanged_snippets_do_not_reload_nginx(box: Box) -> None:
    result = box.run()
    assert result.returncode == 0, result.stderr
    assert not box.ran("systemctl reload nginx")


def test_snippets_nginx_rejects_are_put_back(box: Box) -> None:
    before = (box.snippets / "headers-app.conf").read_text()
    box.push_change("server/deploy/nginx/headers-app.conf", "BROKEN {\n", "a typo")
    result = box.run()
    assert result.returncode != 0
    assert "nginx rejected the new snippets" in result.stderr
    assert (box.snippets / "headers-app.conf").read_text() == before
    assert box.head() == box.before
    assert not box.ran("alembic")


# ── The deploy tool updates itself ───────────────────────────────────────────
def test_an_out_of_date_copy_adopts_the_repository_version_and_re_runs(box: Box) -> None:
    box.self_copy.write_text(box.self_copy.read_text() + "\n# an older copy\n")
    result = box.run(API_PREFLIGHT_EXIT="1")
    assert "re-running that one" in result.stdout
    canonical = box.apps / "server" / "deploy" / "deploy.sh"
    assert box.self_copy.read_bytes() == canonical.read_bytes()
    assert os.access(box.self_copy, os.X_OK)
    # The re-run kept the commit to roll back to, not the one it had just pulled.
    assert box.head() == box.before
    assert result.stdout.count("re-running that one") == 1


# ── systemd units ────────────────────────────────────────────────────────────
def test_units_that_differ_from_the_repository_are_reported(box: Box) -> None:
    (box.systemd / "envelock-api.service").write_text("[Service]\nUser=ubuntu\n")
    result = box.run()
    assert result.returncode == 0, result.stderr
    assert "differ from the repository's: envelock-api.service" in result.stderr
    assert "daemon-reload" in result.stderr


def test_installed_units_matching_the_repository_raise_nothing(box: Box) -> None:
    result = box.run()
    assert result.returncode == 0, result.stderr
    assert "differ from the repository" not in result.stderr
