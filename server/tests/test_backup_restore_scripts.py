"""`deploy/backup.sh` and `deploy/restore.sh`, run against stubbed tools.

What they used to get wrong, and what these pin:

* Backups carried the database and nothing else. SECRET_KEY (it seals every
  authenticator seed and webhook secret) and the worker's private key (it opens
  every mailbox credential) lived only in the env files on the box, so a lost
  disk meant a restored database nobody could use.
* `restore.sh --PRODUCTION` took its "safety dump" with the owner DSN, which
  FORCE ROW LEVEL SECURITY always refuses — and only warned before overwriting
  production. It told you to stop the API but not the worker, and restored
  outside a transaction, so an error left the database half-restored.
* The restore drill counted rows as the owner under FORCE RLS, so every count
  read 0, and nothing compared them with anything: an empty backup passed.

`pg_dump`, `pg_restore`, `psql`, `age`, `rclone` and `systemctl` are stubs that
log their arguments; `age` "encrypts" by copying, so the archive can be opened.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import tarfile
from pathlib import Path

import pytest

DEPLOY = Path(__file__).resolve().parents[1] / "deploy"
BASH = shutil.which("bash")
if BASH is None or shutil.which("sha256sum") is None:  # pragma: no cover
    pytest.skip("needs bash and sha256sum", allow_module_level=True)

_STUBS = {
    "pg_dump": """
echo "pg_dump $*" >> "$CALLS"
if [ -n "${PG_DUMP_FAIL:-}" ]; then
  echo "pg_dump: error: query would be affected by row-level security policy" >&2
  exit 1
fi
for a in "$@"; do case "$a" in --file=*) echo dump > "${a#--file=}" ;; esac; done
""",
    "pg_restore": """
echo "pg_restore $*" >> "$CALLS"
if [ "$1" = --list ]; then
  for i in 1 2 3 4 5 6; do echo "$i; 0 0 TABLE DATA public t$i envelock"; done
fi
exit 0
""",
    "psql": """
sql="$(printf '%s' "$*" | tr '\\n' ' ')"
echo "psql $sql" >> "$CALLS"
case "$sql" in
  *"information_schema.tables"*) echo 33 ;;
  *"FROM mailbox_credentials"*) echo "${DRILL_COUNTS:-3 5 4 4 9}" ;;
  *"SELECT count(*) FROM tenants"*) echo "${LIVE_TENANTS:-3}" ;;
esac
exit 0
""",
    "age": """
echo "age $*" >> "$CALLS"
out=""; src=""
while [ $# -gt 0 ]; do
  case "$1" in -r|-i) shift ;; -o) out="$2"; shift ;; -d) ;; *) src="$1" ;; esac
  shift
done
if [ -n "$src" ]; then cp "$src" "$out"; else cat > "$out"; fi
""",
    "rclone": """
echo "rclone $*" >> "$CALLS"
""",
    "systemctl": """
echo "systemctl $*" >> "$CALLS"
[ "$1" = is-active ] && exit "${SERVICES_ACTIVE_EXIT:-3}"
exit 0
""",
}


def _write_exec(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/usr/bin/env bash\n" + body.lstrip("\n"))
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


@pytest.fixture
def box(tmp_path: Path) -> dict:
    stubs = tmp_path / "stubs"
    for name, body in _STUBS.items():
        _write_exec(stubs / name, body)
    server = tmp_path / "server"
    (server / "deploy").mkdir(parents=True)
    for script in ("backup.sh", "restore.sh"):
        shutil.copy2(DEPLOY / script, server / "deploy" / script)
    (server / ".env").write_text(
        "ENVELOCK_POSTGRES_DSN=postgresql+asyncpg://envelock_app:a@localhost:5432/envelock\n"
        "ENVELOCK_DB_OWNER_DSN=postgresql+asyncpg://envelock:o@localhost:5432/envelock\n"
        "ENVELOCK_DB_BACKUP_DSN=postgresql+asyncpg://envelock_backup:b@localhost:5432/envelock\n"
        "ENVELOCK_SECRET_KEY=the-one-that-seals-totp-seeds\n"
        "ENVELOCK_BACKUP_AGE_RECIPIENT=age1testrecipient\n"
        "ENVELOCK_BACKUP_REMOTE=offbox:bucket/db\n"
    )
    (server / ".env.worker").write_text("ENVELOCK_CREDENTIAL_PRIVATE_KEY=opens-every-mailbox\n")
    backups = tmp_path / "backups"
    backups.mkdir()
    env = {
        "PATH": f"{stubs}:{os.environ.get('PATH', '/usr/bin:/bin')}",
        "HOME": str(tmp_path),
        "CALLS": str(tmp_path / "calls.log"),
        "ENVELOCK_BACKUP_DIR": str(backups),
        # macOS tar would otherwise add AppleDouble `._` entries to the archive.
        "COPYFILE_DISABLE": "1",
    }
    return {"root": tmp_path, "server": server, "backups": backups, "env": env}


def _run(box: dict, script: str, *args: str, stdin: str = "", **extra: str):  # noqa: ANN202
    return subprocess.run(  # noqa: S603
        [BASH, str(box["server"] / "deploy" / script), *args],
        env={**box["env"], **extra}, input=stdin, capture_output=True, text=True, timeout=60,
    )


def _calls(box: dict) -> list[str]:
    log = box["root"] / "calls.log"
    return log.read_text().splitlines() if log.exists() else []


# ── backup.sh: the keys travel with the data ─────────────────────────────────
def test_each_backup_ships_the_env_files_encrypted(box: dict) -> None:
    result = _run(box, "backup.sh", "--label", "predeploy")
    assert result.returncode == 0, result.stderr
    archives = list(box["backups"].glob("envelock-*-predeploy.dump.env.age"))
    assert len(archives) == 1
    # Encrypted to the backup recipient, and both files are inside.
    assert any(c.startswith("age -r age1testrecipient -o") and ".env.age" in c for c in _calls(box))
    with tarfile.open(archives[0]) as tar:
        names = set(tar.getnames())
        assert names == {".env", ".env.worker"}
        secret = tar.extractfile(".env").read().decode()  # type: ignore[union-attr]
        assert "ENVELOCK_SECRET_KEY=the-one-that-seals-totp-seeds" in secret
    shipped = [c for c in _calls(box) if c.startswith("rclone copy")]
    assert any(c.endswith(".env.age offbox:bucket/db") for c in shipped), shipped
    # The plaintext settings were never written next to the dumps.
    assert not [p for p in box["backups"].iterdir() if p.name.endswith((".env", ".tar"))]


def test_without_a_recipient_the_env_files_are_not_stored_at_all(box: dict) -> None:
    env_file = box["server"] / ".env"
    env_file.write_text(
        "\n".join(
            line for line in env_file.read_text().splitlines()
            if not line.startswith(("ENVELOCK_BACKUP_AGE_RECIPIENT", "ENVELOCK_BACKUP_REMOTE"))
        ) + "\n"
    )
    result = _run(box, "backup.sh")
    assert result.returncode == 0, result.stderr
    assert not list(box["backups"].glob("*.env.age"))
    assert ".env and .env.worker are NOT backed up" in result.stderr


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads any file")
def test_an_unreadable_worker_env_fails_the_backup_after_shipping_the_dump(box: dict) -> None:
    worker = box["server"] / ".env.worker"
    worker.chmod(0)
    try:
        result = _run(box, "backup.sh")
    finally:
        worker.chmod(0o600)
    assert result.returncode != 0
    assert "settings files were NOT backed up" in result.stderr
    # The database part still happened: never lose the dump over the keys.
    assert list(box["backups"].glob("envelock-*.dump.age"))
    shipped = [c for c in _calls(box) if c.startswith("rclone copy")]
    assert any(c.endswith(".dump.age offbox:bucket/db") for c in shipped), shipped
    assert not list(box["backups"].glob("*.env.age"))


# ── restore.sh --PRODUCTION ──────────────────────────────────────────────────
def _a_backup(box: dict) -> Path:
    dump = box["backups"] / "envelock-20261030T000000Z-scheduled.dump"
    dump.write_text("dump")
    return dump


def test_production_restore_refuses_while_either_service_runs(box: dict) -> None:
    result = _run(box, "restore.sh", "--PRODUCTION", str(_a_backup(box)),
                  stdin="envelock\n", SERVICES_ACTIVE_EXIT="0")
    assert result.returncode != 0
    assert "envelock-worker" in result.stderr
    assert not any(c.startswith(("pg_dump", "pg_restore")) for c in _calls(box))


def test_production_restore_takes_its_safety_dump_with_the_backup_role(box: dict) -> None:
    result = _run(box, "restore.sh", "--PRODUCTION", str(_a_backup(box)), stdin="envelock\n")
    assert result.returncode == 0, result.stderr
    dumps = [c for c in _calls(box) if c.startswith("pg_dump")]
    assert len(dumps) == 1 and "envelock_backup:b@" in dumps[0], dumps
    restore = next(c for c in _calls(box) if c.startswith("pg_restore") and "--list" not in c)
    assert "--single-transaction" in restore
    assert "envelock:o@" in restore  # the owner drops and recreates the tables


def test_production_restore_stops_when_the_safety_dump_fails(box: dict) -> None:
    result = _run(box, "restore.sh", "--PRODUCTION", str(_a_backup(box)),
                  stdin="envelock\n", PG_DUMP_FAIL="1")
    assert result.returncode != 0
    assert "NOT restoring" in result.stderr
    assert not any(c.startswith("pg_restore") for c in _calls(box))


# ── restore.sh --drill ───────────────────────────────────────────────────────
def test_the_drill_counts_rows_in_the_platform_scope(box: dict) -> None:
    result = _run(box, "restore.sh", "--drill", str(_a_backup(box)))
    assert result.returncode == 0, result.stderr
    assert "tenants=3 users=5 mailboxes=4" in result.stdout
    counted = next(c for c in _calls(box) if "FROM mailbox_credentials" in c)
    assert "SET envelock.system = 'on';" in counted


def test_the_drill_fails_an_empty_backup_of_a_live_database(box: dict) -> None:
    result = _run(box, "restore.sh", "--drill", str(_a_backup(box)),
                  DRILL_COUNTS="0 0 0 0 0", LIVE_TENANTS="12")
    assert result.returncode != 0
    assert "THIS BACKUP IS EMPTY" in result.stderr


def test_the_drill_accepts_an_empty_backup_of_an_empty_database(box: dict) -> None:
    result = _run(box, "restore.sh", "--drill", str(_a_backup(box)),
                  DRILL_COUNTS="0 0 0 0 0", LIVE_TENANTS="0")
    assert result.returncode == 0, result.stderr
