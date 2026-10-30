"""The nginx sites and header snippets in `deploy/nginx/`.

deploy.sh now installs the snippets on every deploy (after `nginx -t`), so a
syntax error in one is a failed deploy rather than a typo that sits in the repo.
These catch it first. The structural check is the inheritance trap the snippets
exist for: nginx drops every inherited `add_header` in a location that sets one
of its own, so a location with its own header must include the snippet again —
the apex's `/assets/` and, before that, the whole apex server served the
dashboard's SPA with no CSP, no X-Frame-Options and no HSTS.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

NGINX_DIR = Path(__file__).resolve().parents[1] / "deploy" / "nginx"
SITES = sorted(NGINX_DIR.glob("envelock-*.conf"))
#: The API sets its own security headers in the app (security/middleware.py).
_APP_HEADERS = {"envelock-api.conf"}


def _blocks(text: str, keyword: str) -> list[str]:
    """Bodies of every `keyword ... { ... }` block, braces matched."""
    bodies = []
    for match in re.finditer(rf"^\s*{keyword}\b[^{{]*\{{", text, flags=re.MULTILINE):
        depth, i = 1, match.end()
        while depth and i < len(text):
            depth += {"{": 1, "}": -1}.get(text[i], 0)
            i += 1
        bodies.append(text[match.end() : i - 1])
    return bodies


def _without_comments(path: Path) -> str:
    return "\n".join(line.split("#", 1)[0] for line in path.read_text().splitlines())


@pytest.mark.parametrize("site", [s for s in SITES if s.name not in _APP_HEADERS], ids=str)
def test_every_static_site_sends_its_security_headers(site: Path) -> None:
    text = _without_comments(site)
    for server in _blocks(text, "server"):
        top_level = re.sub(r"location\b[^{]*\{[^}]*\}", "", server)
        assert "include snippets/headers-" in top_level, f"{site.name}: server block"
    for body in _blocks(text, "location"):
        if "add_header" in body:
            assert "include snippets/headers-" in body, (
                f"{site.name}: a location with its own add_header drops the "
                f"inherited security headers unless it includes the snippet:\n{body}"
            )


@pytest.mark.skipif(shutil.which("nginx") is None, reason="nginx is not installed")
def test_the_sites_and_snippets_pass_nginx_t(tmp_path: Path) -> None:
    (tmp_path / "snippets").mkdir()
    for snippet in [*NGINX_DIR.glob("headers-*.conf"), NGINX_DIR / "cloudflare-realip.conf"]:
        shutil.copy2(snippet, tmp_path / "snippets" / snippet.name)
    (tmp_path / "sites").mkdir()
    for site in SITES:
        # `nginx -t` binds every listen address, and CI runs as a normal user who
        # may not bind below 1024 on Linux. Moving the ports up leaves the syntax
        # under test unchanged.
        text = re.sub(
            r"(\blisten\s+(?:\[::\]:)?)(\d+)",
            lambda m: f"{m.group(1)}{int(m.group(2)) + 20000}",
            site.read_text(),
        )
        (tmp_path / "sites" / site.name).write_text(text)
    conf = tmp_path / "nginx.conf"
    conf.write_text(
        f"pid {tmp_path}/nginx.pid;\nerror_log stderr;\nevents {{}}\n"
        f"http {{\n  access_log off;\n  client_body_temp_path {tmp_path}/client_body;\n"
        f"  include {tmp_path}/sites/*.conf;\n}}\n"
    )
    result = subprocess.run(  # noqa: S603
        [shutil.which("nginx"), "-t", "-p", str(tmp_path), "-c", str(conf), "-e", "stderr"],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr
