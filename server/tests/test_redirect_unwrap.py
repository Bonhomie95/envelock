"""A redirector-wrapped link is judged by its true destination, not the wrapper.

Gmail rewrites every outbound link to `https://www.google.com/url?q=<real>`,
Microsoft SafeLinks to `?url=<real>`, and open redirects to `?u=`/`?redirect=`.
Scoring the visible host let a bare-IP or threat-feed destination ride in behind
a safe-looking google.com / outlook.com host — the exact shape that reached a
real connected inbox in testing.
"""

from __future__ import annotations

from envelock.detections.content import score_url, unwrap_redirect


class _Ctx:
    malicious_domains: frozenset[str] = frozenset()


def test_gmail_wrapped_bare_ip_is_caught() -> None:
    url = "https://www.google.com/url?q=http://203.0.113.10/account-verify?u=admin&source=gmail"
    reasons = score_url(url, sender="gmail.com", ctx=_Ctx())
    assert any("bare IP" in r for r in reasons), reasons
    assert any("redirects to 203.0.113.10" in r for r in reasons), reasons


def test_safelinks_wrapped_destination_is_caught() -> None:
    url = "https://nam01.safelinks.protection.outlook.com/?url=http%3A%2F%2F203.0.113.10%2Fx&data=1"
    assert unwrap_redirect(url) == "http://203.0.113.10/x"
    assert any("bare IP" in r for r in score_url(url, sender="outlook.com", ctx=_Ctx()))


def test_a_clean_wrapped_link_stays_silent() -> None:
    url = "https://www.google.com/url?q=https://docs.example.com/guide&ust=1"
    assert score_url(url, sender="gmail.com", ctx=_Ctx()) == []


def test_an_ordinary_link_is_unchanged() -> None:
    assert unwrap_redirect("https://example.com/page?a=1") is None
    assert score_url("https://example.com/page", sender="example.com", ctx=_Ctx()) == []


def test_a_redirect_chain_cannot_loop() -> None:
    # A wrapper pointing at itself must terminate, not recurse forever.
    url = "https://r.example/?url=https://r.example/?url=https://r.example/?url=http://203.0.113.10/x"
    reasons = score_url(url, sender="r.example", ctx=_Ctx())
    # It stops after a bounded number of hops without raising; may or may not
    # reach the IP, but it must return cleanly.
    assert isinstance(reasons, list)
