"""Warn up front when a provider ships IMAP off / needs an app password.

A customer hit Zoho's IMAP-disabled-by-default and a 'password rejected' with no
explanation. The advisor now carries a per-provider enablement note, surfaced in
the connect plan and appended to an IMAP auth failure, so the user is told which
provider-side switch to flip instead of guessing.
"""

from __future__ import annotations

from envelock.connect.advisor import identify, imap_setup_for_host
from envelock.connect.lookup import ConnectionPlan, plan_payload


def test_host_maps_to_the_right_enablement_note() -> None:
    assert "IMAP" in (imap_setup_for_host("imappro.zoho.com") or "")
    # Regional Zoho hosts match too (via the provider's MX patterns / host).
    assert imap_setup_for_host("imappro.zoho.eu")
    assert "app password" in (imap_setup_for_host("imap.fastmail.com") or "").lower()
    # A provider we connect over OAuth, or an unknown host, carries no note.
    assert imap_setup_for_host("imap.gmail.com") is None
    assert imap_setup_for_host("mail.some-random-co.example") is None


def test_connect_plan_surfaces_the_note_for_zoho() -> None:
    zoho = identify(["mx.zoho.com"])
    assert zoho.id == "zoho", "Zoho MX should identify Zoho"
    plan = ConnectionPlan(
        domain="acme.com", mx_hosts=("mx.zoho.com",), detected=True, provider=zoho,
        imap_host=zoho.imap_host, imap_port=zoho.imap_port,
        recommended=zoho.methods[0], alternatives=zoho.methods[1:], dmarc=None, spf=False,
    )
    payload = plan_payload(plan)
    assert payload["imap"]["enablement"], "Zoho plan must carry the IMAP enablement note"
    assert "IMAP" in payload["imap"]["enablement"]


def test_a_generic_provider_has_no_enablement_note() -> None:
    generic = identify(["mail.unknown-host.example"])
    plan = ConnectionPlan(
        domain="x.com", mx_hosts=("mail.unknown-host.example",), detected=False,
        provider=generic, imap_host="mail.x.com", imap_port=993,
        recommended=generic.methods[0], alternatives=generic.methods[1:],
        dmarc=None, spf=False,
    )
    assert plan_payload(plan)["imap"]["enablement"] is None
