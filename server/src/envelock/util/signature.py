"""Mail-signature extraction for C5 (signature tampering).

C5 fires when the bank details inside a mailbox owner's *sent* signature block
change — the quiet way an attacker who is already in the mailbox redirects every
future payment without touching a single inbound message. To see that we have to
read the owner's own outbound mail and keep a per-mailbox fingerprint of the
signature, which `workers/outbound.watch_signature` diffs on each sync.

Kept deliberately small: the only thing that has to be accurate is the set of
*bank identifiers* in the trailing block, because that is what C5 compares. The
block text itself is stored verbatim as the before/after evidence.
"""

from __future__ import annotations

import re

#: RFC 3676 §4.3 signature delimiter: a line that is exactly "-- " (dash dash
#: space). Mail clients that insert a signature mark it this way, so when it is
#: present it is the one unambiguous boundary.
_SIG_DELIM = re.compile(r"^-- ?$", re.MULTILINE)

#: Fallback when no delimiter: the trailing block is the last few non-empty
#: lines. A business signature is short; ten lines covers name, title, company,
#: phone and bank line without swallowing the quoted message below it.
_FALLBACK_LINES = 10


def extract_signature(body_text: str | None) -> str:
    """The signature block of one outbound message, as plain text.

    Prefers the ``-- `` delimiter; otherwise falls back to the trailing lines of
    the message (stopping at a quoted-reply marker, so a reply's signature is not
    contaminated by the history it quotes). Returns "" when there is nothing
    usable — the caller treats an empty signature as "no baseline yet", never as
    a change.
    """
    text = (body_text or "").replace("\r\n", "\n").replace("\r", "\n")
    if not text.strip():
        return ""

    matches = list(_SIG_DELIM.finditer(text))
    if matches:
        # Everything after the LAST delimiter — a forwarded mail can carry the
        # correspondent's delimiter too, and ours is the final one.
        block = text[matches[-1].end():]
        return block.strip()

    # No delimiter: take the tail, but cut it at the first quoted-reply boundary
    # so "On <date> X wrote:" history below the signature is excluded.
    lines = text.split("\n")
    tail = lines[-_FALLBACK_LINES:]
    cut: list[str] = []
    for line in tail:
        if line.lstrip().startswith(">") or re.match(r"^\s*On .+wrote:\s*$", line):
            break
        cut.append(line)
    return "\n".join(cut).strip()


def signature_bank_ids(signature: str) -> frozenset[str]:
    """Bank identifiers (IBAN/account/sort/routing) present in a signature block.

    This is what C5 actually diffs; the exact extraction must match the learning
    side, so it delegates to the one shared extractor rather than re-parsing.
    """
    from envelock.util.payments import extract_bank_identifiers

    return frozenset(b.identifier for b in extract_bank_identifiers(signature or ""))


__all__ = ["extract_signature", "signature_bank_ids"]
