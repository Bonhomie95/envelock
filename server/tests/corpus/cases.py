"""The labelled corpus.

Every case is a *sequence* of messages with an expected verdict on the last one,
because BEC is a story rather than a message: "the bank details changed" only
means anything relative to what came before.

Two labels, and the second one matters as much as the first:

* ``fraud``  — the last message must raise HIGH or CRITICAL.
* ``benign`` — the last message must NOT. These are the cases that decide whether
  the product survives contact with a real inbox. Their own P5 says alert
  fatigue is the failure mode that kills the product, so a corpus of only
  attacks would measure the wrong half and reward a detector that flags
  everything.

``known_gap=True`` marks a case we currently get wrong on purpose. It is
reported and does not fail the build, so the evasions found in the 2026-09-01
audit stay visible and measurable instead of living in a document nobody
re-reads. Removing a ``known_gap`` flag is what "we improved detection" looks
like; adding one is a decision, not an accident.

Keep these synthetic. Never paste a real customer message in here.
"""

from __future__ import annotations

from dataclasses import dataclass

VENDOR = "billing@northwind-supplies.example"
VENDOR_DOMAIN = "northwind-supplies.example"
GOOD_IBAN = "GB94BARC10201530093459"
FRAUD_IBAN = "GB33BUKB20201555555555"

ZWSP = "​"
NBSP = " "


def msg(
    body: str,
    *,
    sender: str = VENDOR,
    subject: str = "Invoice",
    display: str = "Northwind Supplies",
    extra_headers: str = "",
    content_type: str = "text/plain; charset=utf-8",
) -> bytes:
    return (
        f"From: {display} <{sender}>\r\n"
        "To: pay@acme.com\r\n"
        f"Subject: {subject}\r\n"
        f"Content-Type: {content_type}\r\n"
        f"{extra_headers}"
        "\r\n"
        f"{body}\r\n"
    ).encode()


@dataclass(frozen=True)
class Case:
    id: str
    label: str  # "fraud" | "benign"
    messages: list[bytes]
    why: str
    tags: tuple[str, ...] = ()
    known_gap: bool = False
    gap_note: str = ""


#: Three ordinary invoices that establish the vendor and their account. Most
#: fraud cases replay this first, because a bank change is only detectable
#: against a learned baseline.
def _history() -> list[bytes]:
    return [
        msg(
            f"Invoice {n}. Our account IBAN {GOOD_IBAN} is unchanged. "
            "Payment terms 30 days as agreed.",
            subject=f"Invoice 40{n}",
        )
        for n in (1, 2, 3)
    ]


CASES: list[Case] = []


def _add(case: Case) -> Case:
    CASES.append(case)
    return case


# ── Fraud: the core wedge ────────────────────────────────────────────────────
_add(
    Case(
        id="bank-change-plain",
        label="fraud",
        messages=[
            *_history(),
            msg(
                "Our bank account has changed. Please remit to IBAN "
                f"{FRAUD_IBAN}. This is urgent, we need it today.",
                extra_headers="In-Reply-To: <inv-403@northwind-supplies.example>\r\n",
            ),
        ],
        why="The canonical case the product exists for: a known vendor's account changes.",
        tags=("A1", "wedge"),
    )
)

_add(
    Case(
        id="bank-change-human-spaced-iban",
        label="fraud",
        messages=[
            *_history(),
            msg(
                "Kindly note our updated remittance details: IBAN "
                "GB33 BUKB 2020 1555 5555 55. Please action today.",
            ),
        ],
        why=(
            "The same fraud with the IBAN grouped in fours, which is how every "
            "printed invoice renders it. Before 2026-09-01 this parsed as a UK "
            "sort code and A1 never saw an IBAN at all."
        ),
        tags=("A1", "format"),
    )
)

_add(
    Case(
        id="bank-change-zero-width-space",
        label="fraud",
        messages=[
            *_history(),
            msg(
                "Our bank account has changed. Remit to IBAN "
                f"GB33BUKB2020155{ZWSP}5555555. Urgent.",
            ),
        ],
        why="Invisible character inside the account number. Costs an attacker one keystroke.",
        tags=("A1", "evasion", "unicode"),
    )
)

_add(
    Case(
        id="bank-change-nbsp-separated",
        label="fraud",
        messages=[
            *_history(),
            msg(
                "Updated details: IBAN "
                f"GB33{NBSP}BUKB{NBSP}2020{NBSP}1555{NBSP}5555{NBSP}55. Please pay today.",
            ),
        ],
        why="Non-breaking spaces, which is what a paste out of Word actually produces.",
        tags=("A1", "evasion", "unicode"),
    )
)

_add(
    Case(
        id="bank-change-fullwidth-digits",
        label="fraud",
        messages=[
            *_history(),
            msg(
                "Our bank account has changed. Remit to IBAN "
                + FRAUD_IBAN.replace("2", "２").replace("5", "５")
                + ". Urgent, today please.",
            ),
        ],
        why="Fullwidth digit forms. NFKC folds them; without that the regex sees nothing.",
        tags=("A1", "evasion", "unicode"),
    )
)

_add(
    Case(
        id="novel-vendor-urgent-payment",
        label="fraud",
        messages=[
            msg(
                "Please process payment of 48,900 to IBAN "
                f"{FRAUD_IBAN} today. Keep this between us until the deal is "
                "announced — do not discuss with the wider team.",
                sender="a.director@northwind-suppIies.example",
                display="Alan Director",
                subject="URGENT payment needed today",
            )
        ],
        why=(
            "First contact, payment instruction, urgency and secrecy, from a "
            "lookalike domain (capital-I for l). No history to compare against, "
            "which is exactly the case the risk engine must force to Critical."
        ),
        tags=("A2", "A3", "A14", "first-contact"),
    )
)

_add(
    Case(
        id="html-only-invoice-bank-change",
        label="fraud",
        messages=[
            *_history(),
            msg(
                "<html><body><p>Our bank details have changed.</p>"
                f"<p>Please remit to IBAN <b>{FRAUD_IBAN}</b> urgently today.</p>"
                "</body></html>",
                content_type="text/html; charset=utf-8",
            ),
        ],
        why=(
            "An HTML-only message with no text/plain part. Most real invoices "
            "from accounting systems look exactly like this."
        ),
        tags=("A1", "evasion", "html"),
        known_gap=False,
        gap_note=(
            "Audit finding html-only-mail-invisible-to-group-a: with no "
            "text/plain part the body reaching Group A is empty, so A1 and the "
            "learning path both see nothing. Not yet fixed."
        ),
    )
)

# ── Benign: the half that decides whether anyone keeps the product ───────────
_add(
    Case(
        id="routine-invoice-known-vendor",
        label="benign",
        messages=[
            *_history(),
            msg(
                f"Invoice 404 attached. Account IBAN {GOOD_IBAN} as always. "
                "Payment terms 30 days.",
                subject="Invoice 404",
            ),
        ],
        why="The overwhelmingly common case. Flagging this is how the product gets uninstalled.",
        tags=("precision",),
    )
)

_add(
    Case(
        id="reformatted-same-account",
        label="benign",
        messages=[
            *_history(),
            msg(
                "Invoice 405. Our account: IBAN GB94 BARC 1020 1530 0934 59 "
                "(unchanged). Terms 30 days.",
                subject="Invoice 405",
            ),
        ],
        why=(
            "The SAME account, re-typed with spaces — a new person in their AP "
            "team, or a different invoice template. Before 2026-09-01 this "
            "produced a different identifier and read as a bank change: a "
            "Critical alert, with a callback prompt, about nothing."
        ),
        tags=("precision", "A1", "format"),
    )
)

_add(
    Case(
        id="urgent-but-no-payment",
        label="benign",
        messages=[
            *_history(),
            msg(
                "URGENT: our warehouse is closing early today, can you confirm "
                "the delivery slot immediately? Need an answer right away.",
                subject="URGENT - delivery slot today",
            ),
        ],
        why="Urgency language with no payment instruction. Urgency alone must not be enough.",
        tags=("precision", "A14"),
    )
)

_add(
    Case(
        id="order-numbers-that-look-like-accounts",
        label="benign",
        messages=[
            *_history(),
            msg(
                "Your order 12345678901 has shipped, tracking 998877665. "
                "Reference 60-16-13 on any correspondence.",
                subject="Order shipped",
            ),
        ],
        why=(
            "Long digit runs including something shaped exactly like a UK sort "
            "code, in a message about logistics. The context gate is what keeps "
            "this quiet."
        ),
        tags=("precision",),
    )
)

_add(
    Case(
        id="new-vendor-first-invoice",
        label="benign",
        messages=[
            msg(
                "Thanks for the order. Our invoice is attached; payment details "
                f"are IBAN {GOOD_IBAN}, terms 30 days. Any questions do ask.",
                sender="accounts@fresh-supplier.example",
                display="Fresh Supplier Ltd",
                subject="Invoice 001 - Fresh Supplier",
            )
        ],
        why=(
            "A genuine new supplier's first invoice: no history, payment "
            "instruction, unknown payee. It should be visible but must not be "
            "HIGH — every company onboards suppliers, and if this is a "
            "high-severity alert then every onboarding is one too."
        ),
        tags=("precision", "first-contact"),
    )
)


def by_label(label: str) -> list[Case]:
    return [c for c in CASES if c.label == label]
