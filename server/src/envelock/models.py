"""Persistent models. See PRD.md §12 (billing), §3 (services), E5 (audit trail).

Every tenant-scoped table carries `tenant_id` — multi-tenancy from commit one
(PRD §10). Row-level security policies live in the initial migration.
"""

from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal
from uuid import UUID

from sqlalchemy import (
    BigInteger,
    Boolean,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    false,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from envelock.core.enums import (
    AlertTier,
    IntegrationTier,
    MailboxClass,
    ProtectionLevel,
)
from envelock.db import Base, TimestampMixin, UUIDMixin
from envelock.types import JsonDict, StringList


# ─────────────────────────────────────────────────────────────────────────────
# Tenancy
# ─────────────────────────────────────────────────────────────────────────────
class Tenant(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "tenants"

    name: Mapped[str] = mapped_column(String(255))
    plan: Mapped[str] = mapped_column(String(32), default="guard")  # guard|essential|complete|solo
    billing_term: Mapped[str] = mapped_column(String(16), default="monthly")
    trial_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    trial_ends_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    payment_method_ok: Mapped[bool] = mapped_column(Boolean, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    #: Stripe Customer id, captured from the first completed Checkout. Lets us open
    #: the hosted billing portal so a customer can update the card or cancel.
    stripe_customer_id: Mapped[str | None] = mapped_column(String(64))
    #: Mailbox seats bought on top of the plan's included allowance. Capacity is
    #: `plan seats + this`; each protected mailbox beyond the allowance needs one.
    extra_mailbox_seats: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    #: E13 — metadata-only mode. Message bodies and attachment bytes are never
    #: persisted by any code path, so this is specifically about the SUBJECT
    #: line, the one piece of message content that does reach a durable row.
    #: With it on, the subject is analysed in memory and then dropped; the alert
    #: still carries its own title, so the customer loses nothing operationally.
    #: Regulated buyers ask for exactly this and today the answer was "we can't".
    metadata_only: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="false"
    )
    #: When the monthly "what we caught and why" digest last went out. Null means
    #: never, and the digest job treats a null as "due once this tenant is old
    #: enough to have a month worth reporting on" — a brand-new tenant getting an
    #: empty digest on day one teaches them to filter us.
    last_digest_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    domains: Mapped[list[Domain]] = relationship(back_populates="tenant")


class User(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "users"

    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id"), index=True)
    email: Mapped[str] = mapped_column(String(320), unique=True)
    name: Mapped[str | None] = mapped_column(String(255))
    password_hash: Mapped[str | None] = mapped_column(String(255))
    #: PRD §15.1 three-role model: owner|admin|member. `is_admin` is kept in
    #: sync (admin or owner) for the notification recipient model (E4/E6).
    role: Mapped[str] = mapped_column(String(16), default="member")
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    #: active | pending. A colleague who joins an existing corporate tenant starts
    #: pending and sees nothing until an admin approves them (PRD §15.1).
    status: Mapped[str] = mapped_column(String(16), default="active")
    #: True for a user the owner provisioned with a temporary password — they must
    #: set their own on first sign-in before reaching any tenant data.
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False)
    #: Proof of email ownership (anti tenant-squatting). Enforced at sign-in only
    #: when ENVELOCK_REQUIRE_EMAIL_VERIFICATION is on; null = never verified.
    email_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    #: MFA is mandatory before a session can be held (PRD §15.1). The secret is
    #: provisioned at enrolment and confirmed at first verify.
    totp_secret: Mapped[str | None] = mapped_column(String(64))
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    #: SHA-256 hashes of single-use recovery codes; the codes themselves are
    #: shown exactly once at enrolment and never stored.
    recovery_hashes: Mapped[list[str]] = mapped_column(StringList, default=list)
    #: PRD §8.2 — alerts must reach somewhere the attacker does not control.
    out_of_band_email: Mapped[str | None] = mapped_column(String(320))
    phone: Mapped[str | None] = mapped_column(String(32))
    #: A phone is only trusted as an SMS-escalation target or recovery channel
    #: once its owner has proven possession via a one-time code.
    phone_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    phone_otp_hash: Mapped[str | None] = mapped_column(String(64))
    phone_otp_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


# ─────────────────────────────────────────────────────────────────────────────
# Platform staff (Envelock's own people — NOT a customer tenant)
# ─────────────────────────────────────────────────────────────────────────────
class StaffAccount(Base, UUIDMixin, TimestampMixin):
    """An Envelock operator: support, billing, security, engineering.

    Deliberately a separate table from `users`, with its own credentials and its
    own token type. A platform operator is not a member of any customer tenant,
    so modelling them as one would mean either a fake tenant row or a customer
    account that can read every other customer — and it would put the two
    populations one bug apart. Nothing in the customer product can create,
    promote or authenticate one of these.
    """

    __tablename__ = "staff_accounts"

    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    name: Mapped[str | None] = mapped_column(String(255))
    password_hash: Mapped[str | None] = mapped_column(String(255))
    #: What they were hired to do — drives the default permission set
    #: (auth/staff.py DEPARTMENT_PERMISSIONS).
    department: Mapped[str] = mapped_column(String(32), default="support")
    #: Exceptions on top of the department default. Revocation beats a grant.
    granted_permissions: Mapped[list[str]] = mapped_column(StringList, default=list)
    revoked_permissions: Mapped[list[str]] = mapped_column(StringList, default=list)
    #: active | suspended. Checked on every request, not just at sign-in.
    status: Mapped[str] = mapped_column(String(16), default="active")
    #: A new operator signs in with a one-time password and must replace it
    #: before reaching anything.
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=True)
    totp_secret: Mapped[str | None] = mapped_column(String(64))
    #: MFA is NOT deferrable for staff, unlike customer accounts: these
    #: credentials reach every tenant's metadata.
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    recovery_hashes: Mapped[list[str]] = mapped_column(StringList, default=list)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_login_ip: Mapped[str | None] = mapped_column(String(64))
    created_by: Mapped[str | None] = mapped_column(String(320))
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class StaffAuditEvent(Base, UUIDMixin, TimestampMixin):
    """What an operator did, in its own log.

    The customer-facing `audit_events` table is tenant-scoped and shown to
    customers; platform actions belong somewhere a customer cannot see and an
    operator cannot quietly prune from their own tenant view.
    """

    __tablename__ = "staff_audit_events"

    actor_email: Mapped[str] = mapped_column(String(320), index=True)
    actor_id: Mapped[UUID | None] = mapped_column(Uuid)
    action: Mapped[str] = mapped_column(String(64), index=True)
    target_type: Mapped[str | None] = mapped_column(String(32))
    target_id: Mapped[str | None] = mapped_column(String(64))
    #: The tenant an action touched, when it touched one — so a customer-impacting
    #: action can be traced from either direction.
    tenant_id: Mapped[UUID | None] = mapped_column(Uuid, index=True)
    ip: Mapped[str | None] = mapped_column(String(64))
    detail: Mapped[dict] = mapped_column(JsonDict, default=dict)


# ─────────────────────────────────────────────────────────────────────────────
# Domains
# ─────────────────────────────────────────────────────────────────────────────
class Domain(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "domains"

    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id"), index=True)
    name: Mapped[str] = mapped_column(String(253))
    #: eTLD+1 via Public Suffix List. Never naive splitting — PRD §12.7.
    registrable_domain: Mapped[str] = mapped_column(String(253), index=True)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    verification_token: Mapped[str | None] = mapped_column(String(64))
    #: How the challenge is proven: a DNS TXT record or a CNAME (PRD signup funnel).
    verification_method: Mapped[str] = mapped_column(String(8), default="txt")
    #: Defensive/parked domains are monitored free and unlimited (PRD §12.5).
    is_defensive: Mapped[bool] = mapped_column(Boolean, default=False)
    integration_tier: Mapped[int | None] = mapped_column(Integer)
    mx_hosts: Mapped[list[str] | None] = mapped_column(StringList)
    dmarc_policy: Mapped[str | None] = mapped_column(String(16))  # none|quarantine|reject
    spf_record: Mapped[str | None] = mapped_column(Text)

    tenant: Mapped[Tenant] = relationship(back_populates="domains")

    __table_args__ = (
        UniqueConstraint("tenant_id", "name"),
        # One company = one tenant, enforced by the DATABASE: two simultaneous
        # registrations from the same corporate domain used to both read "no
        # existing tenant" and both create one, splitting the company. Free-mail
        # domains never get a Domain row (registration skips them), so the
        # global uniqueness holds.
        Index("uq_domains_registrable", "registrable_domain", unique=True),
    )


class DomainTrialLedger(Base, TimestampMixin):
    """PRD §12.7 — append-only, permanent, survives tenant deletion.

    A registrable domain is not personal data, so retaining it through erasure
    requests is defensible. That permanence *is* the anti-abuse mechanism.
    """

    __tablename__ = "domain_trial_ledger"

    registrable_domain: Mapped[str] = mapped_column(String(253), primary_key=True)
    first_trial_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    first_tenant_id: Mapped[UUID] = mapped_column(Uuid)
    outcome: Mapped[str] = mapped_column(String(16), default="active")
    payment_fingerprint: Mapped[str | None] = mapped_column(String(128), index=True)
    override_by: Mapped[UUID | None] = mapped_column(Uuid)
    override_reason: Mapped[str | None] = mapped_column(Text)


class GraphVerdict(Base, TimestampMixin):
    """E8 — the cross-tenant counterparty graph, made durable.

    The moat is that one tenant's confirmation protects every other tenant. If it
    lives only in process memory it evaporates on every deploy, so verdicts are
    persisted here and hydrated at startup. Only a domain, a verdict and a
    confirmation count are stored — never a message, an address, or content. The
    reporting tenant ids are kept solely to stop one tenant inflating a count;
    they never cross the tenant boundary in any response.
    """

    __tablename__ = "graph_verdicts"

    registrable_domain: Mapped[str] = mapped_column(String(253), primary_key=True)
    verdict: Mapped[str] = mapped_column(String(16))  # fraudulent|suspicious|legitimate
    confirmations: Mapped[int] = mapped_column(Integer, default=1)
    first_reported: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_reported: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    techniques: Mapped[list[str]] = mapped_column(StringList, default=list)
    reporter_tenant_ids: Mapped[list[str]] = mapped_column(StringList, default=list)


class LookalikeDomain(Base, UUIDMixin, TimestampMixin):
    """D1–D4 findings."""

    __tablename__ = "lookalike_domains"

    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id"), index=True)
    protected_domain: Mapped[str] = mapped_column(String(253), index=True)
    candidate_domain: Mapped[str] = mapped_column(String(253), index=True)
    technique: Mapped[str] = mapped_column(String(32))  # typosquat|homoglyph|cousin|tld_swap
    similarity: Mapped[float] = mapped_column(Numeric(4, 3))
    registered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    #: Weaponisation scoring — MX present means armed (PRD D4).
    has_mx: Mapped[bool] = mapped_column(Boolean, default=False)
    has_web: Mapped[bool] = mapped_column(Boolean, default=False)
    first_seen_source: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16), default="open")

    __table_args__ = (UniqueConstraint("tenant_id", "candidate_domain"),)


# ─────────────────────────────────────────────────────────────────────────────
# Mailboxes
# ─────────────────────────────────────────────────────────────────────────────
class Mailbox(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "mailboxes"

    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id"), index=True)
    domain_id: Mapped[UUID | None] = mapped_column(ForeignKey("domains.id"))
    address: Mapped[str] = mapped_column(String(320), index=True)
    display_name: Mapped[str | None] = mapped_column(String(255))
    #: Drives both pricing and IMAP strategy — PROTECTED holds IDLE, MONITORED
    #: polls (PRD §12.2, §12.11D).
    mailbox_class: Mapped[str] = mapped_column(String(16), default=MailboxClass.MONITORED)
    integration_tier: Mapped[int] = mapped_column(Integer, default=IntegrationTier.FORWARDING)
    #: Configured SourceMechanism values; capabilities are derived from these.
    sources: Mapped[list[str]] = mapped_column(StringList, default=list)
    protection_level: Mapped[str] = mapped_column(String(16), default=ProtectionLevel.LIMITED)
    inactive_detections: Mapped[list[str]] = mapped_column(StringList, default=list)
    is_shared: Mapped[bool] = mapped_column(Boolean, default=False)
    #: Shared mailboxes make concurrency normal — PRD S9.
    known_user_count: Mapped[int] = mapped_column(Integer, default=1)
    backfilled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    #: Set when the stored credential can no longer be used (e.g. the master key
    #: rotated, or the provider revoked the password): the mailbox reads as
    #: "connected" but cannot sync, so the UI must prompt a reconnect instead of
    #: silently protecting nothing.
    needs_reconnect: Mapped[bool] = mapped_column(Boolean, default=False)
    #: Human-readable reason for needs_reconnect, surfaced to the admin.
    connection_error: Mapped[str | None] = mapped_column(String(255))
    #: C11 silent-access detection, opted into per mailbox.
    #:
    #: C11 fires when a message flips to read while no Envelock-covered device is
    #: signed in. That is exactly right for a mailbox read only on covered
    #: devices, and a false-alarm machine for one also read on a phone with no
    #: sensor — every evening read would page the owner. Only the person who
    #: knows how the mailbox is used can make that call, so it is off until they
    #: do. See `platform/sensor.py`.
    silent_access_armed: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=false()
    )
    #: Split key custody hand-off. Under split custody the API cannot decrypt a
    #: mailbox credential, so "Sync now" and "Scan my history" cannot run where
    #: the button is pressed. The API records the request here and the worker —
    #: the only process that can open the credential — carries it out on its
    #: next cycle. Null when nothing is pending.
    sync_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    backfill_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    #: Look-back for a queued history scan, in days.
    backfill_requested_days: Mapped[int | None] = mapped_column(Integer)
    #: Progress and outcome of the most recent queued history scan, written by
    #: the worker and read by the dashboard. The in-memory job registry cannot
    #: carry this across processes.
    backfill_state: Mapped[dict | None] = mapped_column(JsonDict)

    __table_args__ = (UniqueConstraint("tenant_id", "address"),)


class MailboxCredential(Base, UUIDMixin, TimestampMixin):
    """Envelope-encrypted. Decrypted only inside the connection broker (PRD §5.2)."""

    __tablename__ = "mailbox_credentials"

    mailbox_id: Mapped[UUID] = mapped_column(ForeignKey("mailboxes.id"), unique=True)
    tenant_id: Mapped[UUID] = mapped_column(Uuid, index=True)
    kind: Mapped[str] = mapped_column(String(16))  # imap_password|oauth_token
    imap_host: Mapped[str | None] = mapped_column(String(253))
    imap_port: Mapped[int | None] = mapped_column(Integer)
    #: Transport security for the IMAP connection: "ssl" (implicit TLS, usual 993),
    #: "starttls" (upgrade on 143), or "none" (plain — discouraged).
    imap_security: Mapped[str | None] = mapped_column(String(16), default="ssl")
    #: Login username when it differs from the mailbox address (some providers).
    imap_username: Mapped[str | None] = mapped_column(String(320))
    #: SHA-256 of a server certificate this tenant explicitly approved for this
    #: mailbox, lowercase hex. Set only when the customer was shown the
    #: certificate — its names, issuer and expiry — and chose to trust it,
    #: which is how a mailbox on shared hosting whose certificate names the
    #: provider rather than the customer's own domain can connect at all.
    #:
    #: This narrows trust rather than removing it: with a pin set we check the
    #: certificate is byte-for-byte the approved one, so a machine-in-the-middle
    #: is refused even when it holds a certificate a public CA would vouch for.
    #: Null means ordinary strict verification, which is the norm.
    imap_cert_sha256: Mapped[str | None] = mapped_column(String(64))
    #: Ciphertext only. Never logged, never returned by the API.
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary)
    wrapped_dek: Mapped[bytes] = mapped_column(LargeBinary)
    key_id: Mapped[str | None] = mapped_column(String(255))
    #: IMAP sync cursor. UIDs are only monotonic within one UIDVALIDITY epoch, so
    #: we store both: if the server resets UIDVALIDITY we restart the cursor rather
    #: than silently skipping mail (RFC 3501 §2.3.1.1).
    imap_last_uid: Mapped[int | None] = mapped_column(BigInteger)
    imap_uidvalidity: Mapped[int | None] = mapped_column(BigInteger)
    #: Last time the broker successfully polled this mailbox (distinct from the
    #: mailbox's own last_sync_at, which the UI shows).
    imap_last_polled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    #: INBOX UIDs that were unread at the last poll. A UID that was here and is
    #: now read (and still exists) was opened since — which is what C11 asks
    #: about. Bounded to the most recent `sensor.MAX_TRACKED_UNSEEN`. Only kept
    #: for mailboxes with silent-access detection armed.
    imap_unseen_uids: Mapped[list | None] = mapped_column(JsonDict)
    #: OAuth access-token expiry (Tier 1). Plaintext so the refresh scheduler can
    #: find due tokens without decrypting the sealed credential.
    token_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


# ─────────────────────────────────────────────────────────────────────────────
# Counterparties — the A-group state
# ─────────────────────────────────────────────────────────────────────────────
class Counterparty(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "counterparties"

    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id"), index=True)
    registrable_domain: Mapped[str] = mapped_column(String(253), index=True)
    display_name: Mapped[str | None] = mapped_column(String(255))
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    message_count: Mapped[int] = mapped_column(Integer, default=0)
    #: A2 — the number we prompt the user to call. Never the one in the email.
    verified_phone: Mapped[str | None] = mapped_column(String(32))
    #: A12 — historical reply latency baseline, seconds. Dormant: computing it
    #: honestly needs outbound-mail visibility no channel supplies yet.
    median_reply_seconds: Mapped[int | None] = mapped_column(Integer)
    #: A13 — invoice numbers we have seen from this vendor (duplicate-invoice
    #: fraud) and their typical largest amount (EMA; gross-anomaly fraud). Both
    #: had detection code reading them and NOTHING writing them — A13 was
    #: structurally dead. Learned only from unflagged mail (see pipeline.learn).
    seen_invoice_numbers: Mapped[list[str]] = mapped_column(StringList, default=list)
    typical_amount: Mapped[float | None] = mapped_column(Float)
    #: A10 — sending infrastructure fingerprint.
    known_dkim_domains: Mapped[list[str]] = mapped_column(StringList, default=list)
    known_mail_clients: Mapped[list[str]] = mapped_column(StringList, default=list)
    is_trusted: Mapped[bool] = mapped_column(Boolean, default=False)

    __table_args__ = (UniqueConstraint("tenant_id", "registrable_domain"),)


class BankRecord(Base, UUIDMixin, TimestampMixin):
    """A1/A2 — known-good payment details per counterparty.

    Any change to a previously-seen vendor's details is Critical, always.
    """

    __tablename__ = "bank_records"

    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id"), index=True)
    counterparty_id: Mapped[UUID] = mapped_column(ForeignKey("counterparties.id"), index=True)
    scheme: Mapped[str] = mapped_column(String(16))  # iban|swift|ach|sortcode|crypto
    #: Normalised account identifier (IBAN, account no, wallet address).
    identifier: Mapped[str] = mapped_column(String(128))
    bank_name: Mapped[str | None] = mapped_column(String(255))
    country: Mapped[str | None] = mapped_column(String(2))
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    verified_by: Mapped[UUID | None] = mapped_column(Uuid)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    __table_args__ = (
        UniqueConstraint("counterparty_id", "scheme", "identifier"),
        Index("ix_bank_records_lookup", "tenant_id", "counterparty_id", "is_active"),
    )


class SenderProfile(Base, UUIDMixin, TimestampMixin):
    """A9 stylometry baseline, per sending address."""

    __tablename__ = "sender_profiles"

    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id"), index=True)
    address: Mapped[str] = mapped_column(String(320), index=True)
    sample_count: Mapped[int] = mapped_column(Integer, default=0)
    #: Lightweight stylometric features; embeddings live in pgvector separately.
    features: Mapped[dict] = mapped_column(JsonDict, default=dict)

    __table_args__ = (UniqueConstraint("tenant_id", "address"),)


# ─────────────────────────────────────────────────────────────────────────────
# Messages, findings, alerts
# ─────────────────────────────────────────────────────────────────────────────
class Message(Base, UUIDMixin, TimestampMixin):
    """Metadata always; bodies only when metadata-only mode is off (E13)."""

    __tablename__ = "messages"

    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id"), index=True)
    mailbox_id: Mapped[UUID] = mapped_column(ForeignKey("mailboxes.id"), index=True)
    rfc_message_id: Mapped[str | None] = mapped_column(String(998), index=True)
    thread_key: Mapped[str | None] = mapped_column(String(255), index=True)
    direction: Mapped[str] = mapped_column(String(16))
    sender_address: Mapped[str] = mapped_column(String(320), index=True)
    sender_display: Mapped[str | None] = mapped_column(String(255))
    reply_to_address: Mapped[str | None] = mapped_column(String(320))
    subject: Mapped[str | None] = mapped_column(Text)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    source: Mapped[str] = mapped_column(String(32))
    remediable: Mapped[bool] = mapped_column(Boolean, default=False)
    spf: Mapped[str | None] = mapped_column(String(16))
    dkim: Mapped[str | None] = mapped_column(String(16))
    dmarc: Mapped[str | None] = mapped_column(String(16))
    attachment_hashes: Mapped[list[str]] = mapped_column(StringList, default=list)
    body_storage_key: Mapped[str | None] = mapped_column(String(512))
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    #: The provider's handle for this message — the IMAP UID for IMAP-sourced
    #: mail (falls back to the Message-ID for other paths). This is what lets a
    #: human quarantine an already-delivered message later: without it the
    #: manual quarantine endpoint could never name the message to move.
    source_ref: Mapped[str | None] = mapped_column(String(998))
    #: Set when a human asks for quarantine from a process that cannot decrypt
    #: credentials (API/worker custody split) — the IMAP worker executes it on
    #: its next cycle and stamps quarantined_at.
    quarantine_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    quarantined_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class LinkToken(Base, UUIDMixin, TimestampMixin):
    """One rewritten URL (feature 1 — link safety).

    Every URL in a protected message is replaced with `{redirect_base}/r/{token}`
    at delivery. When the token is fetched we re-check the destination live —
    a page that was clean at delivery and weaponised an hour later is the
    standard evasion, and click time is the only moment that catches it.
    """

    __tablename__ = "link_tokens"

    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id"), index=True)
    mailbox_id: Mapped[UUID | None] = mapped_column(ForeignKey("mailboxes.id"))
    message_id: Mapped[UUID | None] = mapped_column(ForeignKey("messages.id"))
    #: URL-safe opaque token carried in the rewritten link. Globally unique —
    #: the redirector is unauthenticated and resolves it without tenant context.
    token: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    original_url: Mapped[str] = mapped_column(Text)
    #: Verdict cached from the most recent check (delivery or click).
    last_verdict: Mapped[str | None] = mapped_column(String(16))
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    click_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")


class LinkClick(Base, UUIDMixin, TimestampMixin):
    """Click ledger: who fetched a rewritten link, when, and what we did."""

    __tablename__ = "link_clicks"

    link_token_id: Mapped[UUID] = mapped_column(ForeignKey("link_tokens.id"), index=True)
    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id"), index=True)
    ip: Mapped[str | None] = mapped_column(String(45))
    user_agent: Mapped[str | None] = mapped_column(String(512))
    #: allowed | warned | blocked — what the redirector answered with.
    action: Mapped[str] = mapped_column(String(16))


class Finding(Base, UUIDMixin, TimestampMixin):
    """One detection firing. Alerts aggregate findings (PRD §8 combination logic)."""

    __tablename__ = "findings"

    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id"), index=True)
    mailbox_id: Mapped[UUID | None] = mapped_column(ForeignKey("mailboxes.id"))
    message_id: Mapped[UUID | None] = mapped_column(ForeignKey("messages.id"))
    alert_id: Mapped[UUID | None] = mapped_column(ForeignKey("alerts.id"), index=True)
    #: Service id from the PRD catalogue — "A1", "C4", "D4".
    service: Mapped[str] = mapped_column(String(8), index=True)
    tier: Mapped[str] = mapped_column(String(16))
    score: Mapped[int] = mapped_column(Integer, default=0)
    summary: Mapped[str] = mapped_column(Text)
    evidence: Mapped[dict] = mapped_column(JsonDict, default=dict)


class Alert(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "alerts"

    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id"), index=True)
    mailbox_id: Mapped[UUID | None] = mapped_column(ForeignKey("mailboxes.id"), index=True)
    tier: Mapped[str] = mapped_column(String(16), index=True)
    title: Mapped[str] = mapped_column(String(255))
    body: Mapped[str] = mapped_column(Text)
    #: The counterparty this alert is about (eTLD+1). Captured at raise time so
    #: that resolving the alert as real fraud can feed the E8 graph automatically.
    counterparty_domain: Mapped[str | None] = mapped_column(String(253), index=True)
    #: Guided out-of-band verification (E3) — the step that stops the loss.
    requires_callback: Mapped[bool] = mapped_column(Boolean, default=False)
    callback_phone: Mapped[str | None] = mapped_column(String(32))
    #: The largest currency-marked amount in the message that produced this
    #: alert, captured at raise time. This is the sum that was about to move to
    #: the wrong account — the single number that turns a renewal conversation
    #: from a cost into a return. Null whenever the message named no amount, or
    #: the alert is not about a payment at all; a null is "unknown", never zero,
    #: and the rollup counts alerts with and without a figure separately so we
    #: never present a partial total as a complete one.
    amount_at_risk: Mapped[float | None] = mapped_column(Float)
    #: ISO code or symbol as written in the message. Amounts in different
    #: currencies are NOT summed — see `prevented_loss` in platform/alerts.py.
    amount_currency: Mapped[str | None] = mapped_column(String(8))
    state: Mapped[str] = mapped_column(String(16), default="open")  # open|acked|resolved|dismissed
    #: AI autoflag — set when the LLM judge independently confirmed this alert as
    #: fraud (and possibly escalated its tier). Surfaced in the UI as a chip; the
    #: confidence and model stay internal (llm_verdicts), never in client copy.
    #: server_default so raw/legacy inserts (and the ALTER on populated tables)
    #: stay valid — matches the migration.
    ai_flagged: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    ai_verdict: Mapped[str | None] = mapped_column(String(16))  # fraud|suspicious|benign
    #: Acknowledgement — not delivery — drives escalation (PRD §8.1).
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    acknowledged_by: Mapped[UUID | None] = mapped_column(Uuid)
    escalated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    #: The furthest escalation stage this alert has reached — "it_admin" then
    #: "all_admins". `escalated_at` alone could not express this: it is a single
    #: timestamp overwritten by each step, so the 60-minute rule matched on every
    #: subsequent cycle and re-escalated the same alert once a minute, forever.
    #: In production that is an SMS per minute to an admin until acknowledged.
    escalated_to: Mapped[str | None] = mapped_column(String(16))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (Index("ix_alerts_open", "tenant_id", "state", "tier"),)


class NotificationDelivery(Base, UUIDMixin, TimestampMixin):
    """One attempt on one rung of the ladder (PRD §8.1). L3 is metered."""

    __tablename__ = "notification_deliveries"

    tenant_id: Mapped[UUID] = mapped_column(Uuid, index=True)
    alert_id: Mapped[UUID] = mapped_column(ForeignKey("alerts.id"), index=True)
    user_id: Mapped[UUID | None] = mapped_column(Uuid)
    rung: Mapped[str] = mapped_column(String(4))  # L0|L1|L2|L3
    channel: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16), default="pending")
    cost_micros: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text)


class AuditEvent(Base, UUIDMixin, TimestampMixin):
    """E5 — IT sees who read, who acted, who ignored."""

    __tablename__ = "audit_events"

    tenant_id: Mapped[UUID] = mapped_column(Uuid, index=True)
    actor_id: Mapped[UUID | None] = mapped_column(Uuid)
    action: Mapped[str] = mapped_column(String(64), index=True)
    target_type: Mapped[str | None] = mapped_column(String(32))
    target_id: Mapped[UUID | None] = mapped_column(Uuid)
    detail: Mapped[dict] = mapped_column(JsonDict, default=dict)


# ─────────────────────────────────────────────────────────────────────────────
# Channel 2 — sensor sessions
# ─────────────────────────────────────────────────────────────────────────────
class SensorSession(Base, UUIDMixin, TimestampMixin):
    """C6/C10/C11. A \\Seen flag flipping with no live session here means
    someone else is in the mailbox."""

    __tablename__ = "sensor_sessions"

    tenant_id: Mapped[UUID] = mapped_column(Uuid, index=True)
    mailbox_id: Mapped[UUID] = mapped_column(ForeignKey("mailboxes.id"), index=True)
    user_id: Mapped[UUID | None] = mapped_column(Uuid)
    device_fingerprint: Mapped[str] = mapped_column(String(128), index=True)
    ip: Mapped[str | None] = mapped_column(String(45))
    asn: Mapped[int | None] = mapped_column(Integer)
    country: Mapped[str | None] = mapped_column(String(2))
    city: Mapped[str | None] = mapped_column(String(128))
    #: Resolved at heartbeat from the sign-in IP (channels/identity/geo.py).
    #: Without these two columns C7 impossible-travel and C14 counterparty-travel
    #: are written but can never fire — the haversine has nothing to measure.
    latitude: Mapped[float | None] = mapped_column(Float)
    longitude: Mapped[float | None] = mapped_column(Float)
    is_vpn: Mapped[bool] = mapped_column(Boolean, default=False)
    is_proxy: Mapped[bool] = mapped_column(Boolean, default=False)
    is_tor: Mapped[bool] = mapped_column(Boolean, default=False)
    browser: Mapped[str | None] = mapped_column(String(64))
    os: Mapped[str | None] = mapped_column(String(64))
    mail_client: Mapped[str | None] = mapped_column(String(64))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AttestedRead(Base, UUIDMixin, TimestampMixin):
    """The sensor saying "this person opened that message, here, just now".

    C11 fires when a message's `\\Seen` flag flips with **no** attestation — that
    is what catches someone else reading the mailbox. Without somewhere to record
    the attestations, every legitimate read looked exactly like an intrusion, so
    the endpoint that received them discarded them and the detection could only
    ever have produced false positives.

    Deliberately short-lived: this is corroboration for a flag change that
    happens within seconds, not a reading history. The retention purge drops it
    with the rest of the identity telemetry.
    """

    __tablename__ = "attested_reads"
    __table_args__ = (
        # The C11 lookup is always (mailbox, message, recently) — index it.
        Index("ix_attested_reads_lookup", "mailbox_id", "message_ref", "read_at"),
    )

    tenant_id: Mapped[UUID] = mapped_column(Uuid, index=True)
    mailbox_id: Mapped[UUID] = mapped_column(ForeignKey("mailboxes.id"), index=True)
    #: Provider-specific handle for the message — an IMAP UID or a Graph id.
    message_ref: Mapped[str] = mapped_column(String(255))
    device_fingerprint: Mapped[str | None] = mapped_column(String(128))
    read_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class SensorDevice(Base, UUIDMixin, TimestampMixin):
    """One enrolled sensor: one install of the browser extension, Thunderbird
    add-on or Outlook add-in, on one device, reporting for one mailbox.

    Sensors authenticate with their own token rather than a user session. A
    session is a key to the whole workspace — alerts, members, billing — and a
    browser extension sits on an ordinary laptop. A sensor token can do exactly
    two things, both for one mailbox: say "this device is here" and say "this
    message was opened here". Stolen, it can post heartbeats; it cannot read a
    single alert.

    Only a SHA-256 of the token is stored. `device_fingerprint` pins the token to
    the device id the client generated when it enrolled, so one token cannot be
    used to impersonate a fleet of devices. A copied browser profile carries the
    same pair to a new network — which the heartbeat treats as a new sign-in and
    runs through C7/C8, so that theft is visible rather than invisible.
    """

    __tablename__ = "sensor_devices"

    tenant_id: Mapped[UUID] = mapped_column(Uuid, index=True)
    user_id: Mapped[UUID] = mapped_column(Uuid, index=True)
    mailbox_id: Mapped[UUID] = mapped_column(ForeignKey("mailboxes.id"), index=True)
    prefix: Mapped[str] = mapped_column(String(16), index=True)
    hashed: Mapped[str] = mapped_column(String(64))
    #: browser | thunderbird | outlook
    client: Mapped[str] = mapped_column(String(32))
    #: What the person sees in the device list, e.g. "Chrome on macOS".
    label: Mapped[str | None] = mapped_column(String(128))
    device_fingerprint: Mapped[str] = mapped_column(String(128))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_ip: Mapped[str | None] = mapped_column(String(45))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class SensorPairing(Base, UUIDMixin, TimestampMixin):
    """A one-time code that turns into a sensor token.

    The person pressing "add a device" is signed into the dashboard; the sensor
    they are installing is not, and must never be handed their session. So the
    dashboard mints a short code bound to one mailbox, the person types it into
    the extension, and the extension trades it — once — for its own scoped
    token. Short-lived and single-use: a code read over a shoulder is worthless
    ten minutes later, and worthless the moment it has been used.
    """

    __tablename__ = "sensor_pairings"

    tenant_id: Mapped[UUID] = mapped_column(Uuid, index=True)
    user_id: Mapped[UUID] = mapped_column(Uuid)
    mailbox_id: Mapped[UUID] = mapped_column(ForeignKey("mailboxes.id"), index=True)
    code_hash: Mapped[str] = mapped_column(String(64), unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class PushSubscription(Base, UUIDMixin, TimestampMixin):
    """L1 — free, self-hosted Web Push."""

    __tablename__ = "push_subscriptions"

    tenant_id: Mapped[UUID] = mapped_column(Uuid, index=True)
    user_id: Mapped[UUID] = mapped_column(index=True)
    endpoint: Mapped[str] = mapped_column(Text, unique=True)
    p256dh: Mapped[str] = mapped_column(String(255))
    auth: Mapped[str] = mapped_column(String(255))


# ─────────────────────────────────────────────────────────────────────────────
# Billing / metering
# ─────────────────────────────────────────────────────────────────────────────
class UsageMeter(Base, UUIDMixin, TimestampMixin):
    """Daily rollup. Fall-through rate is the number that predicts COGS
    (PRD §12.12D) — meter it from day one."""

    __tablename__ = "usage_meters"

    tenant_id: Mapped[UUID] = mapped_column(Uuid, index=True)
    day: Mapped[date] = mapped_column(Date, index=True)
    messages_analysed: Mapped[int] = mapped_column(Integer, default=0)
    attachments_seen: Mapped[int] = mapped_column(Integer, default=0)
    attachments_cache_hit: Mapped[int] = mapped_column(Integer, default=0)
    attachments_static_resolved: Mapped[int] = mapped_column(Integer, default=0)
    #: The expensive fall-through. Target under 5% of attachments_seen.
    attachments_detonated: Mapped[int] = mapped_column(Integer, default=0)
    url_lookups_free: Mapped[int] = mapped_column(Integer, default=0)
    url_lookups_paid: Mapped[int] = mapped_column(Integer, default=0)
    sms_sent: Mapped[int] = mapped_column(Integer, default=0)
    external_cost_micros: Mapped[int] = mapped_column(Integer, default=0)

    __table_args__ = (UniqueConstraint("tenant_id", "day"),)

    __table_args__ = (UniqueConstraint("tenant_id", "day"),)


class ExportToken(Base, UUIDMixin, TimestampMixin):
    """A persisted, read-only export/SIEM API token (PRD §15.3).

    Only a SHA-256 hash is stored — the plaintext is shown once at creation. The
    `prefix` lets a presented token be looked up without a table scan; `scopes`
    are read-only by construction."""

    __tablename__ = "export_tokens"

    tenant_id: Mapped[UUID] = mapped_column(Uuid, index=True)
    prefix: Mapped[str] = mapped_column(String(16), index=True)
    hashed: Mapped[str] = mapped_column(String(64))
    scopes: Mapped[list[str]] = mapped_column(StringList, default=list)
    created_by: Mapped[UUID | None] = mapped_column(Uuid)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class WebhookEndpoint(Base, UUIDMixin, TimestampMixin):
    """A registered outbound SIEM webhook (PRD §15.3). Deliveries are HMAC-signed
    with `secret` and retried on the backoff schedule."""

    __tablename__ = "webhook_endpoints"

    tenant_id: Mapped[UUID] = mapped_column(Uuid, index=True)
    url: Mapped[str] = mapped_column(Text)
    secret: Mapped[str] = mapped_column(String(128))
    events: Mapped[list[str]] = mapped_column(StringList, default=list)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_delivery_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_status: Mapped[str | None] = mapped_column(String(32))


class WebhookDelivery(Base, UUIDMixin, TimestampMixin):
    """One queued outbound delivery — the durable queue behind the SIEM webhooks.

    A row, not an in-memory task, so enqueue happens inside the same transaction
    that raised the alert: an alert cannot be committed without its delivery
    being committed alongside it, and a crash between the two is not a state the
    system can reach.
    """

    __tablename__ = "webhook_deliveries"
    __table_args__ = (
        # The drain query is always "pending, due now, oldest first".
        Index("ix_webhook_deliveries_due", "status", "next_attempt_at"),
    )

    tenant_id: Mapped[UUID] = mapped_column(Uuid, index=True)
    endpoint_id: Mapped[UUID] = mapped_column(
        ForeignKey("webhook_endpoints.id", ondelete="CASCADE"), index=True
    )
    event_type: Mapped[str] = mapped_column(String(64))
    payload: Mapped[dict] = mapped_column(JsonDict, default=dict)
    #: pending | delivered | failed | cancelled
    status: Mapped[str] = mapped_column(String(16), default="pending")
    attempt: Mapped[int] = mapped_column(Integer, default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)


class LlmUsage(Base, UUIDMixin, TimestampMixin):
    """Per-mailbox monthly LLM-judge usage (AI cascade). Backs the cost cap and
    the fall-through/COGS view — the number that predicts spend (PRD §12.12D)."""

    __tablename__ = "llm_usage"

    tenant_id: Mapped[UUID] = mapped_column(Uuid, index=True)
    mailbox_id: Mapped[UUID | None] = mapped_column(Uuid, index=True)
    period: Mapped[str] = mapped_column(String(7))  # YYYY-MM
    calls: Mapped[int] = mapped_column(Integer, default=0)
    cost_micros: Mapped[int] = mapped_column(Integer, default=0)

    __table_args__ = (UniqueConstraint("mailbox_id", "period"),)


class LlmVerdictRecord(Base, UUIDMixin, TimestampMixin):
    """One LLM-judge verdict on one message — the AI autoflag audit trail.

    Every call the cascade makes lands here, whether or not it escalated, so
    (a) an operator can always answer "why did the AI flag this?", and (b) once a
    human disposes of the alert, the row becomes a *labeled example* — the
    training corpus for the phase-2 fine-tuned classifier (PRD §10). The
    confidence/model fields are internal: client copy never includes them.
    """

    __tablename__ = "llm_verdicts"

    tenant_id: Mapped[UUID] = mapped_column(Uuid, index=True)
    mailbox_id: Mapped[UUID | None] = mapped_column(Uuid, index=True)
    message_id: Mapped[UUID | None] = mapped_column(ForeignKey("messages.id"))
    alert_id: Mapped[UUID | None] = mapped_column(ForeignKey("alerts.id"), index=True)
    #: fraud | suspicious | benign — the judge's structured opinion.
    verdict: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    rationale: Mapped[str] = mapped_column(Text, default="")
    #: Whether this verdict actually promoted the alert tier.
    escalated: Mapped[bool] = mapped_column(Boolean, default=False)
    #: The rule tier before / after the cascade — how much the AI moved the needle.
    rule_tier: Mapped[str | None] = mapped_column(String(16))
    final_tier: Mapped[str | None] = mapped_column(String(16))
    provider: Mapped[str] = mapped_column(String(32), default="")
    model: Mapped[str] = mapped_column(String(64), default="")
    input_tokens: Mapped[int] = mapped_column(Integer, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, default=0)
    cost_micros: Mapped[int] = mapped_column(Integer, default=0)
    #: Filled in when a human disposes of the linked alert: confirmed (resolved as
    #: real fraud) | dismissed (false positive). This is the label.
    human_disposition: Mapped[str | None] = mapped_column(String(16))
    labeled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Invoice(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "invoices"

    tenant_id: Mapped[UUID] = mapped_column(Uuid, index=True)
    period_start: Mapped[date] = mapped_column(Date)
    period_end: Mapped[date] = mapped_column(Date)
    currency: Mapped[str] = mapped_column(String(3), default="USD")
    platform_cents: Mapped[int] = mapped_column(Integer, default=0)
    protected_cents: Mapped[int] = mapped_column(Integer, default=0)
    monitored_cents: Mapped[int] = mapped_column(Integer, default=0)
    discount_cents: Mapped[int] = mapped_column(Integer, default=0)
    total_cents: Mapped[int] = mapped_column(Integer, default=0)
    breakdown: Mapped[dict] = mapped_column(JsonDict, default=dict)
    status: Mapped[str] = mapped_column(String(16), default="draft")


__all__ = [
    "Alert",
    "AlertTier",
    "AuditEvent",
    "BankRecord",
    "Counterparty",
    "Decimal",
    "Domain",
    "ExportToken",
    "LlmUsage",
    "LlmVerdictRecord",
    "AttestedRead",
    "WebhookDelivery",
    "WebhookEndpoint",
    "DomainTrialLedger",
    "Finding",
    "GraphVerdict",
    "Invoice",
    "LookalikeDomain",
    "Mailbox",
    "MailboxCredential",
    "Message",
    "NotificationDelivery",
    "PushSubscription",
    "SenderProfile",
    "SensorSession",
    "Tenant",
    "UsageMeter",
    "User",
]
