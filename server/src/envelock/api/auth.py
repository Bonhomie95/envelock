"""Authentication endpoints (PRD §15.1).

Accounts are persisted to the database. The security primitives, role model and
token flow live in `auth/security.py`; this module holds the endpoints and the
thin data-access helpers that read and write the `users` table.

A security product whose own accounts do not survive a restart is indefensible,
so there is no in-memory shortcut here — every account, its MFA secret and its
recovery-code hashes are durable.
"""

from __future__ import annotations

import logging
import secrets
import time
from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from envelock.auth.deps import AdminUser, CurrentUser, SystemScoped
from envelock.auth.email_policy import is_disposable_email
from envelock.auth.security import (
    MFA_PENDING_TTL,
    REFRESH_TTL,
    SENSITIVE_ACTIONS,
    Role,
    TokenError,
    assess_passphrase,
    decode_token,
    dummy_hash,
    generate_numeric_otp,
    generate_recovery_codes,
    generate_totp_secret,
    hash_otp,
    hash_password,
    hash_recovery_code,
    issue_pair,
    issue_token,
    totp_uri,
    verify_password,
    verify_totp,
)
from envelock.db import get_session
from envelock.models import Domain, Tenant, User
from envelock.security.limits import (
    active_lockout,
    active_replay,
    active_revocations,
)
from envelock.util.domains import is_free_mail, registrable_domain

router = APIRouter(
    prefix="/api/v1/auth",
    tags=["auth"],
    # Pre-authentication: sign-in must find a user by email before any tenant
    # is known. See auth.deps.system_scoped.
    dependencies=[SystemScoped],
)
logger = logging.getLogger("envelock.auth")

Session = Annotated[AsyncSession, Depends(get_session)]


def _reset_store() -> None:
    """Test hook: clear persisted accounts (and their tenant-scoped rows) between
    tests. Runs a TRUNCATE on the configured Postgres in a dedicated thread with
    its own event loop, so it works whether or not the caller is already inside a
    running loop. A no-op when the schema has not been created yet."""
    import threading

    from envelock.config import get_settings

    pg = get_settings().postgres_dsn.replace("postgresql+asyncpg://", "postgresql://")
    if not pg.startswith("postgresql://"):
        return

    def _run() -> None:
        import asyncio
        import contextlib

        import asyncpg

        async def _clear() -> None:
            conn = await asyncpg.connect(pg)
            try:
                # CASCADE clears every tenant-scoped table that references these.
                await conn.execute("TRUNCATE users, tenants RESTART IDENTITY CASCADE")
            finally:
                await conn.close()

        # Schema may not exist yet, or the DB may be unavailable — best effort.
        with contextlib.suppress(Exception):
            asyncio.run(_clear())

    thread = threading.Thread(target=_run)
    thread.start()
    thread.join()


# ── Schemas ──────────────────────────────────────────────────────────────────
class RegisterRequest(BaseModel):
    email: EmailStr
    # Length ceilings everywhere: an unbounded password is unbounded scrypt work.
    password: str = Field(min_length=12, max_length=256)
    tenant_name: str = Field(min_length=1, max_length=200)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(max_length=256)


class MfaVerifyRequest(BaseModel):
    mfa_token: str = Field(max_length=4096)
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class RecoveryRequest(BaseModel):
    mfa_token: str = Field(max_length=4096)
    recovery_code: str = Field(max_length=64)


class TokenRequest(BaseModel):
    token: str = Field(max_length=4096)


# ── Helpers ──────────────────────────────────────────────────────────────────
def _generic_401() -> HTTPException:
    """One message for every credential failure.

    Distinguishing "no such account" from "wrong password" hands an attacker a
    free account-enumeration oracle.
    """
    return HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")


async def _user_by_email(session: AsyncSession, email: str) -> User | None:
    return (
        await session.execute(select(User).where(User.email == email))
    ).scalar_one_or_none()


async def _user_by_id(session: AsyncSession, user_id: UUID) -> User:
    user = await session.get(User, user_id)
    if user is None:
        raise _generic_401()
    return user


def _role_of(user: User) -> Role:
    return Role(user.role)


def _issue_mfa_challenge(user: User) -> str:
    return issue_token(
        user_id=user.id,
        tenant_id=user.tenant_id,
        role=_role_of(user),
        typ="mfa_pending",
        ttl=MFA_PENDING_TTL,
    )


async def _complete_login(
    session: AsyncSession, user: User, *, first_time: bool = False
) -> dict:
    await active_lockout().arecord_success(user.email)
    tokens = issue_pair(
        user_id=user.id, tenant_id=user.tenant_id, role=_role_of(user)
    )
    if first_time:
        codes = generate_recovery_codes()
        user.recovery_hashes = [hash_recovery_code(c) for c in codes]
        tokens["recovery_codes"] = codes  # shown exactly once
    await session.commit()
    return tokens


async def _start_signup_trial(session: AsyncSession, tenant: Tenant, email: str) -> None:
    """Give a brand-new tenant the full plan on a trial from minute one.

    A dashboard that shows nothing until a card is entered has no chance to prove
    itself. So signup starts the trial immediately on the top plan; the card is
    only needed later, to keep it. When the trial lapses unpaid the tenant falls
    back to Guard (free), it is never locked out.

    One trial per registrable domain, ever (PRD §12.7) — recorded in the permanent
    ledger so delete-and-re-register cannot farm fresh trials. Free-mail signups
    have no lockable domain; the payment-fingerprint lock at billing/confirm is
    what catches repeat abuse there.
    """
    from envelock.billing.pricing import Plan
    from envelock.config import get_settings
    from envelock.models import DomainTrialLedger

    now = datetime.now(UTC)
    domain_part = email.rsplit("@", 1)[-1] if "@" in email else ""
    reg = registrable_domain(domain_part)

    if reg and not is_free_mail(reg):
        if await session.get(DomainTrialLedger, reg) is not None:
            return  # this domain already used its one trial — stays on Guard
        session.add(
            DomainTrialLedger(
                registrable_domain=reg,
                first_trial_at=now,
                first_tenant_id=tenant.id,
                outcome="active",
            )
        )

    tenant.plan = Plan.COMPLETE.value  # highest plan for the trial
    tenant.trial_started_at = now
    tenant.trial_ends_at = now + timedelta(days=get_settings().trial_days)


async def _verify_step_up(
    user: User, *, password: str, mfa_code: str | None, require_mfa_enrolment: bool = True
) -> None:
    """Re-authenticate before a sensitive change (PRD §15.1 forced re-auth).

    When two-factor is **on**, re-auth means the current password *and* a fresh,
    single-use TOTP code, so a stolen password alone can never change the keys to
    the account.

    When two-factor is **off** (it can be deferred at sign-up), behaviour depends on
    `require_mfa_enrolment`. For changes to the second-factor keys themselves
    (recovery phone, security settings) it stays **True**: we refuse until MFA is on,
    because there is no meaningful re-auth for those without it. For the **password**
    it is **False**: demanding a code the user doesn't have is the "password won't
    change" dead end, so the current password alone is accepted (and still verified).
    Rate-limited and, with MFA, TOTP-replay-guarded like a login.
    """
    if require_mfa_enrolment and not user.mfa_enabled:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "turn on two-factor authentication first — changing your recovery "
            "phone or security settings requires it",
        )

    scope = f"stepup:{user.id}"
    locked, retry_after = await active_lockout().ais_locked(scope)
    if locked:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "too many attempts — wait and try again",
            headers={"Retry-After": str(retry_after)},
        )

    ok = verify_password(password, user.password_hash or dummy_hash())
    if ok and user.mfa_enabled:
        # Second factor required only when the account actually has one.
        if not mfa_code or not verify_totp(user.totp_secret or "", mfa_code):
            ok = False
        elif not await active_replay().acheck_and_record(f"{user.id}:{mfa_code}"):
            ok = False  # a TOTP code is single-use for a step-up too

    if not ok:
        await active_lockout().arecord_failure(scope)
        detail = (
            "re-authentication failed — check your password and authenticator code"
            if user.mfa_enabled
            else "re-authentication failed — check your current password"
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail)
    await active_lockout().arecord_success(scope)


async def _existing_tenant_for_domain(session: AsyncSession, email: str) -> UUID | None:
    """If a corporate email domain already has a tenant, return its id so a
    colleague JOINS it rather than spinning up a second workspace — and a second
    trial — for the same company (PRD §12.7). Free-mail domains (gmail, outlook…)
    have many unrelated users, so they never share a tenant.
    """
    domain_part = email.rsplit("@", 1)[-1] if "@" in email else ""
    reg = registrable_domain(domain_part)
    if not reg or is_free_mail(reg):
        return None
    # Strongest signal: a domain already registered to a tenant.
    domain = (
        await session.execute(
            select(Domain).where(Domain.registrable_domain == reg).limit(1)
        )
    ).scalar_one_or_none()
    if domain is not None:
        if await _tenant_claim_is_credible(session, domain.tenant_id):
            return domain.tenant_id
        return None
    # Fallback for the window before the first user finishes onboarding: a
    # colleague already registered with the same email domain.
    like = "%@" + domain_part.replace("%", r"\%").replace("_", r"\_")
    colleague = (
        await session.execute(select(User).where(User.email.ilike(like)).limit(1))
    ).scalar_one_or_none()
    if colleague is not None and await _tenant_claim_is_credible(
        session, colleague.tenant_id
    ):
        return colleague.tenant_id
    return None


async def _tenant_claim_is_credible(session: AsyncSession, tenant_id: UUID) -> bool:
    """Whether a tenant's claim on its domain is real enough to auto-join.

    With email verification on, a tenant whose every user is unverified is a
    squatter shape: someone registered a fake address on the domain and never
    proved they can read mail there. Routing the company's real employees into
    that tenant as pending members would hand the attacker the whole point of
    one-company-one-tenant. Such a tenant is skipped — the genuine registrant
    gets a fresh tenant instead. (Flag off → every claim counts, as before.)
    """
    from envelock.config import get_settings

    if not get_settings().require_email_verification:
        return True
    verified = (
        await session.execute(
            select(User.id)
            .where(User.tenant_id == tenant_id, User.email_verified_at.is_not(None))
            .limit(1)
        )
    ).first()
    return verified is not None


# ── Endpoints ────────────────────────────────────────────────────────────────
@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(req: RegisterRequest, session: Session) -> dict:
    """First user of a corporate domain becomes its owner; later colleagues from
    the same domain join that tenant as members — one company, one tenant, one
    trial. Free-mail signups each get their own tenant."""
    email = req.email.lower().strip()

    # Reject throwaway inboxes: alerts, recovery and billing all need a real one,
    # and disposable addresses are a trial-abuse vector. This is a format policy
    # independent of whether the account exists, so it leaks no enumeration signal.
    if is_disposable_email(email):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "disposable email addresses are not allowed — use a permanent inbox",
        )

    # Business-only: Envelock protects a company's mail, so it needs a company
    # domain. Consumer inboxes (Gmail, Outlook.com, Yahoo, iCloud…) have no
    # domain we can monitor or verify and each holds thousands of unrelated
    # users. A company on Google Workspace or Microsoft 365 is unaffected — it
    # signs up with its own domain (acme.com), which is not in this list; only
    # the free consumer *domains themselves* are refused. Like the disposable
    # check, this is a policy on the address format, so it leaks no account
    # existence signal.
    reg_domain = registrable_domain(email.rsplit("@", 1)[-1] if "@" in email else "")
    if is_free_mail(reg_domain):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "use your work email — Envelock protects a company domain, so "
            "consumer inboxes like Gmail or Outlook.com can't be used. If your "
            "company uses Google Workspace or Microsoft 365, sign up with your "
            "own company address (you@yourcompany.com).",
        )

    # Reject a domain that plainly doesn't exist (a typo / made-up address like
    # test@hjsbcjsjs.com) before we ever create a tenant. Distinct from OWNERSHIP
    # verification (that comes later, in the dashboard) — this is just "is this a
    # real mail domain at all". Fails open on a transient DNS failure so a resolver
    # blip never blocks a legitimate signup.
    from envelock.config import get_settings
    from envelock.util import dns_verify

    if get_settings().check_email_domain_exists:
        mail_domain = email.rsplit("@", 1)[-1] if "@" in email else ""
        if dns_verify.deliverability_status(mail_domain) == "absent":
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "that email domain doesn't exist or can't receive email — "
                "check the spelling of your address.",
            )

    # Tell the caller plainly that the address is already registered rather than
    # silently "succeeding". (This trades a little account-enumeration hardening for
    # clarity — acceptable for a business tool where the domain is already known and
    # a confusing silent no-op is the bigger problem.)
    if await _user_by_email(session, email) is not None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "this email is already registered — sign in instead, or reset your "
            "password if you've forgotten it.",
        )

    try:
        assess_passphrase(req.password)
        password_hash = hash_password(req.password)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc

    existing_tenant_id = await _existing_tenant_for_domain(session, email)
    if existing_tenant_id is not None:
        # A colleague — join the company's existing tenant as a member, but
        # PENDING: an admin must approve before they see anything (and approval
        # then adds them as a protected mailbox). No new tenant → no second trial,
        # and no second owner/admin: the domain's first registrant is the admin.
        new_user = User(
            id=uuid4(),
            tenant_id=existing_tenant_id,
            email=email,
            password_hash=password_hash,
            role=Role.MEMBER.value,
            is_admin=False,
            status="pending",
        )
        session.add(new_user)
    else:
        # First from this domain (or a free-mail signup) → new owner tenant. This
        # is the single admin for the company; everyone else joins pending.
        tenant = Tenant(id=uuid4(), name=req.tenant_name)
        session.add(tenant)
        # With email verification on, the trial (and the permanent one-per-domain
        # ledger entry) starts at VERIFICATION, not registration — otherwise a
        # squatter registering a fake address on someone else's domain burns that
        # company's only trial forever.
        from envelock.config import get_settings as _gs

        if not _gs().require_email_verification:
            await _start_signup_trial(session, tenant, email)
        new_user = User(
            id=uuid4(),
            tenant_id=tenant.id,
            email=email,
            password_hash=password_hash,
            role=Role.OWNER.value,
            is_admin=True,  # owner has admin oversight (PRD §15.1)
        )
        session.add(new_user)
        # Create the (unverified) domain record now, at registration — not later
        # at bootstrap. This is what makes onboarding resumable and the
        # dashboard's verify-gate reliable: however early the owner quits (before
        # MFA, before verifying), the domain already exists, so on their next
        # sign-in the gate has a domain to prompt them to verify. reg is empty
        # only for a free-mail address, which has no domain to verify.
        reg = registrable_domain(email.rsplit("@", 1)[-1] if "@" in email else "")
        # Free-mail domains (gmail.com…) never get a Domain row: thousands of
        # unrelated tenants share them, they can't be DNS-verified, and the row
        # would collide with the global registrable_domain uniqueness that keeps
        # one company in one tenant.
        # With email verification ON, the row is claimed at VERIFICATION, not
        # here — otherwise a squatter's unverified signup would hold the
        # company's unique domain claim forever.
        if reg and not is_free_mail(reg) and not _gs().require_email_verification:
            from envelock.channels.mail.ingest import new_ingest_token

            session.add(
                Domain(
                    id=uuid4(),
                    tenant_id=tenant.id,
                    name=reg,
                    registrable_domain=reg,
                    verification_token=new_ingest_token(),
                )
            )
    try:
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        if "uq_domains_registrable" in str(exc.orig or exc):
            # A colleague's registration won the race and created the company
            # tenant a moment ago. Retrying joins it as a pending member.
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "your company's workspace was just created — sign up again to "
                "join it.",
            ) from exc
        # Lost a race to a concurrent signup of the same address → it now exists.
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "this email is already registered — sign in instead.",
        ) from exc

    response = {
        "status": "registration_received",
        "mfa_required": True,
        "next": "Sign in, then set up two-factor authentication. You can skip it "
        "for now and turn it on later from your dashboard, but it is strongly "
        "recommended.",
    }
    from envelock.config import get_settings as _gs2

    if _gs2().require_email_verification:
        link = await _send_verification_email(new_user)
        response["verification_required"] = True
        response["next"] = (
            "Check your inbox for a verification link — you can sign in once "
            "your email is confirmed."
        )
        if _gs2().env == "development" and link:
            response["verify_link"] = link
    return response


@router.post("/login")
async def login(req: LoginRequest, session: Session) -> dict:
    email = req.email.lower().strip()

    locked, retry_after = await active_lockout().ais_locked(email)
    if locked:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "too many failed attempts",
            headers={"Retry-After": str(retry_after)},
        )

    user = await _user_by_email(session, email)
    # Compare against a precomputed hash when the account is unknown, so the
    # timing profile matches without doing 32 MB of scrypt per bogus request.
    # `user.password_hash` is nullable — a member provisioned by an admin, or an
    # account created through a path that never set one, has None. Passing that
    # to `verify_password` raised AttributeError inside `stored.split("$")`, so
    # signing in to such an account answered 500 instead of a clean 401. The
    # dummy hash keeps the timing profile identical either way.
    stored = user.password_hash if (user and user.password_hash) else dummy_hash()
    password_ok = verify_password(req.password, stored)

    if user is None or not password_ok:
        await active_lockout().arecord_failure(email)
        raise _generic_401()

    # Only after a correct password (so this is not an enumeration oracle): with
    # verification on, an unproven address may not hold a session — that is the
    # entire anti-squatting control.
    from envelock.config import get_settings as _gs_login

    if _gs_login().require_email_verification and user.email_verified_at is None:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "confirm your email first — we sent you a verification link. "
            "Use 'resend verification' if it expired.",
        )

    return {
        "mfa_setup_required": not user.mfa_enabled,
        "mfa_required": user.mfa_enabled,
        "mfa_token": _issue_mfa_challenge(user),
    }


@router.post("/mfa/setup")
async def mfa_setup(req: TokenRequest, session: Session) -> dict:
    """Exchange an `mfa_pending` token for a TOTP secret to enrol."""
    try:
        claims = decode_token(req.token, expect="mfa_pending")
    except TokenError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc

    user = await _user_by_id(session, claims.sub)
    if user.mfa_enabled:
        # Re-enrolment must go through the authenticated reset flow, or anyone
        # holding the password could replace the second factor.
        raise HTTPException(status.HTTP_409_CONFLICT, "MFA already enabled")

    user.totp_secret = generate_totp_secret()
    await session.commit()
    return {
        "secret": user.totp_secret,
        "otpauth_uri": totp_uri(user.totp_secret, user.email),
        "next": "Confirm with /auth/mfa/verify to activate.",
    }


@router.post("/mfa/verify")
async def mfa_verify(req: MfaVerifyRequest, session: Session) -> dict:
    """Completes login, or activates MFA on first enrolment."""
    try:
        claims = decode_token(req.mfa_token, expect="mfa_pending")
    except TokenError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc

    user = await _user_by_id(session, claims.sub)

    locked, retry_after = await active_lockout().ais_locked(f"mfa:{user.email}")
    if locked:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "too many failed attempts",
            headers={"Retry-After": str(retry_after)},
        )

    if not user.totp_secret:
        raise HTTPException(status.HTTP_409_CONFLICT, "MFA not set up")

    if not verify_totp(user.totp_secret, req.code):
        await active_lockout().arecord_failure(f"mfa:{user.email}")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid code")

    # A TOTP code stays valid for its whole window, so without this an observed
    # code (phishing proxy, shoulder-surf, malware) can be replayed.
    if not await active_replay().acheck_and_record(f"{user.id}:{req.code}"):
        await active_lockout().arecord_failure(f"mfa:{user.email}")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "code already used")

    first_time = not user.mfa_enabled
    user.mfa_enabled = True
    await active_lockout().arecord_success(f"mfa:{user.email}")
    return await _complete_login(session, user, first_time=first_time)


@router.post("/mfa/skip")
async def mfa_skip(req: TokenRequest, session: Session) -> dict:
    """Defer MFA enrolment and start a session now.

    The PRD's stance is that MFA is mandatory, but forcing enrolment inside the
    very first sign-in is a hard onboarding wall: someone evaluating the product
    cannot even see their dashboard without first installing an authenticator app.
    So enrolment is *deferrable* — a session is issued now, the account is flagged
    as MFA-less, and the dashboard nags until it is turned on (auth/mfa/enroll).

    An account that has *already* enabled MFA can never bypass it here — that would
    make the second factor worthless for anyone who set it up.
    """
    try:
        claims = decode_token(req.token, expect="mfa_pending")
    except TokenError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc

    user = await _user_by_id(session, claims.sub)
    if user.mfa_enabled:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "MFA is enabled on this account — verify with your authenticator",
        )

    # No recovery codes: those are issued when MFA is actually turned on, not here.
    tokens = await _complete_login(session, user)
    tokens["mfa_enabled"] = False
    tokens["mfa_deferred"] = True
    return tokens


@router.post("/mfa/enroll")
async def mfa_enroll(principal: CurrentUser, session: Session) -> dict:
    """Authenticated TOTP enrolment for a user who deferred MFA at sign-in.

    Unlike `/mfa/setup` (which trades an `mfa_pending` token) this runs inside an
    established session, so the deferred user can turn MFA on from the dashboard
    without signing out. Returns a fresh secret; confirm it with `/mfa/activate`.
    """
    user = await _user_by_id(session, principal.user_id)
    if user.mfa_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "MFA already enabled")

    user.totp_secret = generate_totp_secret()
    await session.commit()
    return {
        "secret": user.totp_secret,
        "otpauth_uri": totp_uri(user.totp_secret, user.email),
        "next": "Confirm with /auth/mfa/activate to turn MFA on.",
    }


# ── Password reset (forgot password) ─────────────────────────────────────────
#: A reset token is short-lived; long enough to check email, short enough to
#: limit exposure of a leaked link.
PASSWORD_RESET_TTL = timedelta(minutes=30)


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(min_length=12, max_length=256)
    #: Required only when the account has MFA — the authenticator code proves
    #: identity in place of an emailed link.
    code: str | None = Field(default=None, pattern=r"^\d{6}$")


#: A reset link is a live credential in an inbox. One per account per this many
#: seconds stops a distributed attacker filling a victim's inbox (and burning our
#: sending reputation) even when each request comes from a different address.
RESET_COOLDOWN_SECONDS = 60


async def _send_password_reset_email(to: str, link: str):  # noqa: ANN202 — MailResult
    """Email the reset link, and report whether it actually went.

    This used to be hand-rolled blocking `smtplib` inside an async endpoint that
    `return`ed silently when the host looked unconfigured — so on a deployment
    without a relay the caller was told a link had been sent, forever, and no
    mail ever left. It now goes through the same signed, async transport as an
    alert and hands back a truthful result.
    """
    from envelock.notify.mail import send_mail

    result = await send_mail(
        to=to,
        subject="Reset your Envelock password",
        body=(
            "We received a request to reset your Envelock password.\n\n"
            f"Reset it here (valid for 30 minutes):\n{link}\n\n"
            "The link works once. If you didn't ask for this you can ignore this "
            "email — your password has not changed."
        ),
    )
    # The link carries a live 30-minute account-takeover token, so it may only be
    # logged in development. In production/staging the log records that a reset
    # was issued — never the token: anyone with log-read access could otherwise
    # take over any account that requests a reset. An operator recovering a
    # locked-out customer on a relay-less deployment uses the DB-backed flow, not
    # the logs.
    from envelock.config import get_settings

    if get_settings().env == "development":
        logger.info("password reset link for %s (%s): %s", to, result.reason, link)
    else:
        logger.info("password reset issued for %s (%s)", to, result.reason)
    return result


VERIFY_EMAIL_TTL = timedelta(hours=24)


async def _send_verification_email(user: User) -> str | None:
    """Send the proof-of-email-ownership link; returns the link in development
    only (same rule as password reset: the token must never reach prod logs)."""
    from envelock.config import get_settings
    from envelock.notify.mail import send_mail

    settings = get_settings()
    token = issue_token(
        user_id=user.id,
        tenant_id=user.tenant_id,
        role=_role_of(user),
        typ="email_verify",
        ttl=VERIFY_EMAIL_TTL,
    )
    link = f"{settings.web_base_url.rstrip('/')}/verify-email?token={token}"
    result = await send_mail(
        to=user.email,
        subject="Confirm your email for Envelock",
        body=(
            "Confirm this address to activate your Envelock workspace.\n\n"
            f"Verify here (valid for 24 hours):\n{link}\n\n"
            "If you didn't create an Envelock account, you can ignore this email."
        ),
    )
    if settings.env == "development":
        logger.info(
            "email verification link for %s (%s): %s", user.email, result.reason, link
        )
        return link
    logger.info("email verification sent for %s (%s)", user.email, result.reason)
    return None


class VerifyEmailRequest(BaseModel):
    token: str = Field(max_length=4096)


@router.post("/verify-email")
async def verify_email(req: VerifyEmailRequest, session: Session) -> dict:
    """Prove ownership of the registered address (anti tenant-squatting)."""
    try:
        claims = decode_token(req.token, expect="email_verify")
    except TokenError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc
    user = await session.get(User, claims.sub)
    if user is None:
        raise _generic_401()
    if user.email_verified_at is None:
        user.email_verified_at = datetime.now(UTC)
        tenant = await session.get(Tenant, user.tenant_id)
        if tenant is not None and user.role == Role.OWNER.value:
            # Ownership proven — NOW the tenant claims its domain row
            # (registration deferred it so an unverified squatter never holds
            # the unique claim).
            reg = registrable_domain(user.email.rsplit("@", 1)[-1])
            has_domain = (
                await session.execute(
                    select(Domain.id).where(Domain.tenant_id == tenant.id).limit(1)
                )
            ).first()
            if reg and not is_free_mail(reg) and has_domain is None:
                from envelock.channels.mail.ingest import new_ingest_token

                try:
                    async with session.begin_nested():
                        session.add(
                            Domain(
                                id=uuid4(),
                                tenant_id=tenant.id,
                                name=reg,
                                registrable_domain=reg,
                                verification_token=new_ingest_token(),
                            )
                        )
                        await session.flush()
                except IntegrityError:
                    # Another tenant verified this domain first; future
                    # colleague signups route there.
                    pass
            # The domain's one permanent trial starts NOW — at proof of
            # ownership, not at the keystroke that claimed the domain. A
            # squatter who never verifies burns nothing.
            if tenant.trial_started_at is None:
                await _start_signup_trial(session, tenant, user.email)
        await session.commit()
    return {"verified": True}


class ResendVerifyRequest(BaseModel):
    email: EmailStr


@router.post("/verify-email/resend")
async def resend_verify_email(req: ResendVerifyRequest, session: Session) -> dict:
    """Always answers the same shape — no account enumeration."""
    user = await _user_by_email(session, req.email.lower().strip())
    resp: dict = {"status": "sent"}
    if user is not None and user.email_verified_at is None:
        link = await _send_verification_email(user)
        from envelock.config import get_settings

        if get_settings().env == "development" and link:
            resp["verify_link"] = link
    return resp


@router.post("/password/forgot")
async def forgot_password(req: ForgotPasswordRequest, session: Session) -> dict:
    """Begin a password reset.

    Two things have to be true at once, and the previous versions each traded one
    away:

    * **No account enumeration.** The answer must not differ between a real
      address and one that has never been seen — not in shape, not in wording,
      not in whether a token comes back. So an unknown address takes the same
      path and produces the same body.
    * **The truth about delivery.** Whether this deployment has an SMTP relay is
      a property of the deployment, not of the account, so saying so leaks
      nothing — and *not* saying so is what made this feature appear to work
      while sending nothing at all. `email_delivery` reports it.

    A mail-less deployment is not a dead end: any account with an authenticator
    can reset through `/password/reset-with-code`, which needs no email and hands
    out no token, so it is safe to advertise unconditionally.
    """
    from envelock.config import get_settings
    from envelock.notify.mail import is_configured as mail_configured

    email = req.email.lower().strip()
    settings = get_settings()
    can_email = mail_configured()

    # Identical for every caller, real account or not.
    generic: dict = {
        "message": (
            "If that account exists, a reset link has been sent to its email."
            if can_email
            else "This deployment cannot send email yet, so a reset link could "
            "not be sent. If your account has an authenticator, you can reset "
            "your password with a code instead. Otherwise contact your "
            "workspace admin."
        ),
        # A deployment property, not an account property — no oracle.
        "email_delivery": "available" if can_email else "unavailable",
        "code_reset_available": True,
    }

    user = await _user_by_email(session, email)
    if user is None:
        return generic

    # One live link per account per cooldown. Without this the endpoint is an
    # email bomb pointed at any address the attacker knows: the rate-limit bucket
    # is per-caller, so a distributed request set walks straight through it.
    scope = f"pwforgot:{email}"
    if not await active_replay().acheck_and_record(
        scope, ttl=RESET_COOLDOWN_SECONDS
    ):
        return generic

    if not can_email:
        return generic

    token = issue_token(
        user_id=user.id,
        tenant_id=user.tenant_id,
        role=_role_of(user),
        typ="password_reset",
        ttl=PASSWORD_RESET_TTL,
    )
    link = f"{settings.web_base_url.rstrip('/')}/reset-password?token={token}"
    await _send_password_reset_email(user.email, link)

    resp = dict(generic)
    if settings.env == "development":
        resp["reset_link"] = link  # dev convenience, mirrors the OTP dev_code rule
    return resp


class ResetWithCodeRequest(BaseModel):
    email: EmailStr
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")
    new_password: str = Field(min_length=12, max_length=256)


@router.post("/password/reset-with-code")
async def reset_password_with_code(
    req: ResetWithCodeRequest, session: Session
) -> dict:
    """Reset using the authenticator alone — no email, no token.

    This is the path that keeps account recovery working on a deployment whose
    relay is not provisioned yet, and it is why `/password/forgot` can advertise
    a code reset to everyone without leaking anything: nothing is handed out
    here. An attacker who does not hold the authenticator gets the same 401 as
    one who guessed an address that does not exist.

    Deliberately *not* reachable for an account without MFA: possession of an
    email address would then be the only proof, and there is no email in this
    path to prove possession of.
    """
    email = req.email.lower().strip()
    scope = f"pwcode:{email}"

    locked, retry_after = await active_lockout().ais_locked(scope)
    if locked:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "too many attempts — wait and try again",
            headers={"Retry-After": str(retry_after)},
        )

    # One message for every failure: unknown address, no authenticator on the
    # account, and wrong code must be indistinguishable.
    refused = HTTPException(
        status.HTTP_401_UNAUTHORIZED,
        "that email and authenticator code do not match an account with "
        "two-factor enabled.",
    )

    user = await _user_by_email(session, email)
    # Validate the new password before deciding anything, so a weak-password
    # rejection cannot be used to prove the account exists.
    try:
        assess_passphrase(req.new_password)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc

    if user is None or not user.mfa_enabled or not user.totp_secret:
        await active_lockout().arecord_failure(scope)
        raise refused
    if not verify_totp(user.totp_secret, req.code):
        await active_lockout().arecord_failure(scope)
        raise refused
    # A TOTP code is valid for its whole window; a reset must not be replayable
    # with an observed one.
    if not await active_replay().acheck_and_record(f"{user.id}:{req.code}"):
        await active_lockout().arecord_failure(scope)
        raise refused

    await active_lockout().arecord_success(scope)
    user.password_hash = hash_password(req.new_password)
    user.must_change_password = False
    await active_revocations().arevoke_user(
        str(user.id), until=time.time() + REFRESH_TTL.total_seconds()
    )
    await session.commit()
    return {
        "ok": True,
        "sessions_revoked": True,
        "message": "Password updated — sign in with your new password.",
    }


@router.post("/password/reset")
async def reset_password(req: ResetPasswordRequest, session: Session) -> dict:
    """Complete a password reset.

    The token proves the request came from `password/forgot`. For an MFA account,
    a valid authenticator code is also required (the token alone is not enough).
    For a non-MFA account, possession of the emailed token is the proof.
    """
    try:
        claims = decode_token(req.token, expect="password_reset")
    except TokenError as exc:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "this reset link is invalid or has expired"
        ) from exc

    user = await _user_by_id(session, claims.sub)

    try:
        assess_passphrase(req.new_password)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc

    if user.mfa_enabled:
        locked, retry_after = await active_lockout().ais_locked(f"pwreset:{user.email}")
        if locked:
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS,
                "too many attempts",
                headers={"Retry-After": str(retry_after)},
            )
        if not req.code or not verify_totp(user.totp_secret or "", req.code):
            await active_lockout().arecord_failure(f"pwreset:{user.email}")
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED, "invalid authenticator code"
            )
        await active_lockout().arecord_success(f"pwreset:{user.email}")

    # A reset link must work exactly once. Without this it stays live for its
    # whole 30-minute window, so a link recovered from a mailbox, a proxy log or
    # a shared screenshot can be replayed to take the account back after the
    # owner has already used it.
    if await active_revocations().ais_revoked(
        claims.jti, str(claims.sub), issued_at=claims.iat
    ):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "this reset link has already been used — request a new one",
        )
    await active_revocations().arevoke_jti(claims.jti, expires_at=float(claims.exp))

    user.password_hash = hash_password(req.new_password)
    user.must_change_password = False
    # Reset is the "I think I have been compromised" action, so it has to end
    # every other session — otherwise the attacker's refresh token outlives it.
    await active_revocations().arevoke_user(
        str(user.id), until=time.time() + REFRESH_TTL.total_seconds()
    )
    await session.commit()
    return {
        "ok": True,
        "sessions_revoked": True,
        "message": "Password updated — sign in with your new password.",
    }


class MfaActivateRequest(BaseModel):
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


@router.post("/mfa/activate")
async def mfa_activate(
    req: MfaActivateRequest, principal: CurrentUser, session: Session
) -> dict:
    """Confirm the code and enable MFA for an already-authenticated session.

    Issues single-use recovery codes the first time MFA is turned on, exactly as
    the sign-in enrolment path does.
    """
    user = await _user_by_id(session, principal.user_id)
    if user.mfa_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "MFA already enabled")

    locked, retry_after = await active_lockout().ais_locked(f"mfa:{user.email}")
    if locked:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "too many failed attempts",
            headers={"Retry-After": str(retry_after)},
        )

    if not user.totp_secret:
        raise HTTPException(status.HTTP_409_CONFLICT, "start enrolment first")

    if not verify_totp(user.totp_secret, req.code):
        await active_lockout().arecord_failure(f"mfa:{user.email}")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid code")

    # Same replay defence as sign-in: a TOTP code is valid for its whole window.
    if not await active_replay().acheck_and_record(f"{user.id}:{req.code}"):
        await active_lockout().arecord_failure(f"mfa:{user.email}")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "code already used")

    user.mfa_enabled = True
    codes = generate_recovery_codes()
    user.recovery_hashes = [hash_recovery_code(c) for c in codes]
    await active_lockout().arecord_success(f"mfa:{user.email}")
    await session.commit()
    return {"mfa_enabled": True, "recovery_codes": codes}


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(max_length=256)
    new_password: str = Field(min_length=12, max_length=256)
    mfa_code: str | None = Field(default=None, pattern=r"^\d{6}$")


@router.post("/password")
async def change_password(
    req: PasswordChangeRequest, principal: CurrentUser, session: Session
) -> dict:
    """Change the account password behind a step-up re-auth (password + TOTP).

    On success every other session is revoked, so a change made in response to a
    suspected compromise actually kicks the attacker out rather than leaving their
    refresh token alive.
    """
    user = await _user_by_id(session, principal.user_id)
    # The password is the one sensitive change that must work even without MFA —
    # otherwise a user who deferred two-factor can never change it.
    await _verify_step_up(
        user,
        password=req.current_password,
        mfa_code=req.mfa_code,
        require_mfa_enrolment=False,
    )

    try:
        assess_passphrase(req.new_password)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    if verify_password(req.new_password, user.password_hash or ""):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "the new password must be different from the current one",
        )

    user.password_hash = hash_password(req.new_password)
    await active_revocations().arevoke_user(
        str(user.id), until=time.time() + REFRESH_TTL.total_seconds()
    )
    await session.commit()
    return {"status": "password_changed", "sessions_revoked": True}


class InitialPasswordRequest(BaseModel):
    new_password: str = Field(min_length=12, max_length=256)


@router.post("/password/initial")
async def set_initial_password(
    req: InitialPasswordRequest, principal: CurrentUser, session: Session
) -> dict:
    """First-login password change for an owner-provisioned account.

    A user the owner created signs in with a temporary password and must replace
    it before doing anything else. This needs neither the temporary password again
    nor MFA (they have none yet) — it only works while the one-time
    `must_change_password` flag is set, and clears it on success.
    """
    user = await _user_by_id(session, principal.user_id)
    if not user.must_change_password:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "no initial password change is pending"
        )
    try:
        assess_passphrase(req.new_password)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc

    user.password_hash = hash_password(req.new_password)
    user.must_change_password = False
    await session.commit()
    return {"status": "password_set"}


class MfaDisableRequest(BaseModel):
    password: str = Field(max_length=256)
    mfa_code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


@router.post("/mfa/disable")
async def mfa_disable(
    req: MfaDisableRequest, principal: CurrentUser, session: Session
) -> dict:
    """Turn MFA off — only behind the current password AND a valid TOTP code, so
    the second factor cannot be stripped by someone who merely holds a session."""
    user = await _user_by_id(session, principal.user_id)
    if not user.mfa_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "MFA is not enabled")
    await _verify_step_up(user, password=req.password, mfa_code=req.mfa_code)

    user.mfa_enabled = False
    user.totp_secret = None
    user.recovery_hashes = []
    await session.commit()
    return {"mfa_enabled": False}


@router.post("/recovery")
async def recovery(req: RecoveryRequest, session: Session) -> dict:
    """Redeem a single-use recovery code when the authenticator is lost.

    Without this, generating recovery codes at enrolment was theatre — a user
    who lost their device had no way back in.
    """
    try:
        claims = decode_token(req.mfa_token, expect="mfa_pending")
    except TokenError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc

    user = await _user_by_id(session, claims.sub)

    locked, retry_after = await active_lockout().ais_locked(f"rec:{user.email}")
    if locked:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "too many failed attempts",
            headers={"Retry-After": str(retry_after)},
        )

    candidate = hash_recovery_code(req.recovery_code)
    # Constant-time membership test over the stored hashes.
    matched = None
    for stored in user.recovery_hashes or []:
        if secrets.compare_digest(stored, candidate):
            matched = stored
    if matched is None:
        await active_lockout().arecord_failure(f"rec:{user.email}")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid recovery code")

    # Reassign (not mutate in place) so SQLAlchemy tracks the change.
    user.recovery_hashes = [h for h in user.recovery_hashes if h != matched]
    await active_lockout().arecord_success(f"rec:{user.email}")

    tokens = await _complete_login(session, user)
    tokens["recovery_codes_remaining"] = len(user.recovery_hashes)
    tokens["warning"] = (
        "Recovery code consumed. Re-enrol your authenticator and regenerate codes."
    )
    return tokens


@router.post("/refresh")
async def refresh(req: TokenRequest, session: Session) -> dict:
    """Rotating refresh with reuse detection.

    The presented token is revoked on use. If it is presented again it was
    stolen or replayed, so every session for that user is revoked rather than
    just the one token.
    """
    try:
        claims = decode_token(req.token, expect="refresh")
    except TokenError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc

    if await active_revocations().ais_revoked(
        claims.jti, str(claims.sub), issued_at=claims.iat
    ):
        await active_revocations().arevoke_user(
            str(claims.sub), until=time.time() + REFRESH_TTL.total_seconds()
        )
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "For your security, you've been signed out of all devices. "
            "Please sign in again.",
        )

    # Atomic first-use claim (SET NX / one lock hold). The read above and a
    # separate write raced: two simultaneous presentations of one stolen token
    # both saw "not revoked" and both minted pairs — the reuse detector never
    # fired for the exact attack it exists to catch.
    if not await active_revocations().aconsume_jti(
        claims.jti, expires_at=float(claims.exp)
    ):
        await active_revocations().arevoke_user(
            str(claims.sub), until=time.time() + REFRESH_TTL.total_seconds()
        )
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "For your security, you've been signed out of all devices. "
            "Please sign in again.",
        )
    user = await _user_by_id(session, claims.sub)
    # A suspended or rejected account must not be able to mint fresh access
    # tokens for the next fourteen days. Status is checked here, not only on the
    # data routes, so suspension actually ends the session.
    if user.status in {"suspended", "rejected", "disabled"}:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "this account has been suspended — contact your workspace admin",
        )
    return issue_pair(
        user_id=user.id, tenant_id=user.tenant_id, role=_role_of(user)
    )


@router.post("/logout")
async def logout(principal: CurrentUser) -> dict:
    """Revokes every refresh token for the caller."""
    await active_revocations().arevoke_user(
        str(principal.user_id), until=time.time() + REFRESH_TTL.total_seconds()
    )
    return {"status": "logged_out"}


@router.get("/me")
async def me(principal: CurrentUser, session: Session) -> dict:
    user = await _user_by_id(session, principal.user_id)
    return {
        "user_id": str(user.id),
        "tenant_id": str(user.tenant_id),
        "email": user.email,
        "role": user.role,
        "status": user.status,
        "must_change_password": user.must_change_password,
        "mfa_enabled": user.mfa_enabled,
        "phone": user.phone,
        "phone_verified": user.phone_verified,
        "out_of_band_email": user.out_of_band_email,
        "is_admin": principal.is_admin,
        "recovery_codes_remaining": len(user.recovery_hashes or []),
    }


class AlertEmailRequest(BaseModel):
    #: None clears it — alerts then fall back to the login email (the delivery
    #: layer still refuses to send into the alert's own mailbox).
    email: EmailStr | None = None
    current_password: str = Field(max_length=256)
    mfa_code: str | None = Field(default=None, pattern=r"^\d{6}$")


@router.post("/alert-email")
async def set_alert_email(
    req: AlertEmailRequest, principal: CurrentUser, session: Session
) -> dict:
    """Register the out-of-band address HIGH/CRITICAL alerts are emailed to
    (PRD §8.2 — somewhere the attacker does not control). Step-up protected: a
    stolen session must not be able to redirect the alert channel."""
    user = await _user_by_id(session, principal.user_id)
    await _verify_step_up(
        user, password=req.current_password, mfa_code=req.mfa_code
    )
    user.out_of_band_email = req.email.lower() if req.email else None
    await session.commit()
    return {"out_of_band_email": user.out_of_band_email}


@router.get("/sensitive-actions")
async def sensitive_actions(principal: CurrentUser) -> dict:
    """Actions that force a fresh password re-entry regardless of session age."""
    return {"actions": sorted(SENSITIVE_ACTIONS), "role": principal.role.value}


# ── Phone verification (out-of-band + SMS-escalation channel) ─────────────────
class PhoneStartRequest(BaseModel):
    phone: str = Field(min_length=8, max_length=32, pattern=r"^\+?[0-9 ()-]{7,31}$")
    #: Required only when *changing* an already-verified recovery phone — a stolen
    #: session must not be able to swap the out-of-band channel to the attacker's.
    current_password: str | None = Field(default=None, max_length=256)
    mfa_code: str | None = Field(default=None, pattern=r"^\d{6}$")


class PhoneVerifyRequest(BaseModel):
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


_PHONE_OTP_TTL = timedelta(minutes=10)


@router.post("/phone/start")
async def phone_start(
    req: PhoneStartRequest, principal: CurrentUser, session: Session
) -> dict:
    """Begin proving possession of a phone number. A one-time code is sent by SMS;
    the phone is only trusted for out-of-band alerts and SMS escalation once
    verified (PRD §8.1/§8.2)."""
    from envelock.config import get_settings
    from envelock.core.enums import AlertTier
    from envelock.notify.senders import Notification, SmsSender

    locked, retry_after = await active_lockout().ais_locked(f"phone:{principal.user_id}")
    if locked:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "too many attempts",
            headers={"Retry-After": str(retry_after)},
        )

    user = await _user_by_id(session, principal.user_id)
    # Adding a first phone is low-friction; *changing* a verified one is a
    # sensitive action — the recovery channel is what an attacker would redirect.
    if user.phone_verified:
        await _verify_step_up(
            user, password=req.current_password or "", mfa_code=req.mfa_code
        )

    code = generate_numeric_otp()
    user.phone = req.phone.strip()
    user.phone_verified = False
    user.phone_otp_hash = hash_otp(code)
    user.phone_otp_expires_at = datetime.now(UTC) + _PHONE_OTP_TTL
    await session.commit()

    sender = SmsSender()
    delivered = await sender.send(
        Notification(
            alert_id=uuid4(),
            tenant_id=principal.tenant_id,
            tier=AlertTier.LOW,
            title=f"Your Envelock verification code is {code}",
            body="",
        ),
        to=user.phone,
    )

    out: dict = {"status": "code_sent", "delivered": delivered.delivered}
    # Local dev only: surface the code so tests and localhost work without an SMS
    # provider. Never in staging or production — a shared staging box must not
    # hand an OTP to anyone who can call the endpoint.
    if get_settings().env == "development":
        out["dev_code"] = code
    return out


@router.post("/phone/verify")
async def phone_verify(
    req: PhoneVerifyRequest, principal: CurrentUser, session: Session
) -> dict:
    """Confirm the code and mark the phone verified."""
    locked, retry_after = await active_lockout().ais_locked(f"phone:{principal.user_id}")
    if locked:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "too many attempts",
            headers={"Retry-After": str(retry_after)},
        )

    user = await _user_by_id(session, principal.user_id)
    expires = user.phone_otp_expires_at
    if expires is not None and expires.tzinfo is None:
        expires = expires.replace(tzinfo=UTC)
    if not user.phone_otp_hash or expires is None or expires < datetime.now(UTC):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "no active code — start again")

    if not secrets.compare_digest(user.phone_otp_hash, hash_otp(req.code)):
        await active_lockout().arecord_failure(f"phone:{principal.user_id}")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid code")

    user.phone_verified = True
    user.phone_otp_hash = None
    user.phone_otp_expires_at = None
    await active_lockout().arecord_success(f"phone:{principal.user_id}")
    await session.commit()
    return {"phone_verified": True, "phone": user.phone}


@router.get("/admin/users")
async def list_users(principal: AdminUser, session: Session) -> dict:
    """Admin-only, and scoped to the caller's own tenant."""
    rows = (
        await session.execute(
            select(User).where(User.tenant_id == principal.tenant_id)
        )
    ).scalars()
    return {
        "users": [
            {"email": u.email, "role": u.role, "mfa_enabled": u.mfa_enabled}
            for u in rows
        ]
    }
