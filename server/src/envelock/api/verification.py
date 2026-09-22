"""Supplier verification of a payment-detail change (platform/verification.py).

Two surfaces: the team's panel on an alert (signed in), and the one-question
page a supplier opens from the text we send (no account — the unguessable
link is the credential, it is single-use and it expires).
"""

from __future__ import annotations

from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from envelock.auth.deps import ActiveUser, SystemScoped
from envelock.config import get_settings
from envelock.db import get_session
from envelock.models import Alert
from envelock.platform import verification as svc

router = APIRouter(prefix="/api/v1/alerts", tags=["verification"])
public = APIRouter(prefix="/api/v1/verify", tags=["verification"], dependencies=[SystemScoped])
Session = Annotated[AsyncSession, Depends(get_session)]


async def _alert(session: AsyncSession, actor, alert_id: UUID) -> Alert:  # noqa: ANN001
    from envelock.api.tenants import _assert_alert_access

    alert = await session.get(Alert, alert_id)
    if alert is None or alert.tenant_id != actor.tenant_id:
        raise HTTPException(404, "alert not found")
    await _assert_alert_access(session, actor, alert)
    return alert


def _raise(exc: svc.VerificationError) -> None:
    raise HTTPException(exc.status, exc.message) from exc


@router.get("/{alert_id}/verification")
async def get_verification(alert_id: UUID, actor: ActiveUser, session: Session) -> dict:
    alert = await _alert(session, actor, alert_id)
    ctx = await svc.context(session, alert)
    return {
        **ctx,
        "sms_available": svc.sms_available(),
        "attempts": [svc.payload(v) for v in await svc.attempts(session, alert)],
        "alert_state": alert.state,
    }


class CallResult(BaseModel):
    outcome: Literal["confirmed", "denied", "no_answer"]
    note: str | None = Field(default=None, max_length=2000)


@router.post("/{alert_id}/verification/call")
async def record_call(
    alert_id: UUID, body: CallResult, actor: ActiveUser, session: Session
) -> dict:
    alert = await _alert(session, actor, alert_id)
    try:
        v = await svc.record_call(
            session, alert, actor_id=actor.user_id, outcome=body.outcome, note=body.note
        )
    except svc.VerificationError as exc:
        _raise(exc)
    await session.commit()
    return {"attempt": svc.payload(v), "alert_state": alert.state}


@router.post("/{alert_id}/verification/sms")
async def send_sms(alert_id: UUID, actor: ActiveUser, session: Session) -> dict:
    alert = await _alert(session, actor, alert_id)
    try:
        v = await svc.send_sms(
            session, alert, actor_id=actor.user_id, link_base=get_settings().web_base_url
        )
    except svc.VerificationError as exc:
        await session.rollback()
        _raise(exc)
    await session.commit()
    return {"attempt": svc.payload(v)}


@router.get("/{alert_id}/evidence.pdf", response_model=None)
async def evidence_pack(alert_id: UUID, actor: ActiveUser, session: Session) -> Response:
    """The alert's evidence record as a PDF — for an insurer, a bank or the police."""
    import asyncio

    from envelock.governance import evidence_pack as pack
    from envelock.platform.alerts import record_audit

    alert = await _alert(session, actor, alert_id)
    data = await pack.collect(session, alert)
    pdf = await asyncio.to_thread(pack.render, data)
    await record_audit(
        session,
        tenant_id=alert.tenant_id,
        actor_id=actor.user_id,
        action="alert.evidence_exported",
        target_type="alert",
        target_id=alert.id,
        detail={"fingerprint": pack.fingerprint(data)},
    )
    await session.commit()
    return Response(
        pdf,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{data["reference"]}-evidence.pdf"',
            "Cache-Control": "no-store",
        },
    )


class Answer(BaseModel):
    answer: Literal["yes", "no"]


@public.get("/{token}")
async def view(token: str, session: Session) -> dict:
    try:
        return await svc.public_view(session, token)
    except svc.VerificationError as exc:
        _raise(exc)
        raise  # unreachable; for the type checker


@public.post("/{token}")
async def respond(token: str, body: Answer, session: Session) -> dict:
    try:
        return await svc.answer(session, token, yes=body.answer == "yes")
    except svc.VerificationError as exc:
        _raise(exc)
        raise
