"""Request-scoped correlation ids.

`contextvars`, not thread-locals: everything here is async, and a contextvar
follows the logical task across every `await` while staying invisible to the
task next to it. One inbound request therefore stamps the same id on the log line
from the router, the one from the detection pipeline, and the one from the
notification dispatcher — which is the entire point. Without it a production log
is a flat stream of lines with no way to reassemble which request produced which.
"""

from __future__ import annotations

import secrets
from contextvars import ContextVar, Token
from uuid import UUID

_request_id: ContextVar[str | None] = ContextVar("envelock_request_id", default=None)
_tenant_id: ContextVar[str | None] = ContextVar("envelock_tenant_id", default=None)


def new_request_id() -> str:
    """A short, URL-safe id. Short because it is read by a person pasting it from
    a customer's screenshot into a log query, not by a machine."""
    return secrets.token_hex(8)


def bind_request(request_id: str | None = None) -> Token[str | None]:
    """Bind an id for this request. Returns the reset token for the caller."""
    return _request_id.set(request_id or new_request_id())


def bind_tenant(tenant_id: UUID | str | None) -> Token[str | None]:
    """Attach the tenant to every subsequent log line on this task.

    Tenant id, never tenant name or user email: an operational log is read by
    people who do not need the customer's identity to debug a request, and a
    correlation id that is also personal data is one that cannot be shipped to a
    log aggregator without a DPA conversation.
    """
    return _tenant_id.set(str(tenant_id) if tenant_id else None)


def current_request_id() -> str | None:
    return _request_id.get()


def current_tenant_id() -> str | None:
    return _tenant_id.get()


def reset_request(token: Token[str | None]) -> None:
    _request_id.reset(token)


def reset_tenant(token: Token[str | None]) -> None:
    _tenant_id.reset(token)


__all__ = [
    "bind_request",
    "bind_tenant",
    "current_request_id",
    "current_tenant_id",
    "new_request_id",
    "reset_request",
    "reset_tenant",
]
