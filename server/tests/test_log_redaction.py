"""What reaches the journal must not carry customer content or bearer tokens.

Two leaks, both from libraries doing what they do by default:

* SQLAlchemy writes a failed statement's bound values into the exception
  message, and `logger.exception` writes the message to the journal — so a
  malformed email that tripped a column limit logged its own fields.
* uvicorn's access line is the full request target, query string included, and
  Gmail Pub/Sub can only authenticate to us with a `?token=` in the push URL.
"""

from __future__ import annotations

import logging
import os
from types import SimpleNamespace

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError


def _settings(*, production: bool) -> SimpleNamespace:
    return SimpleNamespace(
        is_production=production, db_pool_size=1, db_max_overflow=0, db_nullpool=True
    )


async def _error_text(*, production: bool) -> str:
    from sqlalchemy.ext.asyncio import create_async_engine

    from envelock.db import _engine_kwargs, _normalise_dsn

    engine = create_async_engine(
        _normalise_dsn(os.environ["ENVELOCK_POSTGRES_DSN"]),
        **_engine_kwargs(_settings(production=production)),
    )
    try:
        async with engine.connect() as conn:
            with pytest.raises(DBAPIError) as caught:
                # Fails for a reason the server's own message does not echo, so
                # the only copy of the value is the one SQLAlchemy appends.
                await conn.execute(
                    text("SELECT CAST(:v AS text), 1 / 0"),
                    {"v": "Invoice from finance@victim.example — new IBAN"},
                )
        return str(caught.value)
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_production_database_errors_do_not_carry_the_values() -> None:
    message = await _error_text(production=True)
    assert "victim.example" not in message
    assert "1 / 0" in message  # the statement itself is still there to debug


@pytest.mark.asyncio
async def test_development_keeps_the_values_for_debugging() -> None:
    """Also proves the production test above can see a leak when there is one."""
    assert "victim.example" in await _error_text(production=False)


def _access_record(target: str) -> logging.LogRecord:
    """An access line exactly as uvicorn's protocol classes emit it."""
    return logging.LogRecord(
        "uvicorn.access", logging.INFO, __file__, 1,
        '%s - "%s %s HTTP/%s" %d',
        ("203.0.113.9:51234", "POST", target, "1.1", 202),
        None,
    )


def test_access_lines_keep_query_names_and_drop_values() -> None:
    from envelock.obs.logs import RedactQueryValues

    record = _access_record("/api/v1/webhooks/gmail?token=9f8e7d6c5b4a&attempt=2")
    RedactQueryValues().filter(record)
    line = record.getMessage()
    assert "9f8e7d6c5b4a" not in line
    assert "/api/v1/webhooks/gmail?token=…&attempt=…" in line


def test_access_lines_without_a_query_are_untouched() -> None:
    from envelock.obs.logs import RedactQueryValues

    record = _access_record("/api/v1/status/public")
    RedactQueryValues().filter(record)
    assert '"POST /api/v1/status/public HTTP/1.1" 202' in record.getMessage()


def test_configure_logging_installs_the_redaction_once() -> None:
    from envelock.obs.logs import RedactQueryValues, configure_logging

    configure_logging(level="INFO", json_output=True)
    configure_logging(level="INFO", json_output=True)
    filters = logging.getLogger("uvicorn.access").filters
    assert sum(isinstance(f, RedactQueryValues) for f in filters) == 1
