"""Structured logging.

`structlog` was a declared dependency that nothing imported; logging was
`basicConfig` writing unparseable prose to the journal. This wires it up so that:

* production emits one JSON object per line — greppable, shippable to any log
  service, and queryable by request id or tenant;
* development keeps colour and alignment, because a human reads it directly;
* every line, from anywhere in the codebase, carries the request id and tenant id
  automatically — including lines from modules that still use plain
  `logging.getLogger(...)`, which is most of them and will stay that way.

That last point is why this routes stdlib logging through structlog's processor
chain rather than asking 118 modules to change how they log.
"""

from __future__ import annotations

import logging
import sys
from typing import Any

import structlog

from envelock.obs.context import current_request_id, current_tenant_id


def _add_correlation(
    _logger: Any, _method: str, event_dict: dict[str, Any]
) -> dict[str, Any]:
    """Stamp the request/tenant ids onto every event that has them.

    Absent keys rather than nulls: a scheduler job genuinely has no request id,
    and `"request_id": null` on every background line is noise in a log index.
    """
    if request_id := current_request_id():
        event_dict["request_id"] = request_id
    if tenant_id := current_tenant_id():
        event_dict["tenant_id"] = tenant_id
    return event_dict


def _drop_color_message(
    _logger: Any, _method: str, event_dict: dict[str, Any]
) -> dict[str, Any]:
    """uvicorn duplicates its message under `color_message` for its own
    formatter. In JSON output that is the same text twice on every access line."""
    event_dict.pop("color_message", None)
    return event_dict


#: Shared by both the structlog path and the stdlib bridge, so a line written
#: with `logging.getLogger(__name__).info(...)` comes out in the same shape as
#: one written with `structlog.get_logger()`.
_SHARED_PROCESSORS: list[Any] = [
    structlog.contextvars.merge_contextvars,
    structlog.stdlib.add_log_level,
    structlog.stdlib.add_logger_name,
    _add_correlation,
    _drop_color_message,
    structlog.processors.TimeStamper(fmt="iso", utc=True),
    structlog.processors.StackInfoRenderer(),
]

_configured = False


def configure_logging(*, level: str = "INFO", json_output: bool = True) -> None:
    """Install the processor chain. Idempotent — safe to call from the app
    lifespan and again from a worker entrypoint."""
    global _configured

    renderer: Any = (
        structlog.processors.JSONRenderer()
        if json_output
        else structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty())
    )

    structlog.configure(
        processors=[
            *_SHARED_PROCESSORS,
            structlog.processors.format_exc_info,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        # `foreign_pre_chain` is what makes plain `logging` calls from the rest of
        # the codebase come out structured too.
        foreign_pre_chain=_SHARED_PROCESSORS,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root = logging.getLogger()
    # Replace rather than append: `basicConfig` may already have installed one,
    # and two handlers means every line printed twice.
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(level.upper())

    # uvicorn installs its own handlers on these; leaving them attached prints
    # access lines in uvicorn's format alongside ours.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        uv = logging.getLogger(name)
        uv.handlers.clear()
        uv.propagate = True

    # httpx logs every outbound request at INFO *including the full URL*. Two
    # problems: it is one line per reputation/RDAP/LLM call (the bulk of our log
    # volume), and any provider that authenticates by query parameter writes its
    # key into the log verbatim. We pass keys in headers now, but a future
    # integration that forgets shouldn't leak by default — so httpx speaks only
    # when something actually goes wrong.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)

    _configured = True


def get_logger(name: str | None = None) -> Any:
    """A bound structlog logger. Modules that already use `logging` need no
    change — this is for new code that wants to attach key/value pairs."""
    return structlog.get_logger(name)


def is_configured() -> bool:
    return _configured


__all__ = ["configure_logging", "get_logger", "is_configured"]
