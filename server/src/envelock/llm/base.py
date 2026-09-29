"""Shared types for the LLM cascade: the provider protocol, the injectable HTTP
transport (so every provider is testable without a network), and the structured
verdict a judge returns."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


class LlmError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class LlmVerdict:
    """A judge's structured opinion on one message.

    `verdict` ∈ fraud | suspicious | benign. `confidence` is 0-1. `escalate` asks
    the risk engine to raise the tier; the engine, not the model, owns the final
    action, and a low-confidence or benign verdict never lowers a rule tier.
    """

    verdict: str
    confidence: float
    rationale: str
    escalate: bool = False
    provider: str = ""
    model: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    cost_micros: int = 0
    raw: dict = field(default_factory=dict)

    @property
    def is_fraud(self) -> bool:
        return self.verdict == "fraud"

    @property
    def is_benign(self) -> bool:
        return self.verdict == "benign"


class Transport(Protocol):
    """Injectable HTTP seam. Production uses httpx; tests pass a fake so the whole
    cascade runs deterministically with no network and no key."""

    async def post_json(self, url: str, *, headers: dict, body: dict) -> dict: ...


class HttpxTransport:
    def __init__(self, timeout: float = 20.0) -> None:
        self.timeout = timeout

    async def post_json(self, url: str, *, headers: dict, body: dict) -> dict:
        import httpx

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(url, headers=headers, json=body)
            if resp.status_code >= 400:
                # Provider errors may echo prompts, credentials or private mail.
                raise LlmError(f"provider returned HTTP {resp.status_code}")
            data = resp.json()
        except httpx.HTTPError:
            raise LlmError("provider request failed") from None
        except ValueError:
            raise LlmError("provider returned invalid JSON") from None
        if not isinstance(data, dict):
            raise LlmError("provider returned a non-object response")
        return data


class LlmProvider(Protocol):
    """A minimal single-shot chat interface — one system prompt, one user prompt,
    a JSON object back. Enough for a classification judge; deliberately not a
    general agent surface."""

    name: str
    model: str

    @property
    def configured(self) -> bool: ...

    async def complete_json(self, *, system: str, user: str, max_tokens: int) -> dict: ...
