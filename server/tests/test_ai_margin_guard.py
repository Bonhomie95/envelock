"""A marginal mailbox has to make money at whatever model is configured.

The AI judge's price is set by two settings that live nowhere near the price
list: the model name and the per-mailbox monthly call cap. Today's pair is
comfortable — `gpt-4o-mini` at 200 calls is roughly nine cents per mailbox-month
against a $2.80 annual-discounted Complete seat. The failure mode is somebody
raising the model for accuracy, which is a good instinct, and multiplying the
variable cost by thirty without touching the cap. The bill for that arrives a
month later from the model vendor, spread across every tenant, attributable to
nobody.
"""

from __future__ import annotations

from envelock.billing.margin import (
    AI_COGS_WARN_FRACTION,
    cheapest_marginal_seat_cents,
    check_ai_margin,
    worst_case_ai_cents_per_mailbox_month,
)


def _reload_settings() -> None:
    from envelock.config import get_settings

    get_settings.cache_clear()


def test_the_cheapest_seat_is_essential_on_annual() -> None:
    """$2.00 less 20% — the least we are ever paid for one extra mailbox."""
    assert cheapest_marginal_seat_cents() == 160


def test_the_shipped_default_is_comfortably_profitable(monkeypatch) -> None:
    monkeypatch.setenv("ENVELOCK_LLM_PROVIDER", "openai")
    monkeypatch.setenv("ENVELOCK_OPENAI_MODEL", "gpt-4o-mini")
    monkeypatch.setenv("ENVELOCK_LLM_MAX_CALLS_PER_MAILBOX_MONTH", "200")
    _reload_settings()
    try:
        cents = worst_case_ai_cents_per_mailbox_month()
        assert cents is not None
        # Pennies, not dollars — the judge is not where this product's cost is.
        assert 0 < cents <= 20, cents
        assert check_ai_margin()["ok"] is True
    finally:
        _reload_settings()


def test_a_frontier_model_at_the_same_cap_is_flagged_as_a_loss(
    monkeypatch, logged
) -> None:  # noqa: ANN001
    """The exact mistake this exists to catch: raise the model, leave the cap."""
    monkeypatch.setenv("ENVELOCK_LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("ENVELOCK_ANTHROPIC_MODEL", "claude-opus-5")
    monkeypatch.setenv("ENVELOCK_LLM_MAX_CALLS_PER_MAILBOX_MONTH", "200")
    _reload_settings()
    try:
        margin_log = logged("envelock.billing.margin")
        result = check_ai_margin()
        assert result["ok"] is False, result
        assert result["fraction_of_seat"] > 1.0, result
        assert "exceeds seat revenue" in margin_log.text, margin_log.messages
    finally:
        _reload_settings()


def test_lowering_the_cap_makes_a_bigger_model_safe_again(monkeypatch) -> None:
    """The guard names a remedy; this proves the remedy works, so the advice in
    the log is not folklore."""
    monkeypatch.setenv("ENVELOCK_LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("ENVELOCK_ANTHROPIC_MODEL", "claude-opus-5")
    monkeypatch.setenv("ENVELOCK_LLM_MAX_CALLS_PER_MAILBOX_MONTH", "20")
    _reload_settings()
    try:
        result = check_ai_margin()
        assert result["fraction_of_seat"] <= AI_COGS_WARN_FRACTION, result
        assert result["ok"] is True
    finally:
        _reload_settings()


def test_no_provider_is_not_a_margin_problem(monkeypatch) -> None:
    monkeypatch.setenv("ENVELOCK_LLM_PROVIDER", "none")
    _reload_settings()
    try:
        assert worst_case_ai_cents_per_mailbox_month() is None
        assert check_ai_margin()["ok"] is True
    finally:
        _reload_settings()
