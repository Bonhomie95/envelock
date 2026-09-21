"""The scheduler's "did this job actually do anything?" guard.

This existed as `if result:`, which is true for *any* non-empty dict — and every
job returns one, `{"escalated": 0, "delivered": 0}` included. So each job logged
on every tick whether or not it had work, several lines every 30 seconds,
forever. On a small host that is tens of thousands of daily entries burying the
handful that matter, which is how a real failure goes unnoticed.

These pin the distinction, because the failure mode is silent: nothing breaks,
the logs just stop being worth reading.
"""

from __future__ import annotations

import pytest

from envelock.workers.scheduler import _did_something


@pytest.mark.parametrize(
    ("result", "expected", "why"),
    [
        ({"escalated": 0, "delivered": 0}, False, "idle escalation cycle"),
        ({"escalated": 2, "delivered": 1}, True, "escalated two alerts"),
        ({"escalated": 0, "delivered": 3}, True, "delivered even though none escalated"),
        ({"purged": {"messages": 0, "alerts": 0}}, False, "idle retention, nested zeros"),
        ({"purged": {"messages": 0, "alerts": 9}}, True, "purged nine, nested"),
        ({"refreshed": 0}, False, "no OAuth tokens needed refreshing"),
        ({"refreshed": 4}, True, "refreshed four tokens"),
        (None, False, "job returned nothing"),
        ({}, False, "job returned an empty dict"),
        ([], False, "job returned an empty list"),
        ([{"sent": 0}], False, "list of idle results"),
        ([{"sent": 1}], True, "list containing real work"),
    ],
)
def test_only_real_work_is_worth_a_log_line(
    result: dict | list | None, expected: bool, why: str
) -> None:
    assert _did_something(result) is expected, why


def test_a_dict_of_zeros_is_truthy_which_is_the_whole_point() -> None:
    """Guards the reasoning, not just the behaviour.

    If someone later 'simplifies' `_did_something(result)` back to `if result:`,
    the parametrised cases above fail — but this states plainly *why* the obvious
    version is wrong, so the next reader does not have to rediscover it.
    """
    idle = {"escalated": 0, "delivered": 0}
    assert bool(idle) is True
    assert _did_something(idle) is False
