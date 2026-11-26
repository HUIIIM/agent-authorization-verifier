"""Injected clock for the report layer (design section 4.3, W4 determinism).

Every timestamp that appears in a report comes from a ``Clock`` passed in
by the caller. ``SystemClock.now`` is the ONLY wall-clock read in the
package; the judgment path (verifier, WIT validation, vector construction,
contrast engine) never calls a clock at all -- its only notion of time is
the explicit ``verify_time`` argument each evaluation carries.

A clock is consumed by the report layer only, and only to stamp the
report's volatile ``meta.generated_at`` field, which canonical reports
omit.
"""

from __future__ import annotations

import datetime as _dt
from typing import Protocol


class Clock(Protocol):
    """Source of the current instant, as a timezone-aware UTC datetime."""

    def now(self) -> _dt.datetime: ...


class SystemClock:
    """The wall clock. The single sanctioned wall-clock call site in src/."""

    def now(self) -> _dt.datetime:
        return _dt.datetime.now(_dt.UTC)


class FixedClock:
    """A clock pinned to one instant (tests, reproducible report stamps)."""

    def __init__(self, instant: _dt.datetime) -> None:
        if instant.tzinfo is None:
            raise ValueError("FixedClock needs a timezone-aware instant")
        self._instant = instant.astimezone(_dt.UTC)

    def now(self) -> _dt.datetime:
        return self._instant


def clock_from_spec(spec: str) -> Clock:
    """Build a clock from a CLI spec.

    ``system`` -> the wall clock; ``@<unix seconds>`` or an ISO 8601
    instant with an offset (``2026-11-26T00:00:00Z``) -> a fixed clock.
    """
    if spec == "system":
        return SystemClock()
    if spec.startswith("@"):
        return FixedClock(_dt.datetime.fromtimestamp(int(spec[1:]), _dt.UTC))
    instant = _dt.datetime.fromisoformat(spec)
    return FixedClock(instant)


def format_instant(instant: _dt.datetime) -> str:
    """RFC 3339 UTC form with second precision: 2026-11-26T03:28:07Z."""
    return instant.astimezone(_dt.UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
