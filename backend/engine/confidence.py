"""
ProbeX Engine – baseline confidence layer (false-positive defence).

The single most important rule
-------------------------------
``is_match()`` returns True **only** when a pattern is found in the fuzzed
response AND was **not** already present in the baseline.  This one rule
prevents a page whose footer already contains the word "error" from being
wrongly flagged as SQL Injection.

Scoring contract
----------------
- 0 matchers triggered  → score 0.0  (never report, discard finding)
- 1 matcher triggered   → score 0.6
- 2+ matchers triggered → score 0.9
- MINIMUM_CONFIDENCE    = 0.5  (anything below this is silently dropped)

Zero FastAPI / SQLModel imports — this module must stay standalone.
"""

from __future__ import annotations

import re
from typing import Literal

from engine.models import Baseline

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MINIMUM_CONFIDENCE: float = 0.5
"""Findings with a confidence score below this threshold are discarded."""

_SCORE_TABLE: dict[int, float] = {
    0: 0.0,
    1: 0.6,
}
_SCORE_TWO_PLUS: float = 0.9


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def is_match(
    baseline: Baseline,
    fuzzed_text: str,
    fuzzed_status: int,
    matcher_type: Literal["word", "regex", "status"],
    matcher_value: str | int,
) -> bool:
    """
    Return ``True`` only if the pattern is found in ``fuzzed_text`` (or the
    status code matches) **and** was NOT already present in the baseline.

    This differential check is the core false-positive defence.

    Parameters
    ----------
    baseline:
        The clean, pre-fuzzing ``Baseline`` recorded by ``HttpClient.record_baseline()``.
    fuzzed_text:
        Response body of the fuzzed request.
    fuzzed_status:
        HTTP status code of the fuzzed request.
    matcher_type:
        ``"word"``   – case-insensitive substring search in response body.
        ``"regex"``  – compiled regex search in response body.
        ``"status"`` – exact HTTP status code comparison (uses ``matcher_value``
                       as an ``int``).  Does not compare against baseline body.
    matcher_value:
        The string (for ``"word"`` / ``"regex"`` types) or int (for
        ``"status"``) to match against.

    Returns
    -------
    bool
        ``True`` iff the pattern appears in the fuzzed response but NOT in the
        baseline.  For ``"status"`` matchers, ``True`` iff the fuzzed status
        matches ``matcher_value`` and differs from ``baseline.status``.

    Examples
    --------
    >>> # A page that always shows "syntax error" in its footer:
    >>> baseline = Baseline(status=200, text="Footer: syntax error", elapsed_ms=50.0)
    >>> is_match(baseline, "Footer: syntax error <b>more stuff</b>", 200, "word", "syntax error")
    False   # ← correct: already in baseline, NOT a new injection signal

    >>> # A page that only shows the SQL error after injection:
    >>> baseline = Baseline(status=200, text="Welcome to the store", elapsed_ms=50.0)
    >>> is_match(baseline, "You have an error in your SQL syntax", 500, "word", "SQL syntax")
    True    # ← correct: new signal not present in baseline
    """
    if matcher_type == "word":
        pattern = str(matcher_value)
        in_fuzzed = pattern.lower() in fuzzed_text.lower()
        in_baseline = pattern.lower() in baseline.text.lower()
        return in_fuzzed and not in_baseline

    elif matcher_type == "regex":
        compiled = re.compile(str(matcher_value), re.IGNORECASE | re.DOTALL)
        in_fuzzed = bool(compiled.search(fuzzed_text))
        in_baseline = bool(compiled.search(baseline.text))
        return in_fuzzed and not in_baseline

    elif matcher_type == "status":
        target_status = int(matcher_value)
        return fuzzed_status == target_status and baseline.status != target_status

    return False


def score(matcher_count: int) -> float:
    """
    Convert a count of triggered matchers to a confidence score.

    Scoring table::

        0 matchers  → 0.0  (do not report)
        1 matcher   → 0.6
        2+ matchers → 0.9

    Parameters
    ----------
    matcher_count:
        Number of distinct matchers that returned ``True`` for this finding.

    Returns
    -------
    float
        Confidence score in [0.0, 1.0].
    """
    if matcher_count <= 0:
        return 0.0
    if matcher_count == 1:
        return _SCORE_TABLE[1]
    return _SCORE_TWO_PLUS
