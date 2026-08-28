"""
ProbeX Engine – confidence scorer.

Assigns a confidence value in [0.0, 1.0] to each candidate finding using a
weighted combination of signals:

  - Response delta: how much did the response differ from the baseline?
  - Reflection fidelity: is the payload visible in the response body / header?
  - HTTP status variance: did the status code change in a meaningful way?
  - Error-pattern strength: how clearly does the response match a known error
    pattern (e.g. SQL syntax error, stack trace)?

Zero FastAPI / SQLModel imports — this module must stay standalone.

TODO (Task E2): implement full signal extraction and weight calibration.
"""

from __future__ import annotations


def compute_confidence(
    payload: str,
    baseline_body: str,
    fuzzed_body: str,
    baseline_status: int,
    fuzzed_status: int,
    error_pattern_matched: bool = False,
) -> float:
    """
    Return a confidence score in [0.0, 1.0] for a candidate finding.

    Parameters
    ----------
    payload:
        The payload string that was injected.
    baseline_body:
        HTTP response body before injection (control request).
    fuzzed_body:
        HTTP response body after injection (test request).
    baseline_status:
        HTTP status code of the control request.
    fuzzed_status:
        HTTP status code of the test request.
    error_pattern_matched:
        True if a detector's error-pattern regex matched the fuzzed body.

    Returns
    -------
    float
        Confidence score.  Higher is more likely a true positive.
    """
    score = 0.0

    # Signal 1: payload reflected in response body.
    if payload and payload in fuzzed_body:
        score += 0.4

    # Signal 2: status code changed to a suspicious value.
    if fuzzed_status != baseline_status:
        if fuzzed_status in (500, 503):
            score += 0.3
        else:
            score += 0.1

    # Signal 3: explicit error pattern match from detector.
    if error_pattern_matched:
        score += 0.3

    return min(score, 1.0)
