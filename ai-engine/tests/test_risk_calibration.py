"""TD #14 — Risk Scoring Calibration regression tests.

These tests do not change calculate_risk_score's behavior; they pin down,
as executable assertions, the calibration rationale documented in
analyzers/risk_engine.py's module docstring. Existing tests in test_risk.py
(exact score values, determinism) are untouched and continue to pass
unchanged - see the accompanying patch summary.
"""
from analyzers.risk_engine import calculate_risk_score
from schemas.common import (
    NormalizedFinding,
    SeverityLevel,
    ConfidenceLevel,
    VerificationStatus,
)


def _finding(verification_status, **overrides):
    base = dict(
        id="ARFA-CAL", category="SQL Injection", name="SQLi",
        severity=SeverityLevel.CRITICAL, cvss=9.0,
        confidence=ConfidenceLevel.HIGH, endpoint="/login",
        composite_risk_score=0.0, dedup_fingerprint="cal",
        verification_status=verification_status,
    )
    base.update(overrides)
    return NormalizedFinding(**base)


def test_verification_calibration_ordering_is_monotonic():
    """Locks in the documented ordering: CONFIRMED > LIKELY == PROBABLE >
    POTENTIAL > UNVERIFIED > INCONCLUSIVE > FALSE_POSITIVE, with severity,
    CVSS and confidence held constant so only verification_status varies.
    """
    scores = {
        status: calculate_risk_score(_finding(status))
        for status in (
            VerificationStatus.CONFIRMED,
            VerificationStatus.LIKELY,
            VerificationStatus.PROBABLE,
            VerificationStatus.POTENTIAL,
            VerificationStatus.UNVERIFIED,
            VerificationStatus.INCONCLUSIVE,
            VerificationStatus.FALSE_POSITIVE,
        )
    }

    assert scores[VerificationStatus.CONFIRMED] > scores[VerificationStatus.LIKELY]
    assert scores[VerificationStatus.LIKELY] > scores[VerificationStatus.POTENTIAL]
    assert scores[VerificationStatus.POTENTIAL] > scores[VerificationStatus.UNVERIFIED]
    # Documented, deliberately counter-intuitive step: an attempt that
    # could not resolve (INCONCLUSIVE) is calibrated below a finding that
    # was simply never checked (UNVERIFIED) - see risk_engine.py's
    # calibration table for the rationale.
    assert scores[VerificationStatus.UNVERIFIED] > scores[VerificationStatus.INCONCLUSIVE]
    assert scores[VerificationStatus.INCONCLUSIVE] > scores[VerificationStatus.FALSE_POSITIVE]


def test_likely_and_probable_are_calibrated_identically():
    """LIKELY and PROBABLE must score identically: PROBABLE is the
    original status name, LIKELY was added as an equivalent (see
    VERIFICATION_ORDER in deduplicator.py, which also ranks them equally).
    Calibration must not silently favor one spelling over the other.
    """
    likely = calculate_risk_score(_finding(VerificationStatus.LIKELY))
    probable = calculate_risk_score(_finding(VerificationStatus.PROBABLE))
    assert likely == probable


def test_false_positive_always_scores_zero_regardless_of_severity():
    """A disproven finding must score exactly 0.0 even at CRITICAL/CVSS 10/
    CERTAIN confidence - the outer verification multiplier is a hard
    override, not just a nudge."""
    f = _finding(
        VerificationStatus.FALSE_POSITIVE,
        severity=SeverityLevel.CRITICAL,
        cvss=10.0,
        confidence=ConfidenceLevel.CERTAIN,
    )
    assert calculate_risk_score(f) == 0.0


def test_verification_status_is_a_damping_multiplier_not_just_a_weighted_term():
    """If verification only contributed its 10% weighted share and were
    not also applied as an outer multiplier, CONFIRMED vs FALSE_POSITIVE
    at identical severity/CVSS/confidence would differ by at most ~10
    points. The documented design applies ver_w twice (see risk_engine.py
    module docstring), so the gap must be far larger than that - in this
    case, the full range down to exactly 0.0.
    """
    confirmed = calculate_risk_score(_finding(VerificationStatus.CONFIRMED))
    false_positive = calculate_risk_score(_finding(VerificationStatus.FALSE_POSITIVE))
    assert false_positive == 0.0
    assert confirmed - false_positive > 10.0


def test_calibration_is_deterministic_across_all_statuses():
    """Reproducibility guarantee: calling calculate_risk_score twice for
    every defined verification status yields identical results - no
    hidden state, no randomness."""
    for status in VerificationStatus:
        f = _finding(status)
        assert calculate_risk_score(f) == calculate_risk_score(f)
