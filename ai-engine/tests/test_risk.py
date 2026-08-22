import pytest
from analyzers.risk_engine import calculate_risk_score, evaluate_findings_risk
from schemas.common import NormalizedFinding, SeverityLevel, ConfidenceLevel, VerificationStatus

def test_risk_scoring_deterministic():
    f1 = NormalizedFinding(
        id="ARFA-TEST1", category="SQL Injection", name="SQLi",
        severity=SeverityLevel.CRITICAL, cvss=10.0,
        confidence=ConfidenceLevel.CERTAIN, endpoint="/login",
        verification_status=VerificationStatus.CONFIRMED,
        composite_risk_score=0.0, dedup_fingerprint="abc",
    )
    assert calculate_risk_score(f1) == calculate_risk_score(f1) == 100.0

def test_verification_status_dampens_risk():
    base_args = dict(
        id="ARFA-TEST", category="SQL Injection", name="SQLi",
        severity=SeverityLevel.CRITICAL, cvss=9.0,
        confidence=ConfidenceLevel.HIGH, endpoint="/login",
        composite_risk_score=0.0, dedup_fingerprint="abc",
    )
    confirmed = NormalizedFinding(**base_args, verification_status=VerificationStatus.CONFIRMED)
    unverified = NormalizedFinding(**base_args, verification_status=VerificationStatus.UNVERIFIED)

    assert calculate_risk_score(confirmed) > calculate_risk_score(unverified)
    assert calculate_risk_score(unverified) < 40.0

def test_evaluate_findings_risk():
    f = NormalizedFinding(
        id="ARFA-TEST", category="Info", name="Leak",
        severity=SeverityLevel.LOW, cvss=2.0,
        confidence=ConfidenceLevel.LOW, endpoint="/",
        verification_status=VerificationStatus.POTENTIAL,
        composite_risk_score=0.0, dedup_fingerprint="abc",
    )
    res = evaluate_findings_risk([f])
    assert len(res) == 1
    assert res[0].composite_risk_score > 0.0
