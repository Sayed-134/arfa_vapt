from analyzers.deduplicator import deduplicate_findings
from schemas.common import NormalizedFinding, SeverityLevel, ConfidenceLevel, VerificationStatus

def test_deduplicate_identical_findings():
    f1 = NormalizedFinding(
        id="ARFA-1", category="SQL Injection", name="Error SQLi",
        severity=SeverityLevel.HIGH, cvss=7.5, confidence=ConfidenceLevel.HIGH,
        endpoint="/api/user", parameter="id",
        verification_status=VerificationStatus.POTENTIAL,
        composite_risk_score=50.0, dedup_fingerprint="fingerprint_1",
        occurrence_count=1,
    )
    f2 = NormalizedFinding(
        id="ARFA-2", category="SQL Injection", name="Error SQLi",
        severity=SeverityLevel.CRITICAL, cvss=9.8, confidence=ConfidenceLevel.CERTAIN,
        endpoint="/api/user", parameter="id", evidence="Dumped DB version",
        verification_status=VerificationStatus.CONFIRMED,
        composite_risk_score=95.0, dedup_fingerprint="fingerprint_1",
        occurrence_count=1,
    )
    deduped = deduplicate_findings([f1, f2])
    assert len(deduped) == 1
    res = deduped[0]
    assert res.occurrence_count == 2
    assert res.severity == SeverityLevel.CRITICAL
    assert res.cvss == 9.8
    assert res.verification_status == VerificationStatus.CONFIRMED
    assert res.evidence == "Dumped DB version"
    assert res.composite_risk_score == 95.0
