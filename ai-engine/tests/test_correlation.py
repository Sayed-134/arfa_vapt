from correlation.endpoint_correlator import correlate_endpoints, detect_attack_chains
from schemas.common import NormalizedFinding, SeverityLevel, ConfidenceLevel, VerificationStatus

def test_endpoint_correlation():
    findings = [
        NormalizedFinding(id="ID1", category="XSS", name="Reflected XSS",
            severity=SeverityLevel.MEDIUM, cvss=5.0, confidence=ConfidenceLevel.HIGH,
            endpoint="/users", verification_status=VerificationStatus.CONFIRMED,
            composite_risk_score=55.0, dedup_fingerprint="fp1"),
        NormalizedFinding(id="ID2", category="SQLi", name="SQL Injection",
            severity=SeverityLevel.CRITICAL, cvss=9.0, confidence=ConfidenceLevel.CERTAIN,
            endpoint="/users", verification_status=VerificationStatus.CONFIRMED,
            composite_risk_score=90.0, dedup_fingerprint="fp2"),
        NormalizedFinding(id="ID3", category="Info", name="Path Leak",
            severity=SeverityLevel.LOW, cvss=2.0, confidence=ConfidenceLevel.LOW,
            endpoint="/about", verification_status=VerificationStatus.UNVERIFIED,
            composite_risk_score=10.0, dedup_fingerprint="fp3"),
    ]
    correlated = correlate_endpoints(findings)
    assert len(correlated) == 2
    assert correlated[0].endpoint == "/users"
    assert correlated[0].findings_count == 2
    assert correlated[0].highest_severity == SeverityLevel.CRITICAL
    assert correlated[0].max_risk_score == 90.0
    assert set(correlated[0].finding_ids) == {"ID1", "ID2"}

def test_detect_attack_chains():
    auth = NormalizedFinding(id="ID_AUTH", category="Authentication", name="Bypass",
        severity=SeverityLevel.HIGH, cvss=8.0, confidence=ConfidenceLevel.CERTAIN,
        endpoint="/auth", verification_status=VerificationStatus.CONFIRMED,
        composite_risk_score=80.0, dedup_fingerprint="fp_auth")
    sqli = NormalizedFinding(id="ID_SQLI", category="SQL Injection", name="SQLi",
        severity=SeverityLevel.CRITICAL, cvss=9.5, confidence=ConfidenceLevel.CERTAIN,
        endpoint="/query", verification_status=VerificationStatus.CONFIRMED,
        composite_risk_score=95.0, dedup_fingerprint="fp_sqli")
    chains = detect_attack_chains([auth, sqli])
    assert len(chains) == 1
    assert chains[0].chain_type == "AUTH_BYPASS_TO_RCE_OR_SQLI"
    assert "ID_AUTH" in chains[0].related_finding_ids
    assert "ID_SQLI" in chains[0].related_finding_ids
