from reporting.generator import ReportGenerator
from schemas.common import NormalizedFinding, SeverityLevel, ConfidenceLevel, VerificationStatus

def test_report_generation_deterministic():
    generator = ReportGenerator(engine_version="1.0.0", llm_client=None)
    findings = [NormalizedFinding(
        id="ID1", category="SQL Injection", name="SQLi",
        severity=SeverityLevel.CRITICAL, cvss=9.8,
        confidence=ConfidenceLevel.CERTAIN, endpoint="/login",
        verification_status=VerificationStatus.CONFIRMED,
        composite_risk_score=98.0, dedup_fingerprint="fp1", occurrence_count=1,
    )]
    report = generator.generate(1, findings, [], [])
    assert report.metadata.input_findings_count == 1
    assert report.metadata.deduplicated_count == 1
    assert report.metadata.llm_assisted is False
    assert report.executive_summary.risk_distribution.critical == 1
    assert report.executive_summary.overall_posture_score == 70.0
    assert len(report.executive_summary.key_observations) >= 1
