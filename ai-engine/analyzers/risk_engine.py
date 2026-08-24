from typing import List
from schemas.common import (
    NormalizedFinding,
    SeverityLevel,
    ConfidenceLevel,
    VerificationStatus,
)

SEVERITY_WEIGHTS = {
    SeverityLevel.CRITICAL: 1.0,
    SeverityLevel.HIGH: 0.8,
    SeverityLevel.MEDIUM: 0.5,
    SeverityLevel.LOW: 0.2,
    SeverityLevel.INFO: 0.05,
}

CONFIDENCE_WEIGHTS = {
    ConfidenceLevel.CERTAIN: 1.0,
    ConfidenceLevel.HIGH: 0.85,
    ConfidenceLevel.MEDIUM: 0.65,
    ConfidenceLevel.LOW: 0.4,
}

VERIFICATION_MULTIPLIERS = {
    VerificationStatus.CONFIRMED: 1.0,
    VerificationStatus.LIKELY: 0.8,
    VerificationStatus.PROBABLE: 0.8,
    VerificationStatus.POTENTIAL: 0.6,
    VerificationStatus.UNVERIFIED: 0.4,
    VerificationStatus.INCONCLUSIVE: 0.3,
    VerificationStatus.FALSE_POSITIVE: 0.0,
}


def calculate_risk_score(finding: NormalizedFinding) -> float:
    base_score = (finding.cvss / 10.0) * 100.0 if finding.cvss > 0 else (
        SEVERITY_WEIGHTS.get(finding.severity, 0.1) * 100.0
    )

    sev_w = SEVERITY_WEIGHTS.get(finding.severity, 0.1)
    conf_w = CONFIDENCE_WEIGHTS.get(finding.confidence, 0.5)
    ver_w = VERIFICATION_MULTIPLIERS.get(finding.verification_status, 0.4)

    calculated = (
        (0.5 * base_score)
        + (0.25 * (sev_w * 100.0))
        + (0.15 * (conf_w * 100.0))
        + (0.10 * (ver_w * 100.0))
    )

    final_score = calculated * ver_w
    return round(max(0.0, min(100.0, final_score)), 2)


def evaluate_findings_risk(
    findings: List[NormalizedFinding],
) -> List[NormalizedFinding]:
    updated_findings = []

    for f in findings:
        score = calculate_risk_score(f)
        updated = f.model_copy(update={"composite_risk_score": score})
        updated_findings.append(updated)

    return updated_findings
