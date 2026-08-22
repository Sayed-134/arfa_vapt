from typing import Dict, List

from schemas.common import (
    ConfidenceLevel,
    FindingStatus,
    NormalizedFinding,
    SeverityLevel,
    VerificationStatus,
)


SEVERITY_ORDER = {
    SeverityLevel.CRITICAL: 5,
    SeverityLevel.HIGH: 4,
    SeverityLevel.MEDIUM: 3,
    SeverityLevel.LOW: 2,
    SeverityLevel.INFO: 1,
}

CONFIDENCE_ORDER = {
    ConfidenceLevel.CERTAIN: 4,
    ConfidenceLevel.HIGH: 3,
    ConfidenceLevel.MEDIUM: 2,
    ConfidenceLevel.LOW: 1,
}

VERIFICATION_ORDER = {
    VerificationStatus.CONFIRMED: 4,
    VerificationStatus.PROBABLE: 3,
    VerificationStatus.POTENTIAL: 2,
    VerificationStatus.UNVERIFIED: 1,
}


def _is_better(candidate: NormalizedFinding, current: NormalizedFinding) -> bool:
    candidate_key = (
        candidate.composite_risk_score,
        SEVERITY_ORDER.get(candidate.severity, 0),
        VERIFICATION_ORDER.get(candidate.verification_status, 0),
        CONFIDENCE_ORDER.get(candidate.confidence, 0),
        candidate.cvss,
    )

    current_key = (
        current.composite_risk_score,
        SEVERITY_ORDER.get(current.severity, 0),
        VERIFICATION_ORDER.get(current.verification_status, 0),
        CONFIDENCE_ORDER.get(current.confidence, 0),
        current.cvss,
    )

    return candidate_key > current_key


def _merge_missing_fields(
    strongest: NormalizedFinding,
    other: NormalizedFinding,
) -> NormalizedFinding:
    updates = {}

    optional_fields = (
        "parameter",
        "payload",
        "encoding",
        "evidence",
        "poc",
        "impact",
        "remediation",
        "verification_detail",
    )

    for field_name in optional_fields:
        strongest_value = getattr(strongest, field_name)
        other_value = getattr(other, field_name)

        if strongest_value is None and other_value is not None:
            updates[field_name] = other_value

    if (
        strongest.status == FindingStatus.OPEN
        and other.status != FindingStatus.OPEN
    ):
        updates["status"] = other.status

    if updates:
        return strongest.model_copy(update=updates)

    return strongest


def deduplicate_findings(
    findings: List[NormalizedFinding],
) -> List[NormalizedFinding]:
    groups: Dict[str, List[NormalizedFinding]] = {}

    for finding in findings:
        fingerprint = finding.dedup_fingerprint
        groups.setdefault(fingerprint, []).append(finding)

    deduplicated: List[NormalizedFinding] = []

    for fingerprint, group in groups.items():
        strongest = group[0]

        for candidate in group[1:]:
            if _is_better(candidate, strongest):
                strongest = candidate

        for item in group:
            if item is not strongest:
                strongest = _merge_missing_fields(strongest, item)

        occurrence_count = sum(
            max(1, item.occurrence_count)
            for item in group
        )

        strongest = strongest.model_copy(
            update={
                "occurrence_count": occurrence_count,
                "dedup_fingerprint": fingerprint,
            }
        )

        deduplicated.append(strongest)

    deduplicated.sort(
        key=lambda finding: (
            -finding.composite_risk_score,
            -SEVERITY_ORDER.get(finding.severity, 0),
            finding.dedup_fingerprint,
        )
    )

    return deduplicated
