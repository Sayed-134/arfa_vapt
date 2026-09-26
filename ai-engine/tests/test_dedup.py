from analyzers.deduplicator import deduplicate_findings
from parsers.scanner_parser import parse_raw_go_finding
from schemas.common import (
    AuthContextModel,
    AuthPrincipalModel,
    ConfidenceLevel,
    IDORComparisonModel,
    NormalizedFinding,
    RawGoFinding,
    SeverityLevel,
    VerificationStatus,
)

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


def _auth_context(label, identity):
    return AuthContextModel(
        principal=AuthPrincipalModel(label=label),
        session_ref="ref:deadbeef",
        identity=identity,
    )


def test_deduplicate_findings_preserves_distinct_cross_principal_relationships():
    """TD #11/TD #13 root-cause regression, end to end through the
    *unmodified* deduplicate_findings(): two distinct cross-principal IDOR
    findings for the same endpoint/parameter but different accessors must
    both survive deduplication as separate NormalizedFindings, because the
    TD #11-corrected fingerprint (see scanner_parser._compute_fingerprint)
    no longer collides them onto one dedup_fingerprint. This is the direct
    proof that deduplicator.py itself never needed to change - the defect
    was entirely upstream, in what fingerprint it was handed."""
    owner = _auth_context("owner", "identity-owner")

    raw_a = RawGoFinding(
        category="IDOR", name="Cross-Principal IDOR", endpoint="/profile", parameter="id",
        verification_status="LIKELY",
        idor_comparison=IDORComparisonModel(
            owner=owner, accessor=_auth_context("accessor-a", "identity-accessor-a"),
            relationship="cross_principal_access",
        ),
    )
    raw_b = RawGoFinding(
        category="IDOR", name="Cross-Principal IDOR", endpoint="/profile", parameter="id",
        verification_status="LIKELY",
        idor_comparison=IDORComparisonModel(
            owner=owner, accessor=_auth_context("accessor-b", "identity-accessor-b"),
            relationship="cross_principal_access",
        ),
    )

    finding_a = parse_raw_go_finding(raw_a)
    finding_b = parse_raw_go_finding(raw_b)

    deduped = deduplicate_findings([finding_a, finding_b])

    assert len(deduped) == 2
    accessor_labels = {
        f.idor_comparison.accessor.principal.label for f in deduped
    }
    assert accessor_labels == {"accessor-a", "accessor-b"}


def test_deduplicate_findings_still_merges_identical_cross_principal_duplicates():
    """A true duplicate (same owner, same accessor) must still correctly
    merge into one NormalizedFinding with occurrence_count=2, exactly as
    for any other finding type."""
    owner = _auth_context("owner", "identity-owner")
    accessor = _auth_context("accessor", "identity-accessor")

    def _raw():
        return RawGoFinding(
            category="IDOR", name="Cross-Principal IDOR", endpoint="/profile", parameter="id",
            verification_status="LIKELY",
            idor_comparison=IDORComparisonModel(
                owner=owner, accessor=accessor, relationship="cross_principal_access",
            ),
        )

    finding_1 = parse_raw_go_finding(_raw())
    finding_2 = parse_raw_go_finding(_raw())

    deduped = deduplicate_findings([finding_1, finding_2])

    assert len(deduped) == 1
    assert deduped[0].occurrence_count == 2
    assert deduped[0].idor_comparison.accessor.principal.label == "accessor"
