import pytest

from parsers.scanner_parser import (
    _compute_fingerprint,
    parse_raw_go_finding,
    parse_go_scanner_findings,
)
from schemas.common import (
    AuthContextModel,
    AuthPrincipalModel,
    IDORComparisonModel,
    RawGoFinding,
    SeverityLevel,
    ConfidenceLevel,
    VerificationStatus,
    FindingStatus,
)


def _auth_context(label, identity):
    return AuthContextModel(
        principal=AuthPrincipalModel(label=label),
        session_ref="ref:deadbeef",
        identity=identity,
    )


def test_parse_null_and_missing_verification_fields():
    raw = RawGoFinding(
        category="Injection",
        name="SQLi",
        severity="HIGH",
        cvss=7.5,
        confidence="HIGH",
        endpoint="/api/v1/data",
        parameter="user",
        verification_status=None,
        verification_detail=None,
    )

    normalized = parse_raw_go_finding(raw)

    assert normalized.verification_status == VerificationStatus.UNVERIFIED
    assert normalized.verification_detail is None
    assert normalized.status == FindingStatus.OPEN
    assert normalized.severity == SeverityLevel.HIGH
    assert normalized.confidence == ConfidenceLevel.HIGH


def test_preserve_distinct_verification_statuses():
    statuses = [
        ("CONFIRMED", VerificationStatus.CONFIRMED),
        ("PROBABLE", VerificationStatus.PROBABLE),
        ("POTENTIAL", VerificationStatus.POTENTIAL),
        ("UNVERIFIED", VerificationStatus.UNVERIFIED),
        ("unknown_value", VerificationStatus.UNVERIFIED),
        (None, VerificationStatus.UNVERIFIED),
    ]

    for raw_str, expected in statuses:
        raw = RawGoFinding(
            name="Test",
            category="Test",
            endpoint="/",
            verification_status=raw_str,
        )

        norm = parse_raw_go_finding(raw)

        assert norm.verification_status == expected


def test_parse_full_json_array():
    json_data = """
    [
      {
        "category": "XSS",
        "name": "DOM XSS",
        "severity": "MEDIUM",
        "cvss": 5.4,
        "confidence": "HIGH",
        "endpoint": "/view",
        "parameter": "msg",
        "verification_status": "CONFIRMED",
        "verification_detail": "Execution verified"
      }
    ]
    """

    findings = parse_go_scanner_findings(json_data)

    assert len(findings) == 1

    finding = findings[0]

    assert finding.name == "DOM XSS"
    assert finding.verification_status == VerificationStatus.CONFIRMED
    assert finding.verification_detail == "Execution verified"


# --- TD #11 correction: structured auth_context/idor_comparison parsing,
# and the fingerprint fix mirroring pkg/scanner/scanner.go:fingerprint() ---


def test_normalized_finding_parses_auth_context_and_idor_comparison():
    raw = RawGoFinding(
        category="IDOR",
        name="Cross-Principal IDOR",
        endpoint="/profile",
        parameter="id",
        verification_status="LIKELY",
        auth_context=_auth_context("accessor", "identity-accessor"),
        idor_comparison=IDORComparisonModel(
            owner=_auth_context("owner", "identity-owner"),
            accessor=_auth_context("accessor", "identity-accessor"),
            relationship="cross_principal_access",
        ),
    )

    normalized = parse_raw_go_finding(raw)

    assert normalized.auth_context is not None
    assert normalized.auth_context.principal.label == "accessor"
    assert normalized.idor_comparison is not None
    assert normalized.idor_comparison.owner.principal.label == "owner"
    assert normalized.idor_comparison.accessor.principal.label == "accessor"
    assert normalized.idor_comparison.relationship == "cross_principal_access"


def test_finding_without_idor_comparison_has_none():
    raw = RawGoFinding(category="XSS", name="Reflected XSS", endpoint="/search")
    normalized = parse_raw_go_finding(raw)
    assert normalized.auth_context is None
    assert normalized.idor_comparison is None


def test_compute_fingerprint_distinct_accessors_distinct_fingerprint():
    """TD #11 correction, Python mirror of the Go fingerprint() fix:
    two findings identical in category/name/endpoint/parameter but with
    different accessor identities must produce different fingerprints."""
    owner = _auth_context("owner", "identity-owner")

    idor_a = IDORComparisonModel(
        owner=owner,
        accessor=_auth_context("accessor-a", "identity-accessor-a"),
        relationship="cross_principal_access",
    )
    idor_b = IDORComparisonModel(
        owner=owner,
        accessor=_auth_context("accessor-b", "identity-accessor-b"),
        relationship="cross_principal_access",
    )

    fp_a = _compute_fingerprint("IDOR", "X", "/profile", "id", idor_comparison=idor_a)
    fp_b = _compute_fingerprint("IDOR", "X", "/profile", "id", idor_comparison=idor_b)

    assert fp_a != fp_b


def test_compute_fingerprint_identical_idor_comparison_still_merges():
    owner = _auth_context("owner", "identity-owner")
    accessor = _auth_context("accessor", "identity-accessor")
    idor = IDORComparisonModel(owner=owner, accessor=accessor, relationship="cross_principal_access")

    fp1 = _compute_fingerprint("IDOR", "X", "/profile", "id", idor_comparison=idor)
    fp2 = _compute_fingerprint("IDOR", "X", "/profile", "id", idor_comparison=idor)

    assert fp1 == fp2


def test_compute_fingerprint_nil_idor_comparison_unaffected():
    """Every finding with no idor_comparison must produce exactly the
    pre-fix fingerprint (category|name|endpoint|parameter only)."""
    import hashlib

    fp = _compute_fingerprint("XSS", "Reflected XSS", "/search", "q")
    expected = hashlib.sha256(b"xss|reflected xss|/search|q").hexdigest()
    assert fp == expected


def test_parse_raw_go_finding_distinct_accessors_distinct_ids():
    """End-to-end through parse_raw_go_finding: two RawGoFindings that
    differ only in accessor identity must receive distinct
    NormalizedFinding.id/dedup_fingerprint values."""
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

    norm_a = parse_raw_go_finding(raw_a)
    norm_b = parse_raw_go_finding(raw_b)

    assert norm_a.id != norm_b.id
    assert norm_a.dedup_fingerprint != norm_b.dedup_fingerprint
