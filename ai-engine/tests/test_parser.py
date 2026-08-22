import pytest

from parsers.scanner_parser import (
    parse_raw_go_finding,
    parse_go_scanner_findings,
)
from schemas.common import (
    RawGoFinding,
    SeverityLevel,
    ConfidenceLevel,
    VerificationStatus,
    FindingStatus,
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
