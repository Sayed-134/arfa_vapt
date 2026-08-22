import hashlib
import json
from typing import List, Dict, Any, Union

from schemas.common import (
    RawGoFinding,
    NormalizedFinding,
    SeverityLevel,
    ConfidenceLevel,
    VerificationStatus,
    FindingStatus,
)


def _map_severity(val: Union[str, None]) -> SeverityLevel:
    if not val:
        return SeverityLevel.INFO

    cleaned = str(val).strip().upper()

    try:
        return SeverityLevel(cleaned)
    except ValueError:
        return SeverityLevel.INFO


def _map_confidence(val: Union[str, None]) -> ConfidenceLevel:
    if not val:
        return ConfidenceLevel.LOW

    cleaned = str(val).strip().upper()

    try:
        return ConfidenceLevel(cleaned)
    except ValueError:
        return ConfidenceLevel.LOW


def _map_verification_status(val: Union[str, None]) -> VerificationStatus:
    if not val:
        return VerificationStatus.UNVERIFIED

    cleaned = str(val).strip().upper()

    try:
        return VerificationStatus(cleaned)
    except ValueError:
        return VerificationStatus.UNVERIFIED


def _map_status(val: Union[str, int, None]) -> FindingStatus:
    if val is None:
        return FindingStatus.OPEN

    # Go Scanner currently emits HTTP status codes such as 200.
    # A successful HTTP response represents an active/open finding.
    if isinstance(val, int):
        return FindingStatus.OPEN

    cleaned = str(val).strip().upper()

    try:
        return FindingStatus(cleaned)
    except ValueError:
        return FindingStatus.OPEN


def _compute_fingerprint(
    category: str,
    name: str,
    endpoint: str,
    parameter: Union[str, None],
) -> str:
    norm_cat = (category or "").strip().lower()
    norm_name = (name or "").strip().lower()
    norm_ep = (endpoint or "").strip().lower()
    norm_param = (parameter or "").strip().lower()

    raw = f"{norm_cat}|{norm_name}|{norm_ep}|{norm_param}"

    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _normalize_raw_item(item: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize Go Scanner fields before Pydantic validation.

    The Go Scanner may emit:
      - cvss as a string
      - severity/confidence in mixed case
      - status as an HTTP integer such as 200

    The AI Engine keeps its internal schema deterministic.
    """
    normalized = dict(item)

    if normalized.get("cvss") is not None:
        try:
            normalized["cvss"] = float(normalized["cvss"])
        except (ValueError, TypeError):
            normalized["cvss"] = None

    status = normalized.get("status")
    if isinstance(status, int):
        normalized["status"] = "OPEN"

    return normalized


def parse_raw_go_finding(raw: RawGoFinding) -> NormalizedFinding:
    category = (raw.category or "General Vulnerability").strip()
    name = (raw.name or "Unnamed Finding").strip()
    endpoint = (raw.endpoint or "/").strip()
    parameter = raw.parameter.strip() if raw.parameter else None

    severity = _map_severity(raw.severity)
    confidence = _map_confidence(raw.confidence)
    verification_status = _map_verification_status(
        raw.verification_status
    )
    status = _map_status(raw.status)

    cvss = 0.0

    if raw.cvss is not None:
        try:
            cvss = max(0.0, min(10.0, float(raw.cvss)))
        except (ValueError, TypeError):
            cvss = 0.0
    else:
        defaults = {
            SeverityLevel.CRITICAL: 9.0,
            SeverityLevel.HIGH: 7.5,
            SeverityLevel.MEDIUM: 5.0,
            SeverityLevel.LOW: 2.5,
            SeverityLevel.INFO: 0.0,
        }

        cvss = defaults[severity]

    fingerprint = _compute_fingerprint(
        category,
        name,
        endpoint,
        parameter,
    )

    finding_id = f"ARFA-{fingerprint[:12].upper()}"

    return NormalizedFinding(
        id=finding_id,
        category=category,
        name=name,
        severity=severity,
        cvss=cvss,
        confidence=confidence,
        endpoint=endpoint,
        parameter=parameter,
        payload=raw.payload,
        encoding=raw.encoding,
        evidence=raw.evidence,
        poc=raw.poc,
        impact=raw.impact,
        remediation=raw.remediation,
        status=status,
        verification_status=verification_status,
        verification_detail=raw.verification_detail,
        composite_risk_score=0.0,
        dedup_fingerprint=fingerprint,
        occurrence_count=1,
    )


def parse_go_scanner_findings(
    raw_data: Union[str, bytes, List[Dict[str, Any]], Dict[str, Any]]
) -> List[NormalizedFinding]:

    if isinstance(raw_data, (str, bytes)):
        parsed = json.loads(raw_data)
    else:
        parsed = raw_data

    # Native AI Engine format:
    # [
    #   {...},
    #   {...}
    # ]
    if isinstance(parsed, list):
        items = parsed

    # Go Scanner format:
    # {
    #   "target": "...",
    #   "stats": {...},
    #   "findings": [...]
    # }
    elif isinstance(parsed, dict):
        items = parsed.get("findings")

        if not isinstance(items, list):
            raise ValueError(
                "Go Scanner payload must contain a JSON array under 'findings'."
            )

    else:
        raise ValueError(
            "Input scanner payload must be a JSON array or a Go Scanner result object."
        )

    normalized_list: List[NormalizedFinding] = []

    for item in items:
        if not isinstance(item, dict):
            raise ValueError("Each scanner finding must be a JSON object.")

        raw_obj = RawGoFinding(**_normalize_raw_item(item))
        normalized = parse_raw_go_finding(raw_obj)
        normalized_list.append(normalized)

    return normalized_list
