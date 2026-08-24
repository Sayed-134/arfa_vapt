import json
from pathlib import Path

from app.engine import ARFAEngine
from schemas.common import VerificationStatus


def test_versioned_go_envelope_preserves_scope_and_verification_statuses():
    fixture = Path(__file__).parents[2] / "fixtures" / "go_scan_baseline.json"
    report = ARFAEngine().process(fixture.read_text(encoding="utf-8"))

    assert report.source_scan is not None
    assert report.source_scan.schema_version == "arfa.scan/v1"
    assert report.source_scan.target == "http://127.0.0.1:18080"
    assert report.source_scan.scope["authorized"] is True
    assert report.metadata.input_findings_count == 5
    statuses = {finding.id: finding.verification_status for finding in report.findings}
    assert VerificationStatus.FALSE_POSITIVE in statuses.values()
    assert VerificationStatus.INCONCLUSIVE in statuses.values()


def test_go_contract_fixture_is_valid_json_object():
    fixture = Path(__file__).parents[2] / "fixtures" / "go_scan_baseline.json"
    payload = json.loads(fixture.read_text(encoding="utf-8"))
    assert payload["findings"][0]["category"] == "SQLi"
