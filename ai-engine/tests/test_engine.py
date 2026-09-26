import json
from pathlib import Path
from app.engine import ARFAEngine
from schemas.report import FinalReport
from schemas.common import VerificationStatus

def test_full_pipeline_json_serialization_deserialization():
    raw_scan_json = '''[
      {"category":"SQL Injection","name":"Error-Based SQL Injection","severity":"CRITICAL","cvss":9.8,"confidence":"CERTAIN","endpoint":"/api/v1/users","parameter":"id","payload":"1' OR '1'='1","encoding":"plain","evidence":"syntax error near unexpected token OR","poc":"curl test","impact":"Full database compromise","remediation":"Use parameterized queries.","status":"OPEN","verification_status":"CONFIRMED","verification_detail":"Active syntax dump verified"},
      {"category":"SQL Injection","name":"Error-Based SQL Injection","severity":"CRITICAL","cvss":9.8,"confidence":"HIGH","endpoint":"/api/v1/users","parameter":"id","payload":"1' UNION SELECT NULL--","encoding":"plain","evidence":null,"poc":null,"impact":"Database read","remediation":"Use parameterized queries.","status":null,"verification_status":null,"verification_detail":null},
      {"category":"Authentication","name":"JWT None Algorithm Bypass","severity":"HIGH","cvss":8.1,"confidence":"CERTAIN","endpoint":"/api/v1/auth/verify","parameter":"Authorization","payload":"token","encoding":"base64","evidence":"HTTP 200 OK","poc":"curl test","impact":"Auth bypass","remediation":"Verify signature algorithm.","status":"OPEN","verification_status":"CONFIRMED","verification_detail":"Bypass verified"}
    ]'''
    report = ARFAEngine(llm_url=None).process(raw_scan_json)
    assert isinstance(report, FinalReport)
    reconstituted = FinalReport.model_validate(json.loads(report.model_dump_json()))
    assert reconstituted.metadata.input_findings_count == 3
    assert reconstituted.metadata.deduplicated_count == 2
    assert reconstituted.executive_summary.risk_distribution.critical == 1
    assert reconstituted.executive_summary.risk_distribution.high == 1
    sqli = next(f for f in reconstituted.findings if f.category == "SQL Injection")
    assert sqli.occurrence_count == 2
    assert sqli.verification_status == VerificationStatus.CONFIRMED
    assert sqli.evidence == "syntax error near unexpected token OR"
    assert len(reconstituted.correlated_endpoints) == 2
    # TD #13: category co-occurrence (Authentication + SQL Injection here,
    # with no structured idor_comparison on any finding) no longer
    # produces an AttackChain - only an Evidence-backed Relationship does.
    assert reconstituted.attack_chains == []


def test_full_pipeline_cross_principal_idor_produces_attack_chain():
    """End-to-end (TD #11 correction + TD #13): a Go-shaped finding
    carrying a structured idor_comparison must survive JSON parsing,
    fingerprinting, deduplication, and chain detection, and produce
    exactly one CROSS_PRINCIPAL_ACCESS AttackChain in the final report."""
    raw_scan_json = '''[
      {"category":"IDOR","name":"Cross-Principal IDOR","severity":"HIGH","cvss":7.5,
       "confidence":"CERTAIN","endpoint":"/api/v1/profile","parameter":"id",
       "verification_status":"LIKELY",
       "idor_comparison":{
         "owner":{"principal":{"label":"owner"},"session_ref":"ref:owner","identity":"identity-owner"},
         "accessor":{"principal":{"label":"accessor"},"session_ref":"ref:accessor","identity":"identity-accessor"},
         "relationship":"cross_principal_access"
       }}
    ]'''
    report = ARFAEngine(llm_url=None).process(raw_scan_json)
    reconstituted = FinalReport.model_validate(json.loads(report.model_dump_json()))

    assert reconstituted.metadata.input_findings_count == 1
    finding = reconstituted.findings[0]
    assert finding.idor_comparison is not None
    assert finding.idor_comparison.accessor.principal.label == "accessor"

    assert len(reconstituted.attack_chains) == 1
    chain = reconstituted.attack_chains[0]
    assert chain.chain_type == "CROSS_PRINCIPAL_ACCESS"
    assert chain.related_finding_ids == [finding.id]
    assert chain.verification_status == VerificationStatus.LIKELY
    assert len(chain.relationships) == 1
    assert chain.relationships[0].proof.owner.principal.label == "owner"

def test_examples_scan_results_file_matches_parser():
    scan_file = Path(__file__).parent.parent / "examples" / "scan_results.json"
    if scan_file.exists():
        report = ARFAEngine(llm_url=None).process(scan_file.read_text(encoding="utf-8"))
        assert report.metadata.input_findings_count == 5
        assert report.metadata.deduplicated_count == 4
