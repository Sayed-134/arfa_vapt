from correlation.endpoint_correlator import correlate_endpoints, detect_attack_chains
from schemas.common import (
    AuthContextModel,
    AuthPrincipalModel,
    ConfidenceLevel,
    IDORComparisonModel,
    NormalizedFinding,
    SeverityLevel,
    VerificationStatus,
)

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

def _auth_context(label, session_ref="sess"):
    return AuthContextModel(
        principal=AuthPrincipalModel(label=label),
        session_ref=session_ref,
        identity=f"identity-{label}-{session_ref}",
    )


def _idor_comparison(owner_label, accessor_label, relationship="cross_principal_access"):
    return IDORComparisonModel(
        owner=_auth_context(owner_label),
        accessor=_auth_context(accessor_label),
        relationship=relationship,
    )


def _cross_principal_finding(
    finding_id,
    owner_label="owner",
    accessor_label="accessor",
    verification_status=VerificationStatus.LIKELY,
    endpoint="/profile",
    parameter="id",
):
    return NormalizedFinding(
        id=finding_id, category="IDOR", name="Cross-Principal IDOR",
        severity=SeverityLevel.HIGH, cvss=7.5, confidence=ConfidenceLevel.CERTAIN,
        endpoint=endpoint, parameter=parameter,
        verification_status=verification_status,
        composite_risk_score=70.0, dedup_fingerprint=f"fp_{finding_id}",
        idor_comparison=_idor_comparison(owner_label, accessor_label),
    )


def test_category_cooccurrence_alone_no_chain():
    """TD #13: category co-occurrence (even at different endpoints, the
    old fixture this test replaces) must never, on its own, produce a
    chain - only a structured idor_comparison can."""
    auth = NormalizedFinding(id="ID_AUTH", category="Authentication", name="Bypass",
        severity=SeverityLevel.HIGH, cvss=8.0, confidence=ConfidenceLevel.CERTAIN,
        endpoint="/auth", verification_status=VerificationStatus.CONFIRMED,
        composite_risk_score=80.0, dedup_fingerprint="fp_auth")
    sqli = NormalizedFinding(id="ID_SQLI", category="SQL Injection", name="SQLi",
        severity=SeverityLevel.CRITICAL, cvss=9.5, confidence=ConfidenceLevel.CERTAIN,
        endpoint="/query", verification_status=VerificationStatus.CONFIRMED,
        composite_risk_score=95.0, dedup_fingerprint="fp_sqli")
    assert detect_attack_chains([auth, sqli]) == []


def test_same_endpoint_or_parameter_alone_no_chain():
    """Two findings sharing endpoint AND parameter, different categories,
    but no idor_comparison on either - no chain."""
    a = NormalizedFinding(id="ID_A", category="Information Disclosure", name="Leak",
        severity=SeverityLevel.MEDIUM, cvss=5.0, confidence=ConfidenceLevel.HIGH,
        endpoint="/profile", parameter="id", verification_status=VerificationStatus.CONFIRMED,
        composite_risk_score=50.0, dedup_fingerprint="fp_a")
    b = NormalizedFinding(id="ID_B", category="IDOR", name="Heuristic IDOR",
        severity=SeverityLevel.MEDIUM, cvss=5.0, confidence=ConfidenceLevel.MEDIUM,
        endpoint="/profile", parameter="id", verification_status=VerificationStatus.CONFIRMED,
        composite_risk_score=50.0, dedup_fingerprint="fp_b")
    assert detect_attack_chains([a, b]) == []


def test_cross_principal_relationship_extracted_from_idor_comparison():
    f = _cross_principal_finding("ID1")
    chains = detect_attack_chains([f])
    assert len(chains) == 1
    assert len(chains[0].relationships) == 1
    rel = chains[0].relationships[0]
    assert rel.relationship_type == "cross_principal_access"
    assert rel.finding_ids == ["ID1"]
    assert rel.proof.owner.principal.label == "owner"
    assert rel.proof.accessor.principal.label == "accessor"


def test_relationship_becomes_single_relationship_chain():
    """One eligible Relationship is sufficient to form a complete
    AttackChain - no second finding is required or invented."""
    f = _cross_principal_finding("ID1")
    chains = detect_attack_chains([f])
    assert len(chains) == 1
    assert chains[0].chain_type == "CROSS_PRINCIPAL_ACCESS"
    assert chains[0].related_finding_ids == ["ID1"]
    # the owner side has no Finding of its own - not fabricated
    owner_stage_finding_ids = {s.finding_id for s in chains[0].stages}
    assert owner_stage_finding_ids == {"ID1"}


def test_unverified_idor_comparison_no_relationship():
    for status in (
        VerificationStatus.UNVERIFIED,
        VerificationStatus.INCONCLUSIVE,
        VerificationStatus.FALSE_POSITIVE,
        VerificationStatus.POTENTIAL,
    ):
        f = _cross_principal_finding("IDX", verification_status=status)
        assert detect_attack_chains([f]) == []


def test_eligible_verification_statuses_produce_chains():
    for status in (
        VerificationStatus.CONFIRMED,
        VerificationStatus.LIKELY,
        VerificationStatus.PROBABLE,
    ):
        f = _cross_principal_finding("IDY", verification_status=status)
        chains = detect_attack_chains([f])
        assert len(chains) == 1
        assert chains[0].verification_status == status


def test_verification_status_never_upgraded():
    f = _cross_principal_finding("ID1", verification_status=VerificationStatus.LIKELY)
    chains = detect_attack_chains([f])
    assert chains[0].verification_status == VerificationStatus.LIKELY
    assert chains[0].relationships[0].verification_status == VerificationStatus.LIKELY
    # never silently promoted to CONFIRMED
    assert chains[0].verification_status != VerificationStatus.CONFIRMED


def test_duplicate_relationships_deduplicated():
    """Two literal-duplicate cross-principal findings (identical owner,
    accessor, everything) sharing one dedup_fingerprint-equivalent shape
    must still only produce one Relationship/chain if handed to
    detect_attack_chains twice under the same finding id."""
    f = _cross_principal_finding("ID1")
    chains = detect_attack_chains([f, f])
    assert len(chains) == 1
    assert len(chains[0].relationships) == 1


def test_distinct_accessors_produce_distinct_relationships_and_chains():
    f1 = _cross_principal_finding("ID1", accessor_label="accessor-a")
    f2 = _cross_principal_finding("ID2", accessor_label="accessor-b")
    chains = detect_attack_chains([f1, f2])
    assert len(chains) == 2
    rel_ids = {c.relationships[0].relationship_id for c in chains}
    assert len(rel_ids) == 2


def test_chain_detection_deterministic_same_input():
    f1 = _cross_principal_finding("ID1", accessor_label="accessor-a")
    f2 = _cross_principal_finding("ID2", accessor_label="accessor-b")
    first = [c.model_dump_json() for c in detect_attack_chains([f1, f2])]
    second = [c.model_dump_json() for c in detect_attack_chains([f1, f2])]
    assert first == second


def test_chain_ordering_deterministic():
    f1 = _cross_principal_finding("ID1", accessor_label="accessor-a")
    f2 = _cross_principal_finding("ID2", accessor_label="accessor-b")
    order_a = [c.chain_id for c in detect_attack_chains([f1, f2])]
    order_b = [c.chain_id for c in detect_attack_chains([f2, f1])]
    assert order_a == order_b


def test_evidence_refs_and_relationships_trace_to_real_findings():
    f = _cross_principal_finding("ID1")
    chain = detect_attack_chains([f])[0]
    assert set(chain.evidence_refs).issubset({"ID1"})
    assert set(chain.related_finding_ids).issubset({"ID1"})


def test_chain_never_references_a_finding_id_absent_from_input():
    """Direct test of the required TD #13 invariant: a chain must never
    reference a finding id that is not present in the input findings."""
    f = _cross_principal_finding("ID1")
    chains = detect_attack_chains([f])
    known_ids = {"ID1"}
    for c in chains:
        assert set(c.related_finding_ids).issubset(known_ids)
        for rel in c.relationships:
            assert set(rel.finding_ids).issubset(known_ids)


def test_empty_findings_no_chains():
    assert detect_attack_chains([]) == []


def test_correlate_endpoints_unchanged():
    """Regression: correlate_endpoints() is untouched by TD #13."""
    findings = [
        NormalizedFinding(id="ID1", category="XSS", name="Reflected XSS",
            severity=SeverityLevel.MEDIUM, cvss=5.0, confidence=ConfidenceLevel.HIGH,
            endpoint="/users", verification_status=VerificationStatus.CONFIRMED,
            composite_risk_score=55.0, dedup_fingerprint="fp1"),
        NormalizedFinding(id="ID2", category="SQLi", name="SQL Injection",
            severity=SeverityLevel.CRITICAL, cvss=9.0, confidence=ConfidenceLevel.CERTAIN,
            endpoint="/users", verification_status=VerificationStatus.CONFIRMED,
            composite_risk_score=90.0, dedup_fingerprint="fp2"),
    ]
    correlated = correlate_endpoints(findings)
    assert len(correlated) == 1
    assert correlated[0].findings_count == 2


def test_chain_detection_works_without_llm():
    """detect_attack_chains() takes no LLM client and never touches one -
    deterministic extraction works standalone."""
    f = _cross_principal_finding("ID1")
    chains = detect_attack_chains([f])
    assert len(chains) == 1
