import hashlib
from typing import Dict, List
from schemas.common import (
    AttackChain,
    ChainStage,
    CorrelatedEndpoint,
    NormalizedFinding,
    Relationship,
    RelationshipProof,
    SeverityLevel,
    VerificationStatus,
)

# TD #13 — a Relationship is eligible to form a chain only when its source
# finding's own verification_status is at least this strong. INCONCLUSIVE,
# UNVERIFIED, and FALSE_POSITIVE can never produce an eligible
# Relationship, and this status is preserved unchanged on the Relationship
# and AttackChain - never upgraded, reinterpreted, or inflated.
ELIGIBLE_RELATIONSHIP_VERIFICATION_STATUSES = {
    VerificationStatus.CONFIRMED,
    VerificationStatus.LIKELY,
    VerificationStatus.PROBABLE,
}

SEVERITY_ORDER = {
    SeverityLevel.CRITICAL: 5,
    SeverityLevel.HIGH: 4,
    SeverityLevel.MEDIUM: 3,
    SeverityLevel.LOW: 2,
    SeverityLevel.INFO: 1,
}


def correlate_endpoints(
    findings: List[NormalizedFinding],
) -> List[CorrelatedEndpoint]:
    endpoint_groups: Dict[str, List[NormalizedFinding]] = {}

    for f in findings:
        ep = f.endpoint
        if ep not in endpoint_groups:
            endpoint_groups[ep] = []
        endpoint_groups[ep].append(f)

    correlated_list: List[CorrelatedEndpoint] = []

    for ep, group in endpoint_groups.items():
        highest_sev = SeverityLevel.INFO
        max_risk = 0.0
        finding_ids = []

        for item in group:
            finding_ids.append(item.id)

            if SEVERITY_ORDER[item.severity] > SEVERITY_ORDER[highest_sev]:
                highest_sev = item.severity

            if item.composite_risk_score > max_risk:
                max_risk = item.composite_risk_score

        correlated_list.append(
            CorrelatedEndpoint(
                endpoint=ep,
                findings_count=len(group),
                highest_severity=highest_sev,
                max_risk_score=round(max_risk, 2),
                finding_ids=finding_ids,
            )
        )

    correlated_list.sort(
        key=lambda x: x.max_risk_score,
        reverse=True,
    )

    return correlated_list


def _relationship_id(
    relationship_type: str,
    finding_ids: List[str],
    owner_identity: str,
    accessor_identity: str,
) -> str:
    """Deterministic Relationship identity: same relationship_type +
    participants + proof always yields the same id; a different
    relationship_type or participant/proof always yields a different one.
    Independent of Finding.id/dedup_fingerprint by design (TD #13)."""
    raw = (
        f"{relationship_type}|{','.join(sorted(finding_ids))}"
        f"|{owner_identity}|{accessor_identity}"
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _chain_id(chain_type: str, relationship_ids: List[str]) -> str:
    """Deterministic AttackChain identity, derived from its own
    Relationships' ids - never from unordered set/dict iteration."""
    raw = f"{chain_type}|{','.join(sorted(relationship_ids))}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _extract_cross_principal_relationships(
    findings: List[NormalizedFinding],
) -> List[Relationship]:
    """Extract Evidence-backed Relationships (TD #13) from findings
    carrying a structured TD #11 idor_comparison.

    This is normalization, not inference: every Relationship built here
    represents a fact Go's own verification-adjacent detector logic
    (ScanIDORCrossPrincipal) already proved via idor_comparison - never a
    conclusion drawn from category co-occurrence, endpoint/parameter
    proximity, or payload/evidence text similarity. A finding's structured
    idor_comparison is required; free-form text is never a substitute.

    Eligibility is gated on the *source finding's own* verification_status
    (CONFIRMED/LIKELY/PROBABLE only - see
    ELIGIBLE_RELATIONSHIP_VERIFICATION_STATUSES); the status itself is
    preserved unchanged on the resulting Relationship, never upgraded.
    """
    relationships: List[Relationship] = []

    for f in findings:
        if f.idor_comparison is None:
            continue
        if f.verification_status not in ELIGIBLE_RELATIONSHIP_VERIFICATION_STATUSES:
            continue

        relationship_type = f.idor_comparison.relationship
        rid = _relationship_id(
            relationship_type,
            [f.id],
            f.idor_comparison.owner.identity,
            f.idor_comparison.accessor.identity,
        )
        relationships.append(
            Relationship(
                relationship_id=rid,
                relationship_type=relationship_type,
                finding_ids=[f.id],
                proof=RelationshipProof(
                    owner=f.idor_comparison.owner,
                    accessor=f.idor_comparison.accessor,
                ),
                verification_status=f.verification_status,
            )
        )

    # Deterministic dedup by relationship_id. Today's extraction is 1:1
    # per qualifying finding and should never produce a duplicate id, but
    # the general model does not assume that will always hold for every
    # future relationship type.
    deduped: Dict[str, Relationship] = {}
    for r in relationships:
        deduped[r.relationship_id] = r

    return sorted(deduped.values(), key=lambda r: r.relationship_id)


def _build_cross_principal_chain(relationship: Relationship) -> AttackChain:
    """One eligible cross_principal_access Relationship is, on its own, a
    complete AttackChain: the relationship already asserts - as a single,
    structured, already-proved fact - that a distinct authenticated
    principal reached another principal's resource. There is no separate
    "weakness" finding to combine it with, and none is invented here to
    force a multi-finding shape. The owner participates only through its
    AuthContext, exactly as Go's own IDORComparison represents it - never
    through a fabricated second Finding."""
    owner_label = relationship.proof.owner.principal.label
    accessor_label = relationship.proof.accessor.principal.label

    stages = [
        ChainStage(
            stage="unauthorized_cross_principal_access",
            finding_id=relationship.finding_ids[0],
            description=(
                f"Principal '{accessor_label}' accessed a resource "
                f"belonging to principal '{owner_label}' without "
                f"authorization."
            ),
        ),
    ]

    chain_id = _chain_id(
        relationship.relationship_type,
        [relationship.relationship_id],
    )

    return AttackChain(
        title="Cross-Principal Unauthorized Object Access",
        description=(
            "A distinct, explicitly authenticated principal accessed "
            "another principal's resource without authorization, "
            "evidenced by a structured cross-principal IDOR comparison."
        ),
        chain_type="CROSS_PRINCIPAL_ACCESS",
        related_finding_ids=list(relationship.finding_ids),
        potential_impact=(
            "Unauthorized access to another principal's data or "
            "resources through missing object-level authorization."
        ),
        relationships=[relationship],
        stages=stages,
        evidence_refs=list(relationship.finding_ids),
        chain_id=chain_id,
        verification_status=relationship.verification_status,
    )


def detect_attack_chains(
    findings: List[NormalizedFinding],
) -> List[AttackChain]:
    """Build AttackChains from Evidence-backed Relationships only (TD #13).

    An AttackChain is one or more eligible Relationships - never category
    co-occurrence, same-endpoint/parameter proximity, payload/evidence
    text similarity, or any other heuristic proximity signal. Those
    remain, at most, supporting correlation (see correlate_endpoints,
    unchanged by this function) and never independently produce a chain.

    Today's only relationship source is TD #11's structured
    idor_comparison ("cross_principal_access"). Deterministic: the same
    input findings always produce the same chains, in the same order.
    """
    known_ids = {f.id for f in findings}

    relationships = _extract_cross_principal_relationships(findings)
    chains = [_build_cross_principal_chain(r) for r in relationships]

    # Final provenance invariant: every finding id a chain references must
    # actually exist in the input findings. Given the extraction above only
    # ever sources finding_ids from `findings` itself, this can only ever
    # trip on a future relationship type's bug - it is kept as an explicit,
    # testable guard rather than an assumption.
    chains = [
        c for c in chains if set(c.related_finding_ids).issubset(known_ids)
    ]

    chains.sort(key=lambda c: c.chain_id)

    return chains
