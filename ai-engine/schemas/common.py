from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ConfidenceLevel(str, Enum):
    CERTAIN = "CERTAIN"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class VerificationStatus(str, Enum):
    CONFIRMED = "CONFIRMED"
    LIKELY = "LIKELY"
    PROBABLE = "PROBABLE"
    POTENTIAL = "POTENTIAL"
    UNVERIFIED = "UNVERIFIED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    INCONCLUSIVE = "INCONCLUSIVE"


class FindingStatus(str, Enum):
    OPEN = "OPEN"
    RESOLVED = "RESOLVED"
    SUPPRESSED = "SUPPRESSED"


class AuthPrincipalModel(BaseModel):
    """Mirrors Go's models.AuthPrincipal exactly (TD #11). label is an
    operator-supplied, human-readable reference - never a credential,
    token, or cookie value; nothing here transforms or infers it."""
    label: str


class AuthContextModel(BaseModel):
    """Mirrors Go's models.AuthContext exactly (TD #11). session_ref and
    identity are already safe, one-way-derived, non-secret references (see
    pkg/models/auth_context.go) - never raw credential/session material."""
    principal: AuthPrincipalModel
    session_ref: Optional[str] = None
    identity: str


class IDORComparisonModel(BaseModel):
    """Mirrors Go's models.IDORComparison exactly (TD #11): a structured
    cross-principal IDOR comparison outcome. relationship is a fixed,
    deterministic identifier (e.g. "cross_principal_access"), never
    free-form text."""
    owner: AuthContextModel
    accessor: AuthContextModel
    relationship: str


class RawGoFinding(BaseModel):
    category: Optional[str] = None
    name: Optional[str] = None
    severity: Optional[str] = None
    cvss: Optional[float] = None
    confidence: Optional[str] = None
    endpoint: Optional[str] = None
    parameter: Optional[str] = None
    payload: Optional[str] = None
    encoding: Optional[str] = None
    evidence: Optional[str] = None
    poc: Optional[str] = None
    impact: Optional[str] = None
    remediation: Optional[str] = None
    status: Optional[str] = None
    verification_status: Optional[str] = None
    verification_detail: Optional[str] = None
    # TD #11 — additive, structured principal/session and cross-principal
    # IDOR comparison data. Optional/None for every finding that does not
    # carry it (every finding produced before TD #11, and every non-IDOR
    # finding today).
    auth_context: Optional[AuthContextModel] = None
    idor_comparison: Optional[IDORComparisonModel] = None


class NormalizedFinding(BaseModel):
    id: str
    category: str
    name: str
    severity: SeverityLevel
    cvss: float = Field(ge=0.0, le=10.0)
    confidence: ConfidenceLevel
    endpoint: str
    parameter: Optional[str] = None
    payload: Optional[str] = None
    encoding: Optional[str] = None
    evidence: Optional[str] = None
    poc: Optional[str] = None
    impact: Optional[str] = None
    remediation: Optional[str] = None
    status: FindingStatus = FindingStatus.OPEN
    verification_status: VerificationStatus
    verification_detail: Optional[str] = None
    composite_risk_score: float = Field(ge=0.0, le=100.0)
    dedup_fingerprint: str
    occurrence_count: int = 1
    # TD #11 — additive, structured passthrough (see RawGoFinding above).
    auth_context: Optional[AuthContextModel] = None
    idor_comparison: Optional[IDORComparisonModel] = None


class CorrelatedEndpoint(BaseModel):
    endpoint: str
    findings_count: int
    highest_severity: SeverityLevel
    max_risk_score: float
    finding_ids: List[str]


class RelationshipProof(BaseModel):
    """Type-specific structured proof for a Relationship (TD #13). For
    "cross_principal_access", the embedded AuthContextModel pair mirrors
    Go's own IDORComparison shape exactly (see PLATFORM_STRATEGY.md's
    provenance principle) rather than flattening it, preserving Go<->Python
    semantic continuity and allowing future safe AuthContext fields to flow
    through without redesigning this model. Never carries raw credentials,
    cookies, tokens, or session material - AuthContextModel structurally
    cannot (see AuthContextModel's doc comment)."""
    owner: AuthContextModel
    accessor: AuthContextModel


class Relationship(BaseModel):
    """An Evidence-backed Relationship (TD #13): a Python-side, additive
    representation of a structured fact a detector already proved - never
    an inference over free text, category co-occurrence, or spatial
    proximity (same endpoint/parameter). The base model is intentionally
    relationship-type agnostic; "proof" is the only type-specific part, so
    a future Relationship type needs only its own proof shape and
    extraction logic, never a redesign of this model or of AttackChain."""
    relationship_id: str
    relationship_type: str
    finding_ids: List[str]
    proof: RelationshipProof
    # Preserved, read-only passthrough of the source finding's own
    # verification_status - never computed, upgraded, or reinterpreted
    # here. See AttackChain.verification_status for the chain-level
    # passthrough of the same value.
    verification_status: VerificationStatus


class ChainStage(BaseModel):
    """An optional, additive description of one participant's role in an
    AttackChain. Not foundational to TD #13 correctness - a chain's
    validity never depends on stages being populated or on there being
    more than one. finding_id is None when this stage's participant has no
    Finding of its own (e.g. the owner side of a cross_principal_access
    relationship, whose baseline access never produced a Finding - see
    pkg/detectors/idor.go)."""
    stage: str
    finding_id: Optional[str] = None
    description: str


class AttackChain(BaseModel):
    title: str
    description: str
    chain_type: str
    related_finding_ids: List[str]
    potential_impact: str
    # --- additive, TD #13 ---
    # relationships is the authoritative content of this chain: an
    # AttackChain is one or more eligible Evidence-backed Relationships,
    # never category co-occurrence or a correlation signal on its own.
    relationships: List[Relationship] = Field(default_factory=list)
    stages: List[ChainStage] = Field(default_factory=list)
    # evidence_refs and related_finding_ids/finding_ids are kept
    # semantically distinct even though they happen to coincide for the
    # relationship types available today (see Relationship's doc comment)
    # - evidence_refs points at evidence/proof artifacts, not necessarily
    # 1:1 with participating findings for every future relationship type.
    evidence_refs: List[str] = Field(default_factory=list)
    chain_id: str = ""
    # Read-only passthrough of the strongest/sole relationship's own
    # verification_status - never invented, never upgraded past what the
    # source finding(s) already established.
    verification_status: Optional[VerificationStatus] = None
