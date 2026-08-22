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
    PROBABLE = "PROBABLE"
    POTENTIAL = "POTENTIAL"
    UNVERIFIED = "UNVERIFIED"


class FindingStatus(str, Enum):
    OPEN = "OPEN"
    RESOLVED = "RESOLVED"
    SUPPRESSED = "SUPPRESSED"


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


class CorrelatedEndpoint(BaseModel):
    endpoint: str
    findings_count: int
    highest_severity: SeverityLevel
    max_risk_score: float
    finding_ids: List[str]


class AttackChain(BaseModel):
    title: str
    description: str
    chain_type: str
    related_finding_ids: List[str]
    potential_impact: str
