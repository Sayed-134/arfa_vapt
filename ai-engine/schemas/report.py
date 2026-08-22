from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from .common import (
    NormalizedFinding,
    CorrelatedEndpoint,
    AttackChain,
    SeverityLevel,
)


class RiskDistribution(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class ExecutiveSummary(BaseModel):
    total_findings: int
    unique_findings: int
    overall_posture_score: float = Field(ge=0.0, le=100.0)
    risk_distribution: RiskDistribution
    key_observations: List[str]


class ReportMetadata(BaseModel):
    generated_at: str
    engine_version: str
    input_findings_count: int
    deduplicated_count: int
    llm_assisted: bool


class FinalReport(BaseModel):
    metadata: ReportMetadata
    executive_summary: ExecutiveSummary
    correlated_endpoints: List[CorrelatedEndpoint]
    attack_chains: List[AttackChain]
    findings: List[NormalizedFinding]
    raw_summary: Optional[Dict[str, Any]] = None
