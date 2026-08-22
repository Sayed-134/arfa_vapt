from datetime import datetime, timezone
from typing import List, Optional

from schemas.common import (
    NormalizedFinding,
    CorrelatedEndpoint,
    AttackChain,
    SeverityLevel,
)

from schemas.report import (
    FinalReport,
    ReportMetadata,
    ExecutiveSummary,
    RiskDistribution,
)

from llm.client import LLMClient
from llm.prompts import BUILD_EXECUTIVE_SUMMARY_PROMPT


class ReportGenerator:
    def __init__(
        self,
        engine_version: str = "1.0.0",
        llm_client: Optional[LLMClient] = None,
    ):
        self.engine_version = engine_version
        self.llm_client = llm_client

    def _build_risk_distribution(
        self,
        findings: List[NormalizedFinding],
    ) -> RiskDistribution:
        dist = RiskDistribution()

        for f in findings:
            if f.severity == SeverityLevel.CRITICAL:
                dist.critical += 1
            elif f.severity == SeverityLevel.HIGH:
                dist.high += 1
            elif f.severity == SeverityLevel.MEDIUM:
                dist.medium += 1
            elif f.severity == SeverityLevel.LOW:
                dist.low += 1
            elif f.severity == SeverityLevel.INFO:
                dist.info += 1

        return dist

    def _calculate_posture_score(
        self,
        dist: RiskDistribution,
        total: int,
    ) -> float:
        if total == 0:
            return 100.0

        penalty = (
            (dist.critical * 30.0)
            + (dist.high * 15.0)
            + (dist.medium * 5.0)
            + (dist.low * 1.0)
        )

        score = max(0.0, 100.0 - penalty)
        return round(score, 2)

    def _generate_key_observations(
        self,
        dist: RiskDistribution,
        posture_score: float,
        findings: List[NormalizedFinding],
    ) -> List[str]:
        observations = []

        if dist.critical > 0:
            observations.append(
                f"Urgent action required: {dist.critical} CRITICAL severity vulnerability detected requiring immediate isolation."
            )

        if dist.high > 0:
            observations.append(
                f"High risk surface: {dist.high} HIGH severity issues identified impacting target application boundary."
            )

        if posture_score >= 80.0:
            observations.append(
                "Overall security posture is robust with minimal critical exposure."
            )
        elif posture_score >= 50.0:
            observations.append(
                "Security posture shows moderate exposure requiring prioritized patch cycles."
            )
        else:
            observations.append(
                "Elevated risk posture with multiple unmitigated entry points."
            )

        if self.llm_client and self.llm_client.is_available:
            top_sample = "\n".join(
                [
                    f"- {f.name} ({f.severity.value}) on {f.endpoint}"
                    for f in findings[:5]
                ]
            )

            prompt = BUILD_EXECUTIVE_SUMMARY_PROMPT.format(
                count=len(findings),
                critical=dist.critical,
                high=dist.high,
                medium=dist.medium,
                low=dist.low,
                info=dist.info,
                posture=posture_score,
                top_findings=top_sample,
            )

            ai_obs = self.llm_client.generate_summary_observation(prompt)

            if ai_obs:
                observations.append(f"[AI Observation] {ai_obs}")

        return observations

    def generate(
        self,
        raw_findings_count: int,
        deduplicated_findings: List[NormalizedFinding],
        correlated_endpoints: List[CorrelatedEndpoint],
        attack_chains: List[AttackChain],
    ) -> FinalReport:
        dist = self._build_risk_distribution(deduplicated_findings)

        posture_score = self._calculate_posture_score(
            dist,
            len(deduplicated_findings),
        )

        key_observations = self._generate_key_observations(
            dist,
            posture_score,
            deduplicated_findings,
        )

        exec_summary = ExecutiveSummary(
            total_findings=raw_findings_count,
            unique_findings=len(deduplicated_findings),
            overall_posture_score=posture_score,
            risk_distribution=dist,
            key_observations=key_observations,
        )

        meta = ReportMetadata(
            generated_at=datetime.now(timezone.utc).isoformat(),
            engine_version=self.engine_version,
            input_findings_count=raw_findings_count,
            deduplicated_count=len(deduplicated_findings),
            llm_assisted=bool(
                self.llm_client and self.llm_client.is_available
            ),
        )

        return FinalReport(
            metadata=meta,
            executive_summary=exec_summary,
            correlated_endpoints=correlated_endpoints,
            attack_chains=attack_chains,
            findings=deduplicated_findings,
        )
