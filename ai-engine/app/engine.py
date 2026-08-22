from typing import Union, List, Dict, Any, Optional

from parsers.scanner_parser import parse_go_scanner_findings
from analyzers.risk_engine import evaluate_findings_risk
from analyzers.deduplicator import deduplicate_findings
from correlation.endpoint_correlator import (
    correlate_endpoints,
    detect_attack_chains,
)
from reporting.generator import ReportGenerator
from schemas.report import FinalReport
from llm.client import LLMClient


class ARFAEngine:
    def __init__(self, llm_url: Optional[str] = None):
        self.llm_client = LLMClient(endpoint_url=llm_url) if llm_url else None
        self.report_generator = ReportGenerator(
            engine_version="1.0.0",
            llm_client=self.llm_client,
        )

    def process(
        self,
        raw_input: Union[str, bytes, List[Dict[str, Any]]],
    ) -> FinalReport:
        normalized = parse_go_scanner_findings(raw_input)
        raw_count = len(normalized)

        scored = evaluate_findings_risk(normalized)

        deduped = deduplicate_findings(scored)

        correlated = correlate_endpoints(deduped)
        chains = detect_attack_chains(deduped)

        report = self.report_generator.generate(
            raw_findings_count=raw_count,
            deduplicated_findings=deduped,
            correlated_endpoints=correlated,
            attack_chains=chains,
        )

        return report
