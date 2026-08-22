from typing import List, Dict
from schemas.common import (
    NormalizedFinding,
    CorrelatedEndpoint,
    AttackChain,
    SeverityLevel,
)

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


def detect_attack_chains(
    findings: List[NormalizedFinding],
) -> List[AttackChain]:
    chains: List[AttackChain] = []

    cats: Dict[str, List[str]] = {}

    for f in findings:
        cat_lower = f.category.lower()

        if cat_lower not in cats:
            cats[cat_lower] = []

        cats[cat_lower].append(f.id)

    auth_ids = (
        cats.get("authentication", [])
        + cats.get("session management", [])
        + cats.get("authorization", [])
    )

    injection_ids = (
        cats.get("sql injection", [])
        + cats.get("command injection", [])
        + cats.get("sqli", [])
    )

    idor_ids = (
        cats.get("idor", [])
        + cats.get("broken object level authorization", [])
    )

    if auth_ids and injection_ids:
        chains.append(
            AttackChain(
                title="Broken Authentication to Remote Command / SQL Injection",
                description="Weaknesses in authentication/authorization permit access to vulnerable endpoints where SQL or Command Injection can be executed unhindered.",
                chain_type="AUTH_BYPASS_TO_RCE_OR_SQLI",
                related_finding_ids=list(set(auth_ids + injection_ids)),
                potential_impact="Complete database exfiltration or remote system compromise through unauthorized injection vectors.",
            )
        )

    if auth_ids and idor_ids:
        chains.append(
            AttackChain(
                title="Session Flaw to Direct Object Manipulation (IDOR)",
                description="Improper session or token verification combined with IDOR allows unauthorized tenant data harvesting.",
                chain_type="SESSION_FLAW_TO_DATA_LEAK",
                related_finding_ids=list(set(auth_ids + idor_ids)),
                potential_impact="Mass horizontal and vertical privilege escalation leading to multi-tenant data exposure.",
            )
        )

    info_ids = (
        cats.get("information disclosure", [])
        + cats.get("sensitive data exposure", [])
    )

    xss_ids = (
        cats.get("xss", [])
        + cats.get("cross-site scripting", [])
    )

    if info_ids and xss_ids:
        chains.append(
            AttackChain(
                title="Information Disclosure to Session Takeover via XSS",
                description="Disclosed debug information or token formats reduce exploit complexity for stored or reflected Cross-Site Scripting.",
                chain_type="INFO_LEAK_TO_ACCOUNT_TAKEOVER",
                related_finding_ids=list(set(info_ids + xss_ids)),
                potential_impact="Administrative account compromise and client-side secret exfiltration.",
            )
        )

    return chains
