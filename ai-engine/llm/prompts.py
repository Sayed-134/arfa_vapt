BUILD_EXECUTIVE_SUMMARY_PROMPT = """You are ARFA AI Security Advisor.
Review the following security findings summary and provide a brief executive narrative.

Findings Count: {count}
Risk Breakdown: Critical={critical}, High={high}, Medium={medium}, Low={low}, Info={info}
Overall Security Posture Score: {posture}/100

Top Vulnerabilities:
{top_findings}

Provide 3 actionable executive takeaways.
"""

BUILD_REMEDIATION_PLAN_PROMPT = """Provide a phased remediation plan for the following findings:
{findings}
"""
