"""Composite risk scoring for normalized findings.

TD #14 — Risk Scoring Calibration
==================================
This module's weights were introduced in Phase 1 without a written
rationale. This docstring is that rationale, made explicit and pinned by
``ai-engine/tests/test_risk_calibration.py``. No scoring behavior changes
here - existing scores (and the tests in test_risk.py that assert exact
values) are unchanged; this is documentation plus regression coverage for
calibration decisions that were already in effect.

Design: weighted signals, one damping multiplier
-----------------------------------------------------------
``calculate_risk_score`` combines three signals from the finding into a
weighted base score, then damps that base score by the verification
outcome:

1. **CVSS / severity (50%)** - the primary signal. CVSS is preferred when
   the Go scanner supplied one; severity's own weight is the fallback only
   when CVSS is absent (0.0), so this term never silently double-counts
   both.
2. **Severity (25%)** - reinforces CVSS as a second, coarser signal (a
   scanner-assigned severity independent of any specific CVSS number),
   so a finding is not solely at the mercy of one input.
3. **Detector confidence (15%)** - how sure the *detector* was about its
   own match (CERTAIN..LOW), separate from whether that match was later
   verified.
4. **Verification status (10% inside the weighted sum)** - how sure the
   *verification engine* is, contributing a modest weighted share here.

``ver_w`` (VERIFICATION_MULTIPLIERS) then does double duty: after the
weighted sum above, the *entire* score is multiplied by ``ver_w`` again.
This is intentional, not an accidental double-count. The 10% weighted term
lets verification nudge the score like any other input signal; the outer
multiplication is a deliberate global damping factor so that an unverified
or unresolved finding can never outrank a verified one of the same
severity, no matter how high its CVSS - operationally, a finding nobody
has confirmed is true carries materially less actionable risk than one
that has been, regardless of its theoretical severity. FALSE_POSITIVE's
outer multiplier of 0.0 is what guarantees a disproven finding always
scores exactly 0.0, overriding any CVSS/severity/confidence input.

Verification multiplier calibration table
------------------------------------------
======================  =====  ============================================
Status                  Value  Rationale
======================  =====  ============================================
CONFIRMED               1.0    Reproduced on an independent repeat probe and
                                absent on a benign control (see Go
                                pkg/verification.Verify) - no damping.
LIKELY / PROBABLE       0.8    Strong but not independently reproduced/
                                controlled to the same standard as CONFIRMED.
                                Equal to each other: PROBABLE is the
                                original name, LIKELY was added as an
                                equivalent status (see VERIFICATION_ORDER in
                                deduplicator.py, which also ranks them
                                equally) - calibration must not silently
                                prefer one spelling over the other.
POTENTIAL               0.6    Detector matched, but verification could not
                                strengthen it to LIKELY/CONFIRMED.
UNVERIFIED              0.4    No verification pipeline ran at all for this
                                finding (e.g. Go's IDOR heuristic phase -
                                see ARFA_MASTER_CONTEXT.md §8 item 11).
                                Deliberately calibrated *above*
                                INCONCLUSIVE: nothing here actively failed,
                                verification was simply never attempted.
INCONCLUSIVE            0.3    Verification *was* attempted and could not
                                reach a conclusion (e.g. a repeat or control
                                probe failed - see Go
                                pkg/verification.Result.Status). Calibrated
                                *below* UNVERIFIED: an attempt that could not
                                resolve carries slightly more doubt than a
                                finding that was simply never checked.
FALSE_POSITIVE          0.0    Actively disproven (evidence also present for
                                a benign control value) - always scores 0.0.
======================  =====  ============================================
"""

from typing import List
from schemas.common import (
    NormalizedFinding,
    SeverityLevel,
    ConfidenceLevel,
    VerificationStatus,
)

SEVERITY_WEIGHTS = {
    SeverityLevel.CRITICAL: 1.0,
    SeverityLevel.HIGH: 0.8,
    SeverityLevel.MEDIUM: 0.5,
    SeverityLevel.LOW: 0.2,
    SeverityLevel.INFO: 0.05,
}

CONFIDENCE_WEIGHTS = {
    ConfidenceLevel.CERTAIN: 1.0,
    ConfidenceLevel.HIGH: 0.85,
    ConfidenceLevel.MEDIUM: 0.65,
    ConfidenceLevel.LOW: 0.4,
}

# See the module docstring's calibration table above for the rationale
# behind each value, in particular why INCONCLUSIVE (0.3) is calibrated
# below UNVERIFIED (0.4) despite sounding like it should be "more resolved".
VERIFICATION_MULTIPLIERS = {
    VerificationStatus.CONFIRMED: 1.0,
    VerificationStatus.LIKELY: 0.8,
    VerificationStatus.PROBABLE: 0.8,
    VerificationStatus.POTENTIAL: 0.6,
    VerificationStatus.UNVERIFIED: 0.4,
    VerificationStatus.INCONCLUSIVE: 0.3,
    VerificationStatus.FALSE_POSITIVE: 0.0,
}


def calculate_risk_score(finding: NormalizedFinding) -> float:
    # base_score: CVSS is the primary signal when the Go scanner supplied
    # one; severity's own weight is only a fallback for the rare finding
    # with no CVSS at all (cvss <= 0), so this term never double-counts
    # both CVSS and severity - severity gets its own, separate 25% weight
    # below regardless of which branch fired here.
    base_score = (finding.cvss / 10.0) * 100.0 if finding.cvss > 0 else (
        SEVERITY_WEIGHTS.get(finding.severity, 0.1) * 100.0
    )

    sev_w = SEVERITY_WEIGHTS.get(finding.severity, 0.1)
    conf_w = CONFIDENCE_WEIGHTS.get(finding.confidence, 0.5)
    ver_w = VERIFICATION_MULTIPLIERS.get(finding.verification_status, 0.4)

    # Weighted sum of the three signals (CVSS/severity, severity, detector
    # confidence, verification status) - see the module docstring for why
    # each weight is what it is.
    calculated = (
        (0.5 * base_score)
        + (0.25 * (sev_w * 100.0))
        + (0.15 * (conf_w * 100.0))
        + (0.10 * (ver_w * 100.0))
    )

    # Deliberate second application of ver_w as a global damping
    # multiplier on the whole score - see "Design: three independent
    # signals, one damping multiplier" in the module docstring. This is
    # what makes FALSE_POSITIVE always score exactly 0.0 and what keeps an
    # UNVERIFIED/INCONCLUSIVE finding from ever outscoring a CONFIRMED one
    # of equal severity.
    final_score = calculated * ver_w
    return round(max(0.0, min(100.0, final_score)), 2)


def evaluate_findings_risk(
    findings: List[NormalizedFinding],
) -> List[NormalizedFinding]:
    updated_findings = []

    for f in findings:
        score = calculate_risk_score(f)
        updated = f.model_copy(update={"composite_risk_score": score})
        updated_findings.append(updated)

    return updated_findings
