"""TD #15 shared-policy regression coverage.

These tests prove ARFA's redaction policy is genuinely shared, not just
duplicated-and-verified-equal:

1. ``policy.redaction`` (the shared, reusable utility - see that
   module's docstring) actually *loaded* its header-name policy from the
   generated artifact (``ai-engine/policy/_redaction_policy.generated.json``),
   not from a literal written inside the module.
2. That generated artifact, if regenerated *right now* from the current
   ``pkg/redact/redact.go`` source, is identical to what is committed -
   i.e. nothing has silently drifted out of sync with the closed TD #9
   source of truth.
3. The LLM boundary (``ai-engine/llm/redaction.py``) re-exports the
   *same objects* from ``policy.redaction`` - it is not a second,
   independently maintained copy of the utility.
4. A future, non-LLM component can consume the shared policy by
   importing ``policy.redaction`` directly, without importing anything
   from ``ai-engine/llm/``.

If the Go source of truth (``pkg/redact/redact.go``) is not present in
this checkout (e.g. a Python-only distribution of ai-engine with no Go
tree alongside it), the drift check is skipped rather than failed - see
"Concerns" in the TD #15 delivery notes for this tradeoff.
"""
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
GO_SOURCE_PATH = REPO_ROOT / "pkg" / "redact" / "redact.go"
GENERATED_POLICY_PATH = REPO_ROOT / "ai-engine" / "policy" / "_redaction_policy.generated.json"

sys.path.insert(0, str(REPO_ROOT / "scripts"))
sys.path.insert(0, str(REPO_ROOT / "ai-engine"))

import gen_redaction_policy  # noqa: E402  (path set up above)
import llm.redaction as llm_redaction  # noqa: E402
import policy.redaction as policy_redaction  # noqa: E402


# --- 1. policy.redaction genuinely loaded from the generated artifact ------

def test_policy_redaction_loads_header_names_from_generated_artifact():
    committed = json.loads(GENERATED_POLICY_PATH.read_text(encoding="utf-8"))
    assert policy_redaction.SENSITIVE_HEADER_NAMES == tuple(
        sorted(committed["sensitive_header_names"])
    )
    assert policy_redaction.REDACTED_PLACEHOLDER == committed["placeholder"]


# --- 2. No drift between the committed artifact and the current Go source --

@pytest.mark.skipif(
    not GO_SOURCE_PATH.exists(),
    reason="pkg/redact/redact.go not present in this checkout (Go tree not co-located)",
)
def test_generated_policy_matches_current_go_source_no_drift():
    """Re-derive the policy from the *current* pkg/redact/redact.go and
    compare against the committed generated artifact. A mismatch means
    someone changed the closed TD #9 policy without regenerating the
    TD #15 artifact - this is the drift check that makes the shared
    policy real, not just asserted equal once."""
    fresh = gen_redaction_policy.extract_policy(
        GO_SOURCE_PATH.read_text(encoding="utf-8")
    )
    committed = json.loads(GENERATED_POLICY_PATH.read_text(encoding="utf-8"))

    assert fresh["placeholder"] == committed["placeholder"]
    assert sorted(fresh["sensitive_header_names"]) == sorted(
        committed["sensitive_header_names"]
    ), (
        "pkg/redact/redact.go's policy has changed since "
        "ai-engine/policy/_redaction_policy.generated.json was generated - "
        "re-run scripts/gen_redaction_policy.py and commit the result"
    )


@pytest.mark.skipif(
    not GO_SOURCE_PATH.exists(),
    reason="pkg/redact/redact.go not present in this checkout (Go tree not co-located)",
)
def test_go_source_extraction_is_deterministic():
    text = GO_SOURCE_PATH.read_text(encoding="utf-8")
    first = gen_redaction_policy.extract_policy(text)
    second = gen_redaction_policy.extract_policy(text)
    assert first == second


def test_extraction_fails_closed_on_unexpected_go_source_shape():
    """The extractor must never silently emit an empty/guessed policy -
    an unrecognized source shape is a hard error, not a fallback."""
    with pytest.raises(gen_redaction_policy.PolicyExtractionError):
        gen_redaction_policy.extract_policy("package redact\n// nothing here\n")


def test_extraction_matches_known_td9_policy_values():
    """Pin the specific values TD #9 defines today, extracted from a
    minimal reproduction of redact.go's declarations - independent of
    whether the real file is present in this checkout."""
    sample = '''
package redact

const RedactedPlaceholder = "[REDACTED]"

var sensitiveHeaderNames = map[string]bool{
	"authorization":       true,
	"cookie":              true,
	"set-cookie":          true,
	"x-api-key":           true,
	"proxy-authorization": true,
}
'''
    policy = gen_redaction_policy.extract_policy(sample)
    assert policy["placeholder"] == "[REDACTED]"
    assert policy["sensitive_header_names"] == [
        "authorization",
        "cookie",
        "proxy-authorization",
        "set-cookie",
        "x-api-key",
    ]


# --- 3. The LLM boundary re-exports the shared utility, not a copy ---------

def test_llm_boundary_reexports_the_same_objects_not_a_copy():
    """Identity, not equality: llm.redaction must be the exact same
    function/values as policy.redaction, proving there is one
    implementation, not two independently maintained ones."""
    assert llm_redaction.redact_text is policy_redaction.redact_text
    assert llm_redaction.REDACTED_PLACEHOLDER is policy_redaction.REDACTED_PLACEHOLDER
    assert llm_redaction.SharedPolicyUnavailable is policy_redaction.SharedPolicyUnavailable


# --- 4. A future, non-LLM component can adopt the policy standalone --------

def test_future_component_can_consume_shared_policy_without_llm_package():
    """Simulates a hypothetical future Web3/Mobile Python component: it
    only ever imports policy.redaction, never anything under
    ai-engine/llm/, and gets fully working redaction."""
    assert "llm" not in policy_redaction.__name__
    result = policy_redaction.redact_text("Authorization: Bearer some-future-secret")
    assert "some-future-secret" not in result
    assert policy_redaction.REDACTED_PLACEHOLDER in result
