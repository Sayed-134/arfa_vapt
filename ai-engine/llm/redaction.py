"""LLM boundary re-export of ARFA's shared redaction policy (TD #15).

This module is kept only so existing imports (``ai-engine/llm/client.py``
and existing tests) do not need to change. The actual, reusable
redaction utility lives in ``ai-engine/policy/redaction.py`` - see that
module's docstring for the full design rationale (policy source, why it
is not LLM-specific, why a future component should import it directly
instead of this module).

Nothing is reimplemented here: every name below is the *same object*
imported from ``policy.redaction``, not a second copy - see
``ai-engine/tests/test_redaction_policy_sync.py`` for the regression
test that pins this (identity, not just equality).
"""
from policy.redaction import (  # noqa: F401  (re-exported for llm.client and existing callers)
    REDACTED_PLACEHOLDER,
    SharedPolicyUnavailable,
    redact_text,
)
