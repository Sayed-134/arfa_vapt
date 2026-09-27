"""ARFA's shared, deterministic redaction policy.

This module is ARFA's one reusable redaction utility for Python
components. It is deliberately **not** part of ``ai-engine/llm/`` (the
LLM boundary): a future component that needs this same policy - a Web3
credential scanner, a Mobile evidence pipeline, or any other future
Python component - imports this module directly and never needs to
touch the LLM boundary code (``ai-engine/llm/``) to get it. The LLM
boundary (``ai-engine/llm/redaction.py``) is itself just one consumer of
this module (see that module's docstring).

Policy source (no independent duplicate):
    The header-name portion of this policy (``authorization``,
    ``cookie``, ``set-cookie``, ``x-api-key``, ``proxy-authorization``)
    is loaded at import time from ``_redaction_policy.generated.json``,
    a small artifact mechanically derived from ``pkg/redact/redact.go``
    by ``scripts/gen_redaction_policy.py`` (see that script's
    docstring). ``pkg/redact/redact.go`` is closed (TD #9) and is never
    modified, imported at runtime, or reinterpreted here - it remains
    the single authored source of truth for that list; this module only
    consumes a generated derivative of it. If the generated artifact is
    missing or malformed, loading fails closed (raises
    ``SharedPolicyUnavailable``) rather than silently falling back to a
    hand-maintained duplicate, since that would recreate exactly the
    "two independently maintained lists" problem this module exists to
    avoid.

    On top of that shared header-name policy, this module adds explicit,
    fixed text-redaction extensions with no Go counterpart (``pkg/redact/``
    only ever handled HTTP header names): Bearer/Basic credential
    schemes, API-key-like values, password-like fields, and
    secret-bearing ``name=value``/``name: value`` pairs as they appear in
    free text, URL query strings, or form-style bodies. These are not
    policy duplication - they are additional scope this module owns
    outright.

Design principle (unchanged from TD #9's ``pkg/redact``): an explicit,
fixed set of names/patterns only - no heuristic, statistical, ML, or
LLM-based inference of what "looks" sensitive. The same input always
produces the same output. Redaction is scoped to secret-shaped
constructs only (a name/scheme immediately followed by its value) so
that ordinary analytical prose - finding names, categories, endpoints,
severities, CVSS scores, remediation text - is never touched merely for
mentioning a word like "token" in passing.
"""
from pathlib import Path
from typing import Optional
import json
import re

_POLICY_PATH = Path(__file__).with_name("_redaction_policy.generated.json")


class SharedPolicyUnavailable(RuntimeError):
    """Raised when the generated shared-policy artifact is missing or
    malformed. Fail-closed by design (see module docstring): this module
    never falls back to a hand-maintained duplicate of the header-name
    list if the shared artifact cannot be loaded. Regenerate the
    artifact with ``scripts/gen_redaction_policy.py``.
    """


def load_shared_header_policy(path: Path = _POLICY_PATH) -> dict:
    """Load the header-name policy generated from ``pkg/redact/redact.go``.

    Returns ``{"placeholder": str, "sensitive_header_names": tuple}``.
    Any future component may call this directly instead of importing the
    module-level constants below, if it wants to reload from a different
    path (e.g. in a test).
    """
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        placeholder = data["placeholder"]
        header_names = tuple(sorted(data["sensitive_header_names"]))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise SharedPolicyUnavailable(
            f"could not load shared redaction policy from {path}: {exc}"
        ) from exc
    if not header_names or not placeholder:
        raise SharedPolicyUnavailable(
            f"shared redaction policy at {path} is empty or malformed"
        )
    return {"placeholder": placeholder, "sensitive_header_names": header_names}


_SHARED_POLICY = load_shared_header_policy()

#: Placeholder substituted for any redacted value. Loaded from the
#: generated artifact, which mirrors ``pkg/redact.RedactedPlaceholder``
#: (TD #9) exactly - see module docstring.
REDACTED_PLACEHOLDER = _SHARED_POLICY["placeholder"]

#: The header-name set pkg/redact/redact.go (TD #9) defines, mechanically
#: derived rather than hand-copied - see module docstring.
SENSITIVE_HEADER_NAMES = _SHARED_POLICY["sensitive_header_names"]

# Explicit, fixed field/parameter names with no Go counterpart - this
# module's own extension, not a duplicate of anything in pkg/redact/.
# See module docstring for why this is not a heuristic.
_SENSITIVE_FIELD_NAMES = (
    "api_key",
    "apikey",
    "api-key",
    "access_token",
    "access-token",
    "client_secret",
    "client-secret",
    "secret",
    "token",
    "password",
    "passwd",
    "pwd",
)

_ALL_SENSITIVE_NAMES = tuple(
    sorted(set(SENSITIVE_HEADER_NAMES) | set(_SENSITIVE_FIELD_NAMES))
)
_NAME_ALTERNATION = "|".join(re.escape(name) for name in _ALL_SENSITIVE_NAMES)

# 1. "Name: value" header-style lines (Authorization:, Cookie:, X-Api-Key:,
#    Password:, ...). Case-insensitive, matches the whole remainder of the
#    line so a sensitive value can never partially survive on the same
#    line as its field name. Scoped to lines that *start* with the field
#    name (optional leading whitespace only) so prose that merely mentions
#    a sensitive-sounding word mid-sentence is untouched.
_HEADER_LINE_RE = re.compile(
    rf"(?im)^([ \t]*(?:{_NAME_ALTERNATION})[ \t]*:)[ \t]*.*$"
)

# 2. "name=value" / "name: value" pairs as they appear inline in free
#    text, URL query strings, or form-encoded bodies (e.g.
#    "token=abc123", "?access_token=xyz&user=alice"). Requires the
#    separator and a value to be present, so a bare mention of the word
#    (e.g. "the token expired") is never touched.
_KV_PAIR_RE = re.compile(
    rf"(?i)\b({_NAME_ALTERNATION})\b\s*[:=]\s*([^\s&,;]+)"
)

# 3. Bearer / Basic authentication scheme values, wherever they occur -
#    inside an Authorization-style value or embedded directly in prose.
_BEARER_BASIC_RE = re.compile(r"(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9\-._~+/]+=*")


def redact_text(text: Optional[str]) -> Optional[str]:
    """Deterministically redact sensitive content from ``text``.

    Applies, in a fixed order, the header-name policy shared with
    ``pkg/redact/`` (TD #9) plus this module's own text/credential
    extensions (see module docstring). ``None`` or empty input is
    returned unchanged - there is nothing to redact. The same input
    always produces the same output; nothing is redacted based on
    heuristic content inspection, only on membership in the fixed
    name/pattern lists above, and only where a name is actually paired
    with a value (or a Bearer/Basic scheme is present) - not merely
    mentioned. Ordinary analytical/security prose (finding names,
    categories, endpoints, severities, CVSS scores, remediation
    guidance) is preserved untouched.

    This function never raises for ordinary string input. Callers (see
    ``ai-engine/llm/redaction.py``) still wrap it in ``try/except`` so
    any unexpected failure is treated fail-closed rather than allowing
    raw content through.
    """
    if not text:
        return text

    redacted = _BEARER_BASIC_RE.sub(REDACTED_PLACEHOLDER, text)
    redacted = _HEADER_LINE_RE.sub(rf"\1 {REDACTED_PLACEHOLDER}", redacted)
    redacted = _KV_PAIR_RE.sub(
        lambda m: f"{m.group(1)}={REDACTED_PLACEHOLDER}", redacted
    )
    return redacted
