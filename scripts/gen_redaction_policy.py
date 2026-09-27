#!/usr/bin/env python3
"""Generate the shared redaction policy artifact from pkg/redact/redact.go.

TD #15 requires that the Go (TD #9, `pkg/redact`) and Python (TD #15,
`ai-engine/llm/redaction.py`) redaction boundaries share one policy
source rather than maintain two independent copies of the sensitive
header-name list.

`pkg/redact/redact.go` is closed (TD #9) and is not modified by TD #15.
Instead, this script treats `pkg/redact/redact.go`'s existing
`sensitiveHeaderNames` map and `RedactedPlaceholder` constant as the
single source of truth, and mechanically derives a small JSON artifact
from that Go source text. Nothing here re-implements or reinterprets the
policy - it extracts the exact literal values already committed in the
closed Go file.

The extraction is intentionally narrow and deterministic: it matches
only the two specific declarations `pkg/redact/redact.go` is known to
contain (see PHASE_4_TD_SPECS.md TD #9). It is not a general Go parser
and does not attempt to understand arbitrary Go source - if the
declarations it looks for are not found in the expected shape, it fails
loudly (non-zero exit / raised exception) rather than silently emitting
an empty or stale policy. This mirrors the project's "explicit list, no
inference, conservative fallback" design principle (see TD #5, TD #9).

Usage:
    python3 scripts/gen_redaction_policy.py \\
        --go-source pkg/redact/redact.go \\
        --out ai-engine/policy/_redaction_policy.generated.json

The artifact lives in `ai-engine/policy/` - ARFA's shared, reusable
Python redaction utility (see that package's `redaction.py`) - rather
than under `ai-engine/llm/`, so that a future non-LLM Python component
can consume the same policy without importing anything from the LLM
boundary.

Re-run this script and commit the regenerated artifact whenever
`pkg/redact/redact.go`'s policy declarations change. A companion test
(`ai-engine/tests/test_redaction_policy_sync.py`) re-derives the policy
from the current Go source at test time and fails if it no longer
matches the committed artifact, so drift cannot go unnoticed.
"""
import argparse
import json
import re
import sys
from pathlib import Path

_PLACEHOLDER_RE = re.compile(
    r'const\s+RedactedPlaceholder\s*=\s*"([^"]*)"'
)

# Captures the body of `var sensitiveHeaderNames = map[string]bool{ ... }`
# non-greedily up to the first closing brace, matching the exact,
# single-purpose literal in pkg/redact/redact.go.
_MAP_BLOCK_RE = re.compile(
    r"var\s+sensitiveHeaderNames\s*=\s*map\[string\]bool\{(.*?)\}",
    re.DOTALL,
)

# Within the map body: "name": true entries.
_MAP_ENTRY_RE = re.compile(r'"([a-z0-9\-]+)"\s*:\s*true')


class PolicyExtractionError(RuntimeError):
    """Raised when the expected Go declarations cannot be found/parsed.

    Deliberately fatal (fail-closed): a policy artifact must never be
    generated from a partial or guessed extraction.
    """


def extract_policy(go_source_text: str) -> dict:
    placeholder_match = _PLACEHOLDER_RE.search(go_source_text)
    if not placeholder_match:
        raise PolicyExtractionError(
            "could not find 'const RedactedPlaceholder = \"...\"' in the "
            "given Go source"
        )

    map_match = _MAP_BLOCK_RE.search(go_source_text)
    if not map_match:
        raise PolicyExtractionError(
            "could not find 'var sensitiveHeaderNames = map[string]bool{...}' "
            "in the given Go source"
        )

    names = sorted(set(_MAP_ENTRY_RE.findall(map_match.group(1))))
    if not names:
        raise PolicyExtractionError(
            "sensitiveHeaderNames map was found but no \"name\": true "
            "entries could be extracted from it"
        )

    return {
        "source": "pkg/redact/redact.go",
        "placeholder": placeholder_match.group(1),
        "sensitive_header_names": names,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--go-source",
        default="pkg/redact/redact.go",
        help="Path to the closed TD #9 Go source file (default: %(default)s)",
    )
    parser.add_argument(
        "--out",
        default="ai-engine/policy/_redaction_policy.generated.json",
        help="Path to write the generated JSON artifact (default: %(default)s)",
    )
    args = parser.parse_args(argv)

    go_source_path = Path(args.go_source)
    try:
        go_source_text = go_source_path.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"error: could not read {go_source_path}: {exc}", file=sys.stderr)
        return 1

    try:
        policy = extract_policy(go_source_text)
    except PolicyExtractionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(policy, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
