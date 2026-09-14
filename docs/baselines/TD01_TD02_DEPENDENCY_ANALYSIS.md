# TD #1 ↔ TD #2 Dependency Analysis

**Scope:** Read-only analysis. No implementation of TD #1 or TD #2 is
included in this task or this document.

**Source inspected:** `pkg/crawler/crawler.go`, `pkg/crawler/canonical.go`,
`pkg/models/models.go`, `pkg/scanner/scanner.go`, at commit `933309e`
(current `main` at time of analysis — see §0).

**References:** `ARFA_MASTER_CONTEXT.md` §8 / §18 Phase 4:

- TD #1 — "Crawler is regex/GET oriented."
- TD #2 — "Forms and POST discovery need proper support."

## 0. Baseline state note

`ARFA_MASTER_CONTEXT.md` §2 records `main` as `94cf2fa`. The live clone
used for this analysis (`git clone` from `github.com/Sayed-134/arfa_vapt`,
verified immediately before analysis, per the project's standing rule to
never assume repository state from cache) is at `933309e` — four commits
ahead, all documentation-only (`PLATFORM_STRATEGY.md` addition, Zetsu
note, TD #3 closure docs). No Phase 4 code beyond the already-closed TD #3
canonicalization work has landed. This does not affect the TD #1/#2
analysis below, but is flagged here per the project's source-of-truth
rule: `ARFA_MASTER_CONTEXT.md`'s recorded commit hash is stale relative to
`origin/main` and should be refreshed independently of this task.

## 1. What the crawler actually does today

`Crawler.Crawl()` (`pkg/crawler/crawler.go`):

1. Maintains a BFS `queue` of URLs, bounded by `maxPages`.
2. Fetches each URL with a **hardcoded** `"GET"` request
   (`c.client.Do(ctx, "GET", u, nil)`, line 62).
3. Extracts candidate parameter names with three independent, flat
   regexes applied to the raw response body:
   - `linkRe` — any `href=`/`src=`/`action=` attribute value, used only
     for link discovery (queueing more pages), not parameters.
   - `inputRe` — `<input ... name="...">`, anywhere in the document.
   - `selectRe` — `<textarea|select ... name="...">`, anywhere in the
     document.
4. Every matched `name` from steps (3) is unioned into one flat
   `Parameters` list attached to the endpoint's URL — **regardless of
   which `<form>`, if any, actually contains that input**, and regardless
   of that form's `method` or `action`.
5. Builds exactly one `models.Endpoint{URL: u, Method: "GET", Parameters: p}`
   per discovered page. `Method` is `"GET"` at both construction sites
   (line 83 and the zero-endpoint fallback at line 105) — there is no
   code path that ever produces a non-GET `Endpoint`.

`models.Endpoint` already declares a `FormParameters []string
"json:\"form_parameters,omitempty\""` field (`pkg/models/models.go:9`), but
a repo-wide search confirms this field is **never written to and never
read anywhere** — it is a placeholder the model anticipates, not a
capability that exists yet. There is likewise no occurrence of the string
`"POST"` anywhere under `pkg/`.

Downstream, `pkg/scanner`'s `Transport` interface and `rawProbe` already
accept an arbitrary method string
(`s.http.Do(ctx, ep.Method, ep.URL, params)` in `scanner.go`), and always
use whatever `ep.Method` the crawler assigned. **The probe/verification
layer is not the blocker for POST support — it already passes `ep.Method`
through unmodified.** The blocker is entirely upstream, in the crawler:
nothing ever discovers a form's method, action, or which inputs are
scoped to which form, and nothing ever constructs an `Endpoint` with
`Method: "POST"`.

## 2. Is TD #1 "half of TD #2"?

**Partially — TD #1's necessary rework is a prerequisite for TD #2, but
TD #1 as scoped ("regex/GET orientation") does not itself require
delivering POST support.** Two separable problems are tangled in the
current implementation:

| Problem | Owned by |
|---|---|
| Parsing is three independent, unscoped regexes with no notion of document structure (a `<form>` element, its boundary, its own `method`/`action`) | TD #1 |
| Every discovered endpoint is unconditionally `Method: "GET"` | Both — the *cause* is TD #1's flat extraction; the *fix target* (emitting `POST` endpoints, form-encoded submission) is TD #2 |
| No `<form>`-scoped parameter grouping (which inputs belong to which submission) | TD #2, but structurally requires TD #1's parser to have an element/DOM concept in the first place |
| POST body construction / content-type handling for probes | TD #2 only — `pkg/scanner`'s `Transport`/`rawProbe` already accept a method; this is new work regardless of TD #1 |

So: a **minimal, strictly-scoped TD #1** (e.g., swapping the three flat
regexes for a real HTML tokenizer/parser to fix correctness bugs —
malformed HTML, nested quotes, self-closing tags, case sensitivity —
while still emitting a single flat `Parameters` list and still hardcoding
`Method: "GET"`) would **not** deliver TD #2 and would leave the
`FormParameters` field still unused. That is a legitimate, isolated TD #1.

But if TD #1 is implemented by introducing genuine DOM/element awareness
(which a real parser naturally provides), the *cheapest* way to get there
is to model `<form>` boundaries at the same time — because a proper
parser has no reason to still special-case "match `<input>` anywhere in
the byte stream" once it can walk the tree. That version of TD #1 would
substantially overlap TD #2's discovery half (parsing `<form
method=... action=...>`, scoping inputs to their form), leaving only
POST-body construction/probing genuinely unique to TD #2.

**Conclusion: not "TD #1 = half of TD #2" as a fixed fact — it depends on
how narrowly TD #1 is scoped.** The two TDs share a real, single point of
architectural overlap (the crawler's HTML parsing strategy), but TD #2
also has scanner-side work (POST body/content-type handling for probes)
that is entirely outside TD #1 regardless of scoping choice.

## 3. Recommendation

Given the project's standing TD-isolation rule (one TD per branch, no
cross-contamination, minimal reviewable diffs — `ARFA_MASTER_CONTEXT.md`
§13/§15, `ARCHITECTURE.md` §26), the two safe options are:

**Option A — Sequence them, TD #1 first, scoped narrowly (recommended).**
Implement TD #1 as a parsing-robustness fix only: replace the three flat
regexes with a real HTML parser, fix the known correctness gaps (matching
scoped to element context, not raw byte-offset regex), but **do not**
change `Method` handling and **do not** introduce form-scoped grouping in
TD #1's diff. Explicitly design the new parser with an extensible
element/node model (so TD #2 doesn't have to redo the parsing foundation
from scratch), but keep TD #1's *behavioral* diff to parsing correctness
only. Then implement TD #2 afterward, on its own branch, adding
`<form>`-element awareness (action/method extraction, scoped
`FormParameters`) and the scanner-side POST submission path.

- Preserves strict TD isolation and small, reviewable diffs.
- Avoids parsing the HTML twice in production (TD #2 reuses TD #1's
  parser, it just doesn't get built in the same patch).
- Risk: if TD #1's reviewer/tests implicitly expect form-awareness
  "since we're already rewriting the parser," scope creep is likely —
  this must be called out explicitly in the TD #1 plan and enforced at
  patch-review time.

**Option B — Merge into a single combined TD (not recommended given
current process).** Avoids writing the parser twice, but produces a
larger, harder-to-review diff spanning crawler discovery, endpoint model
usage (`FormParameters`), and scanner probe construction — in tension
with the project's "minimal, single-scope, isolated" TD workflow and with
`ARCHITECTURE.md`'s explicit `pkg/scanner`/`pkg/crawler` protected-path
rule (changes must be "the minimum required," §25).

**This analysis makes no recommendation on reordering relative to other
open TDs (#4–#16)** — only on the internal relationship between #1 and
#2. Reordering the Phase 4 backlog itself is Sayed's call.

## 4. What this analysis is not

This document does not design TD #1 or TD #2's implementation, does not
propose an HTML parser library, and does not modify `pkg/crawler` or any
other source file. It is strictly the dependency read requested for this
baseline task.
