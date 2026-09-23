package detectors

import (
	"arfa/pkg/models"
	"context"
	"net/url"
	"strconv"
	"strings"
)

// IDORProbe performs a raw parameter probe for IDOR analysis using an
// explicit value rather than a models.Payload, because IDOR mutation is
// derived from the endpoint's own original identifier value (e.g. id=482 ->
// id=481, id=483), not from a line in the payload database.
type IDORProbe func(ctx context.Context, ep models.Endpoint, param, value string) models.ProbeResult

// ScanIDOR performs lightweight differential analysis on numeric-looking
// identifier parameters: it requests the endpoint's original value, then a
// decremented and an incremented neighbour, and flags cases where a mutated
// identifier still returns a substantive, distinct 200 response.
//
// This is a heuristic signal only. It always reports Confidence "Low" and
// VerificationStatus "UNVERIFIED" — never CONFIRMED — because confirming a
// real IDOR requires knowing whether the returned record belongs to a
// different principal/account, which needs authenticated, application-
// specific context this scanner does not have. A human must confirm these.
func ScanIDOR(ctx context.Context, ep models.Endpoint, probe IDORProbe) []models.Finding {
	var out []models.Finding
	u, err := url.Parse(ep.URL)
	if err != nil {
		return out
	}
	q := u.Query()
	for _, param := range ep.Parameters {
		raw := q.Get(param)
		if raw == "" {
			continue
		}
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			continue
		}
		baseline := probe(ctx, ep, param, raw)
		if baseline.Err != nil || baseline.Status != 200 || len(baseline.Body) == 0 {
			continue
		}
		for _, delta := range []int64{-1, 1} {
			if n+delta < 0 {
				continue
			}
			mutated := strconv.FormatInt(n+delta, 10)
			pr := probe(ctx, ep, param, mutated)
			if pr.Err != nil || pr.Status != 200 {
				continue
			}
			if looksLikeDenial(pr.Body) {
				continue
			}
			if len(pr.Body) > 40 && similarity(baseline.Body, pr.Body) < 0.98 {
				out = append(out, models.Finding{
					Category:           "IDOR",
					Name:                "Potential Insecure Direct Object Reference",
					Severity:            "Medium",
					CVSS:                "6.5",
					Confidence:          "Low",
					Endpoint:            ep.URL,
					Parameter:           param,
					Payload:             mutated,
					Encoding:            "plain",
					Evidence:            "Adjacent identifier returned a distinct, substantive HTTP 200 response",
					PoC:                 pr.URL,
					Impact:              "Requires manual confirmation that the returned data belongs to a different principal/object owner.",
					Remediation:         "Enforce object-level authorization checks server-side; never rely on client-supplied identifiers alone.",
					Status:              pr.Status,
					VerificationStatus:  string(Unverified),
					VerificationDetail:  "IDOR requires authenticated, application-specific confirmation this scanner cannot perform automatically",
				})
			}
		}
	}
	return out
}

// AuthProbe has the same shape as IDORProbe. It is a distinct named type
// so TD #11's context-aware IDOR call sites are explicit about supplying a
// probe that has already been bound to a specific AuthContext's session
// material (e.g. an auth header) by the caller - pkg/detectors never sees
// or stores that raw material, only the safe models.AuthContext reference
// passed alongside it (see PrincipalProbe).
type AuthProbe func(ctx context.Context, ep models.Endpoint, param, value string) models.ProbeResult

// PrincipalProbe pairs a models.AuthContext with the AuthProbe that
// executes requests under it, for TD #11's context-aware IDOR functions.
type PrincipalProbe struct {
	Context models.AuthContext
	Probe   AuthProbe
}

// ScanIDORWithContext runs the same single-principal heuristic as ScanIDOR
// and additionally attaches authCtx, when non-nil, to every resulting
// finding - recording which explicit, operator-supplied principal/session
// the probe executed under (TD #11 — IDOR authenticated principal/session
// context). It does not change ScanIDOR's own detection logic, evidence,
// or VerificationStatus: results remain always UNVERIFIED, same as
// ScanIDOR (see its doc comment). A single principal alone is still never
// enough to confirm - or even suggest - cross-principal access; only
// ScanIDORCrossPrincipal's explicit multi-context comparison does that.
func ScanIDORWithContext(ctx context.Context, ep models.Endpoint, probe IDORProbe, authCtx *models.AuthContext) []models.Finding {
	findings := ScanIDOR(ctx, ep, probe)
	if authCtx == nil {
		return findings
	}
	for i := range findings {
		attached := *authCtx
		findings[i].AuthContext = &attached
	}
	return findings
}

// ScanIDORCrossPrincipal performs an explicit, evidence-based
// cross-principal IDOR comparison (TD #11): for each of owner's own
// numeric identifier values, it checks whether any of others can also
// access the same resource under its own distinct, explicitly-supplied
// AuthContext.
//
// This never returns VerificationStatus CONFIRMED. A same-shape,
// non-denial response obtained by a different, explicitly authenticated
// principal is evidence that object-level authorization may be missing -
// not proof that the underlying record actually belongs to a different
// principal/tenant. Only a human with application-specific knowledge can
// close that gap (see ARCHITECTURE.md's human-in-the-loop principle and
// ARFA_MASTER_CONTEXT.md §10, "A human must confirm these"). Findings this
// function produces are reported at VerificationStatus LIKELY.
//
// Both owner and every entry in others must carry a distinct, explicit
// AuthContext (non-nil Probe, non-empty Context.Identity): per
// PHASE_4_TD_SPECS.md TD #11, "من غير context كافي -> INCONCLUSIVE أو
// LIKELY، مش CONFIRMED" (without sufficient context: INCONCLUSIVE or
// LIKELY, never CONFIRMED). Any candidate lacking sufficient context -
// owner's own probe failing/erroring/denied, an entry in others missing
// its Probe or Context, or an entry sharing owner's own Identity - is
// simply skipped rather than guessed at, so insufficient context never
// produces a finding at all (and therefore never a false CONFIRMED).
func ScanIDORCrossPrincipal(ctx context.Context, ep models.Endpoint, owner PrincipalProbe, others []PrincipalProbe) []models.Finding {
	var out []models.Finding
	if owner.Probe == nil || owner.Context.Identity == "" {
		return out
	}
	u, err := url.Parse(ep.URL)
	if err != nil {
		return out
	}
	q := u.Query()
	for _, param := range ep.Parameters {
		raw := q.Get(param)
		if raw == "" {
			continue
		}
		if _, err := strconv.ParseInt(raw, 10, 64); err != nil {
			continue
		}
		baseline := owner.Probe(ctx, ep, param, raw)
		if baseline.Err != nil || baseline.Status != 200 || len(baseline.Body) == 0 || looksLikeDenial(baseline.Body) {
			// Insufficient context/evidence to compare against - never guess.
			continue
		}
		for _, other := range others {
			if other.Probe == nil || other.Context.Identity == "" || other.Context.Identity == owner.Context.Identity {
				// No explicit, distinct context supplied for this
				// candidate: not a cross-principal comparison.
				continue
			}
			pr := other.Probe(ctx, ep, param, raw)
			if pr.Err != nil || pr.Status != 200 {
				continue
			}
			if looksLikeDenial(pr.Body) {
				// Properly restricted: the other principal was denied
				// access to owner's own resource.
				continue
			}
			if len(pr.Body) > 40 && similarity(baseline.Body, pr.Body) >= 0.90 {
				attached := other.Context
				out = append(out, models.Finding{
					Category:           "IDOR",
					Name:               "Cross-Principal Insecure Direct Object Reference",
					Severity:           "High",
					CVSS:               "7.5",
					Confidence:         "Medium",
					Endpoint:           ep.URL,
					Parameter:          param,
					Payload:            raw,
					Encoding:           "plain",
					Evidence:           "A distinct, explicitly authenticated principal received a substantively similar, non-denial response for another principal's own identifier value",
					PoC:                pr.URL,
					Impact:             "A different authenticated principal may be able to access another principal's resource; requires manual confirmation of actual data ownership.",
					Remediation:        "Enforce object-level authorization checks server-side for every authenticated principal; never rely on client-supplied identifiers alone.",
					Status:             pr.Status,
					VerificationStatus: "LIKELY",
					VerificationDetail: "Cross-principal comparison: principal \"" + attached.Principal.Label + "\" accessed a resource identified by principal \"" + owner.Context.Principal.Label + "\"'s own identifier value under explicit, distinct auth contexts. Not CONFIRMED: application-specific ownership still requires human confirmation.",
					AuthContext:        &attached,
					IDORComparison: &models.IDORComparison{
						Owner:        owner.Context,
						Accessor:     attached,
						Relationship: models.IDORCrossPrincipalAccess,
					},
				})
			}
		}
	}
	return out
}

// Unverified mirrors verification.Unverified without importing the
// verification package, to avoid an import cycle (verification does not
// need to know about detectors, and detectors should not need to know about
// verification's internals beyond this one string constant).
const Unverified = "UNVERIFIED"

func looksLikeDenial(body string) bool {
	b := strings.ToLower(body)
	for _, m := range []string{"not found", "forbidden", "unauthorized", "access denied", "no such", "error"} {
		if strings.Contains(b, m) {
			return true
		}
	}
	return false
}

// similarity is a crude length-ratio + prefix-overlap heuristic — enough to
// separate "same templated error/empty page" from "a different substantive
// record" without a real diff algorithm or a new dependency (this project
// runs stdlib-only; see loader.go / http.go for the same constraint).
func similarity(a, b string) float64 {
	if a == b {
		return 1
	}
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	shorter, longer := a, b
	if len(a) > len(b) {
		shorter, longer = b, a
	}
	match := 0
	for i := 0; i < len(shorter); i++ {
		if shorter[i] == longer[i] {
			match++
		} else {
			break
		}
	}
	lengthRatio := float64(len(shorter)) / float64(len(longer))
	prefixRatio := float64(match) / float64(len(shorter))
	return (lengthRatio + prefixRatio) / 2
}
