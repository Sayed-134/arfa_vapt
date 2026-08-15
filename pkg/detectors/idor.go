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
