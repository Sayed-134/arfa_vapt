package models

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

// TestEvidence_TD9FieldsSurviveJSONRoundTrip locks in that the new additive
// fields serialize and deserialize without loss, alongside the pre-existing
// Evidence fields.
func TestEvidence_TD9FieldsSurviveJSONRoundTrip(t *testing.T) {
	ev := Evidence{
		Timestamp:          "2026-09-19T00:00:00Z",
		Endpoint:           "http://x/search",
		Parameter:          "q",
		Category:           "XSS",
		RequestMethod:      "GET",
		RequestURL:         "http://x/search?q=%3Cxsstestmarker%3E",
		RequestQueryParams: url.Values{"q": []string{"<xsstestmarker>"}},
		RequestHeaders:     map[string]string{"User-Agent": "Arfa-VAPT/1.0", "Accept": "text/html"},
		ResponseStatus:     200,
		ResponseSnippet:    "<html>...</html>",
		ResponseBodyLength: 17,
		ResponseHash:       "deadbeef",
		ResponseHeaders:    map[string]string{"Content-Type": "text/html", "Set-Cookie": "[REDACTED]"},
		VerificationTrace:  []string{"verdict: CONFIRMED"},
	}

	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}

	var decoded Evidence
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}

	if decoded.RequestQueryParams.Get("q") != "<xsstestmarker>" {
		t.Fatalf("RequestQueryParams did not survive round trip: %+v", decoded.RequestQueryParams)
	}
	if len(decoded.RequestFormParams) != 0 {
		t.Fatalf("expected RequestFormParams to remain empty, got %+v", decoded.RequestFormParams)
	}
	if decoded.RequestHeaders["User-Agent"] != "Arfa-VAPT/1.0" {
		t.Fatalf("RequestHeaders did not survive round trip: %+v", decoded.RequestHeaders)
	}
	if decoded.ResponseBodyLength != 17 {
		t.Fatalf("ResponseBodyLength did not survive round trip: got %d", decoded.ResponseBodyLength)
	}
	if decoded.ResponseHeaders["Set-Cookie"] != "[REDACTED]" {
		t.Fatalf("ResponseHeaders did not survive round trip: %+v", decoded.ResponseHeaders)
	}
	// Pre-existing fields must remain unaffected by the additive change.
	if decoded.ResponseHash != "deadbeef" || decoded.RequestMethod != "GET" {
		t.Fatalf("pre-existing Evidence fields regressed: %+v", decoded)
	}
}

// TestEvidence_TD9FieldsOmittedWhenEmpty confirms the additive/omitempty
// contract: an Evidence value that never populates the new TD #9 fields
// (e.g. built by code that predates TD #9) must not gain spurious empty
// keys in its JSON output, preserving compatibility for existing
// consumers - mirroring the existing omitempty test pattern already used
// for VerificationConfidence/EvidenceDetail in pkg/report.
func TestEvidence_TD9FieldsOmittedWhenEmpty(t *testing.T) {
	ev := Evidence{
		Timestamp:       "2026-09-19T00:00:00Z",
		Endpoint:        "http://x",
		Parameter:       "id",
		Category:        "IDOR",
		RequestMethod:   "GET",
		RequestURL:      "http://x?id=1",
		ResponseStatus:  200,
		ResponseSnippet: "ok",
		ResponseHash:    "abc123",
	}

	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}
	s := string(b)
	for _, key := range []string{
		"request_query_params",
		"request_form_params",
		"request_headers",
		"response_body_length",
		"response_headers",
	} {
		if strings.Contains(s, "\""+key+"\"") {
			t.Fatalf("expected %q to be omitted from JSON when empty, but it was present:\n%s", key, s)
		}
	}
}
