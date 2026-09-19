package redact

import (
	"net/http"
	"reflect"
	"testing"
)

// --- Headers (http.Header input) -------------------------------------------

func TestHeaders_AuthorizationRedacted(t *testing.T) {
	h := http.Header{"Authorization": []string{"Bearer sometoken123"}}
	got := Headers(h)
	if got["Authorization"] != RedactedPlaceholder {
		t.Fatalf("expected Authorization to be redacted, got %q", got["Authorization"])
	}
}

func TestHeaders_CookieAndSetCookieRedacted(t *testing.T) {
	h := http.Header{
		"Cookie":     []string{"session=abc123"},
		"Set-Cookie": []string{"session=abc123; HttpOnly"},
	}
	got := Headers(h)
	if got["Cookie"] != RedactedPlaceholder {
		t.Fatalf("expected Cookie to be redacted, got %q", got["Cookie"])
	}
	if got["Set-Cookie"] != RedactedPlaceholder {
		t.Fatalf("expected Set-Cookie to be redacted, got %q", got["Set-Cookie"])
	}
}

func TestHeaders_ApiKeyAndProxyAuthorizationRedacted(t *testing.T) {
	h := http.Header{
		"X-Api-Key":           []string{"sk-live-abc123"},
		"Proxy-Authorization": []string{"Basic dXNlcjpwYXNz"},
	}
	got := Headers(h)
	if got["X-Api-Key"] != RedactedPlaceholder {
		t.Fatalf("expected X-Api-Key to be redacted, got %q", got["X-Api-Key"])
	}
	if got["Proxy-Authorization"] != RedactedPlaceholder {
		t.Fatalf("expected Proxy-Authorization to be redacted, got %q", got["Proxy-Authorization"])
	}
}

func TestHeaders_MatchingIsCaseInsensitive(t *testing.T) {
	h := http.Header{"AUTHORIZATION": []string{"Bearer x"}, "cookie": []string{"a=b"}}
	got := Headers(h)
	if got["AUTHORIZATION"] != RedactedPlaceholder || got["cookie"] != RedactedPlaceholder {
		t.Fatalf("expected case-insensitive redaction, got %+v", got)
	}
}

func TestHeaders_NonSensitiveHeadersPreserved(t *testing.T) {
	h := http.Header{"Content-Type": []string{"text/html"}, "X-Test": []string{"value"}}
	got := Headers(h)
	if got["Content-Type"] != "text/html" {
		t.Fatalf("expected Content-Type preserved unredacted, got %q", got["Content-Type"])
	}
	if got["X-Test"] != "value" {
		t.Fatalf("expected X-Test preserved unredacted, got %q", got["X-Test"])
	}
}

func TestHeaders_MultiValueSensitiveHeaderFullyRedacted(t *testing.T) {
	// A repeated header line must never let a sensitive value survive by
	// hiding in a second occurrence - Headers joins all values first,
	// then redacts the whole joined value.
	h := http.Header{"Cookie": []string{"a=1", "b=2"}}
	got := Headers(h)
	if got["Cookie"] != RedactedPlaceholder {
		t.Fatalf("expected all Cookie values to be redacted together, got %q", got["Cookie"])
	}
}

func TestHeaders_EmptyOrNilReturnsNil(t *testing.T) {
	if got := Headers(nil); got != nil {
		t.Fatalf("expected nil input to return nil, got %+v", got)
	}
	if got := Headers(http.Header{}); got != nil {
		t.Fatalf("expected empty input to return nil, got %+v", got)
	}
}

func TestHeaders_Deterministic(t *testing.T) {
	h := http.Header{"Authorization": []string{"Bearer x"}, "X-Test": []string{"v"}}
	first := Headers(h)
	second := Headers(h)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("expected redacting the same input twice to yield identical results, got %+v and %+v", first, second)
	}
}

// --- PlainHeaders (map[string]string input) ---------------------------------

func TestPlainHeaders_SensitiveNameRedacted(t *testing.T) {
	got := PlainHeaders(map[string]string{"Authorization": "Bearer x", "User-Agent": "Arfa-VAPT/1.0"})
	if got["Authorization"] != RedactedPlaceholder {
		t.Fatalf("expected Authorization to be redacted, got %q", got["Authorization"])
	}
	if got["User-Agent"] != "Arfa-VAPT/1.0" {
		t.Fatalf("expected User-Agent preserved unredacted, got %q", got["User-Agent"])
	}
}

func TestPlainHeaders_EmptyOrNilReturnsNil(t *testing.T) {
	if got := PlainHeaders(nil); got != nil {
		t.Fatalf("expected nil input to return nil, got %+v", got)
	}
	if got := PlainHeaders(map[string]string{}); got != nil {
		t.Fatalf("expected empty input to return nil, got %+v", got)
	}
}

func TestPlainHeaders_Deterministic(t *testing.T) {
	in := map[string]string{"Cookie": "a=b", "Accept": "text/html"}
	first := PlainHeaders(in)
	second := PlainHeaders(in)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("expected redacting the same input twice to yield identical results, got %+v and %+v", first, second)
	}
}
