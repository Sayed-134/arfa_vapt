package scope

import (
	"testing"
	"time"
)

func TestAuthorizeRequiresAcknowledgement(t *testing.T) {
	if _, err := Authorize("http://127.0.0.1:18080", false, time.Now()); err == nil {
		t.Fatal("expected authorization gate")
	}
}

func TestAuthorizeCreatesRecordedScope(t *testing.T) {
	s, err := Authorize("https://example.test", true, time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if !s.Authorized || s.AuthorizationMethod != "cli_acknowledgement" || s.AuthorizedAt != "1970-01-01T00:00:00Z" {
		t.Fatalf("unexpected scope: %+v", s)
	}
}
