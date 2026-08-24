package models

import (
	"encoding/json"
	"testing"
)

func TestScanEnvelopeContractIsAdditive(t *testing.T) {
	r := ScanResult{SchemaVersion: "arfa.scan/v1", Target: "http://127.0.0.1", Scope: ScanScope{Authorized: true, AuthorizationMethod: "cli_acknowledgement"}, Findings: []Finding{{Category: "SQLi", VerificationStatus: "FALSE_POSITIVE"}}}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["schema_version"] != "arfa.scan/v1" {
		t.Fatal("schema version was not serialized")
	}
	if decoded["scope"].(map[string]any)["authorized"] != true {
		t.Fatal("scope was not serialized")
	}
	if decoded["findings"].([]any)[0].(map[string]any)["verification_status"] != "FALSE_POSITIVE" {
		t.Fatal("verification status was changed")
	}
}
