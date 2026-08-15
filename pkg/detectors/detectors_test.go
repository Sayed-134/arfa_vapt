package detectors

import (
	"arfa/pkg/models"
	"context"
	"net/http"
	"testing"
)

func fakeProbe(body string, headers http.Header) Probe {
	return func(context.Context, string, string, map[string]string, models.Payload) models.ProbeResult {
		return models.ProbeResult{URL: "http://test", Status: 200, Body: body, Headers: headers}
	}
}

func TestLFINeedsRelevantPayload(t *testing.T) {
	d := LFI{}
	ep := models.Endpoint{URL: "http://test/?file=x", Method: "GET", Parameters: []string{"file"}}
	p := models.Payload{Category: "LFI", Value: "hello"}
	if got := d.Detect(context.Background(), ep, p, fakeProbe("root:x:0:0", nil)); len(got) != 0 {
		t.Fatalf("false positive: got %d", len(got))
	}
}

func TestXXENeedsXMLPayload(t *testing.T) {
	d := XXE{}
	ep := models.Endpoint{URL: "http://test/?xml=x", Method: "GET", Parameters: []string{"xml"}}
	p := models.Payload{Category: "XXE", Value: "hello"}
	if got := d.Detect(context.Background(), ep, p, fakeProbe("xxe-marker", nil)); len(got) != 0 {
		t.Fatalf("false positive: got %d", len(got))
	}
}
