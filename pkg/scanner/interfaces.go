package scanner

import (
	"context"
	"net/http"
	"time"

	"arfa/pkg/models"
	"arfa/pkg/verification"
)

// CrawlerIface is the subset of *crawler.Crawler the Scanner needs. It
// exists so a future crawler implementation (or a test double) can be
// substituted without changing Scanner's internals - this is an adapter
// seam, not a behavior change: crawler.Crawler already satisfies it
// unmodified.
type CrawlerIface interface {
	Crawl(ctx context.Context, target string) ([]models.Endpoint, int, error)
}

// Transport is the subset of *httpclient.Client the Scanner needs to issue
// a probe. Same rationale as CrawlerIface: httpclient.Client already
// satisfies this signature unmodified, so wiring it in is purely additive.
type Transport interface {
	Do(ctx context.Context, method, rawURL string, params map[string]string) (string, int, http.Header, time.Duration, error)
}

// Verifier is the subset of the verification package's behavior the
// Scanner needs. verification.Verify already has exactly this signature as
// a free function; verifierFunc below adapts it to this interface with no
// logic changes, so the default wiring is behavior-identical to calling
// verification.Verify directly.
type Verifier interface {
	Verify(ctx context.Context, ep models.Endpoint, param string, originalValue string, evidenceCheck func(models.ProbeResult) bool, probe verification.Prober) verification.Result
}

// verifierFunc adapts a function value with verification.Verify's exact
// signature to the Verifier interface.
type verifierFunc func(ctx context.Context, ep models.Endpoint, param string, originalValue string, evidenceCheck func(models.ProbeResult) bool, probe verification.Prober) verification.Result

func (f verifierFunc) Verify(ctx context.Context, ep models.Endpoint, param string, originalValue string, evidenceCheck func(models.ProbeResult) bool, probe verification.Prober) verification.Result {
	return f(ctx, ep, param, originalValue, evidenceCheck, probe)
}

// defaultVerifier wires the package-level verification.Verify function
// (the same one the scanner called directly before Milestone 2) as the
// default Verifier implementation.
var defaultVerifier Verifier = verifierFunc(verification.Verify)
