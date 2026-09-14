package crawler

import (
	"arfa/pkg/httpclient"
	"arfa/pkg/models"
	"context"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

// Crawler performs a bounded BFS crawl of a target, discovering endpoints
// and the parameters associated with them. It is intentionally HTTP-only
// (no JavaScript execution) and GET-only: every discovered Endpoint is
// Method: "GET". Form-based (POST) discovery and form-scoped parameter
// grouping are explicitly out of scope here - see ARFA_MASTER_CONTEXT.md
// TD #1 (parsing robustness, this file) and TD #2 (forms / POST
// discovery, not implemented here).
type Crawler struct {
	client   *httpclient.Client
	maxPages int
}

// New constructs a Crawler. maxPages < 1 defaults to 30, matching the
// pre-existing behavior.
func New(c *httpclient.Client, maxPages int) *Crawler {
	if maxPages < 1 {
		maxPages = 30
	}
	return &Crawler{client: c, maxPages: maxPages}
}

// canonicalOrOriginal returns CanonicalizeURL(raw) when it succeeds, or raw
// unchanged when the URL cannot be parsed. A canonicalization failure must
// never abort a crawl or a probe - it only means that one URL is compared/
// stored in its original, unnormalized form.
func canonicalOrOriginal(raw string) string {
	if c, err := CanonicalizeURL(raw); err == nil {
		return c
	}
	return raw
}

// parsePage parses an HTML document from raw bytes using
// golang.org/x/net/html's tokenizer (not the tree-building parser: the
// crawler only needs a flat stream of start-tags and their attributes, not
// a DOM).
//
// It returns:
//   - links: every attribute value for href, src, or action, in document
//     order, across any element. This intentionally matches the previous
//     regex-based behavior, which matched those attribute names on any
//     element, not on a fixed element set. Values are returned as-authored
//     (no fragment stripping, no normalization) - the caller feeds them
//     through canonicalOrOriginal, which is where fragment removal already
//     happens.
//   - names: the value of the name attribute for input, textarea, and
//     select elements only, in document order.
//
// Parsing is resilient to malformed input: the tokenizer is designed to
// recover from unclosed tags, stray text, and similar defects, and it
// returns whatever tokens it can extract rather than failing outright.
func parsePage(body string) (links, names []string) {
	z := html.NewTokenizer(strings.NewReader(body))
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			// io.EOF or a tokenizer error - either way, stop. The
			// tokenizer guarantees no panic here; any partial tokens
			// already emitted above have been consumed.
			return links, names
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}
		tok := z.Token()

		// link discovery: href / src / action on any element.
		for _, attr := range tok.Attr {
			switch strings.ToLower(attr.Key) {
			case "href", "src", "action":
				v := strings.TrimSpace(attr.Val)
				if v != "" {
					links = append(links, v)
				}
			}
		}

		// parameter discovery: name on input / textarea / select only.
		switch strings.ToLower(tok.Data) {
		case "input", "textarea", "select":
			for _, attr := range tok.Attr {
				if strings.ToLower(attr.Key) == "name" {
					v := strings.TrimSpace(attr.Val)
					if v != "" {
						names = append(names, v)
					}
					break
				}
			}
		}
	}
}

// Crawl performs a bounded breadth-first crawl starting at target.
//
// It returns the discovered Endpoints (each Method: "GET"), the number of
// canonical URLs actually visited (pages), and an error only when the
// target URL itself cannot be parsed. Per-URL fetch errors are swallowed
// and the crawl continues - matching the previous behavior.
//
// Behavioral contract preserved from the pre-TD-#1 implementation:
//   - Every discovered Endpoint has Method: "GET".
//   - Query-string parameter names from the endpoint's own URL are
//     included in Endpoint.Parameters.
//   - name attributes of input / textarea / select elements anywhere on
//     the page are included in Endpoint.Parameters, as one flat list.
//   - Only http/https links on the same host (case-insensitive) as the
//     target are followed.
//   - URLs are compared and stored in canonical form via CanonicalizeURL.
//   - maxPages bounds the number of distinct canonical URLs visited.
//   - If no endpoints are discovered, the canonicalized target itself is
//     returned as a single GET endpoint.
//
// Parsing improvements added by TD #1 (vs. the previous flat-regex
// implementation):
//   - attribute values may be double-quoted, single-quoted, or unquoted;
//   - attribute and element names are matched case-insensitively per the
//     HTML5 tokenizer (a <A HREF=/x> is recognized);
//   - self-closing tags (<input name="q" />) are recognized;
//   - malformed-but-parseable HTML yields its well-formed portions.
func (c *Crawler) Crawl(ctx context.Context, target string) ([]models.Endpoint, int, error) {
	base, err := url.Parse(target)
	if err != nil {
		return nil, 0, err
	}
	host := strings.ToLower(base.Host)
	queue := []string{target}
	// seen and eps are keyed by each URL's canonical form (see
	// canonical.go), not the raw, as-discovered string. TD #3: without
	// this, URLs differing only by scheme/host case, an explicit default
	// port, a fragment, or query-parameter order were treated as distinct
	// pages/endpoints - duplicating crawl work, inflating detector job
	// counts, and burning the maxPages budget on the same page seen under
	// different spellings.
	seen := map[string]bool{}
	eps := map[string]models.Endpoint{}

	for len(queue) > 0 && len(seen) < c.maxPages {
		raw := queue[0]
		queue = queue[1:]
		u := canonicalOrOriginal(raw)
		if seen[u] {
			continue
		}
		seen[u] = true

		body, status, _, _, e := c.client.Do(ctx, "GET", u, nil)
		if e != nil || status == 0 {
			continue
		}

		links, names := parsePage(body)

		// Parameters: query-string keys from the endpoint's own URL,
		// followed by name attributes discovered on the page.
		p := []string{}
		if x, er := url.Parse(u); er == nil {
			for k := range x.Query() {
				p = append(p, k)
			}
		}
		p = append(p, names...)
		p = uniq(p)

		if len(p) > 0 || strings.Contains(u, "?") {
			eps[u] = models.Endpoint{URL: u, Method: "GET", Parameters: p}
		}

		// Link discovery: resolve each discovered link against the base
		// target URL, keep only same-host http/https links, and queue
		// them if not already seen. Fragment handling is left to
		// canonicalOrOriginal - a link like "/path#section" is queued
		// as-is here, and its fragment is removed when its canonical form
		// is computed.
		for _, rawLink := range links {
			ref, er := url.Parse(rawLink)
			if er != nil {
				continue
			}
			abs := base.ResolveReference(ref)
			if strings.EqualFold(abs.Host, host) && (abs.Scheme == "http" || abs.Scheme == "https") {
				absCanon := canonicalOrOriginal(abs.String())
				if !seen[absCanon] {
					queue = append(queue, abs.String())
				}
			}
		}
	}

	if len(eps) == 0 {
		t := canonicalOrOriginal(target)
		eps[t] = models.Endpoint{URL: t, Method: "GET"}
	}

	out := make([]models.Endpoint, 0, len(eps))
	for _, e := range eps {
		out = append(out, e)
	}
	return out, len(seen), nil
}

// uniq returns a with duplicates removed, preserving first-seen order.
func uniq(a []string) []string {
	m := map[string]bool{}
	o := []string{}
	for _, x := range a {
		if !m[x] {
			m[x] = true
			o = append(o, x)
		}
	}
	return o
}
