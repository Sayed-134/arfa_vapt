package crawler

import (
	"arfa/pkg/httpclient"
	"arfa/pkg/models"
	"context"
	"net/url"
	"regexp"
	"strings"
)

type Crawler struct {
	client   *httpclient.Client
	maxPages int
}

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
	linkRe := regexp.MustCompile(`(?i)(?:href|src|action)\s*=\s*["']([^"'#]+)`)
	inputRe := regexp.MustCompile(`(?i)<input[^>]*\bname=["']([^"']+)["']`)
	selectRe := regexp.MustCompile(`(?i)<(?:textarea|select)[^>]*\bname=["']([^"']+)["']`)
	for len(queue) > 0 && len(seen) < c.maxPages {
		raw := queue[0]
		queue = queue[1:]
		u := canonicalOrOriginal(raw)
		if seen[u] {
			continue
		}
		seen[u] = true
		body, status, _, _, e := c.client.Do(ctx, "GET", u, nil)
		if e != nil {
			continue
		}
		if status == 0 {
			continue
		}
		p := []string{}
		if x, er := url.Parse(u); er == nil {
			for k := range x.Query() {
				p = append(p, k)
			}
		}
		for _, m := range inputRe.FindAllStringSubmatch(body, -1) {
			p = append(p, m[1])
		}
		for _, m := range selectRe.FindAllStringSubmatch(body, -1) {
			p = append(p, m[1])
		}
		p = uniq(p)
		if len(p) > 0 || strings.Contains(u, "?") {
			eps[u] = models.Endpoint{URL: u, Method: "GET", Parameters: p}
		}
		for _, m := range linkRe.FindAllStringSubmatch(body, -1) {
			ref, er := url.Parse(m[1])
			if er != nil {
				continue
			}
			abs := base.ResolveReference(ref)
			// Host comparison is case-insensitive, matching the lowercase
			// normalization CanonicalizeURL applies to scheme/host - a
			// differently-cased host for the same target was previously
			// (incorrectly) treated as off-scope and never queued.
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
