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
// (no JavaScript execution). TD #2 adds first-class HTML <form> discovery:
// a form's own method (GET or POST; missing/invalid defaults to GET) and
// resolved action URL determine a second, form-scoped Endpoint distinct
// from the page-level GET endpoint that TD #1 already produced - see
// PLATFORM_STRATEGY.md §12.4 (the TD #2 decision log entry) for the scope
// boundary (form-urlencoded POST only; no multipart, JSON, cookies, or
// other methods).
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

// discoveredForm is one <form>...</form> element parsed off a page: its own
// method/action, and the name attributes of the input/textarea/select
// fields found between its start and end tag (in document order).
// Elements outside any <form> never contribute to a discoveredForm's
// fields - see parsePage.
type discoveredForm struct {
	method string // always "GET" or "POST" - see parsePage's method handling
	action string // raw, as-authored action attribute value; "" if absent/empty
	fields []string
}

// parsePage parses an HTML document from raw bytes using
// golang.org/x/net/html's tokenizer (not the tree-building parser: the
// crawler only needs a flat stream of start/end tags and their attributes,
// not a DOM).
//
// It returns:
//   - links: every attribute value for href, src, or action, in document
//     order, across any element. This intentionally matches the previous
//     regex-based behavior, which matched those attribute names on any
//     element, not on a fixed element set - so a <form action="..."> is
//     still discovered as a link too, unchanged from before TD #2. Values
//     are returned as-authored (no fragment stripping, no normalization) -
//     the caller feeds them through canonicalOrOriginal, which is where
//     fragment removal already happens.
//   - names: the value of the name attribute for input, textarea, and
//     select elements only, in document order, regardless of whether the
//     element is inside a <form> - this is the pre-TD-#2, page-scoped flat
//     list and is unchanged so existing (non-form) GET-endpoint behavior
//     is preserved exactly.
//   - forms: one discoveredForm per top-level, well-formed <form>...</form>
//     found on the page (TD #2). A field is attributed to a form only when
//     its start tag appears between that form's start and end tag; fields
//     outside any <form> appear only in names, never in forms[i].fields.
//     A <form> is only closed by seeing its own </form> end tag or by
//     end-of-document; nested <form> tags are not expected in valid HTML
//     and are not specially handled beyond "the innermost currently-open
//     form receives fields until its own end tag closes it".
//
// Parsing is resilient to malformed input: the tokenizer is designed to
// recover from unclosed tags, stray text, and similar defects, and it
// returns whatever tokens it can extract rather than failing outright. An
// unclosed <form> at end-of-document is still returned (closed implicitly
// at EOF), consistent with the tokenizer-level resilience TD #1 relies on
// elsewhere in this function.
func parsePage(body string) (links, names []string, forms []discoveredForm) {
	z := html.NewTokenizer(strings.NewReader(body))
	var current *discoveredForm
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			// io.EOF or a tokenizer error - either way, stop. The
			// tokenizer guarantees no panic here; any partial tokens
			// already emitted above have been consumed. An still-open
			// form is closed here rather than discarded.
			if current != nil {
				forms = append(forms, *current)
				current = nil
			}
			return links, names, forms
		}

		if tt == html.EndTagToken {
			tok := z.Token()
			if current != nil && strings.ToLower(tok.Data) == "form" {
				forms = append(forms, *current)
				current = nil
			}
			continue
		}

		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}
		tok := z.Token()

		// link discovery: href / src / action on any element - unchanged
		// from TD #1, applies to <form> too.
		for _, attr := range tok.Attr {
			switch strings.ToLower(attr.Key) {
			case "href", "src", "action":
				v := strings.TrimSpace(attr.Val)
				if v != "" {
					links = append(links, v)
				}
			}
		}

		tag := strings.ToLower(tok.Data)

		if tag == "form" {
			f := discoveredForm{method: "GET"} // missing/invalid method defaults to GET
			for _, attr := range tok.Attr {
				switch strings.ToLower(attr.Key) {
				case "method":
					if strings.EqualFold(strings.TrimSpace(attr.Val), "POST") {
						f.method = "POST"
					}
					// any other value (including empty, "get", or an
					// invalid method string) leaves f.method at its "GET"
					// default - see the TD #2 requirement that
					// missing/invalid method resolves to GET.
				case "action":
					f.action = strings.TrimSpace(attr.Val)
				}
			}
			if tt == html.SelfClosingTagToken {
				// A self-closing <form/> has no fields and closes
				// immediately; still recorded (with zero fields) for
				// consistency, though Crawl skips fieldless forms.
				forms = append(forms, f)
			} else {
				current = &f
			}
			continue
		}

		// parameter discovery: name on input / textarea / select only -
		// unchanged from TD #1. TD #2 additionally attributes the same
		// name to the currently-open form, if any.
		if tag == "input" || tag == "textarea" || tag == "select" {
			for _, attr := range tok.Attr {
				if strings.ToLower(attr.Key) == "name" {
					v := strings.TrimSpace(attr.Val)
					if v != "" {
						names = append(names, v)
						if current != nil {
							current.fields = append(current.fields, v)
						}
					}
					break
				}
			}
		}
	}
}

// Crawl performs a bounded breadth-first crawl starting at target.
//
// It returns the discovered Endpoints, the number of canonical URLs
// actually visited (pages), and an error only when the target URL itself
// cannot be parsed. Per-URL fetch errors are swallowed and the crawl
// continues - matching the previous behavior.
//
// Behavioral contract preserved from the pre-TD-#2 implementation:
//   - Query-string parameter names from a GET endpoint's own URL are
//     included in Endpoint.Parameters.
//   - name attributes of input / textarea / select elements anywhere on
//     the page are included in the page's own GET Endpoint.Parameters, as
//     one flat list - regardless of whether TD #2 also attributes the same
//     field to an enclosing <form>.
//   - Only http/https links on the same host (case-insensitive) as the
//     target are followed. A <form action="..."> is still discovered as a
//     link and queued for crawling too (pre-existing, unrelated to form
//     submission - see parsePage), unchanged by TD #2.
//   - URLs are compared and stored in canonical form via CanonicalizeURL.
//   - maxPages bounds the number of distinct canonical URLs visited.
//   - If no endpoints are discovered, the canonicalized target itself is
//     returned as a single GET endpoint.
//
// TD #2 additions (forms / POST discovery):
//   - Endpoint identity is (URL, Method): the same canonical URL can now
//     appear as both a GET and a POST Endpoint, kept separate.
//   - Each discovered <form> with at least one named field contributes a
//     second endpoint at the form's resolved action URL (the crawled
//     page's own URL when action is empty/absent), using that form's own
//     method: GET fields go into Parameters, POST fields go into
//     FormParameters.
//   - When the same (URL, Method) is reached more than once (e.g. a page
//     GET endpoint and a same-URL GET form, or two forms on different
//     pages sharing an action), their parameter/form-parameter sets are
//     unioned and deduplicated rather than one overwriting the other.
//
// Parsing improvements added by TD #1 (vs. the pre-TD-#1 flat-regex
// implementation), unchanged by TD #2:
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
	// seen is keyed by each URL's canonical form (see canonical.go), not
	// the raw, as-discovered string. TD #3: without this, URLs differing
	// only by scheme/host case, an explicit default port, a fragment, or
	// query-parameter order were treated as distinct pages - duplicating
	// crawl work, inflating detector job counts, and burning the maxPages
	// budget on the same page seen under different spellings.
	seen := map[string]bool{}
	// eps is keyed by canonical URL + method (TD #2 endpoint identity),
	// not URL alone - see addEndpoint.
	eps := map[string]models.Endpoint{}

	addEndpoint := func(epURL, method string, params, formParams []string) {
		key := epURL + "\x00" + method
		existing, ok := eps[key]
		if !ok {
			eps[key] = models.Endpoint{URL: epURL, Method: method, Parameters: uniq(params), FormParameters: uniq(formParams)}
			return
		}
		// Same (URL, Method) reached again - union and dedup rather than
		// overwrite, per the TD #2 merge requirement.
		existing.Parameters = uniq(append(existing.Parameters, params...))
		existing.FormParameters = uniq(append(existing.FormParameters, formParams...))
		eps[key] = existing
	}

	for len(queue) > 0 && len(seen) < c.maxPages {
		raw := queue[0]
		queue = queue[1:]
		u := canonicalOrOriginal(raw)
		if seen[u] {
			continue
		}
		seen[u] = true

		body, status, _, _, e := c.client.Do(ctx, httpclient.Request{Method: "GET", URL: u})
		if e != nil || status == 0 {
			continue
		}

		links, names, forms := parsePage(body)

		// GET endpoint for the page itself: query-string keys from the
		// endpoint's own URL, followed by name attributes discovered
		// anywhere on the page (unchanged from before TD #2).
		p := []string{}
		pageURL, pageURLErr := url.Parse(u)
		if pageURLErr == nil {
			for k := range pageURL.Query() {
				p = append(p, k)
			}
		}
		p = append(p, names...)
		p = uniq(p)

		if len(p) > 0 || strings.Contains(u, "?") {
			addEndpoint(u, "GET", p, nil)
		}

		// TD #2: one additional endpoint per discovered <form> with at
		// least one named field. A fieldless form has nothing to mutate
		// and is skipped - it contributes no endpoint.
		for _, f := range forms {
			if len(f.fields) == 0 {
				continue
			}
			actionAbs := u
			if f.action != "" && pageURLErr == nil {
				if ref, er := url.Parse(f.action); er == nil {
					actionAbs = pageURL.ResolveReference(ref).String()
				}
			}
			actionCanon := canonicalOrOriginal(actionAbs)
			fields := uniq(f.fields)
			if f.method == "POST" {
				addEndpoint(actionCanon, "POST", nil, fields)
			} else {
				addEndpoint(actionCanon, "GET", fields, nil)
			}
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
		eps[t+"\x00GET"] = models.Endpoint{URL: t, Method: "GET"}
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
