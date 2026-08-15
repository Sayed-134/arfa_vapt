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
func (c *Crawler) Crawl(ctx context.Context, target string) ([]models.Endpoint, int, error) {
	base, err := url.Parse(target)
	if err != nil {
		return nil, 0, err
	}
	host := base.Host
	queue := []string{target}
	seen := map[string]bool{}
	eps := map[string]models.Endpoint{}
	linkRe := regexp.MustCompile(`(?i)(?:href|src|action)\s*=\s*["']([^"'#]+)`)
	inputRe := regexp.MustCompile(`(?i)<input[^>]*\bname=["']([^"']+)["']`)
	selectRe := regexp.MustCompile(`(?i)<(?:textarea|select)[^>]*\bname=["']([^"']+)["']`)
	for len(queue) > 0 && len(seen) < c.maxPages {
		u := queue[0]
		queue = queue[1:]
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
			if abs.Host == host && (abs.Scheme == "http" || abs.Scheme == "https") && !seen[abs.String()] {
				queue = append(queue, abs.String())
			}
		}
	}
	if len(eps) == 0 {
		eps[target] = models.Endpoint{URL: target, Method: "GET"}
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
