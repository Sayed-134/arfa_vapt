package crawler

import (
	"net"
	"net/url"
	"sort"
	"strings"
)

// CanonicalizeURL returns a normalized string representation of rawURL.
// It lowercases scheme and host, strips default ports (80/443), removes fragments,
// normalizes empty paths to "/", and sorts query parameters deterministically.
func CanonicalizeURL(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL, err
	}

	// 1. Lowercase scheme and host
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)

	// 2. Strip default ports
	if host, port, err := net.SplitHostPort(u.Host); err == nil {
		if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
			u.Host = host
		}
	}

	// 3. Remove fragments
	u.Fragment = ""
	u.RawFragment = ""

	// 4. Ensure path defaults to "/" when empty
	if u.Path == "" {
		u.Path = "/"
	}

	// 5. Sort query parameters deterministically
	q := u.Query()
	if len(q) > 0 {
		keys := make([]string, 0, len(q))
		for k := range q {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		var buf strings.Builder
		for _, k := range keys {
			vs := q[k]
			sort.Strings(vs)
			for _, v := range vs {
				if buf.Len() > 0 {
					buf.WriteByte('&')
				}
				buf.WriteString(url.QueryEscape(k))
				buf.WriteString("=")
				buf.WriteString(url.QueryEscape(v))
			}
		}
		u.RawQuery = buf.String()
	}

	return u.String(), nil
}
