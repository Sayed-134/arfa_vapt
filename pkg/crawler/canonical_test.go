package crawler

import (
	"testing"
)

func TestCanonicalizeURL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "lowercase scheme and host",
			input:    "HTTP://EXAMPLE.COM/path",
			expected: "http://example.com/path",
		},
		{
			name:     "strip default http port 80",
			input:    "http://example.com:80/test",
			expected: "http://example.com/test",
		},
		{
			name:     "strip default https port 443",
			input:    "https://example.com:443/test",
			expected: "https://example.com/test",
		},
		{
			name:     "keep non-default port",
			input:    "http://example.com:8080/test",
			expected: "http://example.com:8080/test",
		},
		{
			name:     "strip fragment",
			input:    "http://example.com/page#section",
			expected: "http://example.com/page",
		},
		{
			name:     "sort query parameters",
			input:    "http://example.com/search?b=2&a=1&c=3",
			expected: "http://example.com/search?a=1&b=2&c=3",
		},
		{
			name:     "empty path defaults to slash",
			input:    "http://example.com",
			expected: "http://example.com/",
		},
		{
			name:     "combined canonicalization",
			input:    "HTTPS://EXAMPLE.COM:443/search?z=9&a=1#fragment",
			expected: "https://example.com/search?a=1&z=9",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CanonicalizeURL(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.expected {
				t.Errorf("CanonicalizeURL(%q) = %q; want %q", tt.input, got, tt.expected)
			}
		})
	}
}
