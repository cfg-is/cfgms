// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package workflow

import (
	"context"
	"net/netip"
	"net/url"
	"strings"
	"testing"
)

func TestHTTPClientRejectsUnsafeDestinations(t *testing.T) {
	t.Parallel()

	client := NewHTTPClient(HTTPClientConfig{})
	for _, target := range []string{
		"file:///etc/passwd",
		"http://localhost/admin",
		"http://service.localhost/admin",
		"http://127.0.0.1/admin",
		"http://[::1]/admin",
		"http://[::ffff:127.0.0.1]/admin",
		"http://169.254.169.254/latest/meta-data/",
		"http://10.0.0.1/admin",
		"http://100.64.0.1/admin",
		"http://user:password@example.com/",
	} {
		target := target
		t.Run(target, func(t *testing.T) {
			err := client.validateHTTPConfig(&HTTPConfig{URL: target, Method: "GET"})
			if err == nil {
				t.Fatalf("unsafe workflow destination %q was accepted", target)
			}
		})
	}
}

func TestHTTPClientAllowsPublicHTTPSDestination(t *testing.T) {
	t.Parallel()

	client := NewHTTPClient(HTTPClientConfig{})
	if err := client.validateHTTPConfig(&HTTPConfig{
		URL:    "https://api.example.com/v1/resources",
		Method: "POST",
	}); err != nil {
		t.Fatalf("public HTTPS destination rejected: %v", err)
	}
}

func TestHTTPClientRequestBodyLimit(t *testing.T) {
	t.Parallel()

	client := NewHTTPClient(HTTPClientConfig{MaxRequestBodyBytes: 4})
	_, err := client.createHTTPRequest(context.Background(), &HTTPConfig{
		URL:    "https://api.example.com/",
		Method: "POST",
		Body:   "12345",
	})
	if err == nil || !strings.Contains(err.Error(), "request body exceeds") {
		t.Fatalf("expected request body limit error, got %v", err)
	}
}

func TestForbiddenWorkflowIPRanges(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{
		"0.0.0.0", "127.0.0.1", "10.0.0.1", "172.16.0.1",
		"192.168.0.1", "169.254.169.254", "100.64.0.1",
		"198.18.0.1", "::", "::1", "fc00::1", "fe80::1",
		"::ffff:127.0.0.1",
	} {
		if !isForbiddenWorkflowIP(netip.MustParseAddr(raw)) {
			t.Errorf("expected %s to be forbidden", raw)
		}
	}
	if isForbiddenWorkflowIP(netip.MustParseAddr("93.184.216.34")) {
		t.Error("expected a public address to be permitted")
	}
}

func TestWorkflowRedirectOriginCheck(t *testing.T) {
	t.Parallel()

	parse := func(raw string) *url.URL {
		t.Helper()
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}

	if !sameOrigin(parse("https://example.com/a"), parse("https://example.com:443/b")) {
		t.Error("equivalent HTTPS origins were not recognized")
	}
	if sameOrigin(parse("https://example.com/a"), parse("https://other.example/b")) {
		t.Error("cross-host redirect was accepted")
	}
	if sameOrigin(parse("http://example.com/a"), parse("https://example.com/a")) {
		t.Error("cross-scheme redirect was accepted")
	}
}
