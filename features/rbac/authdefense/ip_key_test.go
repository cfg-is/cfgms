// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package authdefense

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestIPKey(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"ipv4 unchanged", "203.0.113.7", "203.0.113.7"},
		{"ipv4-mapped ipv6 keyed as ipv4", "::ffff:203.0.113.7", "203.0.113.7"},
		{"ipv6 bucketed to /64", "2001:db8:1:2:aaaa:bbbb:cccc:dddd", "2001:db8:1:2::/64"},
		{"ipv6 same /64 same key", "2001:db8:1:2::1", "2001:db8:1:2::/64"},
		{"ipv6 different /64", "2001:db8:1:3::1", "2001:db8:1:3::/64"},
		{"ipv6 loopback", "::1", "::/64"},
		{"unparseable returned unchanged", "not-an-ip", "not-an-ip"},
		{"empty stays empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, IPKey(tt.in))
		})
	}
}

// TestDefense_DefaultExtractor_IPv6SharesSlash64Bucket drives the real middleware
// with the default extractor: failures from one address in a /64 throttle a
// different address in the same /64, but not one in a different /64.
func TestDefense_DefaultExtractor_IPv6SharesSlash64Bucket(t *testing.T) {
	clock := NewTestClock(time.Time{})
	cfg := DefaultConfig()
	cfg.IPRateLimit = 3
	cfg.IPRingSize = 3
	cfg.IPRateWindow = 1 * time.Minute
	cfg.GCTriggerThreshold = 1_000_000

	d := New(cfg, newTestLogger(t), WithClock(clock))
	defer d.Stop()

	handler := d.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	do := func(remote string) int {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}

	for i := 0; i < 3; i++ {
		assert.Equal(t, http.StatusUnauthorized, do("[2001:db8:1:2::10]:40000"))
	}

	assert.Equal(t, http.StatusTooManyRequests, do("[2001:db8:1:2:ffff::99]:40001"),
		"a different address in the same /64 must share the throttled bucket")
	assert.Equal(t, http.StatusUnauthorized, do("[2001:db8:1:3::10]:40002"),
		"an address in a different /64 must not be throttled")
}
