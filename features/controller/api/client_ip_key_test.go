// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Issue #4573: every per-IP auth throttle resolves the client through
// trusted_proxies and buckets IPv6 by /64 via Server.clientIPKey.

const (
	ipKeyTestProxyPeer   = "10.0.0.5:443"
	ipKeyTestClientA     = "198.51.100.1"
	ipKeyTestClientB     = "198.51.100.2"
	ipKeyTestUntrusted   = "203.0.113.9:5555"
	ipKeyTestV6Throttled = "2001:db8:1:2::/64"
	ipKeyTestV6SameNet   = "[2001:db8:1:2:abcd::1]:5555"
	ipKeyTestV6OtherNet  = "[2001:db8:1:3::1]:5555"
)

func trustTestProxyNet(t *testing.T, s *Server) {
	t.Helper()
	_, proxyNet, err := net.ParseCIDR("10.0.0.0/8")
	require.NoError(t, err)
	s.trustedProxies = []net.IPNet{*proxyNet}
}

// ipKeyTestRequest builds a request whose TCP peer is remote and, when xff is
// non-empty, carries an X-Forwarded-For header.
func ipKeyTestRequest(method, path, remote, xff string) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = remote
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	return req
}

func TestClientIPKey_Resolution(t *testing.T) {
	s := setupTestServer(t)
	trustTestProxyNet(t, s)

	tests := []struct {
		name   string
		remote string
		xff    string
		want   string
	}{
		{"trusted proxy: forwarded client A", ipKeyTestProxyPeer, ipKeyTestClientA, ipKeyTestClientA},
		{"trusted proxy: forwarded client B", ipKeyTestProxyPeer, ipKeyTestClientB, ipKeyTestClientB},
		{"untrusted peer: forwarded header ignored", ipKeyTestUntrusted, ipKeyTestClientA, "203.0.113.9"},
		{"ipv6 peer bucketed to /64", ipKeyTestV6SameNet, "", ipKeyTestV6Throttled},
		{"ipv6 forwarded client bucketed to /64", ipKeyTestProxyPeer, "2001:db8:1:2::77", ipKeyTestV6Throttled},
		{"ipv4-mapped ipv6 peer keyed as ipv4", "[::ffff:203.0.113.9]:5555", "", "203.0.113.9"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := ipKeyTestRequest(http.MethodGet, "/", tt.remote, tt.xff)
			assert.Equal(t, tt.want, s.clientIPKey(req))
		})
	}
}

// TestClientIPKey_AuthDefenseMiddleware drives the server's real authDefense
// middleware (wired in New) until the per-IP tier trips, then checks which
// clients share the throttled bucket.
func TestClientIPKey_AuthDefenseMiddleware(t *testing.T) {
	failing := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})

	do := func(s *Server, remote, xff string) int {
		rec := httptest.NewRecorder()
		s.authDefense.Middleware(failing).ServeHTTP(rec,
			ipKeyTestRequest(http.MethodPost, "/api/v1/test", remote, xff))
		return rec.Code
	}
	exhaust := func(t *testing.T, s *Server, remote, xff string) {
		t.Helper()
		for i := 0; i < 10_000; i++ {
			if do(s, remote, xff) == http.StatusTooManyRequests {
				return
			}
		}
		t.Fatalf("per-IP limit never tripped for remote=%s xff=%s", remote, xff)
	}

	t.Run("trusted proxy: forwarded clients limited independently", func(t *testing.T) {
		s := setupTestServer(t)
		trustTestProxyNet(t, s)
		exhaust(t, s, ipKeyTestProxyPeer, ipKeyTestClientA)

		assert.Equal(t, http.StatusTooManyRequests, do(s, ipKeyTestProxyPeer, ipKeyTestClientA))
		assert.Equal(t, http.StatusUnauthorized, do(s, ipKeyTestProxyPeer, ipKeyTestClientB),
			"a different forwarded client behind the same proxy must have its own bucket")
	})

	t.Run("untrusted peer: forwarded header ignored", func(t *testing.T) {
		s := setupTestServer(t)
		trustTestProxyNet(t, s)
		exhaust(t, s, ipKeyTestUntrusted, ipKeyTestClientA)

		assert.Equal(t, http.StatusTooManyRequests, do(s, ipKeyTestUntrusted, ipKeyTestClientB),
			"rotating X-Forwarded-For from an untrusted peer must not escape its bucket")
	})

	t.Run("ipv6: same /64 shares a bucket, different /64 does not", func(t *testing.T) {
		s := setupTestServer(t)
		exhaust(t, s, "[2001:db8:1:2::10]:5555", "")

		assert.Equal(t, http.StatusTooManyRequests, do(s, ipKeyTestV6SameNet, ""))
		assert.Equal(t, http.StatusUnauthorized, do(s, ipKeyTestV6OtherNet, ""))
	})
}

// throttleSite exercises one handler-level per-IP throttle: record trips the
// "ip:<key>" bucket, finish sends one request through the real handler.
type throttleSite struct {
	name   string
	setup  func(t *testing.T) (record func(key string), finish func(remote, xff string) int)
	failsN int
}

func TestClientIPKey_HandlerThrottleSites(t *testing.T) {
	sites := []throttleSite{
		{
			name:   "passkey login finish",
			failsN: 4,
			setup: func(t *testing.T) (func(string), func(string, string) int) {
				s, _ := setupPasskeySessionServer(t)
				trustTestProxyNet(t, s)
				return s.recordPasskeyLoginFailure, func(remote, xff string) int {
					const ceremonyID = "ip-key-ceremony"
					s.passkeyLoginSessions.Store(ceremonyID, &passkeyLoginSession{
						data:         webauthn.SessionData{},
						expires:      time.Now().Add(5 * time.Minute),
						discoverable: true,
					})
					req := ipKeyTestRequest(http.MethodPost, "/api/v1/web/passkey/login/finish", remote, xff)
					req.AddCookie(&http.Cookie{Name: cookiePasskeyCeremony, Value: ceremonyID})
					rec := httptest.NewRecorder()
					s.handlePasskeyLoginFinish(rec, req)
					return rec.Code
				}
			},
		},
		{
			name:   "step-up elevation finish",
			failsN: 4,
			setup: func(t *testing.T) (func(string), func(string, string) int) {
				s, username := setupWebAuthnServer(t, tvRPID, []string{tvOrigin})
				trustTestProxyNet(t, s)
				return s.recordElevateFailure, func(remote, xff string) int {
					const sessID = "ip-key-elevate"
					injectElevateSession(s, sessID, webauthn.SessionData{}, time.Minute, username)
					req := withPrincipal(ipKeyTestRequest(http.MethodPost, "/api/v1/webauthn/elevate/finish", remote, xff),
						&Principal{ID: username})
					req = req.WithContext(context.WithValue(req.Context(), webSessionIDContextKey, sessID))
					rec := httptest.NewRecorder()
					s.handleStepUpFinish(rec, req)
					return rec.Code
				}
			},
		},
		{
			name:   "operator-payload sign finish",
			failsN: 4,
			setup: func(t *testing.T) (func(string), func(string, string) int) {
				s, username := setupOperatorPayloadSignServer(t)
				trustTestProxyNet(t, s)
				return s.recordSignFailure, func(remote, xff string) int {
					const sessID = "ip-key-sign"
					s.operatorPayloadSignSessions.Store(sessID, &operatorPayloadSignSession{
						data:      webauthn.SessionData{},
						expires:   time.Now().Add(time.Minute),
						accountID: username,
					})
					req := withPrincipal(ipKeyTestRequest(http.MethodPost, "/api/v1/operator-payload/sign/finish", remote, xff),
						&Principal{ID: username})
					req = req.WithContext(context.WithValue(req.Context(), webSessionIDContextKey, sessID))
					rec := httptest.NewRecorder()
					s.handleOperatorPayloadSignFinish(rec, req)
					return rec.Code
				}
			},
		},
	}

	for _, site := range sites {
		t.Run(site.name, func(t *testing.T) {
			t.Run("trusted proxy: forwarded clients limited independently", func(t *testing.T) {
				record, finish := site.setup(t)
				for i := 0; i < site.failsN; i++ {
					record("ip:" + ipKeyTestClientA)
				}
				assert.Equal(t, http.StatusTooManyRequests, finish(ipKeyTestProxyPeer, ipKeyTestClientA))
				assert.NotEqual(t, http.StatusTooManyRequests, finish(ipKeyTestProxyPeer, ipKeyTestClientB),
					"a different forwarded client behind the same proxy must not be throttled")
			})

			t.Run("untrusted peer: forwarded header ignored", func(t *testing.T) {
				record, finish := site.setup(t)
				for i := 0; i < site.failsN; i++ {
					record("ip:" + ipKeyTestClientA)
				}
				assert.NotEqual(t, http.StatusTooManyRequests, finish(ipKeyTestUntrusted, ipKeyTestClientA),
					"a spoofed X-Forwarded-For from an untrusted peer must not select the forwarded bucket")

				record2, finish2 := site.setup(t)
				for i := 0; i < site.failsN; i++ {
					record2("ip:203.0.113.9")
				}
				assert.Equal(t, http.StatusTooManyRequests, finish2(ipKeyTestUntrusted, ipKeyTestClientB),
					"an untrusted peer must stay in its own bucket whatever X-Forwarded-For it sends")
			})

			t.Run("ipv6: same /64 shares a bucket, different /64 does not", func(t *testing.T) {
				record, finish := site.setup(t)
				for i := 0; i < site.failsN; i++ {
					record("ip:" + ipKeyTestV6Throttled)
				}
				assert.Equal(t, http.StatusTooManyRequests, finish(ipKeyTestV6SameNet, ""))
				assert.NotEqual(t, http.StatusTooManyRequests, finish(ipKeyTestV6OtherNet, ""))
			})
		})
	}
}
