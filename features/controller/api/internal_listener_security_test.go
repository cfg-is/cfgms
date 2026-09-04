// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPrivateListenAddressValidation(t *testing.T) {
	t.Parallel()

	for _, address := range []string{"127.0.0.1:9444", "10.20.30.40:9444", "192.168.1.5:9444", "[::1]:9444", "[fd00::1]:9444"} {
		if err := validatePrivateListenAddr(address); err != nil {
			t.Errorf("private address %q rejected: %v", address, err)
		}
	}
	for _, address := range []string{"", "0.0.0.0:9444", "[::]:9444", "8.8.8.8:9444", "raft.example.com:9444", "127.0.0.1:0"} {
		if err := validatePrivateListenAddr(address); err == nil {
			t.Errorf("unsafe address %q accepted", address)
		}
	}
}

func TestProductMetricsAreOnlyOnPrivateRouter(t *testing.T) {
	s := setupTestServer(t)
	key := NewEphemeralTestKey(t, s, []string{
		"monitoring:read-metrics",
		"monitoring:read-component-metrics",
	}, "test-tenant", 5*time.Minute)

	tests := []struct {
		path              string
		privateStatusCode int
	}{
		{
			path:              "/api/v1/monitoring/metrics",
			privateStatusCode: http.StatusOK,
		},
		{
			path:              "/api/v1/monitoring/components/controller/metrics",
			privateStatusCode: http.StatusServiceUnavailable,
		},
	}

	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			publicReq := httptest.NewRequest(http.MethodGet, tc.path, nil)
			publicReq.Header.Set("X-API-Key", key)
			publicRec := httptest.NewRecorder()
			s.router.ServeHTTP(publicRec, publicReq)
			if publicRec.Code != http.StatusNotFound {
				t.Fatalf("public metrics route returned %d, want 404", publicRec.Code)
			}

			privateReq := httptest.NewRequest(http.MethodGet, tc.path, nil)
			privateReq.Header.Set("X-API-Key", key)
			privateRec := httptest.NewRecorder()
			s.metricsRouter.ServeHTTP(privateRec, privateReq)
			if privateRec.Code != tc.privateStatusCode {
				t.Fatalf("private metrics route returned %d, want %d: %s",
					privateRec.Code, tc.privateStatusCode, privateRec.Body.String())
			}
		})
	}
}

func TestPrivateMetricsRouterRetainsAuthentication(t *testing.T) {
	s := setupRouteTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/monitoring/metrics", nil)
	rec := httptest.NewRecorder()

	s.metricsRouter.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated private metrics request returned %d, want 401", rec.Code)
	}
}
