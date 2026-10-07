//go:build cfgms_test_endpoints

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"
	"os"
)

// registerTestRoutes adds integration-test administration endpoints only to a
// controller built with the cfgms_test_endpoints build tag. Runtime opt-in is a
// second guard against accidentally exposing a specially built test binary.
func registerTestRoutes(s *Server) {
	testOnly := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if os.Getenv("CFGMS_ENABLE_TEST_ENDPOINTS") != "true" {
				http.NotFound(w, r)
				return
			}
			next(w, r)
		}
	}

	s.router.HandleFunc("/api/v1/test/stewards/{id}/config", testOnly(s.handleUpdateStewardConfig)).Methods("PUT", "OPTIONS")
	s.router.HandleFunc("/api/v1/test/stewards/{id}/status", testOnly(s.handleTestSetStewardStatus)).Methods("PUT")
	s.router.HandleFunc("/api/v1/test/audit/count", testOnly(s.handleTestAuditCount)).Methods("GET")
}
