// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/mux"

	cfgpkg "github.com/cfgis/cfgms/pkg/config"
	"github.com/cfgis/cfgms/pkg/logging"
	secretsiface "github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

const (
	// configTestMaxPerTenant is the maximum number of connection-test requests
	// allowed per tenant per hour before the rate limit triggers HTTP 429.
	configTestMaxPerTenant = 10
	// configTestWindow is the rolling window for the per-tenant rate limit.
	configTestWindow = time.Hour
)

// configSourceTestResponse is returned by POST /api/v1/tenants/{id}/config-source/test.
type configSourceTestResponse struct {
	Reachable bool   `json:"reachable"`
	Error     string `json:"error,omitempty"`
}

// configTestRecord tracks per-tenant request counts within the current window.
type configTestRecord struct {
	mu          sync.Mutex
	count       int
	windowStart time.Time
}

// allowConfigTest returns true when the tenant is within the rate limit window.
// It increments the counter on success.
func (r *configTestRecord) allowConfigTest() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	if now.Sub(r.windowStart) >= configTestWindow {
		r.count = 0
		r.windowStart = now
	}
	if r.count >= configTestMaxPerTenant {
		return false
	}
	r.count++
	return true
}

// MountPointValidator is the interface exposed to the Server for connection testing.
// It is satisfied by cfgpkg.DefaultMountPointValidator and by test doubles.
type MountPointValidator = cfgpkg.MountPointValidator

// handleConfigSourceTest implements POST /api/v1/tenants/{id}/config-source/test.
//
// Security model:
//   - RBAC gate: the requirePermission("tenant", "manage") middleware fires before
//     this handler is invoked, ensuring no outbound connection is made on HTTP 403.
//   - Rate limit: max 10 requests per tenant per hour (per-process counter).
//   - Actor: always extracted from the authenticated request context.
//   - Credentials: fetched from the server's SecretStore only.
//   - URL: sanitized before any logging.
func (s *Server) handleConfigSourceTest(w http.ResponseWriter, r *http.Request) {
	// Snapshot handler-level fields under the read lock to avoid races with SetMountPointValidator.
	s.mu.RLock()
	validator := s.mountPointValidator
	configSS := s.configSourceSecretStore
	s.mu.RUnlock()

	// Actor is extracted from the authenticated context only — never from request body.
	actor, _ := r.Context().Value(userIDContextKey).(string)
	if actor == "" {
		actor = "unknown"
	}

	vars := mux.Vars(r)
	tenantID := vars["id"]
	if tenantID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "tenant id is required", "MISSING_TENANT_ID")
		return
	}

	// Rate limit: max configTestMaxPerTenant requests per tenant per hour.
	val, _ := s.configSourceRateLimits.LoadOrStore(tenantID, &configTestRecord{
		windowStart: time.Now(),
	})
	rec := val.(*configTestRecord)
	if !rec.allowConfigTest() {
		s.writeErrorResponse(w, http.StatusTooManyRequests,
			"config source test rate limit exceeded (max 10 per hour per tenant)",
			"RATE_LIMIT_EXCEEDED")
		return
	}

	// Fetch tenant to get config source metadata.
	if s.tenantManager == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "tenant manager not available", "SERVICE_UNAVAILABLE")
		return
	}
	tenant, err := s.tenantManager.GetTenant(r.Context(), tenantID)
	if err != nil {
		s.logger.Error("config-source test: failed to fetch tenant",
			"tenant_id", tenantID,
			"error", err)
		s.writeErrorResponse(w, http.StatusNotFound, "tenant not found", "TENANT_NOT_FOUND")
		return
	}

	// Parse config source from tenant metadata.
	info, err := cfgpkg.ParseConfigSource(tenant.Metadata)
	if err != nil {
		s.logger.Error("config-source test: invalid config source metadata",
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"error", err)
		s.writeResponse(w, http.StatusOK, configSourceTestResponse{
			Reachable: false,
			Error:     "invalid config source metadata: " + err.Error(),
		})
		return
	}

	if info.Type != cfgpkg.ConfigSourceTypeGit {
		s.writeResponse(w, http.StatusOK, configSourceTestResponse{
			Reachable: false,
			Error:     "tenant does not have a git config source configured",
		})
		return
	}

	// No validator configured: report not-configured rather than silently succeeding.
	if validator == nil {
		s.writeResponse(w, http.StatusOK, configSourceTestResponse{
			Reachable: false,
			Error:     "connection test not available: mount point validator not configured",
		})
		return
	}

	// Determine which secret store to use for credential lookup.
	var ss secretsiface.SecretStore
	if configSS != nil {
		ss = configSS
	} else {
		ss = s.secretStore
	}

	// Perform the outbound connection test. RBAC gate has already passed.
	testErr := validator.ValidateMountPoint(r.Context(), info, ss)
	if testErr != nil {
		s.logger.Info("config-source test: remote not reachable",
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"url", logging.SanitizeLogValue(info.URL),
			"error", testErr)
		s.writeResponse(w, http.StatusOK, configSourceTestResponse{
			Reachable: false,
			Error:     testErr.Error(),
		})
		return
	}

	s.logger.Info("config-source test: remote reachable",
		"tenant_id", logging.SanitizeLogValue(tenantID),
		"url", logging.SanitizeLogValue(info.URL),
		"actor", logging.SanitizeLogValue(actor))

	s.writeResponse(w, http.StatusOK, configSourceTestResponse{Reachable: true})
}

// SetMountPointValidator wires a MountPointValidator into the server for use by
// the config-source test endpoint. Call after New() and before Start().
// If ss is nil, the handler falls back to the server's own SecretStore.
func (s *Server) SetMountPointValidator(v MountPointValidator, ss secretsiface.SecretStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mountPointValidator = v
	s.configSourceSecretStore = ss
}
