// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	pkgconfig "github.com/cfgis/cfgms/pkg/config"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
)

// handleListConfigs handles GET /api/v1/configs
// Scope is always the authenticated tenant from context; the optional ?tenant_id=
// query param must match the authenticated tenant and is used as a no-op filter
// (it cannot broaden scope beyond the context tenant). This mirrors the pattern
// in handleListStewards and prevents cross-tenant enumeration.
func (s *Server) handleListConfigs(w http.ResponseWriter, r *http.Request) {
	// Authenticated tenant is always the source of truth for scope.
	tenantID := "default"
	if tid, ok := r.Context().Value(ctxkeys.TenantID).(string); ok && tid != "" {
		tenantID = tid
	}

	// If tenant_id query param is provided, it must match the authenticated tenant.
	if qp := r.URL.Query().Get("tenant_id"); qp != "" && qp != tenantID {
		s.writeErrorResponse(w, http.StatusForbidden,
			"tenant_id filter must match authenticated tenant", "TENANT_MISMATCH")
		return
	}

	configs, err := s.configService.ListConfigurations(r.Context(), tenantID)
	if err != nil {
		s.logger.Error("Failed to list configurations",
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list configurations", "INTERNAL_ERROR")
		return
	}

	if configs == nil {
		configs = []*pkgconfig.ConfigurationSummary{}
	}

	s.writeSuccessResponse(w, configs)
}
