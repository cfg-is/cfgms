// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	pkgconfig "github.com/cfgis/cfgms/pkg/config"
	"github.com/cfgis/cfgms/pkg/logging"
)

// handleListConfigs handles GET /api/v1/configs
// Scope is the authenticated tenant from context — the root tenant for a root
// caller (Issue #4665) — or a tenant named with ?tenant_id= that the caller is
// authorized for (selectListTenant), so the filter can never broaden scope past
// the caller's authority. This prevents cross-tenant enumeration.
func (s *Server) handleListConfigs(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := s.selectListTenant(w, r, "GET /api/v1/configs")
	if !ok {
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
