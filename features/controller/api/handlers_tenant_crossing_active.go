// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// ActiveTenantCrossingResponse is one entry of the active-crossings feed: the
// crossing response plus the tenant's display name.
type ActiveTenantCrossingResponse struct {
	TenantCrossingResponse
	// TenantName is the owning tenant's name. For a root-scoped caller it is filled
	// only when the tenant is an MSP visible to root; root never sees client tenant
	// names.
	TenantName string `json:"tenant_name"`
}

// handleListActiveTenantCrossings implements GET /api/v1/tenant-crossings/active.
// It returns the approved, unexpired, unrevoked crossings the caller may see and is
// derived from the store on every call, so the console's elevation indicator shows
// exactly while a crossing is active:
//   - a caller below root sees every active grant and break-glass whose tenant is in
//     its own subtree;
//   - a root-scoped caller subject to the boundary sees the break-glass crossings
//     held by that principal plus every active grant (a grant admits all root
//     support);
//   - an unrestricted caller not subject to the boundary sees every active crossing.
func (s *Server) handleListActiveTenantCrossings(w http.ResponseWriter, r *http.Request) {
	if s.tenantCrossingStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "tenant crossing store not available", "TENANT_CROSSING_UNAVAILABLE")
		return
	}
	ctx := r.Context()
	principal, _ := ctx.Value(principalContextKey).(*Principal)
	callerTenant := callerTenantFilter(ctx)
	rootScoped := subjectToTenantCrossingBoundary(principal)

	active, err := s.tenantCrossingStore.ListActiveTenantCrossings(ctx, time.Now().UTC())
	if err != nil {
		s.logger.Error("Failed to list active tenant crossings",
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "failed to list active crossings", "LIST_FAILED")
		return
	}

	root := s.rootTenantID(ctx)
	out := make([]ActiveTenantCrossingResponse, 0, len(active))
	for _, c := range active {
		if c == nil || c.ApprovalState == business.TenantCrossingApprovalPending {
			continue
		}
		switch {
		case rootScoped:
			if c.Kind == business.TenantCrossingKindBreakGlass && (principal == nil || c.PrincipalID != principal.ID) {
				continue
			}
		case callerTenant == "": //architecture:allow-root-scope -- unrestricted caller not subject to the boundary (unbound bootstrap certificate) sees the whole feed, as it lists every tenant
		case callerTenant == noTenantScope || !s.tenantSubtreeContains(ctx, callerTenant, c.TenantID):
			continue
		}

		entry := ActiveTenantCrossingResponse{TenantCrossingResponse: s.toTenantCrossingResponse(ctx, c)}
		entry.TenantName = s.activeCrossingTenantName(r, c.TenantID, root, rootScoped)
		out = append(out, entry)
	}
	s.writeSuccessResponse(w, out)
}

// activeCrossingTenantName resolves the display name for a feed entry. A root-scoped
// caller gets a name only for an MSP (a direct child of root); client tenant names
// are never shown to root.
func (s *Server) activeCrossingTenantName(r *http.Request, tenantID, root string, rootScoped bool) string {
	if s.tenantManager == nil {
		return ""
	}
	t, err := s.tenantManager.GetTenant(r.Context(), tenantID)
	if err != nil || t == nil {
		return ""
	}
	if rootScoped && (root == "" || t.ParentID != root) {
		return ""
	}
	return t.Name
}
