// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"io"
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerStewardActionRoutes) }

// registerStewardActionRoutes registers the steward service and process action
// endpoints (Issue #4628). Each is gated by its own AssuranceStrong permission and
// wrapped in tenantScopedTerminalWrapper, so the {id} steward is resolved against the
// caller's tenant scope (404 across tenants) and the ADR-025 crossing boundary before
// the handler runs. The permission check is outermost: a caller without the grant
// learns nothing about whether the steward exists.
//
// POST /stewards/{id}/actions/prepare serves both kinds from one path, so it picks
// the permission from the body's target_kind (see handlePrepareStewardAction) and
// then applies the same gate as the action endpoint of that kind.
func registerStewardActionRoutes(s *Server, api *mux.Router) {
	serviceHandler := s.tenantScopedStewardActionWrapper(s.handlePostStewardAction(stewardActionKindService))
	processHandler := s.tenantScopedStewardActionWrapper(s.handlePostStewardAction(stewardActionKindProcess))

	api.Handle("/stewards/{id}/services/{name}/actions",
		s.requirePermission("steward", "service-control")(serviceHandler)).Methods("POST")
	api.Handle("/stewards/{id}/processes/{pid}/actions",
		s.requirePermission("steward", "process-control")(processHandler)).Methods("POST")

	prepareService := s.requirePermission("steward", "service-control")(s.tenantScopedStewardActionWrapper(http.HandlerFunc(s.handlePrepareStewardAction)))
	prepareProcess := s.requirePermission("steward", "process-control")(s.tenantScopedStewardActionWrapper(http.HandlerFunc(s.handlePrepareStewardAction)))
	api.Handle("/stewards/{id}/actions/prepare", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, stewardActionMaxBodyBytes)
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			s.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", "INVALID_REQUEST")
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(raw))
		kind, _ := peekStewardActionKind(raw)
		switch kind {
		case stewardActionKindService:
			prepareService.ServeHTTP(w, r)
		case stewardActionKindProcess:
			prepareProcess.ServeHTTP(w, r)
		default:
			s.writeErrorResponse(w, http.StatusBadRequest, "target_kind must be service or process", "INVALID_ACTION")
		}
	})).Methods("POST")
}

// tenantScopedStewardActionWrapper is tenantScopedTerminalWrapper for the action
// routes, whose steward path variable is {id} rather than {steward_id}: it
// resolves the steward's tenant and enforces tenant scope and the ADR-025
// crossing boundary with the same decisions.
func (s *Server) tenantScopedStewardActionWrapper(next http.Handler) http.Handler {
	scoped := s.tenantScopedTerminalWrapper(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		aliased := make(map[string]string, len(vars)+1)
		for k, v := range vars {
			aliased[k] = v
		}
		aliased["steward_id"] = vars["id"]
		scoped.ServeHTTP(w, mux.SetURLVars(r, aliased))
	})
}
