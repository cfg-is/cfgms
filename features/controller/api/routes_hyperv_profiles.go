// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerHypervProfileRoutes) }

func registerHypervProfileRoutes(s *Server, api *mux.Router) {
	// Hyper-V VM-provisioning profile endpoints (Issue #3785). create/delete are
	// gated at AssuranceStrong + RequireUserPresence in assurance.go — the
	// surface is root-code-execution-equivalent on every future VM that
	// references the profile.
	profiles := api.PathPrefix("/hyperv/profiles").Subrouter()
	profiles.Handle("", s.requirePermission("hyperv-profile", "list")(http.HandlerFunc(s.handleListHypervProfiles))).Methods("GET")
	profiles.Handle("", s.requirePermission("hyperv-profile", "create")(http.HandlerFunc(s.handleCreateHypervProfile))).Methods("POST")
	profiles.Handle("/{name}", s.requirePermission("hyperv-profile", "read")(http.HandlerFunc(s.handleGetHypervProfile))).Methods("GET")
	profiles.Handle("/{name}", s.requirePermission("hyperv-profile", "delete")(http.HandlerFunc(s.handleDeleteHypervProfile))).Methods("DELETE")
}
