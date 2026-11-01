// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerDirectoryCredentialRoutes) }

// registerDirectoryCredentialRoutes registers the one-time initial-password routes
// (Issue #5559). Both carry Cache-Control: no-store on every response, including the
// step-up challenge, so a proxy or browser never keeps one. The list route is a plain
// permission; the reveal route's Strong floor and presence tap come from
// permissionAssurance. requirePermission does not tenant-scope {id}, so the reveal
// handler authorises the record's tenant itself.
func registerDirectoryCredentialRoutes(s *Server, api *mux.Router) {
	dir := api.PathPrefix("/directory").Subrouter()
	guard := func(resource, action string, h http.HandlerFunc) http.Handler {
		return noStore(s.requirePermission(resource, action)(h))
	}
	dir.Handle("/credentials", guard("directory", "credential-list", s.handleListDirectoryCredentials)).Methods("GET")
	dir.Handle("/credentials/{id}/reveal", guard("directory", "credential-reveal", s.handleRevealDirectoryCredential)).Methods("POST")
}

func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		next.ServeHTTP(w, r)
	})
}
