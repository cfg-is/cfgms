// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerDirectoryRoutes) }

// registerDirectoryRoutes registers the read-only /api/v1/directory routes
// (Issue #5557). All of them require directory:read; none is a mutation, so none
// carries an assurance floor. requirePermission does not tenant-scope {id} routes, so
// every by-id handler authorises through the entity read path itself.
func registerDirectoryRoutes(s *Server, api *mux.Router) {
	dir := api.PathPrefix("/directory").Subrouter()
	read := func(h http.HandlerFunc) http.Handler {
		return s.requirePermission("directory", "read")(h)
	}

	dir.Handle("/users", read(s.handleListDirectoryUsers)).Methods("GET")
	dir.Handle("/groups", read(s.handleListDirectoryGroups)).Methods("GET")

	dir.Handle("/users/{source}/{id}/groups", read(s.handleListDirectoryUserGroups)).Methods("GET")
	dir.Handle("/users/{source}/{id}", read(s.handleGetDirectoryUser)).Methods("GET")

	dir.Handle("/groups/{source}/{id}/members", read(s.handleListDirectoryGroupMembers)).Methods("GET")
	dir.Handle("/groups/{source}/{id}/membership-changes", read(s.handleListDirectoryMembershipChanges)).Methods("GET")
	dir.Handle("/groups/{source}/{id}", read(s.handleGetDirectoryGroup)).Methods("GET")
}
