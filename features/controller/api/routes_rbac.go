// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerRBACRoutes) }

func registerRBACRoutes(s *Server, api *mux.Router) {
	// RBAC management endpoints
	rbac := api.PathPrefix("/rbac").Subrouter()

	// Permissions
	rbac.Handle("/permissions", s.requirePermission("rbac", "list-permissions")(http.HandlerFunc(s.handleListPermissions))).Methods("GET")
	rbac.Handle("/permissions/{id}", s.requirePermission("rbac", "read-permission")(http.HandlerFunc(s.handleGetPermission))).Methods("GET")

	// Roles
	rbac.Handle("/roles", s.requirePermission("rbac", "list-roles")(http.HandlerFunc(s.handleListRoles))).Methods("GET")
	rbac.Handle("/roles", s.requirePermission("rbac", "create-role")(http.HandlerFunc(s.handleCreateRole))).Methods("POST")
	rbac.Handle("/roles/{id}", s.requirePermission("rbac", "read-role")(http.HandlerFunc(s.handleGetRole))).Methods("GET")
	rbac.Handle("/roles/{id}", s.requirePermission("rbac", "update-role")(http.HandlerFunc(s.handleUpdateRole))).Methods("PUT")
	rbac.Handle("/roles/{id}", s.requirePermission("rbac", "delete-role")(http.HandlerFunc(s.handleDeleteRole))).Methods("DELETE")

	// Subject role bindings
	rbac.Handle("/subjects/{id}/roles", s.requirePermission("rbac", "list-subject-roles")(http.HandlerFunc(s.handleGetSubjectRoles))).Methods("GET")
	rbac.Handle("/subjects/{id}/roles", s.requirePermission("rbac", "assign-role")(http.HandlerFunc(s.handleAssignSubjectRole))).Methods("POST")
	rbac.Handle("/subjects/{id}/roles/{role_id}", s.requirePermission("rbac", "revoke-role")(http.HandlerFunc(s.handleRevokeSubjectRole))).Methods("DELETE")
}
