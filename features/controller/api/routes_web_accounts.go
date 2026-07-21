// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerWebAccountRoutes) }

func registerWebAccountRoutes(s *Server, api *mux.Router) {
	// Web-admin account provisioning endpoints (Issue #2490, #2733, #2780).
	// GET /web/accounts — permission-gated only (reads are outside the AssuranceStrong surface; see Issue #2733).
	// POST/DELETE /web/accounts — AssuranceStrong via permissionAssurance, mirroring the tenants-create registration.
	webAccounts := api.PathPrefix("/web/accounts").Subrouter()
	webAccounts.Handle("", s.requirePermission("web-account", "list")(http.HandlerFunc(s.handleListWebAccounts))).Methods("GET")
	webAccounts.Handle("", s.requirePermission("web-account", "create")(http.HandlerFunc(s.handleCreateWebAccount))).Methods("POST")
	webAccounts.Handle("/{username}", s.requirePermission("web-account", "delete")(http.HandlerFunc(s.handleDeleteWebAccount))).Methods("DELETE")

	// WebAuthn passkey / FIDO2 registration endpoints (Issue #2782).
	// Both routes require webauthn:register permission (AssuranceStrong via permissionAssurance)
	// — this is a credential-minting surface, consistent with session:create.
	webAccounts.Handle("/{username}/webauthn/register/begin",
		s.requirePermission("webauthn", "register")(http.HandlerFunc(s.handleWebAuthnRegisterBegin))).Methods("POST")
	webAccounts.Handle("/{username}/webauthn/register/finish",
		s.requirePermission("webauthn", "register")(http.HandlerFunc(s.handleWebAuthnRegisterFinish))).Methods("POST")

	// WebAuthn credential management endpoints (Issue #2783: cfg CLI bootstrap).
	// list: permission-gated only (read — outside the AssuranceStrong surface, per ADR-021).
	// revoke: webauthn:revoke permission (AssuranceStrong — credential-removal surface).
	webAccounts.Handle("/{username}/webauthn/credentials",
		s.requirePermission("webauthn", "list")(http.HandlerFunc(s.handleWebAuthnListCredentials))).Methods("GET")
	webAccounts.Handle("/{username}/webauthn/revoke/{credential_id}",
		s.requirePermission("webauthn", "revoke")(http.HandlerFunc(s.handleWebAuthnRevokeCredential))).Methods("POST")
}
