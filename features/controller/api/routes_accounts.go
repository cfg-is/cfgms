// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerAccountRoutes) }

func registerAccountRoutes(s *Server, api *mux.Router) {
	// Web-admin account provisioning endpoints (Issue #2490, #2733, #2780, #2974, #3126, #3574).
	// GET /accounts — permission-gated only (reads are outside the AssuranceStrong surface; see Issue #2733).
	// POST/DELETE /accounts — AssuranceStrong via permissionAssurance, mirroring the tenants-create registration.
	// GET /accounts/{username} — permission-gated only (read surface; see Issue #3126).
	// PUT /accounts/{username} — AssuranceStrong via permissionAssurance (Issue #3126).
	// POST /accounts/{username}/enrollment-link/revoke — AssuranceStrong; revokes an outstanding magic link (Issue #2974).
	accounts := api.PathPrefix("/accounts").Subrouter()
	accounts.Handle("", s.requirePermission("account", "list")(http.HandlerFunc(s.handleListAccounts))).Methods("GET")
	accounts.Handle("", s.requirePermission("account", "create")(http.HandlerFunc(s.handleCreateAccount))).Methods("POST")
	accounts.Handle("/{username}", s.requirePermission("account", "get")(http.HandlerFunc(s.handleGetAccount))).Methods("GET")
	accounts.Handle("/{username}", s.requirePermission("account", "update")(http.HandlerFunc(s.handleUpdateAccount))).Methods("PUT")
	accounts.Handle("/{username}", s.requirePermission("account", "delete")(http.HandlerFunc(s.handleDeleteAccount))).Methods("DELETE")
	// Issue #2974: enrollment magic link revocation endpoint.
	accounts.Handle("/{username}/enrollment-link/revoke",
		s.requirePermission("account", "revoke-enrollment-link")(http.HandlerFunc(s.handleRevokeEnrollmentLink))).Methods("POST")

	// WebAuthn passkey / FIDO2 registration endpoints (Issue #2782).
	// Both routes require webauthn:register permission (AssuranceStrong via permissionAssurance)
	// — this is a credential-minting surface, consistent with session:create.
	accounts.Handle("/{username}/webauthn/register/begin",
		s.requirePermission("webauthn", "register")(http.HandlerFunc(s.handleWebAuthnRegisterBegin))).Methods("POST")
	accounts.Handle("/{username}/webauthn/register/finish",
		s.requirePermission("webauthn", "register")(http.HandlerFunc(s.handleWebAuthnRegisterFinish))).Methods("POST")

	// WebAuthn credential management endpoints (Issue #2783: cfg CLI bootstrap).
	// list: permission-gated only (read — outside the AssuranceStrong surface, per ADR-021).
	// revoke: webauthn:revoke permission (AssuranceStrong — credential-removal surface).
	accounts.Handle("/{username}/webauthn/credentials",
		s.requirePermission("webauthn", "list")(http.HandlerFunc(s.handleWebAuthnListCredentials))).Methods("GET")
	accounts.Handle("/{username}/webauthn/revoke/{credential_id}",
		s.requirePermission("webauthn", "revoke")(http.HandlerFunc(s.handleWebAuthnRevokeCredential))).Methods("POST")

	// mTLS admin certificate binding endpoints (Issue #3578).
	// bind/revoke: cert-binding:bind / cert-binding:revoke (AssuranceStrong — credential-mutation surface).
	// list: cert-binding:list (permission-gated only — reads are outside the AssuranceStrong surface).
	// rotate: cert-binding:rotate (AssuranceStrong — atomic bind-new + revoke-old, Issue #3579).
	accounts.Handle("/{username}/certs/bind",
		s.requirePermission("cert-binding", "bind")(http.HandlerFunc(s.handleBindCert))).Methods("POST")
	accounts.Handle("/{username}/certs",
		s.requirePermission("cert-binding", "list")(http.HandlerFunc(s.handleListCertBindings))).Methods("GET")
	accounts.Handle("/{username}/certs/revoke/{serial}",
		s.requirePermission("cert-binding", "revoke")(http.HandlerFunc(s.handleRevokeCertBinding))).Methods("POST")
	accounts.Handle("/{username}/certs/rotate/{old_serial}",
		s.requirePermission("cert-binding", "rotate")(http.HandlerFunc(s.handleRotateCert))).Methods("POST")
}
