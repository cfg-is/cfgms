// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/features/controller/transport"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
)

// terminalTicketSubprotocolPrefix prefixes the WebSocket subprotocol carrying the ticket.
const terminalTicketSubprotocolPrefix = "cfgms.ticket."

func init() { RegisterRoutes(registerTerminalRoutes) }

// registerTerminalRoutes registers GET /terminal/ws/{steward_id} behind the
// "terminal:create" permission gate (AssuranceStrong per permissionAssurance).
// The handler is resolved lazily from s.terminalHandler so it can be wired via
// SetTerminalHandler after the server is constructed.
//
// Cross-tenant isolation: requirePermission only checks the RBAC verb; it does
// not scope the {steward_id} resource to the caller's tenant. The handler is
// therefore wrapped in tenantScopedTerminalWrapper, which resolves the steward's
// tenant and rejects (404) any steward outside the caller's tenant subtree —
// the same protection the telemetry route gets from tenantScopedTelemetryWrapper.
func registerTerminalRoutes(s *Server, api *mux.Router) {
	api.Handle(
		"/terminal/ws/{steward_id}",
		s.requirePermission("terminal", "create")(s.tenantScopedTerminalWrapper(s.terminalTicketWrapper(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.mu.RLock()
			h := s.terminalHandler
			s.mu.RUnlock()
			if h == nil {
				http.Error(w, "terminal service not available", http.StatusServiceUnavailable)
				return
			}
			h.ServeHTTP(w, r)
		})))),
	).Methods("GET")

	// Browsers cannot attach an operator proof to a WebSocket upgrade, so the Shell tab
	// prepares the signed content here and trades the proof for a one-time ticket.
	api.Handle(
		"/terminal/prepare/{steward_id}",
		s.requirePermission("terminal", "create")(s.tenantScopedTerminalWrapper(http.HandlerFunc(s.handleTerminalPrepare))),
	).Methods("POST")
	api.Handle(
		"/terminal/tickets/{steward_id}",
		s.requirePermission("terminal", "create")(s.tenantScopedTerminalWrapper(http.HandlerFunc(s.handleTerminalTicket))),
	).Methods("POST")
}

// tenantScopedTerminalWrapper enforces cross-tenant isolation on the terminal
// WebSocket route. A scoped principal in tenant A holding terminal:create must
// not be able to open an interactive shell to a steward owned by another tenant.
// It replicates the steward-scoping logic used by tenantScopedTelemetryWrapper
// and handleGetStewardDNA: the caller may only reach stewards in its own tenant
// or a descendant tenant. Out-of-scope (or unknown) stewards return 404 so the
// endpoint does not disclose steward existence across tenants. The {steward_id}
// path variable carries the target steward ID.
//
// Root-scoped principals (ADR-025 Decision 1, Issue #3303): the route path carries
// {steward_id} rather than a tenant ID, so requirePermission's
// extractBoundaryTenantFromRequest returns "" and the middleware root-scoped crossing
// check is skipped. The wrapper resolves the steward's tenant from the registry and
// enforces the ADR-025 Decision 1 boundary inline — same approach as the reboot-window
// handler. tenantAuthNeedsCrossing emits a step-up-shaped crossing challenge
// (ADR-025 Decision 3); tenantAuthDenied returns 404 (existence oracle).
//
// Every branch below ends in an explicit decision (proceed, challenge, or refuse) —
// there is no implicit fall-through to next.ServeHTTP. Issue #4337: callerTenant == ""
// with a principal that was also neither RootScoped nor tenant-scoped used to match no
// case here and fall through to next.ServeHTTP unconditionally. It is now routed
// through authorizeTenantAccess like every other branch, which already has a decision
// for that exact shape (Amendment 4 A4.2: deny unless certificate-authenticated) — so
// the fix is one code path handling every callerTenant == "" principal uniformly,
// rather than a bespoke refusal bolted on beside it.
func (s *Server) tenantScopedTerminalWrapper(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		stewardID := vars["steward_id"]
		if stewardID == "" {
			s.writeErrorResponse(w, http.StatusBadRequest, "Steward ID is required", "MISSING_STEWARD_ID")
			return
		}
		callerTenant := callerTenantFilter(r.Context())
		info, exists := s.controllerService.GetStewardInfo(stewardID)

		if callerTenant != "" { //architecture:allow-root-scope -- tenant-scoped callers; a root caller is decided by authorizeTenantAccess below
			stewardTenant := ""
			if exists {
				stewardTenant = info.TenantID
			}
			if !exists || !s.tenantSubtreeContains(r.Context(), callerTenant, stewardTenant) {
				// 404 instead of 403 to avoid disclosing steward existence across tenants.
				s.writeErrorResponse(w, http.StatusNotFound, "Steward not found", "STEWARD_NOT_FOUND")
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		if !exists {
			s.writeErrorResponse(w, http.StatusNotFound, "Steward not found", "STEWARD_NOT_FOUND")
			return
		}

		// callerTenant == "" and steward exists: delegate to authorizeTenantAccess for
		// every principal shape, not only ones subject to the crossing boundary. Its
		// callerTenant == "" branches already cover: unconditional legacy access for a
		// certificate-authenticated, non-boundary-subject admin (the 31 pre-existing
		// branches authorizeTenantAccess's doc comment describes, provably unchanged
		// here too); the ADR-025 Decision 1 crossing gate for a principal subject to the
		// boundary (subjectToTenantCrossingBoundary — Issue #4337: GlobalScope for an
		// account-bound principal, so a low-assurance session for a root-scope account
		// still gates here); and Amendment 4 A4.2's deny for every other shape — the
		// fall-through this story closes, now a real decision instead of an absent one.
		//
		// The tenantManager nil-guard only applies when the principal is actually
		// boundary-subject: authorizeTenantAccess never dereferences tenantManager for
		// the other two branches, so skipping it there would fail closed on a caller
		// this guard was never meant to affect.
		principal, _ := r.Context().Value(principalContextKey).(*Principal)
		stewardTenant := info.TenantID
		if subjectToTenantCrossingBoundary(principal) && s.tenantManager == nil {
			// Fail closed: no ancestry source wired, treat as if no crossing is active.
			s.writeTenantCrossingChallenge(w, stewardTenant)
			return
		}
		switch s.authorizeTenantAccess(r.Context(), principal, stewardTenant) {
		case tenantAuthAllowed:
			next.ServeHTTP(w, r)
		case tenantAuthNeedsCrossing:
			s.writeTenantCrossingChallenge(w, stewardTenant)
		default:
			principalID := ""
			if principal != nil {
				principalID = principal.ID
			}
			s.logger.Warn("Terminal access refused: principal has no tenant scope and is not authorized for this steward",
				"steward_id", logging.SanitizeLogValue(stewardID),
				"principal_id", logging.SanitizeLogValue(principalID))
			s.writeErrorResponse(w, http.StatusNotFound, "Steward not found", "STEWARD_NOT_FOUND")
		}
	})
}

// terminalTicketFromRequest extracts the single cfgms.ticket.<ticket> subprotocol from
// the Sec-WebSocket-Protocol header. The ticket is never read from the URL.
func terminalTicketFromRequest(r *http.Request) (string, bool) {
	ticket := ""
	for _, v := range r.Header.Values("Sec-WebSocket-Protocol") {
		for _, tok := range strings.Split(v, ",") {
			tok = strings.TrimSpace(tok)
			if !strings.HasPrefix(tok, terminalTicketSubprotocolPrefix) {
				continue
			}
			if ticket != "" {
				return "", false
			}
			ticket = strings.TrimPrefix(tok, terminalTicketSubprotocolPrefix)
		}
	}
	return ticket, ticket != ""
}

// terminalTicketWrapper redeems the one-time terminal ticket and hands the verified
// operator proof to the handler through the request context. It runs after the tenant
// gate, so an unauthenticated or out-of-tenant caller can neither burn another user's
// ticket nor probe for one. The ticket must belong to the calling principal (raw ID
// compared, never the sanitised form), tenant, web session and the steward in the path;
// any mismatch is 403 and the ticket is already consumed.
func (s *Server) terminalTicketWrapper(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stewardID := mux.Vars(r)["steward_id"]
		refuse := func(reason string) {
			s.logger.Warn("Terminal ticket refused",
				"steward_id", logging.SanitizeLogValue(stewardID),
				"reason", reason)
			s.writeErrorResponse(w, http.StatusForbidden, "valid terminal ticket required", "TERMINAL_TICKET_REQUIRED")
		}

		ticket, ok := terminalTicketFromRequest(r)
		if !ok {
			refuse("no ticket presented")
			return
		}
		principal, _ := r.Context().Value(principalContextKey).(*Principal)
		if principal == nil {
			refuse("no authenticated principal")
			return
		}
		rec, outcome := s.takeTerminalTicket(r.Context(), hashTerminalTicket(ticket))
		if outcome == ceremonyUnavailable {
			s.writeCeremonyUnavailable(w)
			return
		}
		if outcome != ceremonyOK || rec == nil || !time.Now().Before(rec.expires) {
			refuse("ticket unknown, used or expired")
			return
		}

		// The ticket records the steward's tenant at mint time; the caller was already
		// authorised for that steward (possibly as an ancestor tenant) by the tenant gate.
		info, known := s.controllerService.GetStewardInfo(stewardID)
		if !known || info == nil || rec.tenantID != info.TenantID {
			refuse("ticket tenant mismatch")
			return
		}
		if rec.principalID != principal.ID || rec.stewardID != stewardID ||
			rec.webSessionID != webSessionIDFromContext(r) {
			refuse("ticket not issued to this caller or steward")
			return
		}

		callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)
		proof := &transport.TerminalProof{
			StewardID:     rec.stewardID,
			UserID:        rec.principalID,
			TenantID:      callerTenant,
			TerminalShell: rec.terminalShell,
			Params:        terminalProofParams(rec),
		}
		ctx := transport.WithTerminalProof(r.Context(), proof)
		// A cookie or Bearer session is re-checked against the shared store for as
		// long as the shell runs; mTLS and API-key principals carry no session.
		if ref, ok := r.Context().Value(authSessionContextKey).(authSessionRef); ok {
			ctx = transport.WithSessionRecheck(ctx, ref.stillLive)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// terminalProofParams renders the ticket's operator envelope as the command params
// steward_action carries, so the steward verifies it unchanged.
func terminalProofParams(rec *terminalTicketRecord) map[string]interface{} {
	params := map[string]interface{}{
		"targets":    rec.targets,
		"nonce":      rec.nonce,
		"expires_at": rec.expiresAt.UTC().Format(time.RFC3339),
	}
	if rec.x509 != nil {
		params["signature_algorithm"] = rec.x509.Algorithm
		params["signature_value"] = rec.x509.Value
		params["signature_public_key"] = rec.x509.PublicKey
	}
	if rec.webAuthn != nil {
		b64 := base64.StdEncoding.EncodeToString
		params["webauthn_authenticator_data"] = b64(rec.webAuthn.AuthenticatorData)
		params["webauthn_client_data_json"] = b64(rec.webAuthn.ClientDataJSON)
		params["webauthn_signature"] = b64(rec.webAuthn.Signature)
		params["webauthn_credential_id"] = b64(rec.webAuthn.CredentialID)
		if rec.manifest != "" {
			params["webauthn_manifest"] = rec.manifest
		}
	}
	return params
}
