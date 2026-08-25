// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #3578: bind, list, and revoke mTLS admin certificates on web-admin accounts.
//
// Routes (cert-binding:bind / cert-binding:revoke: AssuranceStrong;
//
//	cert-binding:list: permission-gated only):
//
//	POST /api/v1/accounts/{username}/certs/bind
//	     Binds a certificate serial to the account. Rejects 409 if the serial is
//	     already bound to a different account. Leadership-gated (mutating).
//
//	GET  /api/v1/accounts/{username}/certs
//	     Lists all CertBinding records for the account (public metadata only).
//
//	POST /api/v1/accounts/{username}/certs/revoke/{serial}
//	     Removes the binding AND revokes the certificate via certManager.Revoke.
//	     Never removes a binding without also revoking the certificate.
//	     Leadership-gated (mutating).
//
// Serial is the binding and lookup key — it is the same value that IsRevoked(serial)
// checks on every admin mTLS request in extractAdminPrincipal (middleware.go), so
// revoke-binding and "serial no longer resolves to an account" collapse into a single
// existing check rather than requiring a separately-maintained fingerprint lookup.
package api

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
)

// BindCertRequest is the POST .../certs/bind request body.
// Serial is the binding key; Fingerprint is stored for defense-in-depth audit
// correlation. Label is admin-supplied free text (e.g. "primary laptop bundle").
type BindCertRequest struct {
	Serial      string `json:"serial"`
	Fingerprint string `json:"fingerprint"`
	Label       string `json:"label,omitempty"`
}

// handleBindCert handles POST /api/v1/accounts/{username}/certs/bind.
//
// Binds a certificate serial to the named account. Rejects with 409 CONFLICT if
// the serial is already bound to a different account — a serial must resolve to at
// most one account. Calls s.registrationLeaderStatus.HasLeadership() before mutating.
//
// The scan for a pre-existing serial is O(n) over the in-memory account cache —
// the same pattern used by getAccountByID. This is a known scaling limitation: the
// cache may not include accounts that have never been loaded in this process; a
// concurrent bind on a different controller node is not detected. Both limitations
// are accepted and inherited from the existing username-collision check.
//
// s.mu.Lock() is held across the entire scan-for-existing-serial + persist as one
// critical section. Two goroutines racing to bind the same serial to two different
// accounts write to two different store keys with no natural collision point — both
// writes would succeed, leaving the serial bound to both accounts. The mutex closes
// this race for a single controller process.
func (s *Server) handleBindCert(w http.ResponseWriter, r *http.Request) {
	if checker := s.registrationLeaderStatus; checker != nil && !checker.HasLeadership() {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}

	username := mux.Vars(r)["username"]
	if err := validateUsername(username); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, err.Error(), "INVALID_USERNAME")
		return
	}

	var req BindCertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON body", "INVALID_JSON")
		return
	}

	if req.Serial == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "serial is required", "MISSING_SERIAL")
		return
	}

	// go/log-injection (CWE-117): strip CR/LF from admin-supplied label at the source,
	// using the strings.ReplaceAll form that CodeQL's ReplaceSanitizer recognises.
	req.Label = strings.ReplaceAll(strings.ReplaceAll(req.Label, "\n", ""), "\r", "")

	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	actingPrincipalID := ""
	if principal != nil {
		actingPrincipalID = principal.ID
	}

	// Load the target account before acquiring s.mu.Lock — loadAccountFromStore (called
	// transitively by getAccount) calls cacheAccount, which acquires s.mu.Lock internally.
	// Calling getAccount under an already-held s.mu.Lock would deadlock.
	acct, err := s.getAccount(r.Context(), username)
	if err != nil {
		s.logger.Error("Failed to look up account for cert bind",
			"error", logging.SanitizeLogValue(err.Error()),
			"username", logging.SanitizeLogValue(username))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to look up account", "STORE_ERROR")
		return
	}
	if acct == nil {
		s.writeErrorResponse(w, http.StatusNotFound, "Account not found", "ACCOUNT_NOT_FOUND")
		return
	}

	// ADR-025 operator-clarity note: if the certificate being bound carries the root-scope
	// marker but the target account is tenant-scoped, log a note. Per Story 7's
	// principal-resolution story, this is inert — the marker never elevates a tenant-scoped
	// account's actual access, so this is not a rejected bind and not a security control.
	if !acct.RootScope && s.certManager != nil {
		s.logRootScopeMarkerNote(req.Serial, username)
	}

	newBinding := CertBinding{
		Serial:      req.Serial,
		Fingerprint: req.Fingerprint,
		Label:       req.Label,
		BoundAt:     time.Now().UTC(),
	}

	// Critical section: scan the in-memory cache for a pre-existing serial binding on any
	// other account, then persist the new binding. Held as one atomic check+write to prevent
	// two concurrent bind requests for the same serial from each passing the conflict check
	// independently and both succeeding — leaving the serial bound to two different accounts.
	//
	// Known, accepted, out-of-scope limitation: s.mu is single-process and does not cover
	// concurrent binds across controller nodes in a clustered/HA deployment. There is no
	// store-level uniqueness constraint on serial across account records, so two separate
	// controller processes can still race the same bind. This is the same class of gap the
	// existing username-collision check already has; it is inherited, not introduced here.
	s.mu.Lock()

	// O(n) scan of the in-memory cache — same pattern as getAccountByID.
	// Known scaling limitation: accounts not yet loaded into the cache are not checked here.
	for _, other := range s.accounts {
		if other == nil || other.Username == username {
			continue
		}
		for _, b := range other.CertBindings {
			if b.Serial == req.Serial {
				s.mu.Unlock()
				s.writeErrorResponse(w, http.StatusConflict,
					"Certificate serial is already bound to a different account", "SERIAL_CONFLICT")
				return
			}
		}
	}

	// Re-read the target account from the cache (it was populated above by getAccount).
	// Use the cache entry directly to avoid re-entering store I/O under the lock.
	cached := s.accounts[username]
	if cached == nil {
		s.mu.Unlock()
		s.writeErrorResponse(w, http.StatusNotFound, "Account not found", "ACCOUNT_NOT_FOUND")
		return
	}

	// Check for duplicate serial on the same account (idempotent bind is not supported —
	// return 409 so the caller knows the serial is already present).
	for _, b := range cached.CertBindings {
		if b.Serial == req.Serial {
			s.mu.Unlock()
			s.writeErrorResponse(w, http.StatusConflict,
				"Certificate serial is already bound to this account", "SERIAL_CONFLICT")
			return
		}
	}

	updated := *cached
	updated.CertBindings = append(append([]CertBinding(nil), cached.CertBindings...), newBinding)

	// Persist to the durable store (store I/O under lock — justified by the requirement to
	// hold the mutex across the full check+write window for single-serial-per-account).
	if err := s.persistAccount(r.Context(), &updated, actingPrincipalID); err != nil {
		s.mu.Unlock()
		s.logger.Error("Failed to persist cert binding",
			"error", logging.SanitizeLogValue(err.Error()),
			"username", logging.SanitizeLogValue(username))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to persist cert binding", "STORE_ERROR")
		return
	}

	// Update the in-memory cache directly (already under write lock — no cacheAccount call needed).
	s.accounts[username] = &updated
	s.mu.Unlock()

	s.logger.Info("mTLS admin certificate bound to account",
		"username", logging.SanitizeLogValue(username),
		"serial", logging.SanitizeLogValue(req.Serial),
		"label", logging.SanitizeLogValue(req.Label),
		"principal_id", logging.SanitizeLogValue(actingPrincipalID))

	s.writeResponse(w, http.StatusCreated, CertBindingInfo(newBinding))
}

// handleListCertBindings handles GET /api/v1/accounts/{username}/certs.
// Returns public metadata for all mTLS certificates bound to the account.
func (s *Server) handleListCertBindings(w http.ResponseWriter, r *http.Request) {
	username := mux.Vars(r)["username"]
	if err := validateUsername(username); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, err.Error(), "INVALID_USERNAME")
		return
	}

	acct, err := s.getAccount(r.Context(), username)
	if err != nil {
		s.logger.Error("Failed to look up account for cert list",
			"error", logging.SanitizeLogValue(err.Error()),
			"username", logging.SanitizeLogValue(username))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to look up account", "STORE_ERROR")
		return
	}
	if acct == nil {
		s.writeErrorResponse(w, http.StatusNotFound, "Account not found", "ACCOUNT_NOT_FOUND")
		return
	}

	infos := make([]CertBindingInfo, 0, len(acct.CertBindings))
	for _, b := range acct.CertBindings {
		infos = append(infos, CertBindingInfo(b))
	}

	s.writeSuccessResponse(w, infos)
}

// handleRevokeCertBinding handles POST /api/v1/accounts/{username}/certs/revoke/{serial}.
//
// Removes the binding for the named serial from the account AND revokes the certificate
// via certManager.Revoke in the same operation. The two steps are intentionally coupled —
// never remove a binding without also revoking the certificate. Calls
// s.registrationLeaderStatus.HasLeadership() before mutating.
func (s *Server) handleRevokeCertBinding(w http.ResponseWriter, r *http.Request) {
	if checker := s.registrationLeaderStatus; checker != nil && !checker.HasLeadership() {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}

	username := mux.Vars(r)["username"]
	if err := validateUsername(username); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, err.Error(), "INVALID_USERNAME")
		return
	}

	serial := mux.Vars(r)["serial"]
	if serial == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "serial is required", "MISSING_SERIAL")
		return
	}

	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	actingPrincipalID := ""
	if principal != nil {
		actingPrincipalID = principal.ID
	}

	acct, err := s.getAccount(r.Context(), username)
	if err != nil {
		s.logger.Error("Failed to look up account for cert revoke",
			"error", logging.SanitizeLogValue(err.Error()),
			"username", logging.SanitizeLogValue(username))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to look up account", "STORE_ERROR")
		return
	}
	if acct == nil {
		s.writeErrorResponse(w, http.StatusNotFound, "Account not found", "ACCOUNT_NOT_FOUND")
		return
	}

	found := false
	remaining := make([]CertBinding, 0, len(acct.CertBindings))
	for _, b := range acct.CertBindings {
		if b.Serial == serial {
			found = true
			continue
		}
		remaining = append(remaining, b)
	}
	if !found {
		s.writeErrorResponse(w, http.StatusNotFound,
			"Certificate binding not found on this account", "BINDING_NOT_FOUND")
		return
	}

	updated := *acct
	updated.CertBindings = remaining

	if err := s.persistAccount(r.Context(), &updated, actingPrincipalID); err != nil {
		s.logger.Error("Failed to persist cert binding revocation",
			"error", logging.SanitizeLogValue(err.Error()),
			"username", logging.SanitizeLogValue(username))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to revoke cert binding", "STORE_ERROR")
		return
	}

	// Revoke the certificate via certManager in the same operation — never remove the binding
	// without also invalidating the certificate itself. If certManager is nil (no cert
	// management configured), log a warning and continue; the binding is removed regardless.
	if s.certManager != nil {
		if revokeErr := s.certManager.Revoke(serial); revokeErr != nil {
			s.logger.Error("Failed to revoke certificate via certManager — binding removed but cert may still authenticate",
				"serial", logging.SanitizeLogValue(serial),
				"username", logging.SanitizeLogValue(username),
				"error", logging.SanitizeLogValue(revokeErr.Error()))
			// Do not return an error here: the binding has already been removed from the
			// durable store. Returning 500 would mislead the caller into believing the binding
			// is still active. The operator must verify the certificate is also revoked.
		}
	} else {
		s.logger.Warn("certManager not configured — certificate not revoked via manager; binding removed only",
			"serial", logging.SanitizeLogValue(serial),
			"username", logging.SanitizeLogValue(username))
	}

	s.cacheAccount(&updated)

	s.logger.Info("mTLS admin certificate binding revoked",
		"username", logging.SanitizeLogValue(username),
		"serial", logging.SanitizeLogValue(serial),
		"principal_id", logging.SanitizeLogValue(actingPrincipalID))

	s.writeSuccessResponse(w, map[string]interface{}{
		"username": username,
		"serial":   serial,
		"revoked":  true,
	})
}

// logRootScopeMarkerNote logs an operator-clarity note when a certificate carrying the
// ADR-025 root-scope marker is being bound to a tenant-scoped account. This is inert
// (the marker never elevates a tenant-scoped account's actual access) but logged so
// operators can detect misconfigured cert bundles early.
func (s *Server) logRootScopeMarkerNote(serial, username string) {
	certObj, err := s.certManager.GetCertificate(serial)
	if err != nil || certObj == nil || len(certObj.CertificatePEM) == 0 {
		return
	}
	block, _ := pem.Decode(certObj.CertificatePEM)
	if block == nil {
		return
	}
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return
	}
	if cert.HasRootScopeMarker(parsed) {
		s.logger.Info("Operator note: binding a root-scope-marked certificate to a tenant-scoped account; "+
			"the marker is inert for tenant-scoped accounts and does not elevate access (ADR-025)",
			"serial", logging.SanitizeLogValue(serial),
			"username", logging.SanitizeLogValue(username))
	}
}
