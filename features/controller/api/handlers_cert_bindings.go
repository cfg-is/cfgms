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
//	     Revokes the certificate via certManager.Revoke FIRST (fail-closed), then
//	     removes the binding from the durable store. Leadership-gated (mutating).
//
// Serial is the binding and lookup key — it is the same value that IsRevoked(serial)
// checks on every admin mTLS request in extractAdminPrincipal (middleware.go), so
// revoke-binding and "serial no longer resolves to an account" collapse into a single
// existing check rather than requiring a separately-maintained fingerprint lookup.
//
// Security notes:
//   - req.Serial is validated against certSerialRE at ingress on the bind path; this
//     prevents path-traversal into the cert-store filesystem (go/path-injection).
//   - All three handlers enforce tenant-subtree scope via isWithinTenantScope to prevent
//     IDOR across tenant boundaries.
//   - The revoke path follows fail-closed ordering: certManager.Revoke fires before the
//     binding is removed from the durable store. A revocation failure returns 500 with
//     the binding intact.
package api

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
)

// certSerialRE constrains certificate serial numbers to alphanumeric characters, max 40
// chars. CFGMS-issued serials are 128-bit random decimals (≤39 digits); external CA
// serials are commonly hex. Both are purely alphanumeric, so this rejects any
// path-traversal payload (slashes, dots, etc.) that would otherwise reach filepath.Join
// inside the cert store. go/path-injection (GHAS #3578).
var certSerialRE = regexp.MustCompile(`^[0-9a-zA-Z]{1,40}$`)

// fingerprintRE accepts common certificate fingerprint formats: colon-separated hex pairs
// (AA:BB:...), raw hex strings, and algorithm-prefixed digests (sha256:hex, sha256:base64…).
// All letters and digits are accepted so that any common format fits without format negotiation.
// Max 256 chars covers SHA-512 with colons (3 chars per byte × 64 bytes = 192 chars + prefix).
var fingerprintRE = regexp.MustCompile(`^[0-9a-zA-Z:_.+/=-]{1,256}$`)

// maxCertBindingsPerAccount caps the number of mTLS certificates that can be bound to a
// single account. The entire CertBindings slice is serialised into the account metadata
// blob, which is decrypted on the authentication hot path (getAccount/getAccountByID).
const maxCertBindingsPerAccount = 50

// BindCertRequest is the POST .../certs/bind request body.
// Serial is the binding key; Fingerprint is stored for audit correlation. Label is
// admin-supplied free text (e.g. "primary laptop bundle").
type BindCertRequest struct {
	Serial      string `json:"serial"`
	Fingerprint string `json:"fingerprint"`
	Label       string `json:"label,omitempty"`
}

// sanitizeCertLabel strips control characters that could cause terminal-escape injection
// or confuse CLI consumers of the label field. The CR/LF strip uses the strings.ReplaceAll
// form that CodeQL's ReplaceSanitizer recognises; the second pass covers remaining C0/C1
// control characters (NUL, ESC, DEL, C1 block) and Unicode line terminators.
func sanitizeCertLabel(label string) string {
	// CodeQL ReplaceSanitizer-recognised form for CR/LF.
	label = strings.ReplaceAll(strings.ReplaceAll(label, "\n", ""), "\r", "")
	// Strip remaining control characters.
	var b strings.Builder
	for _, r := range label {
		switch {
		case r < 0x20: // C0 controls (NUL, BEL, BS, TAB family, ESC, etc.)
		case r == 0x7F: // DEL
		case r >= 0x80 && r <= 0x9F: // C1 controls
		case r == 0x85 || r == 0x2028 || r == 0x2029: // Unicode line terminators
		case unicode.Is(unicode.Cf, r): // format characters (bidi overrides, ZWJ, etc.)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// handleBindCert handles POST /api/v1/accounts/{username}/certs/bind.
//
// Binds a certificate serial to the named account. Rejects with 409 CONFLICT if
// the serial is already bound to a different account — a serial must resolve to at
// most one account. Calls s.registrationLeaderStatus.HasLeadership() before mutating.
//
// s.mu.Lock() is held across the entire cross-account serial scan + persist as one
// critical section. Two goroutines racing to bind the same serial to two different
// accounts write to two different store keys with no natural collision point — both
// writes would succeed, leaving the serial bound to both accounts. The mutex closes
// this race for a single controller process.
//
// Known, accepted out-of-scope limitations:
//   - s.mu is single-process; concurrent binds across HA controller nodes are not caught.
//   - The cross-account scan covers only the in-memory account cache; accounts that have
//     never been loaded in this process are not checked.
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
	// Validate serial format at ingress. certSerialRE accepts only alphanumeric characters,
	// max 40 chars — matching the path-variable validation in validationMiddleware (line 151).
	// This prevents path-traversal payloads from reaching filepath.Join in the cert store
	// (go/path-injection, GHAS #3578). It also ensures bind-side and revoke-side serials use
	// the same character set, closing the asymmetry that would create unrevokable bindings.
	if !certSerialRE.MatchString(req.Serial) {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"invalid serial format: must be 1-40 alphanumeric characters", "INVALID_SERIAL")
		return
	}

	if req.Fingerprint != "" && !fingerprintRE.MatchString(req.Fingerprint) {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"invalid fingerprint format: must be hex characters and colons, max 256 characters", "INVALID_FINGERPRINT")
		return
	}

	// Sanitize label at ingress: strip control characters that could cause terminal-escape
	// injection or confuse CLI/SPA consumers of the label returned by GET .../certs.
	req.Label = sanitizeCertLabel(req.Label)
	if len(req.Label) > 128 {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"label too long: max 128 characters", "LABEL_TOO_LONG")
		return
	}

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

	// Tenant isolation: reject callers that are outside the account's tenant subtree.
	// An out-of-subtree caller receives 403 regardless of whether any binding exists —
	// leaking binding state would create an existence oracle across tenants.
	if !isWithinTenantScope(s.callerTenantID(r), acct.TenantID) {
		s.writeErrorResponse(w, http.StatusForbidden, "Access to this account is not permitted", "FORBIDDEN")
		return
	}

	// ADR-025 operator-clarity note: if the certificate being bound carries the root-scope
	// marker but the target account is tenant-scoped, log a note. Per Story 7's
	// principal-resolution story, this is inert — the marker never elevates a tenant-scoped
	// account's actual access, so this is not a rejected bind and not a security control.
	// req.Serial is validated above, so it is safe to pass to certManager here.
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

	if len(cached.CertBindings) >= maxCertBindingsPerAccount {
		s.mu.Unlock()
		s.writeErrorResponse(w, http.StatusConflict,
			"Maximum certificate bindings per account reached", "BINDING_LIMIT_REACHED")
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

	s.emitAccountAudit(r.Context(), "account.cert_binding.created", updated.TenantID, actingPrincipalID, username,
		map[string]interface{}{"serial": req.Serial})

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

	// Tenant isolation: an out-of-subtree caller receives 403 regardless of binding state.
	if !isWithinTenantScope(s.callerTenantID(r), acct.TenantID) {
		s.writeErrorResponse(w, http.StatusForbidden, "Access to this account is not permitted", "FORBIDDEN")
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
// Revokes the named certificate via certManager.Revoke FIRST (fail-closed), then removes
// the binding from the durable store. Calls s.registrationLeaderStatus.HasLeadership()
// before mutating.
//
// Ordering rationale: revoking the cert first means that if the subsequent persist fails,
// the cert is already invalid and the operator sees an active-looking binding pointing to
// a revoked cert. This is preferable to the opposite (binding removed but cert still valid),
// which would silently leave a valid credential with no associated account record.
//
// If certManager is nil (no cert management configured) the request is refused with 503.
// Removing a binding without revoking would leave a still-valid admin-marked certificate
// with no bound account, which extractAdminPrincipal resolves through the bootstrap
// fallback as unscoped root — so an unrevokable unbind is a privilege escalation, not a
// partial success. Revocation is authoritative on this path or the path is closed.
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

	// The validationMiddleware validates {serial} via certSerialRE before this handler runs.
	// The empty check is defensive; mux does not route an empty path segment.
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

	// Load outside lock — getAccount calls cacheAccount which acquires s.mu.Lock internally.
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

	// Tenant isolation: an out-of-subtree caller receives 403 regardless of binding state.
	if !isWithinTenantScope(s.callerTenantID(r), acct.TenantID) {
		s.writeErrorResponse(w, http.StatusForbidden, "Access to this account is not permitted", "FORBIDDEN")
		return
	}

	// Verify the binding exists before attempting revocation (outside lock — read-only check).
	bindingFound := false
	for _, b := range acct.CertBindings {
		if b.Serial == serial {
			bindingFound = true
			break
		}
	}
	if !bindingFound {
		s.writeErrorResponse(w, http.StatusNotFound,
			"Certificate binding not found on this account", "BINDING_NOT_FOUND")
		return
	}

	// Step 1: Revoke the certificate BEFORE removing the binding (fail-closed ordering).
	// If revocation fails, we return 500 with the binding intact — the caller can retry.
	// If certManager is nil the certificate cannot be revoked at all, so the unbind is
	// refused: an unbound-but-valid admin certificate resolves through extractAdminPrincipal's
	// bootstrap fallback as unscoped root, which would make the unbind an escalation for a
	// tenant-scoped account. The binding stays intact and the caller gets 503.
	if s.certManager == nil {
		s.logger.Error("Refusing to remove certificate binding: certManager not configured, "+
			"certificate cannot be revoked",
			"serial", logging.SanitizeLogValue(serial),
			"username", logging.SanitizeLogValue(username))
		s.writeErrorResponse(w, http.StatusServiceUnavailable,
			"Certificate management is not configured; the certificate cannot be revoked, "+
				"so the binding cannot be removed", "CERT_MANAGER_UNAVAILABLE")
		return
	}
	if revokeErr := s.certManager.Revoke(serial); revokeErr != nil {
		s.logger.Error("Failed to revoke certificate via certManager; binding not removed",
			"serial", logging.SanitizeLogValue(serial),
			"username", logging.SanitizeLogValue(username),
			"error", logging.SanitizeLogValue(revokeErr.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError,
			"Failed to revoke certificate; binding not removed", "REVOKE_FAILED")
		return
	}
	certRevoked := true

	// Step 2: Remove the binding from the durable store under the write lock.
	// Re-read from the cache inside the lock so we don't lose concurrent mutations
	// (e.g. a concurrent bind or passkey change) that modified the account blob
	// between the getAccount call above and this persist.
	s.mu.Lock()

	cached := s.accounts[username]
	if cached == nil {
		s.mu.Unlock()
		// The cert has already been revoked at this point. Log the inconsistency.
		s.logger.Error("Account disappeared from cache after cert revocation; binding state unknown",
			"serial", logging.SanitizeLogValue(serial),
			"username", logging.SanitizeLogValue(username))
		s.writeErrorResponse(w, http.StatusInternalServerError,
			"Account state error after cert revocation", "STATE_ERROR")
		return
	}

	remaining := make([]CertBinding, 0, len(cached.CertBindings))
	for _, b := range cached.CertBindings {
		if b.Serial != serial {
			remaining = append(remaining, b)
		}
	}

	updated := *cached
	updated.CertBindings = remaining

	if err := s.persistAccount(r.Context(), &updated, actingPrincipalID); err != nil {
		s.mu.Unlock()
		// The cert has already been revoked. Log a prominent warning: the cert is invalid
		// but the binding still appears active. Manual cleanup may be needed.
		s.logger.Error("Certificate revoked but binding persist failed; cert is revoked, binding may still appear active",
			"serial", logging.SanitizeLogValue(serial),
			"username", logging.SanitizeLogValue(username),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError,
			"Certificate revoked but binding removal failed; cert is no longer valid", "PARTIAL_REVOKE")
		return
	}

	s.accounts[username] = &updated
	s.mu.Unlock()

	s.logger.Info("mTLS admin certificate binding revoked",
		"username", logging.SanitizeLogValue(username),
		"serial", logging.SanitizeLogValue(serial),
		"cert_revoked", certRevoked,
		"principal_id", logging.SanitizeLogValue(actingPrincipalID))

	s.emitAccountAudit(r.Context(), "account.cert_binding.revoked", updated.TenantID, actingPrincipalID, username,
		map[string]interface{}{"serial": serial, "cert_revoked": certRevoked})

	s.writeSuccessResponse(w, map[string]interface{}{
		"username":     username,
		"serial":       serial,
		"cert_revoked": certRevoked,
		"revoked":      true,
	})
}

// logRootScopeMarkerNote logs an operator-clarity note when a certificate carrying the
// ADR-025 root-scope marker is being bound to a tenant-scoped account. This is inert
// (the marker never elevates a tenant-scoped account's actual access) but logged so
// operators can detect misconfigured cert bundles early.
//
// Precondition: serial has been validated against certSerialRE before this call.
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
