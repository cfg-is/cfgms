// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/controlplane/internaldelivery"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/session"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// RotateSigningCertRequest is the optional JSON body for the rotate endpoint.
// OverlapDays uses a pointer so an explicit 0 is distinguishable from an
// unset field: 0 means "no overlap, retire the old cert immediately"; nil
// means "use the default overlap window".
type RotateSigningCertRequest struct {
	OverlapDays *int `json:"overlap_days,omitempty"`
	// Force, when true, bypasses the in-progress guard so an operator-initiated
	// rotation succeeds even when the previous overlap window has not yet
	// expired. Defaults to false; CLI/UI flows that surface operator intent
	// should set this to true.
	Force bool `json:"force,omitempty"`
}

// defaultRotationOverlapDays is the overlap window applied when the operator
// does not pass overlap_days in the request body.
const defaultRotationOverlapDays = 7

// RotateSigningCertResponse is the JSON response from the rotate endpoint.
type RotateSigningCertResponse struct {
	OldSerial        string `json:"old_serial"`
	NewSerial        string `json:"new_serial"`
	OverlapDays      int    `json:"overlap_days"`
	StewardsNotified int    `json:"stewards_notified"`
	OverlapExpiresAt string `json:"overlap_expires_at,omitempty"`
}

// handleRotateSigningCert handles POST /api/v1/certificates/signing/rotate.
// Requires AssuranceStrong (mTLS admin cert); weaker principals are rejected with 403
// even when rbacService is nil, preventing the RBAC-nil bypass. certificate:rotate is
// AssuranceStrong-gated in permissionAssurance — this guard mirrors that bar so the
// defense holds even if rbacService is nil.
func (s *Server) handleRotateSigningCert(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireSigningAdmin(w, r, s.signingRotationService != nil,
		"Signing rotation service not available", "rotation")
	if !ok {
		return
	}

	var req RotateSigningCertRequest
	if r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON body", "INVALID_JSON")
			return
		}
	}

	overlapDays := defaultRotationOverlapDays
	if req.OverlapDays != nil {
		overlapDays = *req.OverlapDays
		if overlapDays < 0 {
			s.writeErrorResponse(w, http.StatusBadRequest, "overlap_days must be >= 0", "INVALID_OVERLAP_DAYS")
			return
		}
	}

	result, err := s.signingRotationService.Rotate(r.Context(), principal.CertSerial, overlapDays, req.Force)
	if err != nil {
		// A non-forced rotation requested while a previous overlap window is still
		// open is a client-recoverable conflict, not a server fault: surface 409 so
		// callers can retry with force=true (or wait for the window to close).
		if errors.Is(err, cert.ErrSigningRotationInProgress) {
			s.logger.Warn("Signing certificate rotation rejected: rotation in progress",
				"operator_serial", logging.SanitizeLogValue(principal.CertSerial))
			s.writeErrorResponse(w, http.StatusConflict, "Signing rotation already in progress", "ROTATION_IN_PROGRESS")
			return
		}
		// The cluster has not yet moved to the shared signing identity, so a
		// rotation would strand nodes that still sign with their own keys.
		if errors.Is(err, cert.ErrSigningMigrationPending) {
			s.logger.Warn("Signing certificate rotation rejected: signing identity migration pending",
				"operator_serial", logging.SanitizeLogValue(principal.CertSerial))
			s.writeErrorResponse(w, http.StatusConflict,
				"Signing rotation is unavailable until the cluster signing identity migration completes", "SIGNING_MIGRATION_PENDING")
			return
		}
		s.logger.Error("Signing certificate rotation failed",
			"operator_serial", logging.SanitizeLogValue(principal.CertSerial),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Rotation failed", "ROTATION_ERROR")
		return
	}

	s.emitSigningRotationAudit(r.Context(), principal.CertSerial, result)

	s.writeSuccessResponse(w, RotateSigningCertResponse{
		OldSerial:        result.OldSerial,
		NewSerial:        result.NewSerial,
		OverlapDays:      result.OverlapWindowDays,
		StewardsNotified: result.StewardsNotified,
		OverlapExpiresAt: result.OverlapExpiresAt,
	})
}

// requireSigningAdmin is the gate shared by the signing-certificate operations
// that act on the fleet-wide signing CA (rotate and emergency revoke). It writes
// the denial response itself and returns ok=false when the caller is refused;
// op names the operation in log lines and denial text ("rotation", "revocation").
//
// The gates, in order:
//   - an authenticated principal;
//   - AssuranceStrong (mTLS admin cert). Defense-in-depth: requirePermission
//     skips checks when rbacService is nil (RBAC-nil bypass), and a CA-key
//     operation must NEVER be reachable by a sub-Strong-assurance principal;
//   - the backing service is wired (available);
//   - an unscoped (root) caller (Issue #4334). The signing CA is a single
//     fleet-wide resource owned by no tenant; the AssuranceStrong gate proves the
//     credential, never the caller's tenant scope, and an unset scope is refused
//     by the same IsRoot() check (Issue #4316 fail-closed contract);
//   - a certificate-authenticated session (Issue #4665): a root web or Bearer
//     session, which a phished passkey could yield, may not act on the signing CA.
func (s *Server) requireSigningAdmin(w http.ResponseWriter, r *http.Request, available bool, unavailableMsg, op string) (*Principal, bool) {
	principal, ok := r.Context().Value(principalContextKey).(*Principal)
	if !ok || principal == nil {
		s.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", "AUTHENTICATION_REQUIRED")
		return nil, false
	}

	if principal.Assurance < session.AssuranceStrong {
		s.writeErrorResponse(w, http.StatusForbidden, "Admin certificate required", "FORBIDDEN")
		return nil, false
	}

	if !available {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, unavailableMsg, "SERVICE_UNAVAILABLE")
		return nil, false
	}

	scope, _ := r.Context().Value(ctxkeys.TenantScopeKey).(ctxkeys.TenantScope)
	if !scope.IsRoot() { //architecture:allow-root-scope -- the signing CA is one fleet-wide resource owned by no tenant
		s.logger.Warn("Denied tenant-scoped signing certificate "+op,
			"operator_serial", logging.SanitizeLogValue(principal.CertSerial))
		s.writeErrorResponse(w, http.StatusForbidden,
			"Signing certificate "+op+" is available to unscoped administrators only", "FORBIDDEN")
		return nil, false
	}

	if principal.CertSerial == "" {
		s.logger.Warn("Denied signing certificate "+op+" from a non-certificate session",
			"principal_id", logging.SanitizeLogValue(principal.ID))
		s.writeErrorResponse(w, http.StatusForbidden,
			"Signing certificate "+op+" requires an admin certificate", "FORBIDDEN")
		return nil, false
	}
	return principal, true
}

// SigningMigrationProgressResponse is the JSON response from the signing
// migration progress endpoint.
type SigningMigrationProgressResponse struct {
	SharedSerial         string   `json:"shared_serial"`
	Stewards             int      `json:"stewards"`
	Confirmed            int      `json:"confirmed"`
	Unconfirmed          []string `json:"unconfirmed_steward_ids"`
	UnconfirmedTruncated bool     `json:"unconfirmed_truncated"`
}

// handleGetSigningMigrationProgress handles GET /api/v1/certificates/signing/migration
// (Issue #4797): how many stewards have confirmed the shared signing certificate
// and which have not (a bounded list). It shares rotation's admin-certificate gate,
// because the report spans the whole fleet and is tenant-independent.
func (s *Server) handleGetSigningMigrationProgress(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	svc := s.stewardSigningMigration
	s.mu.RUnlock()
	principal, ok := s.requireSigningAdmin(w, r, svc != nil,
		"Steward signing migration not available", "migration progress")
	if !ok {
		return
	}

	progress, err := svc.Progress(r.Context())
	if err != nil {
		switch {
		case errors.Is(err, service.ErrStewardMigrationNotShared):
			s.writeErrorResponse(w, http.StatusConflict,
				"The cluster has no shared signing certificate yet", "NOT_SHARED_MODE")
		case errors.Is(err, service.ErrStewardMigrationUnavailable):
			s.writeErrorResponse(w, http.StatusServiceUnavailable,
				"Steward signing migration not available", "SERVICE_UNAVAILABLE")
		default:
			s.logger.Error("Signing migration progress failed",
				"operator_serial", logging.SanitizeLogValue(principal.CertSerial),
				"error", logging.SanitizeLogValue(err.Error()))
			s.writeErrorResponse(w, http.StatusInternalServerError, "Progress unavailable", "MIGRATION_PROGRESS_ERROR")
		}
		return
	}
	unconfirmed := progress.Unconfirmed
	if unconfirmed == nil {
		unconfirmed = []string{}
	}
	s.writeSuccessResponse(w, SigningMigrationProgressResponse{
		SharedSerial:         progress.SharedSerial,
		Stewards:             progress.Stewards,
		Confirmed:            progress.Confirmed,
		Unconfirmed:          unconfirmed,
		UnconfirmedTruncated: progress.UnconfirmedTruncated,
	})
}

// RevokeSigningCertRequest is the JSON body for the signing-certificate revoke endpoint.
type RevokeSigningCertRequest struct {
	Serial string `json:"serial"`
	Reason string `json:"reason"`
}

// RevokeSigningCertResponse is the JSON response from the revoke endpoint.
type RevokeSigningCertResponse struct {
	Serial            string `json:"serial"`
	StewardsNotified  int    `json:"stewards_notified"`
	RetiredFromCursor bool   `json:"retired_from_cursor"`
}

// maxRevokeSigningBodyBytes bounds the revoke request body.
const maxRevokeSigningBodyBytes = 4096

// handleRevokeSigningCert handles POST /api/v1/certificates/signing/revoke
// (Issue #4795): it withdraws one named signing certificate from the whole fleet
// immediately. It shares rotation's admin-certificate gate. The current signing
// certificate cannot be revoked in one step (409): rotate first, then revoke the
// superseded serial.
func (s *Server) handleRevokeSigningCert(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireSigningAdmin(w, r, s.signingRetirementService != nil,
		"Signing retirement service not available", "revocation")
	if !ok {
		return
	}

	var req RevokeSigningCertRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRevokeSigningBodyBytes)).Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON body", "INVALID_JSON")
		return
	}
	if req.Serial == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "serial is required", "VALIDATION_ERROR")
		return
	}
	if len(req.Reason) > maxSigningRevokeReasonLen {
		s.writeErrorResponse(w, http.StatusBadRequest, "reason must be at most 256 characters", "VALIDATION_ERROR")
		return
	}

	result, err := s.signingRetirementService.Revoke(r.Context(), principal.CertSerial, req.Serial, req.Reason)
	if err != nil {
		switch {
		case errors.Is(err, cert.ErrInvalidSerial):
			s.writeErrorResponse(w, http.StatusBadRequest, "serial is not a valid certificate serial number", "VALIDATION_ERROR")
		case errors.Is(err, cert.ErrRevokeCurrentSigningCert):
			s.writeErrorResponse(w, http.StatusConflict,
				"The current signing certificate cannot be revoked; rotate first, then revoke the superseded serial", "CURRENT_SIGNING_CERT")
		default:
			s.logger.Error("Signing certificate revocation failed",
				"operator_serial", logging.SanitizeLogValue(principal.CertSerial),
				"serial", logging.SanitizeLogValue(req.Serial),
				"error", logging.SanitizeLogValue(err.Error()))
			s.writeErrorResponse(w, http.StatusInternalServerError, "Revocation failed", "REVOCATION_ERROR")
		}
		return
	}

	s.emitSigningRevokeAudit(r.Context(), principal.CertSerial, req.Reason, result)

	s.writeSuccessResponse(w, RevokeSigningCertResponse{
		Serial:            result.Serial,
		StewardsNotified:  result.StewardsNotified,
		RetiredFromCursor: result.RetiredFromCursor,
	})
}

// ElectSigningCertRequest is the JSON body for the signing-certificate elect endpoint.
type ElectSigningCertRequest struct {
	Serial string `json:"serial"`
}

// ElectSigningCertResponse is the JSON response from the elect endpoint.
type ElectSigningCertResponse struct {
	Serial string `json:"serial"`
}

// maxElectSigningBodyBytes bounds the elect request body.
const maxElectSigningBodyBytes = 1024

// handleElectSigningCert handles POST /api/v1/certificates/signing/elect (Issue
// #4796): it names one node-local signing certificate, already imported into the
// migration namespace, as the cluster's shared signing certificate by creating the
// signing cursor. It shares rotation's admin-certificate gate. It never overrides
// an existing cursor (409 naming its serial) and never picks a serial itself.
func (s *Server) handleElectSigningCert(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireSigningAdmin(w, r, s.certManager != nil,
		"Certificate manager not available", "election")
	if !ok {
		return
	}

	var req ElectSigningCertRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxElectSigningBodyBytes)).Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON body", "INVALID_JSON")
		return
	}
	if req.Serial == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "serial is required", "VALIDATION_ERROR")
		return
	}

	cursor, created, err := s.certManager.ElectSharedSigningSerial(r.Context(), req.Serial)
	if err != nil {
		switch {
		case errors.Is(err, cert.ErrInvalidSerial):
			s.writeErrorResponse(w, http.StatusBadRequest, "serial is not a valid certificate serial number", "VALIDATION_ERROR")
		case errors.Is(err, cert.ErrSigningSerialNotMigrated):
			s.writeErrorResponse(w, http.StatusBadRequest,
				"serial is not in the migration namespace; only a validated, imported signing certificate can be elected", "SERIAL_NOT_MIGRATED")
		case errors.Is(err, cert.ErrSigningSerialRevoked):
			s.writeErrorResponse(w, http.StatusBadRequest,
				"serial is revoked; a revoked signing certificate cannot be elected", "SERIAL_REVOKED")
		case errors.Is(err, cert.ErrNoSigningKeyStore):
			s.writeErrorResponse(w, http.StatusConflict,
				"Signing certificate election applies to clustered controllers only", "NOT_CLUSTER_MODE")
		default:
			s.logger.Error("Signing certificate election failed",
				"operator_serial", logging.SanitizeLogValue(principal.CertSerial),
				"serial", logging.SanitizeLogValue(req.Serial),
				"error", logging.SanitizeLogValue(err.Error()))
			s.writeErrorResponse(w, http.StatusInternalServerError, "Election failed", "ELECTION_ERROR")
		}
		return
	}
	if !created {
		s.writeErrorResponse(w, http.StatusConflict,
			"A shared signing certificate is already elected: serial "+logging.SanitizeLogValue(cursor.CurrentSerial), "ALREADY_ELECTED")
		return
	}

	s.emitSigningElectionAudit(r.Context(), principal.CertSerial, cursor.CurrentSerial)
	s.writeSuccessResponse(w, ElectSigningCertResponse{Serial: cursor.CurrentSerial})
}

// emitSigningElectionAudit records an explicit election with the operator's
// certificate serial and the elected serial. No PEM or key material. No-op when
// auditManager is nil.
func (s *Server) emitSigningElectionAudit(ctx context.Context, operatorSerial, serial string) {
	if s.auditManager == nil {
		return
	}
	b := audit.NewEventBuilder().
		Tenant(audit.SystemTenantID).
		Type(business.AuditEventSecurityEvent).
		Action("signing_certificate_elected").
		User(logging.SanitizeLogValue(operatorSerial), business.AuditUserTypeHuman).
		Resource("signing_certificate", logging.SanitizeLogValue(serial), "").
		Result(business.AuditResultSuccess).
		Severity(business.AuditSeverityHigh).
		Details(map[string]interface{}{
			"operator_serial": logging.SanitizeLogValue(operatorSerial),
			"serial":          logging.SanitizeLogValue(serial),
		})
	if err := s.auditManager.RecordEvent(ctx, b); err != nil {
		s.logger.Warn("Failed to emit signing election audit event",
			"error", logging.SanitizeLogValue(err.Error()))
	}
}

// maxSigningRevokeReasonLen bounds the operator-supplied revoke reason.
const maxSigningRevokeReasonLen = 256

// emitSigningRevokeAudit records a signing-certificate revocation with the
// operator's certificate serial, the revoked serial, the reason and the number of
// stewards notified. No PEM or key material. No-op when auditManager is nil.
func (s *Server) emitSigningRevokeAudit(ctx context.Context, operatorSerial, reason string, result *service.RevokeResult) {
	if s.auditManager == nil {
		return
	}
	b := audit.NewEventBuilder().
		Tenant(audit.SystemTenantID).
		Type(business.AuditEventSecurityEvent).
		Action("signing_certificate_revoked").
		User(logging.SanitizeLogValue(operatorSerial), business.AuditUserTypeHuman).
		Resource("signing_certificate", logging.SanitizeLogValue(result.Serial), "").
		Result(business.AuditResultSuccess).
		Severity(business.AuditSeverityHigh).
		Details(map[string]interface{}{
			"operator_serial":     logging.SanitizeLogValue(operatorSerial),
			"serial":              logging.SanitizeLogValue(result.Serial),
			"reason":              logging.SanitizeLogValue(reason),
			"stewards_notified":   result.StewardsNotified,
			"retired_from_cursor": result.RetiredFromCursor,
		})
	if err := s.auditManager.RecordEvent(ctx, b); err != nil {
		s.logger.Warn("Failed to emit signing revoke audit event",
			"error", logging.SanitizeLogValue(err.Error()))
	}
}

// emitSigningRotationAudit records a successful signing-certificate rotation with
// the operator's certificate serial, the old and new signing serials and the node
// that performed it. Only serials and identifiers are recorded; no PEM or key
// material. No-op when auditManager is nil.
func (s *Server) emitSigningRotationAudit(ctx context.Context, operatorSerial string, result *service.RotationResult) {
	if s.auditManager == nil {
		return
	}
	b := audit.NewEventBuilder().
		Tenant(audit.SystemTenantID).
		Type(business.AuditEventSecurityEvent).
		Action("signing_certificate_rotated").
		User(logging.SanitizeLogValue(operatorSerial), business.AuditUserTypeHuman).
		Resource("signing_certificate", logging.SanitizeLogValue(result.NewSerial), "").
		Result(business.AuditResultSuccess).
		Severity(business.AuditSeverityHigh).
		Details(map[string]interface{}{
			"operator_serial":    logging.SanitizeLogValue(operatorSerial),
			"old_serial":         logging.SanitizeLogValue(result.OldSerial),
			"new_serial":         logging.SanitizeLogValue(result.NewSerial),
			"node_id":            logging.SanitizeLogValue(result.NodeID),
			"overlap_days":       result.OverlapWindowDays,
			"overlap_expires_at": result.OverlapExpiresAt,
		})
	if err := s.auditManager.RecordEvent(ctx, b); err != nil {
		s.logger.Warn("Failed to emit signing rotation audit event",
			"error", logging.SanitizeLogValue(err.Error()))
	}
}

// handleListCertificates handles GET /api/v1/certificates
func (s *Server) handleListCertificates(w http.ResponseWriter, r *http.Request) {
	if s.certManager == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Certificate manager not available", "SERVICE_UNAVAILABLE")
		return
	}

	// Get steward_id filter from query params
	stewardID := r.URL.Query().Get("steward_id")

	// Get certificates from certificate manager
	certificates := make([]CertificateInfo, 0)
	if stewardID != "" {
		// Filter by steward ID (common name)
		certInfos, err := s.certManager.GetCertificateByCommonName(stewardID)
		if err != nil {
			s.logger.Error("Failed to get certificates for steward", "steward_id", logging.SanitizeLogValue(stewardID), "error", logging.SanitizeLogValue(err.Error()))
			s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get certificates", "INTERNAL_ERROR")
			return
		}

		for _, certInfo := range certInfos {
			// The owning steward is the certificate's recorded ClientID, never the
			// caller-supplied query param. GetCertificateByCommonName matches on
			// COMMON NAME, which is independent of the owner (a cert may be issued
			// with an FQDN common name while ClientID is the steward ID — see
			// service.CertificateProvisioningRequest). Labelling the result with the
			// query param would make the tenant-scope filter below evaluate a
			// caller-controlled string instead of the resource's actual owner,
			// disclosing other tenants' certificates. Fall back to the query param
			// only when the cert carries no ClientID at all, in which case it is a
			// controller-internal cert that the scope filter treats as unattributable.
			ownerStewardID := certInfo.ClientID
			if ownerStewardID == "" {
				ownerStewardID = stewardID
			}
			certificates = append(certificates, CertificateInfo{
				SerialNumber:        certInfo.SerialNumber,
				CommonName:          certInfo.CommonName,
				StewardID:           ownerStewardID,
				IsValid:             certInfo.IsValid,
				IssuedAt:            certInfo.CreatedAt,
				ExpiresAt:           certInfo.ExpiresAt,
				DaysUntilExpiration: safeInt32(certInfo.DaysUntilExpiration), // Safe conversion with bounds validation
				NeedsRenewal:        certInfo.NeedsRenewal,
			})
		}
	} else {
		certInfos, err := s.certManager.ListCertificates()
		if err != nil {
			s.logger.Error("Failed to list certificates", "error", logging.SanitizeLogValue(err.Error()))
			s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list certificates", "INTERNAL_ERROR")
			return
		}
		for _, certInfo := range certInfos {
			certificates = append(certificates, CertificateInfo{
				SerialNumber:        certInfo.SerialNumber,
				CommonName:          certInfo.CommonName,
				StewardID:           certInfo.ClientID,
				IsValid:             certInfo.IsValid,
				IssuedAt:            certInfo.CreatedAt,
				ExpiresAt:           certInfo.ExpiresAt,
				DaysUntilExpiration: safeInt32(certInfo.DaysUntilExpiration),
				NeedsRenewal:        certInfo.NeedsRenewal,
			})
		}
	}

	// A failed owner lookup is fatal only for the boundary-subject read decision
	// below; for every other caller TenantID is display enrichment and the
	// tenant-scope filter performs its own fail-closed lookups.
	tenantLookupErr := s.attachCertTenants(r.Context(), certificates)

	// Apply tenant-scope filter: scoped callers only see certs for stewards
	// within their own tenant subtree. Only an unscoped admin (callerTenant == "")
	// skips filtering; every scoped caller requires an evaluable steward store.
	callerTenant := callerTenantFilter(r.Context())
	readScope := s.tenantReadScope(r, "GET /api/v1/certificates")
	if readScope.boundarySubject() {
		// A boundary-subject root caller sees root's own and crossing-covered
		// tenants' certificates; ownership comes from the steward record, so the
		// filter cannot be evaluated without the steward store.
		if s.stewardStore == nil {
			s.logger.Error("certificate list failed: steward store not configured for boundary-subject caller")
			s.writeErrorResponse(w, http.StatusServiceUnavailable, "Fleet store unavailable", "SERVICE_UNAVAILABLE")
			return
		}
		if tenantLookupErr != nil {
			// A certificate whose owner could not be resolved would carry an empty
			// TenantID and pass the crossing check as unattributable. Fail the
			// request rather than disclose client-tenant certificates during a
			// store fault.
			s.logger.Error("certificate list failed: owner lookup failed for boundary-subject caller",
				"error", logging.SanitizeLogValue(tenantLookupErr.Error()))
			s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list certificates", "INTERNAL_ERROR")
			return
		}
		certificates = filterCertsByReadScope(certificates, readScope)
		readScope.LogSummary()
	}
	if callerTenant != "" { //architecture:allow-root-scope -- tenant-scoped subtree filter; a boundary-subject root caller is decided by readScope above
		if s.stewardStore == nil {
			// Without the steward store, subtree membership cannot be evaluated at
			// all. Returning the unfiltered list would disclose every tenant's
			// certificates, so fail closed the same way handleDecommissionSteward
			// and the registration-refresh handlers do.
			s.logger.Error("certificate list failed: steward store not configured",
				"caller_tenant", logging.SanitizeLogValue(callerTenant))
			s.writeErrorResponse(w, http.StatusServiceUnavailable, "Fleet store unavailable", "SERVICE_UNAVAILABLE")
			return
		}

		scoped, err := s.filterCertsByTenantScope(r.Context(), certificates, callerTenant)
		if err != nil {
			// The scope filter could not be evaluated. Returning the unfiltered
			// list would disclose other tenants' certificates, so fail the request.
			s.logger.Error("Failed to apply tenant scope to certificate list",
				"caller_tenant", logging.SanitizeLogValue(callerTenant), "error", logging.SanitizeLogValue(err.Error()))
			s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list certificates", "INTERNAL_ERROR")
			return
		}
		certificates = scoped
	}

	s.writeSuccessResponse(w, certificates)
}

// attachCertTenants sets TenantID on each certificate from its owning steward's
// record. Rows with no steward or no durable record (ErrStewardNotFound) are
// genuinely unattributable and keep an empty tenant. Any other lookup failure
// also leaves the tenant empty, and the first such failure is returned so a
// caller whose visibility decision depends on TenantID can fail closed instead
// of treating the row as unattributable.
func (s *Server) attachCertTenants(ctx context.Context, certs []CertificateInfo) error {
	if s.stewardStore == nil {
		return nil
	}
	var lookupErr error
	tenants := make(map[string]string)
	for i := range certs {
		id := certs[i].StewardID
		if id == "" {
			continue
		}
		tenant, cached := tenants[id]
		if !cached {
			if record, err := s.stewardStore.GetSteward(ctx, id); err == nil {
				tenant = record.TenantID
			} else if !errors.Is(err, business.ErrStewardNotFound) {
				s.logger.Warn("Tenant lookup for certificate failed",
					"error", logging.SanitizeLogValue(err.Error()))
				if lookupErr == nil {
					lookupErr = fmt.Errorf("steward lookup for certificate owner failed: %w", err)
				}
			}
			tenants[id] = tenant
		}
		certs[i].TenantID = tenant
	}
	return lookupErr
}

// filterCertsByReadScope drops the certificates whose owning tenant a
// boundary-subject root caller has no crossing for. A certificate with no
// attributable tenant (controller-internal, or a steward with no durable record)
// stays visible, as it does for every other caller. The caller must have
// rejected the request if attachCertTenants reported a lookup failure, so an
// empty TenantID here only ever means genuinely unattributable.
func filterCertsByReadScope(certs []CertificateInfo, readScope *tenantReadScope) []CertificateInfo {
	filtered := make([]CertificateInfo, 0, len(certs))
	for _, c := range certs {
		if readScope.Skips(c.TenantID) {
			continue
		}
		filtered = append(filtered, c)
	}
	return filtered
}

// filterCertsByTenantScope keeps only the certificates a caller scoped to
// callerTenant is entitled to see. A certificate is dropped only when its owning
// steward is demonstrably outside callerTenant's subtree; certificates that
// cannot be attributed to any tenant are left visible rather than dropped.
//
//   - Empty StewardID: controller-internal cert (CA/signing/server). Not a
//     tenant-scoped resource, so always kept.
//   - business.ErrStewardNotFound: the certificate has no owning steward record
//     to check a tenant against (e.g. controller-internal certs, or a steward
//     that exists only in the in-memory registry and not yet in the durable
//     store — Issue #2929), so per story AC it is kept and visible fleet-wide,
//     same as today.
//   - Any other store error: returned to the caller so the request fails instead of
//     degrading to no filtering at all during a storage outage.
//
// callerTenant == "" is an unscoped admin: the certificates are returned unchanged,
// including unattributable ones. GetSteward lookups are deduped by StewardID
// within the request.
func (s *Server) filterCertsByTenantScope(ctx context.Context, certs []CertificateInfo, callerTenant string) ([]CertificateInfo, error) {
	if callerTenant == "" {
		// Unscoped admin — no subtree to restrict to.
		return certs, nil
	}

	subtree := s.tenantSubtreeIDs(ctx, callerTenant)

	// scopeCache maps StewardID → whether that steward is within the caller's subtree.
	scopeCache := make(map[string]bool)

	filtered := make([]CertificateInfo, 0, len(certs))
	for _, c := range certs {
		if c.StewardID == "" {
			// No owning steward — controller-internal or signing cert.
			// Not a tenant-scoped resource; always visible.
			filtered = append(filtered, c)
			continue
		}

		if inScope, cached := scopeCache[c.StewardID]; cached {
			if inScope {
				filtered = append(filtered, c)
			}
			continue
		}

		record, err := s.stewardStore.GetSteward(ctx, c.StewardID)
		if err != nil {
			if errors.Is(err, business.ErrStewardNotFound) {
				// No durable record — no tenant owner to check against, so the
				// cert is kept and visible fleet-wide, per story AC.
				scopeCache[c.StewardID] = true
				filtered = append(filtered, c)
				continue
			}
			// Genuine store fault: the scope decision cannot be made at all.
			return nil, fmt.Errorf("steward lookup for tenant scope failed: %w", err)
		}

		inScope := subtree.Contains(record.TenantID)
		scopeCache[c.StewardID] = inScope
		if inScope {
			filtered = append(filtered, c)
		}
	}
	return filtered, nil
}

// RevokeCertificateResponse is returned by POST /api/v1/certificates/{serial}/revoke.
// IsValid reflects the post-revocation state (always false after a successful revoke).
// IsRevoked confirms the serial is on the revocation list so the UI can update
// without a second round-trip.
type RevokeCertificateResponse struct {
	SerialNumber string `json:"serial_number"`
	IsValid      bool   `json:"is_valid"`
	IsRevoked    bool   `json:"is_revoked"`
}

// handleGetCertificate handles GET /api/v1/certificates/{serial}.
// Returns CertificateInfo for the given serial number. Callers scoped to a tenant
// may only see certificates whose owning steward lives within their subtree — an
// out-of-scope serial returns 404 (same as unknown serial) to avoid disclosing
// cross-tenant certificate existence.
func (s *Server) handleGetCertificate(w http.ResponseWriter, r *http.Request) {
	if s.certManager == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Certificate manager not available", "SERVICE_UNAVAILABLE")
		return
	}

	vars := mux.Vars(r)
	serial := vars["serial"]

	certData, err := s.certManager.GetCertificate(serial)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			s.writeErrorResponse(w, http.StatusNotFound, "Certificate not found", "CERTIFICATE_NOT_FOUND")
		} else {
			s.logger.Error("Failed to get certificate",
				"serial", logging.SanitizeLogValue(serial),
				"error", logging.SanitizeLogValue(err.Error()))
			s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get certificate", "INTERNAL_ERROR")
		}
		return
	}

	// Tenant-scope check: callers scoped to a tenant subtree may only see
	// certificates whose owning steward lives within that subtree.
	// Unscoped admins (callerTenant == "") see everything.
	// Controller-internal certs (ClientID == "") have no tenant owner and are always visible.
	callerTenant := callerTenantFilter(r.Context())
	if certData.ClientID != "" && s.tenantReadScope(r, "GET /api/v1/certificates/{serial}").boundarySubject() {
		// A boundary-subject root caller reaches a client tenant's certificate only
		// through a crossing; the owning tenant is the steward record's tenant.
		if s.stewardStore == nil {
			s.logger.Error("certificate get failed: steward store not configured for boundary-subject caller")
			s.writeErrorResponse(w, http.StatusServiceUnavailable, "Fleet store unavailable", "SERVICE_UNAVAILABLE")
			return
		}
		owner, ownerErr := s.stewardStore.GetSteward(r.Context(), certData.ClientID)
		switch {
		case ownerErr == nil:
			if !s.authorizeCrossingRead(w, r, owner.TenantID, "GET /api/v1/certificates/{serial}", func() {
				s.writeErrorResponse(w, http.StatusNotFound, "Certificate not found", "CERTIFICATE_NOT_FOUND")
			}) {
				return
			}
		case errors.Is(ownerErr, business.ErrStewardNotFound):
			// No durable record: unattributable, visible fleet-wide like the list.
		default:
			s.logger.Error("Failed to resolve certificate owner for tenant scope",
				"serial", logging.SanitizeLogValue(serial),
				"client_id", logging.SanitizeLogValue(certData.ClientID),
				"error", logging.SanitizeLogValue(ownerErr.Error()))
			s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get certificate", "INTERNAL_ERROR")
			return
		}
	}
	if callerTenant != "" && certData.ClientID != "" { //architecture:allow-root-scope -- tenant-scoped subtree check; a boundary-subject root caller is decided by the crossing gate above
		if s.stewardStore == nil {
			s.logger.Error("certificate get failed: steward store not configured",
				"caller_tenant", logging.SanitizeLogValue(callerTenant))
			s.writeErrorResponse(w, http.StatusServiceUnavailable, "Fleet store unavailable", "SERVICE_UNAVAILABLE")
			return
		}

		record, err := s.stewardStore.GetSteward(r.Context(), certData.ClientID)
		if err != nil {
			if !errors.Is(err, business.ErrStewardNotFound) {
				s.logger.Error("Failed to resolve certificate owner for tenant scope",
					"serial", logging.SanitizeLogValue(serial),
					"client_id", logging.SanitizeLogValue(certData.ClientID),
					"error", logging.SanitizeLogValue(err.Error()))
				s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get certificate", "INTERNAL_ERROR")
				return
			}
			// ErrStewardNotFound: no durable record — unattributable, visible fleet-wide
			// (same rule as filterCertsByTenantScope for the list endpoint).
		} else if !s.isWithinTenantScope(r.Context(), callerTenant, record.TenantID) { //architecture:allow-root-scope -- tenant-scoped subtree check; a boundary-subject root caller is decided by the crossing gate above
			// Out-of-scope: return 404 to avoid leaking cross-tenant serial existence.
			s.writeErrorResponse(w, http.StatusNotFound, "Certificate not found", "CERTIFICATE_NOT_FOUND")
			return
		}
	}

	daysUntil := int(time.Until(certData.ExpiresAt).Hours() / 24)
	s.writeSuccessResponse(w, CertificateInfo{
		SerialNumber:        certData.SerialNumber,
		CommonName:          certData.CommonName,
		StewardID:           certData.ClientID,
		IsValid:             certData.IsValid,
		ExpiresAt:           certData.ExpiresAt,
		DaysUntilExpiration: safeInt32(daysUntil),
		NeedsRenewal:        daysUntil < 30,
	})
}

// handleRevokeCertificate handles POST /api/v1/certificates/{serial}/revoke.
// Tenant-scope check runs BEFORE calling Revoke — an out-of-scope revoke is a
// denial-of-service against the owning steward's mTLS connectivity.
func (s *Server) handleRevokeCertificate(w http.ResponseWriter, r *http.Request) {
	if s.certManager == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Certificate manager not available", "SERVICE_UNAVAILABLE")
		return
	}

	vars := mux.Vars(r)
	serial := vars["serial"]

	// Resolve the cert first to verify existence and get the owning steward.
	certData, err := s.certManager.GetCertificate(serial)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			s.writeErrorResponse(w, http.StatusNotFound, "Certificate not found", "CERTIFICATE_NOT_FOUND")
		} else {
			s.logger.Error("Failed to get certificate for revocation",
				"serial", logging.SanitizeLogValue(serial),
				"error", logging.SanitizeLogValue(err.Error()))
			s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to revoke certificate", "INTERNAL_ERROR")
		}
		return
	}

	// Tenant-scope check before revoking. A cross-tenant revoke is sabotage:
	// it kills a steward's mTLS connectivity without the owning tenant's consent.
	//
	// Revoke fails closed: unlike the read/list path, a tenant-scoped caller may
	// revoke only certificates POSITIVELY attributed to its own subtree. A cert
	// with an empty ClientID is controller-internal (CA, signing, server) and a
	// cert whose steward has no durable record is unattributable — revoking
	// either would let a client-level admin sever mTLS for the whole fleet or
	// for another tenant's steward. Both are denied with the same 404 used for
	// out-of-scope certs so no cross-tenant existence is leaked. Only an
	// unscoped admin (empty caller tenant) may revoke those.
	callerTenant := callerTenantFilter(r.Context())
	if callerTenant != "" { //architecture:allow-root-scope -- tenant-scoped callers; a root caller is checked by authorizeRootCertIdentities in the else branch
		if certData.ClientID == "" {
			s.logger.Warn("Denied tenant-scoped revoke of unattributable certificate",
				"serial", logging.SanitizeLogValue(serial),
				"caller_tenant", logging.SanitizeLogValue(callerTenant))
			s.writeErrorResponse(w, http.StatusNotFound, "Certificate not found", "CERTIFICATE_NOT_FOUND")
			return
		}

		if s.stewardStore == nil {
			s.logger.Error("certificate revoke failed: steward store not configured",
				"caller_tenant", logging.SanitizeLogValue(callerTenant))
			s.writeErrorResponse(w, http.StatusServiceUnavailable, "Fleet store unavailable", "SERVICE_UNAVAILABLE")
			return
		}

		record, err := s.stewardStore.GetSteward(r.Context(), certData.ClientID)
		if err != nil {
			if !errors.Is(err, business.ErrStewardNotFound) {
				s.logger.Error("Failed to resolve certificate owner for revocation scope",
					"serial", logging.SanitizeLogValue(serial),
					"client_id", logging.SanitizeLogValue(certData.ClientID),
					"error", logging.SanitizeLogValue(err.Error()))
				s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to revoke certificate", "INTERNAL_ERROR")
				return
			}
			// ErrStewardNotFound: no durable record, so the cert cannot be
			// attributed to this caller's subtree — deny.
			s.logger.Warn("Denied tenant-scoped revoke of certificate with no steward record",
				"serial", logging.SanitizeLogValue(serial),
				"client_id", logging.SanitizeLogValue(certData.ClientID),
				"caller_tenant", logging.SanitizeLogValue(callerTenant))
			s.writeErrorResponse(w, http.StatusNotFound, "Certificate not found", "CERTIFICATE_NOT_FOUND")
			return
		}
		if access := s.tenantAccessForScope(r.Context(), callerTenantScope(r), record.TenantID, "POST /api/v1/certificates/{serial}/revoke"); access != tenantAuthAllowed {
			if !s.writeTenantCrossingIfNeeded(w, access, record.TenantID) {
				s.writeErrorResponse(w, http.StatusNotFound, "Certificate not found", "CERTIFICATE_NOT_FOUND")
			}
			return
		}
	} else if !s.authorizeRootCertIdentities(w, r, callerTenantScope(r), "POST /api/v1/certificates/{serial}/revoke", func() {
		s.writeErrorResponse(w, http.StatusNotFound, "Certificate not found", "CERTIFICATE_NOT_FOUND")
	}, certData.ClientID) {
		// An explicitly root caller (callerTenantFilter's ""): a certificate issued to
		// a client tenant's steward needs a crossing (Issue #4665).
		return
	}

	if err := s.certManager.Revoke(serial); err != nil {
		s.logger.Error("Failed to revoke certificate",
			"serial", logging.SanitizeLogValue(serial),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to revoke certificate", "INTERNAL_ERROR")
		return
	}

	s.writeSuccessResponse(w, RevokeCertificateResponse{
		SerialNumber: serial,
		IsValid:      false,
		IsRevoked:    true,
	})
}

// isClusterNodeIdentity reports whether id is a controller cluster node ID — an
// identity the internal-delivery peer authorizer admits on CommonName — which no
// provisioned certificate may carry (Issue #4665).
func (s *Server) isClusterNodeIdentity(id string) bool {
	if id == "" {
		return false
	}
	s.mu.RLock()
	nodeIDs := s.deliveryPeerNodeIDs
	s.mu.RUnlock()
	if nodeIDs == nil {
		return false
	}
	for _, nodeID := range nodeIDs() {
		if nodeID != "" && nodeID == id {
			return true
		}
	}
	return false
}

// authorizeRootCertIdentities checks, for a root caller, every steward a
// certificate names — for provisioning, its steward_id and, when it differs, its
// common_name (the identity consumers authenticate on); for revocation, the
// steward it was issued to — that already exists: each one's tenant must pass
// tenantAccessForScope, so a root caller subject to the ADR-025 boundary cannot
// mint, impersonate or revoke a client tenant's steward certificate without a
// crossing (Issue #4665). An identity that names no existing steward (new-device
// onboarding, a controller-internal certificate) stays root's. On refusal it
// writes the crossing challenge, or calls deny, and returns false.
func (s *Server) authorizeRootCertIdentities(w http.ResponseWriter, r *http.Request, scope ctxkeys.TenantScope, route string, deny func(), identities ...string) bool {
	if s.stewardStore == nil {
		principal, _ := r.Context().Value(principalContextKey).(*Principal)
		if subjectToTenantCrossingBoundary(principal) {
			// The identities cannot be attributed, so the crossing boundary cannot
			// be applied: fail closed.
			s.logger.Error("certificate provision failed: steward store not configured")
			s.writeErrorResponse(w, http.StatusServiceUnavailable, "Fleet store unavailable", "SERVICE_UNAVAILABLE")
			return false
		}
		return true
	}
	seen := make(map[string]bool, len(identities))
	for _, id := range identities {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		record, err := s.stewardStore.GetSteward(r.Context(), id)
		if err != nil && !errors.Is(err, business.ErrStewardNotFound) {
			s.logger.Error("Failed to resolve steward for provisioning tenant scope",
				"steward_id", logging.SanitizeLogValue(id),
				"error", logging.SanitizeLogValue(err.Error()))
			s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to provision certificate", "INTERNAL_ERROR")
			return false
		}
		if err != nil || record == nil || record.ID == "" {
			continue
		}
		if access := s.tenantAccessForScope(r.Context(), scope, record.TenantID, route); access != tenantAuthAllowed {
			if !s.writeTenantCrossingIfNeeded(w, access, record.TenantID) {
				deny()
			}
			return false
		}
	}
	return true
}

// handleProvisionCertificate handles POST /api/v1/certificates/provision
func (s *Server) handleProvisionCertificate(w http.ResponseWriter, r *http.Request) {
	if s.certProvisioningService == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Certificate provisioning service not available", "SERVICE_UNAVAILABLE")
		return
	}

	// Parse request body
	var provisionReq CertificateProvisionRequest
	if err := json.NewDecoder(r.Body).Decode(&provisionReq); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON body", "INVALID_JSON")
		return
	}

	// Validate required fields
	if provisionReq.StewardID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Steward ID is required", "MISSING_STEWARD_ID")
		return
	}

	// Issue #4334: tenant containment. A tenant-scoped caller may provision a
	// certificate only for a steward with a durable record inside its own subtree.
	// An unset scope is refused outright regardless of the target (Issue #4316
	// fail-closed contract): the certificate:provision permission grant does not by
	// itself prove a valid caller scope was established.
	//
	// Fails closed on an absent record, exactly like the revoke path above: with no
	// durable record the requested steward_id cannot be attributed to this caller's
	// subtree, and this endpoint returns a CA-signed client certificate *and its
	// private key*, so "not yet attributable" must not mean "allowed". Otherwise any
	// unused steward_id is a free pass through the containment check. New-device
	// onboarding therefore runs as a root/unscoped operation (or after the steward is
	// registered to a tenant), not as an unattributable tenant-scoped provision.
	scope, _ := r.Context().Value(ctxkeys.TenantScopeKey).(ctxkeys.TenantScope)
	if scope.IsUnset() {
		s.writeErrorResponse(w, http.StatusForbidden, "Access to this steward is not permitted", "FORBIDDEN")
		return
	}
	if scope.IsRoot() { //architecture:allow-root-scope -- root keeps new-device onboarding and the free-form Subject; authorizeRootCertIdentities holds every existing steward the certificate would name to tenantAccessForScope
		if !s.authorizeRootCertIdentities(w, r, scope, "POST /api/v1/certificates/provision", func() {
			s.writeErrorResponse(w, http.StatusForbidden, "Access to this steward is not permitted", "FORBIDDEN")
		}, provisionReq.StewardID, provisionReq.CommonName) {
			return
		}
	} else {
		if s.stewardStore == nil {
			s.logger.Error("certificate provision failed: steward store not configured")
			s.writeErrorResponse(w, http.StatusServiceUnavailable, "Fleet store unavailable", "SERVICE_UNAVAILABLE")
			return
		}
		record, err := s.stewardStore.GetSteward(r.Context(), provisionReq.StewardID)
		if err != nil && !errors.Is(err, business.ErrStewardNotFound) {
			s.logger.Error("Failed to resolve steward for provisioning tenant scope",
				"steward_id", logging.SanitizeLogValue(provisionReq.StewardID),
				"error", logging.SanitizeLogValue(err.Error()))
			s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to provision certificate", "INTERNAL_ERROR")
			return
		}
		// errors.Is(err, ErrStewardNotFound), or a store that reports success with no
		// record: unattributable either way. Denied with the same message and status as
		// an out-of-subtree steward so the endpoint is not a fleet-existence oracle.
		if err != nil || record == nil || record.ID == "" {
			s.logger.Warn("Denied tenant-scoped provision for steward with no durable record",
				"steward_id", logging.SanitizeLogValue(provisionReq.StewardID))
			s.writeErrorResponse(w, http.StatusForbidden, "Access to this steward is not permitted", "FORBIDDEN")
			return
		}
		if access := s.tenantAccessForScope(r.Context(), scope, record.TenantID, "POST /api/v1/certificates/provision"); access != tenantAuthAllowed {
			if !s.writeTenantCrossingIfNeeded(w, access, record.TenantID) {
				s.writeErrorResponse(w, http.StatusForbidden, "Access to this steward is not permitted", "FORBIDDEN")
			}
			return
		}

		// The containment check above resolves the steward by steward_id, but the
		// identity that consumers actually authenticate on is the certificate Subject,
		// which the service copies from the request body
		// (certificate_provisioning_service.go → cert.ClientCertConfig): PeerStewardID
		// (pkg/transport/quic/tls.go) derives control-plane steward identity from
		// CommonName alone, and the internal-delivery peer authorizer
		// (pkg/controlplane/internaldelivery/peer_auth.go) refuses steward leaves on the
		// Subject Organization marker while accepting a CommonName that matches a cluster
		// node ID. A caller-supplied CommonName/Organization would therefore let a
		// tenant-scoped caller pass containment with its own steward_id and still receive
		// a certificate impersonating another tenant's steward — or a cluster node. So for
		// a non-root caller the Subject is taken from the resolved record, and an explicit
		// request value is honoured only when it already matches. Root/unscoped callers,
		// who hold fleet-wide authority by definition, keep the free-form Subject.
		if provisionReq.CommonName != "" && provisionReq.CommonName != record.ID {
			s.logger.Warn("Denied tenant-scoped provision with a common_name that is not the steward's identity",
				"steward_id", logging.SanitizeLogValue(provisionReq.StewardID),
				"common_name", logging.SanitizeLogValue(provisionReq.CommonName))
			s.writeErrorResponse(w, http.StatusForbidden,
				"common_name must match the steward's identity", "FORBIDDEN")
			return
		}
		if provisionReq.Organization != "" && provisionReq.Organization != internaldelivery.StewardCertOrganization {
			s.logger.Warn("Denied tenant-scoped provision with a non-steward organization",
				"steward_id", logging.SanitizeLogValue(provisionReq.StewardID),
				"organization", logging.SanitizeLogValue(provisionReq.Organization))
			s.writeErrorResponse(w, http.StatusForbidden,
				"organization must be the steward certificate organization", "FORBIDDEN")
			return
		}
		provisionReq.StewardID = record.ID
		provisionReq.CommonName = record.ID
		// Set explicitly rather than left empty: the service's default organization is
		// deployment-configurable (SetCertificateDefaults), and the steward marker is what
		// keeps this leaf out of the internal-delivery cluster-node path.
		provisionReq.Organization = internaldelivery.StewardCertOrganization
	}

	if provisionReq.CommonName == "" {
		provisionReq.CommonName = provisionReq.StewardID // Default to steward ID
	}

	// Every certificate this endpoint mints is a steward leaf, for every caller
	// (Issue #4665). The internal-delivery peer authorizer admits a controller-CA
	// leaf whose CommonName is a cluster node ID unless it carries the steward
	// Organization, so a caller-chosen Organization — or a CommonName naming a
	// cluster node — would hand back the private key of a controller peer
	// identity. The steward Organization is therefore always stamped, any other
	// requested Organization is refused, and no identity may name a cluster node.
	if provisionReq.Organization != "" && provisionReq.Organization != internaldelivery.StewardCertOrganization {
		s.logger.Warn("Denied provision with a non-steward organization",
			"steward_id", logging.SanitizeLogValue(provisionReq.StewardID),
			"organization", logging.SanitizeLogValue(provisionReq.Organization))
		s.writeErrorResponse(w, http.StatusForbidden,
			"organization must be the steward certificate organization", "FORBIDDEN")
		return
	}
	provisionReq.Organization = internaldelivery.StewardCertOrganization
	if s.isClusterNodeIdentity(provisionReq.StewardID) || s.isClusterNodeIdentity(provisionReq.CommonName) {
		s.logger.Warn("Denied provision naming a cluster node identity",
			"steward_id", logging.SanitizeLogValue(provisionReq.StewardID),
			"common_name", logging.SanitizeLogValue(provisionReq.CommonName))
		s.writeErrorResponse(w, http.StatusForbidden,
			"a steward certificate may not name a cluster node", "FORBIDDEN")
		return
	}

	// Create service request
	req := &service.CertificateProvisioningRequest{
		StewardID:    provisionReq.StewardID,
		CommonName:   provisionReq.CommonName,
		Organization: provisionReq.Organization,
		ValidityDays: int(provisionReq.ValidityDays),
	}

	// Call provisioning service. Today's service reports every failure as both a
	// non-nil error and Success == false, but that pairing is a service convention,
	// not something this handler may assume: a nil response or an unsuccessful
	// response is a failure on its own, and the log detail is derived by
	// provisionFailureDetail so no branch dereferences a possibly-nil error. The
	// service's Message field carries internal error text (CA state, filesystem
	// paths) and is deliberately logged rather than returned to the caller.
	provisionResp, err := s.certProvisioningService.ProvisionCertificate(r.Context(), req)
	if err != nil || provisionResp == nil || !provisionResp.Success {
		s.logger.Error("Failed to provision certificate",
			"steward_id", logging.SanitizeLogValue(provisionReq.StewardID),
			"common_name", logging.SanitizeLogValue(provisionReq.CommonName),
			"error", logging.SanitizeLogValue(provisionFailureDetail(provisionResp, err)))
		// Issue #4346: the two service-layer refusals below are client input/
		// authorization errors, not internal failures — map them to their own
		// status rather than the generic 500 every other provisioning failure gets.
		switch {
		case errors.Is(err, service.ErrValidityCeilingExceeded):
			s.writeErrorResponse(w, http.StatusBadRequest,
				fmt.Sprintf("validity_days must not exceed %d", service.MaxCertificateValidityDays),
				"VALIDITY_DAYS_EXCEEDS_MAXIMUM")
		case errors.Is(err, service.ErrCrossTenantCertificateAccess):
			s.writeErrorResponse(w, http.StatusForbidden, "Access to this steward is not permitted", "FORBIDDEN")
		default:
			s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to provision certificate", "INTERNAL_ERROR")
		}
		return
	}

	// Convert to API response
	result := CertificateProvisionResult{
		CertificatePEM:   string(provisionResp.CertificatePEM),
		PrivateKeyPEM:    string(provisionResp.PrivateKeyPEM),
		CACertificatePEM: string(provisionResp.CACertificatePEM),
		SerialNumber:     provisionResp.SerialNumber,
		ExpiresAt:        provisionResp.ExpiresAt,
	}

	s.writeResponse(w, http.StatusCreated, result)
}

// provisionFailureDetail renders the log detail for a failed certificate
// provisioning attempt. Each failure condition checked by the caller gets its own
// branch — service error, absent response, unsuccessful response — so a service
// that reports failure without returning an error (or returns nothing at all) is
// logged accurately instead of panicking on a nil err.Error() call. The returned
// text is internal detail for the log only; callers receive a generic message.
func provisionFailureDetail(resp *service.CertificateProvisioningResponse, err error) string {
	switch {
	case err != nil:
		return err.Error()
	case resp == nil:
		return "provisioning service returned no response and no error"
	case resp.Message != "":
		return "provisioning service reported failure without an error: " + resp.Message
	default:
		return "provisioning service reported failure without an error"
	}
}

// safeInt32 safely converts an int to int32 with bounds validation
func safeInt32(value int) int32 {
	// Clamp to int32 max to prevent overflow
	if value > 2147483647 {
		return 2147483647
	}
	if value < -2147483648 {
		return -2147483648
	}
	return int32(value) // Safe: bounds validated above
}
