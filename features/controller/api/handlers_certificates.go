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
	"github.com/cfgis/cfgms/pkg/cert"
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
	principal, ok := r.Context().Value(principalContextKey).(*Principal)
	if !ok || principal == nil {
		s.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", "AUTHENTICATION_REQUIRED")
		return
	}

	// Defense-in-depth: mirror the AssuranceStrong bar for certificate:rotate.
	// requirePermission skips checks when rbacService is nil (RBAC-nil bypass);
	// a CA-key operation must NEVER be reachable by a sub-Strong-assurance principal.
	if principal.Assurance < session.AssuranceStrong {
		s.writeErrorResponse(w, http.StatusForbidden, "Admin certificate required", "FORBIDDEN")
		return
	}

	if s.signingRotationService == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Signing rotation service not available", "SERVICE_UNAVAILABLE")
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
		s.logger.Error("Signing certificate rotation failed",
			"operator_serial", logging.SanitizeLogValue(principal.CertSerial),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Rotation failed", "ROTATION_ERROR")
		return
	}

	s.writeSuccessResponse(w, RotateSigningCertResponse{
		OldSerial:        result.OldSerial,
		NewSerial:        result.NewSerial,
		OverlapDays:      result.OverlapWindowDays,
		StewardsNotified: result.StewardsNotified,
		OverlapExpiresAt: result.OverlapExpiresAt,
	})
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
			s.logger.Error("Failed to get certificates for steward", "steward_id", logging.SanitizeLogValue(stewardID), "error", err)
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
				ExpiresAt:           certInfo.ExpiresAt,
				DaysUntilExpiration: safeInt32(certInfo.DaysUntilExpiration), // Safe conversion with bounds validation
				NeedsRenewal:        certInfo.NeedsRenewal,
			})
		}
	} else {
		certInfos, err := s.certManager.ListCertificates()
		if err != nil {
			s.logger.Error("Failed to list certificates", "error", err)
			s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list certificates", "INTERNAL_ERROR")
			return
		}
		for _, certInfo := range certInfos {
			certificates = append(certificates, CertificateInfo{
				SerialNumber:        certInfo.SerialNumber,
				CommonName:          certInfo.CommonName,
				StewardID:           certInfo.ClientID,
				IsValid:             certInfo.IsValid,
				ExpiresAt:           certInfo.ExpiresAt,
				DaysUntilExpiration: safeInt32(certInfo.DaysUntilExpiration),
				NeedsRenewal:        certInfo.NeedsRenewal,
			})
		}
	}

	// Apply tenant-scope filter: scoped callers only see certs for stewards
	// within their own tenant subtree. Only an unscoped admin (callerTenant == "")
	// skips filtering; every scoped caller requires an evaluable steward store.
	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)
	if callerTenant != "" {
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
				"caller_tenant", logging.SanitizeLogValue(callerTenant), "error", err)
			s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list certificates", "INTERNAL_ERROR")
			return
		}
		certificates = scoped
	}

	s.writeSuccessResponse(w, certificates)
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

		inScope := isWithinTenantScope(callerTenant, record.TenantID)
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
	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)
	if callerTenant != "" && certData.ClientID != "" {
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
		} else if !isWithinTenantScope(callerTenant, record.TenantID) {
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
	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)
	if callerTenant != "" {
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
		if !isWithinTenantScope(callerTenant, record.TenantID) {
			s.writeErrorResponse(w, http.StatusNotFound, "Certificate not found", "CERTIFICATE_NOT_FOUND")
			return
		}
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

	if provisionReq.CommonName == "" {
		provisionReq.CommonName = provisionReq.StewardID // Default to steward ID
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
	provisionResp, err := s.certProvisioningService.ProvisionCertificate(req)
	if err != nil || provisionResp == nil || !provisionResp.Success {
		s.logger.Error("Failed to provision certificate",
			"steward_id", logging.SanitizeLogValue(provisionReq.StewardID),
			"common_name", logging.SanitizeLogValue(provisionReq.CommonName),
			"error", logging.SanitizeLogValue(provisionFailureDetail(provisionResp, err)))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to provision certificate", "INTERNAL_ERROR")
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
