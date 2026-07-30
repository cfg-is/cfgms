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
			"error", err)
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
			certificates = append(certificates, CertificateInfo{
				SerialNumber:        certInfo.SerialNumber,
				CommonName:          certInfo.CommonName,
				StewardID:           stewardID,
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
	// within their own tenant subtree. An unscoped admin (callerTenant == "")
	// or a missing stewardStore skips filtering entirely.
	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)
	if callerTenant != "" && s.stewardStore != nil {
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

// isWithinTenantScope reports whether targetTenant falls within callerTenant's
// subtree. Returns true when callerTenant is empty (unscoped admin), when both
// are equal, or when targetTenant is a descendant (starts with callerTenant+"/").
func isWithinTenantScope(callerTenant, targetTenant string) bool {
	if callerTenant == "" {
		return true
	}
	return targetTenant == callerTenant || strings.HasPrefix(targetTenant, callerTenant+"/")
}

// filterCertsByTenantScope keeps only the certificates a caller scoped to
// callerTenant is entitled to see. It fails CLOSED, matching the sibling steward
// scoping in tenantScopedTelemetryWrapper: a certificate is returned only when
// its owning steward's TenantID is demonstrably inside callerTenant's subtree.
//
//   - Empty StewardID: controller-internal cert (CA/signing/server). Not a
//     tenant-scoped resource, so always kept.
//   - business.ErrStewardNotFound: the certificate cannot be attributed to any
//     tenant, so it is DROPPED for scoped callers. A steward that exists only in
//     the in-memory registry and not in the durable store (Issue #2929) must not
//     leak its serial, common name and expiry to every other tenant.
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
				// No durable record — the cert is not demonstrably within the
				// caller's subtree. Drop it rather than disclose it.
				scopeCache[c.StewardID] = false
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

	// Call provisioning service. The service reports every failure as both a
	// non-nil error and Success == false — the two are never independent — so a
	// single failure branch covers both, plus a nil-response guard. The service's
	// Message field carries internal error text (CA state, filesystem paths) and is
	// deliberately logged rather than returned to the caller.
	provisionResp, err := s.certProvisioningService.ProvisionCertificate(req)
	if err != nil || provisionResp == nil || !provisionResp.Success {
		s.logger.Error("Failed to provision certificate",
			"steward_id", logging.SanitizeLogValue(provisionReq.StewardID),
			"common_name", logging.SanitizeLogValue(provisionReq.CommonName),
			"error", err)
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
