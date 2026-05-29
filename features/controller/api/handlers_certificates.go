// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"encoding/json"
	"net/http"

	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/pkg/logging"
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
// Requires mTLS admin cert (IsAdmin=true); non-admin principals are rejected with 403
// even when rbacService is nil, preventing the RBAC-nil bypass.
func (s *Server) handleRotateSigningCert(w http.ResponseWriter, r *http.Request) {
	principal, ok := r.Context().Value(principalContextKey).(*Principal)
	if !ok || principal == nil {
		s.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", "AUTHENTICATION_REQUIRED")
		return
	}

	// Explicit IsAdmin guard — must precede any RBAC or rotation logic.
	// requirePermission skips checks when rbacService is nil (RBAC-nil bypass);
	// a CA-key operation must NEVER be reachable by a non-admin principal.
	if !principal.IsAdmin {
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

	s.writeSuccessResponse(w, certificates)
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

	// Call provisioning service
	provisionResp, err := s.certProvisioningService.ProvisionCertificate(req)
	if err != nil {
		s.logger.Error("Failed to provision certificate",
			"steward_id", logging.SanitizeLogValue(provisionReq.StewardID),
			"common_name", logging.SanitizeLogValue(provisionReq.CommonName),
			"error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to provision certificate", "INTERNAL_ERROR")
		return
	}

	// Check response success
	if !provisionResp.Success {
		s.writeErrorResponse(w, http.StatusBadRequest, provisionResp.Message, "PROVISION_ERROR")
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
