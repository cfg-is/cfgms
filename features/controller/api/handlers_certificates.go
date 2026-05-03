// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package api

import (
	"encoding/json"
	"net/http"

	"github.com/cfgis/cfgms/features/controller/service"
)

// handleListCertificates handles GET /api/v1/certificates
func (s *Server) handleListCertificates(w http.ResponseWriter, r *http.Request) {
	if s.certManager == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Certificate manager not available", "SERVICE_UNAVAILABLE")
		return
	}

	// Get steward_id filter from query params
	stewardID := r.URL.Query().Get("steward_id")

	// Get certificates from certificate manager
	var certificates []CertificateInfo
	if stewardID != "" {
		// Filter by steward ID (common name)
		certInfos, err := s.certManager.GetCertificateByCommonName(stewardID)
		if err != nil {
			s.logger.Error("Failed to get certificates for steward", "steward_id", stewardID, "error", err)
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
		// Get all certificates - this would require a new method in cert manager
		// For now, return empty list with a note
		s.logger.Info("Listing all certificates not implemented yet")
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
			"steward_id", provisionReq.StewardID,
			"common_name", provisionReq.CommonName,
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
