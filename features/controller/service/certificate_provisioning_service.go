// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
)

// ErrValidityCeilingExceeded is returned (wrapped) by ProvisionCertificate when
// req.ValidityDays exceeds MaxCertificateValidityDays, so callers such as the
// REST handler can distinguish this client input error from an internal
// provisioning failure and map it to 400 rather than 500.
var ErrValidityCeilingExceeded = errors.New("requested validity_days exceeds the maximum")

// ErrCrossTenantCertificateAccess is returned (wrapped) by ProvisionCertificate
// when a tenant-scoped caller's context is refused by the cross-tenant
// containment check, so callers such as the REST handler can map it to 403
// rather than 500.
var ErrCrossTenantCertificateAccess = errors.New("cross-tenant certificate access denied")

// MaxCertificateValidityDays bounds a caller-requested ValidityDays. A request
// exceeding it is refused outright, not silently clamped (Issue #4346) — a
// silent clamp would let a caller believe it got the validity period it asked
// for, when policy quietly shortened it. 825 days matches the CA/Browser
// Forum's historical public-TLS ceiling: long enough for a legitimate steward
// certificate's operational lifetime, short enough that a certificate issued
// under a compromised or over-broad grant does not stay valid indefinitely
// after the compromise is discovered — module_trust-class blast-radius
// reasoning (CLAUDE.md Threat Model) applied to certificate lifetime.
const MaxCertificateValidityDays = 825

// StewardTenantResolver resolves the tenant that authoritatively owns a
// steward ID, backed by the controller's live registry (Issue #4346).
// *ControllerService satisfies this interface via TenantForDevice.
type StewardTenantResolver interface {
	TenantForDevice(deviceID string) (tenantID string, known bool)
}

// CertificateProvisioningRequest represents a request to provision a certificate
type CertificateProvisioningRequest struct {
	StewardID    string
	CommonName   string
	Organization string
	ValidityDays int
}

// CertificateProvisioningResponse represents the response from certificate provisioning
type CertificateProvisioningResponse struct {
	Success          bool
	Message          string
	CertificatePEM   []byte
	PrivateKeyPEM    []byte
	CACertificatePEM []byte
	SerialNumber     string
	ExpiresAt        time.Time
}

// CertificateProvisioningService provides certificate provisioning functionality
type CertificateProvisioningService struct {
	certManager         *cert.Manager
	logger              logging.Logger
	defaultValidityDays int
	defaultOrganization string

	// tenantResolver resolves a steward's owning tenant for the cross-tenant
	// containment check in ProvisionCertificate (Issue #4346). Nil when not
	// wired via SetTenantResolver, in which case the check is skipped — this
	// service-layer check is defense-in-depth alongside the REST handler's own
	// containment check (Issue #4334), not a replacement for it.
	tenantResolver StewardTenantResolver
}

// NewCertificateProvisioningService creates a new certificate provisioning service
func NewCertificateProvisioningService(certManager *cert.Manager, logger logging.Logger) *CertificateProvisioningService {
	return &CertificateProvisioningService{
		certManager:         certManager,
		logger:              logger,
		defaultValidityDays: 365, // Default to 1 year
		defaultOrganization: "CFGMS Stewards",
	}
}

// SetCertificateDefaults sets default values for certificate provisioning
func (s *CertificateProvisioningService) SetCertificateDefaults(validityDays int, organization string) {
	if validityDays > 0 {
		s.defaultValidityDays = validityDays
	}
	if organization != "" {
		s.defaultOrganization = organization
	}
}

// SetTenantResolver wires the authoritative steward→tenant resolver used by
// ProvisionCertificate's cross-tenant containment check (Issue #4346).
func (s *CertificateProvisioningService) SetTenantResolver(resolver StewardTenantResolver) {
	s.tenantResolver = resolver
}

// ProvisionCertificate provisions a new certificate for a steward.
//
// ctx carries the caller's ctxkeys.TenantScope (Issue #4346). A root-scoped or
// unset-scope caller is passed through unchecked here — root is unrestricted by
// definition, and an unset scope means no caller identity reached this service
// call at all (an internal or test caller not wired to the tenant model),
// mirroring GetConfiguration's established pattern of skipping its own guard
// when no tenant context is present (Issue #1572). A tenant-scoped caller is
// refused when the resolver (SetTenantResolver) can identify req.StewardID's
// owning tenant and it falls outside the caller's scope. This is
// defense-in-depth alongside the REST handler's own containment check (Issue
// #4334): several service-layer callers exist beyond that one handler, and a
// future one must not have to remember to re-derive this check itself.
func (s *CertificateProvisioningService) ProvisionCertificate(ctx context.Context, req *CertificateProvisioningRequest) (*CertificateProvisioningResponse, error) {
	if req == nil {
		return &CertificateProvisioningResponse{
			Success: false,
			Message: "Request cannot be nil",
		}, fmt.Errorf("provision request is required")
	}

	if req.StewardID == "" {
		return &CertificateProvisioningResponse{
			Success: false,
			Message: "Steward ID is required",
		}, fmt.Errorf("steward ID is required")
	}

	if req.ValidityDays > MaxCertificateValidityDays {
		return &CertificateProvisioningResponse{
			Success: false,
			Message: fmt.Sprintf("Requested validity_days %d exceeds the maximum of %d", req.ValidityDays, MaxCertificateValidityDays),
		}, fmt.Errorf("%w: requested %d, maximum %d", ErrValidityCeilingExceeded, req.ValidityDays, MaxCertificateValidityDays)
	}

	if s.tenantResolver != nil {
		if scope, ok := ctx.Value(ctxkeys.TenantScopeKey).(ctxkeys.TenantScope); ok && scope.IsTenant() {
			if ownerTenant, known := s.tenantResolver.TenantForDevice(req.StewardID); known {
				if !certTenantScopeContains(scope.Path(), ownerTenant) {
					s.logger.Warn("Denied cross-tenant certificate provisioning",
						"steward_id", logging.SanitizeLogValue(req.StewardID),
						"steward_tenant", logging.SanitizeLogValue(ownerTenant),
						"caller_tenant", logging.SanitizeLogValue(scope.Path()))
					return &CertificateProvisioningResponse{
						Success: false,
						Message: "Access to this steward is not permitted",
					}, fmt.Errorf("%w: steward %s", ErrCrossTenantCertificateAccess, logging.SanitizeLogValue(req.StewardID))
				}
			}
		}
	}

	// Set defaults
	commonName := req.CommonName
	if commonName == "" {
		commonName = req.StewardID
	}

	organization := req.Organization
	if organization == "" {
		organization = s.defaultOrganization
	}

	validityDays := req.ValidityDays
	if validityDays <= 0 {
		validityDays = s.defaultValidityDays
	}

	// Create client certificate configuration
	clientConfig := &cert.ClientCertConfig{
		CommonName:         commonName,
		Organization:       organization,
		OrganizationalUnit: "Stewards",
		ValidityDays:       validityDays,
		KeySize:            2048,
		ClientID:           req.StewardID,
	}

	s.logger.Info("Provisioning certificate for steward",
		"steward_id", req.StewardID,
		"common_name", commonName,
		"organization", organization,
		"validity_days", validityDays)

	// Generate the certificate
	certificate, err := s.certManager.GenerateClientCertificate(clientConfig)
	if err != nil {
		s.logger.Error("Failed to generate certificate",
			"steward_id", req.StewardID,
			"common_name", commonName,
			"error", err)
		return &CertificateProvisioningResponse{
			Success: false,
			Message: fmt.Sprintf("Failed to generate certificate: %v", err),
		}, fmt.Errorf("failed to generate certificate: %w", err)
	}

	// Get CA certificate
	caCertPEM, err := s.certManager.GetCACertificate()
	if err != nil {
		s.logger.Error("Failed to get CA certificate",
			"steward_id", req.StewardID,
			"error", err)
		return &CertificateProvisioningResponse{
			Success: false,
			Message: fmt.Sprintf("Failed to get CA certificate: %v", err),
		}, fmt.Errorf("failed to get CA certificate: %w", err)
	}

	s.logger.Info("Certificate provisioned successfully",
		"steward_id", req.StewardID,
		"serial_number", certificate.SerialNumber,
		"expires_at", certificate.ExpiresAt)

	return &CertificateProvisioningResponse{
		Success:          true,
		Message:          "Certificate provisioned successfully",
		CertificatePEM:   certificate.CertificatePEM,
		PrivateKeyPEM:    certificate.PrivateKeyPEM,
		CACertificatePEM: caCertPEM,
		SerialNumber:     certificate.SerialNumber,
		ExpiresAt:        certificate.ExpiresAt,
	}, nil
}

// GetCertificateInfo retrieves certificate information by serial number
func (s *CertificateProvisioningService) GetCertificateInfo(serialNumber string) (*cert.CertificateInfo, error) {
	certificate, err := s.certManager.GetCertificate(serialNumber)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate: %w", err)
	}

	return &cert.CertificateInfo{
		Type:                certificate.Type,
		CommonName:          certificate.CommonName,
		SerialNumber:        certificate.SerialNumber,
		CreatedAt:           certificate.CreatedAt,
		ExpiresAt:           certificate.ExpiresAt,
		IsValid:             certificate.IsValid,
		Fingerprint:         certificate.Fingerprint,
		Issuer:              certificate.Issuer,
		ClientID:            certificate.ClientID,
		DaysUntilExpiration: int(time.Until(certificate.ExpiresAt).Hours() / 24),
		NeedsRenewal:        time.Until(certificate.ExpiresAt).Hours()/24 <= 30,
	}, nil
}

// ListCertificatesBySteward retrieves all certificates for a specific steward
func (s *CertificateProvisioningService) ListCertificatesBySteward(stewardID string) ([]*cert.CertificateInfo, error) {
	return s.certManager.GetCertificateByCommonName(stewardID)
}

// certTenantScopeContains reports whether resourceTenant falls within the
// subtree rooted at callerTenant. Mirrors isWithinTenantScope in the api
// package (features/controller/api/middleware.go), duplicated here to avoid a
// service→api import cycle — the same reasoning already documented on
// storedRoleConfig in config_service_v2.go. Unlike that api-package sibling,
// an empty callerTenant is never treated as unrestricted here: the caller in
// ProvisionCertificate only reaches this function when scope.IsTenant() is
// true, so an empty path is a tenant scope built without one (ctxkeys'
// documented "indistinguishable from no restriction" case) and must fail
// closed, not open.
func certTenantScopeContains(callerTenant, resourceTenant string) bool {
	if callerTenant == "" {
		return false
	}
	return resourceTenant == callerTenant ||
		strings.HasPrefix(resourceTenant, callerTenant+"/")
}
