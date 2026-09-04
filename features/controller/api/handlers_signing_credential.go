// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"time"

	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/session"
)

// signingCredentialValidityDays is the validity period for CSR-issued payload-signing
// certificates (Issue #3693). This credential is unrelated to mTLS transport auth
// (adminCertValidityDays in features/controller/initialization) so it carries its own
// constant rather than sharing one across packages.
const signingCredentialValidityDays = 365

// SigningCredentialRequest is the JSON body for POST /api/v1/signing-credential/request.
// Only the caller-generated public key crosses the wire — the private key never
// leaves the operator's machine (Issue #3693 AC).
type SigningCredentialRequest struct {
	PublicKeyPEM string `json:"public_key_pem"`
}

// SigningCredentialResponse is the JSON response from POST /api/v1/signing-credential/request.
type SigningCredentialResponse struct {
	CertificatePEM   string    `json:"certificate_pem"`
	CACertificatePEM string    `json:"ca_certificate_pem"`
	SerialNumber     string    `json:"serial_number"`
	ExpiresAt        time.Time `json:"expires_at"`
}

// handleRequestSigningCredential handles POST /api/v1/signing-credential/request.
//
// Issues a CSR-based payload-signing certificate (Issue #3693, consuming Issue #3692's
// cert.CA.SignClientCertificateRequest primitive): the caller generates an ECDSA P-256
// keypair locally and submits only the public key here. The CA never generates or sees
// a private key for this credential — cert.Certificate.PrivateKeyPEM is always empty
// for it.
//
// The issued certificate carries cert.PayloadSigningMarkerOID (via
// cert.SetPayloadSigningMarker), never cert.AdminMarkerOID. This is a distinct
// credential purpose from the mTLS admin transport bundle: it authenticates
// payload-signing (operatorpayload.Envelope, stories S5b/S8), never mTLS session
// auth, and must remain distinguishable from an ordinary admin bundle at verification
// time — reusing the admin marker here would erase that distinction.
//
// Gated by the "signing-credential:request" permission, registered by Issue #3687 at
// {Min: session.AssuranceStrong, RequireUserPresence: true} — enforced by the
// requirePermission middleware before this handler ever runs. The Assurance check
// below is defense-in-depth only, mirroring handleRotateSigningCert.
func (s *Server) handleRequestSigningCredential(w http.ResponseWriter, r *http.Request) {

	principal, ok := r.Context().Value(principalContextKey).(*Principal)
	if !ok || principal == nil {
		s.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", "AUTHENTICATION_REQUIRED")
		return
	}

	// Defense-in-depth: mirror the AssuranceStrong bar signing-credential:request
	// carries in permissionAssurance (Issue #3687). requirePermission skips checks
	// when rbacService is nil (RBAC-nil bypass); a payload-signing credential must
	// NEVER be mintable by a sub-Strong-assurance principal.
	if principal.Assurance < session.AssuranceStrong {
		s.writeErrorResponse(w, http.StatusForbidden, "Strong assurance required", "FORBIDDEN")
		return
	}

	if s.certManager == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Certificate manager not available", "SERVICE_UNAVAILABLE")
		return
	}

	var req SigningCredentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON body", "INVALID_JSON")
		return
	}
	if req.PublicKeyPEM == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "public_key_pem is required", "MISSING_PUBLIC_KEY")
		return
	}

	pubKey, err := parseSigningCredentialPublicKey(req.PublicKeyPEM)
	if err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"Invalid public key: only PEM-encoded ECDSA P-256 SubjectPublicKeyInfo is accepted", "INVALID_PUBLIC_KEY")
		return
	}

	// The certificate's identity is the authenticated principal's own identity, never
	// a client-supplied field — a caller-chosen CommonName would let any principal
	// holding this permission mint a signing credential impersonating someone else.
	commonName := principal.Name
	if commonName == "" {
		commonName = principal.ID
	}
	if commonName == "" {
		s.writeErrorResponse(w, http.StatusForbidden, "Authenticated identity required", "MISSING_IDENTITY")
		return
	}

	issuedCert, err := s.certManager.SignClientCertificateRequest(pubKey, &cert.ClientCertConfig{
		CommonName:       commonName,
		Organization:     "CFGMS",
		ClientID:         principal.ID,
		ValidityDays:     signingCredentialValidityDays,
		TemplateModifier: cert.SetPayloadSigningMarker,
	})
	if err != nil {
		s.logger.Error("Failed to issue payload-signing credential",
			"principal", logging.SanitizeLogValue(commonName),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to issue signing credential", "INTERNAL_ERROR")
		return
	}

	caPEM, err := s.certManager.GetCACertificate()
	if err != nil {
		s.logger.Error("Failed to load CA certificate for signing credential response",
			"principal", logging.SanitizeLogValue(commonName),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to issue signing credential", "INTERNAL_ERROR")
		return
	}

	s.logger.Info("Issued payload-signing credential",
		"principal", logging.SanitizeLogValue(commonName),
		"serial", issuedCert.SerialNumber)

	s.writeResponse(w, http.StatusCreated, SigningCredentialResponse{
		CertificatePEM:   string(issuedCert.CertificatePEM),
		CACertificatePEM: string(caPEM),
		SerialNumber:     issuedCert.SerialNumber,
		ExpiresAt:        issuedCert.ExpiresAt,
	})
}

// parseSigningCredentialPublicKey decodes a PEM-encoded PKIX SubjectPublicKeyInfo and
// verifies it is an ECDSA P-256 key — the only algorithm this endpoint accepts. P-256
// is fast to generate locally and scriptmodule.VerifyScriptSignature already supports
// verifying it via the ecdsa-sha256 algorithm (Issue #3693 AC).
func parseSigningCredentialPublicKey(pemStr string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in public_key_pem")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKIX public key: %w", err)
	}
	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("unsupported public key type %T: only ECDSA P-256 is accepted", pub)
	}
	if ecdsaPub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("unsupported ECDSA curve: only P-256 is accepted")
	}
	return ecdsaPub, nil
}
