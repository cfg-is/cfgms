// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"

	"github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
)

// RevocationManifestKind identifies RevocationManifest's payload shape. It exists
// so a manifest can never be confused with a signed config/DNA payload — both are
// signed with the same PurposeSigning certificate, but only a revocation manifest
// carries this Kind (Issue #3691).
const RevocationManifestKind = "operator-cert-revocation"

// RevocationManifest is the compact, signable set of currently revoked
// operator-certificate serials. RevokedSerials is always sorted so the same
// underlying revocation state serializes to identical bytes before signing.
type RevocationManifest struct {
	Kind           string   `json:"kind"`
	Version        int64    `json:"version"`
	RevokedSerials []string `json:"revoked_serials"`
}

// SignedRevocationManifest is the JSON body served by
// GET /api/v1/certificates/revocation-manifest.
type SignedRevocationManifest struct {
	Manifest  RevocationManifest         `json:"manifest"`
	Signature *signature.ConfigSignature `json:"signature"`
}

// buildRevocationManifest reads the current revocation state from certMgr and
// builds the deterministic manifest to sign. Version is the count of revoked
// serials: Manager.Revoke only ever adds an entry (there is no un-revoke
// primitive), so this count strictly increases with every new revocation and
// never regresses.
func buildRevocationManifest(certMgr *cert.Manager) (*RevocationManifest, error) {
	entries, err := certMgr.ListRevoked()
	if err != nil {
		return nil, fmt.Errorf("list revoked certificates: %w", err)
	}

	serials := make([]string, 0, len(entries))
	for _, e := range entries {
		serials = append(serials, e.Serial)
	}
	sort.Strings(serials)

	return &RevocationManifest{
		Kind:           RevocationManifestKind,
		Version:        int64(len(serials)),
		RevokedSerials: serials,
	}, nil
}

// signRevocationManifest signs manifest with the controller's current
// PurposeSigning certificate, reusing the same signature.NewSigner construction
// pattern used for config/DNA signing (features/controller/service/signing_rotation.go).
func signRevocationManifest(certMgr *cert.Manager, manifest *RevocationManifest) (*signature.ConfigSignature, error) {
	signingCert, err := certMgr.GetCurrentCertForPurpose(cert.PurposeSigning)
	if err != nil {
		return nil, fmt.Errorf("get signing certificate: %w", err)
	}

	signer, err := signature.NewSigner(&signature.SignerConfig{
		CertificatePEM: signingCert.CertificatePEM,
		PrivateKeyPEM:  signingCert.PrivateKeyPEM,
	})
	if err != nil {
		return nil, fmt.Errorf("construct signer: %w", err)
	}

	data, err := json.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("marshal manifest: %w", err)
	}

	sig, err := signer.Sign(data)
	if err != nil {
		return nil, fmt.Errorf("sign manifest: %w", err)
	}
	return sig, nil
}

// handleGetRevocationManifest handles GET /api/v1/certificates/revocation-manifest.
// It exports the existing Manager.Revoke/ListRevoked revocation state as a signed,
// read-only manifest for a later story's steward-side consumer (Issue #3691). This
// adds no new mutation surface: revocation itself remains gated behind
// certificate:revoke at AssuranceStrong; this endpoint only reads and signs
// already-recorded revocation state, gated at certificate:list.
//
// Unscoped principals only. The manifest is fleet-wide by construction — a steward
// verifying it must see EVERY revoked serial, and Version is the fleet-wide revoked
// count, so a per-tenant subset would be a validly signed manifest that silently
// omits revocations and whose Version is not comparable across callers. Because the
// payload cannot be tenant-scoped without breaking what it is for, the endpoint is
// closed to tenant-scoped callers instead: a scoped operator holding certificate:list
// gets 403, not other tenants' serials. The scoped-visibility path for certificate
// data remains handleListCertificates/handleGetCertificate, which filter per tenant
// subtree (filterCertsByTenantScope). Note the revocation store is not limited to
// operator certs despite RevocationManifestKind — handleRevokeCertificate writes
// steward-cert serials into the same store, so serving it unfiltered to a scoped
// caller would disclose other tenants' steward certificates.
func (s *Server) handleGetRevocationManifest(w http.ResponseWriter, r *http.Request) {
	// Authorization before resource state: a scoped caller learns nothing about
	// controller configuration from this endpoint.
	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)
	if callerTenant != "" {
		s.logger.Warn("Denied tenant-scoped access to fleet-wide revocation manifest",
			"caller_tenant", logging.SanitizeLogValue(callerTenant))
		s.writeErrorResponse(w, http.StatusForbidden,
			"Revocation manifest is available to unscoped administrators only", "FORBIDDEN")
		return
	}

	if s.certManager == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Certificate manager not available", "SERVICE_UNAVAILABLE")
		return
	}

	manifest, err := buildRevocationManifest(s.certManager)
	if err != nil {
		s.logger.Error("Failed to build revocation manifest", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to build revocation manifest", "INTERNAL_ERROR")
		return
	}

	sig, err := signRevocationManifest(s.certManager, manifest)
	if err != nil {
		s.logger.Error("Failed to sign revocation manifest", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to sign revocation manifest", "INTERNAL_ERROR")
		return
	}

	s.writeSuccessResponse(w, SignedRevocationManifest{
		Manifest:  *manifest,
		Signature: sig,
	})
}
