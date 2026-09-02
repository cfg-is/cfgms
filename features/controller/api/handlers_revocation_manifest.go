// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"

	"github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

// RevocationManifestKind identifies RevocationManifest's payload shape. It exists
// so a manifest can never be confused with a signed config/DNA payload — both are
// signed with the same PurposeSigning certificate, but only a revocation manifest
// carries this Kind (Issue #3691).
const RevocationManifestKind = "operator-cert-revocation"

// AuthorizedWebAuthnCredentialKind discriminates AuthorizedWebAuthnCredential from any
// future manifest entry type sitting alongside RevokedSerials — a Kind-discriminated
// sibling entry type (Issue #3697).
const AuthorizedWebAuthnCredentialKind = "webauthn-credential"

// AuthorizedWebAuthnCredential is a CA-signed roster entry (Issue #3697) naming one
// registered WebAuthn credential's COSE public key, keyed by credential ID, so a
// steward verifying a WebAuthn-signed operator payload can resolve the signer's public
// key from a source it independently trusts rather than an unsigned, live controller
// claim. CredentialID and PublicKey mirror WebAuthnCredential.ID/.PublicKey exactly.
type AuthorizedWebAuthnCredential struct {
	Kind         string `json:"kind"`
	CredentialID []byte `json:"credential_id"`
	PublicKey    []byte `json:"public_key"`
}

// RevocationManifest is the compact, signable set of currently revoked
// operator-certificate serials, plus (Issue #3697) the fleet-wide roster of authorized
// WebAuthn credential public keys. RevokedSerials is always sorted, and
// AuthorizedWebAuthnCredentials is always sorted by CredentialID, so the same
// underlying state serializes to identical bytes before signing.
type RevocationManifest struct {
	Kind                          string                         `json:"kind"`
	Version                       int64                          `json:"version"`
	RevokedSerials                []string                       `json:"revoked_serials"`
	AuthorizedWebAuthnCredentials []AuthorizedWebAuthnCredential `json:"authorized_webauthn_credentials,omitempty"`
}

// SignedRevocationManifest is the JSON body served by
// GET /api/v1/certificates/revocation-manifest.
//
// SignerCertificatePEM (Issue #3697) is the PurposeSigning certificate Signature was
// produced with — added so a caller with no other side channel to the controller's
// current signing certificate (e.g. a steward verifying a WebAuthn-signed operator
// payload embedded in an inline command, features/steward/commands) can independently
// chain-verify it against its own trusted CA roots before trusting Signature. This is a
// response-shape addition only: the signing mechanism itself (same PurposeSigning cert,
// same signature.NewSigner construction) is unchanged.
type SignedRevocationManifest struct {
	Manifest             RevocationManifest         `json:"manifest"`
	Signature            *signature.ConfigSignature `json:"signature"`
	SignerCertificatePEM string                     `json:"signer_certificate_pem"`
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

// buildAuthorizedWebAuthnCredentials reads every registered WebAuthn credential
// fleet-wide (across every account, not tenant-scoped — the manifest is fleet-wide by
// construction, same rationale as RevokedSerials) and flattens them into CA-signed
// manifest entries keyed by credential ID (Issue #3697), so a steward can resolve a
// WebAuthn credential's public key from a source it independently trusts instead of an
// unsigned, live controller claim. Entries are sorted by CredentialID so the manifest
// serializes to identical bytes regardless of account enumeration order. A nil
// secretStore (e.g. some test servers) yields an empty roster, not an error — a manifest
// with no WebAuthn credentials is a valid, signable state.
func (s *Server) buildAuthorizedWebAuthnCredentials(ctx context.Context) ([]AuthorizedWebAuthnCredential, error) {
	if s.secretStore == nil {
		return nil, nil
	}
	metas, err := s.secretStore.ListSecrets(ctx, &secretsif.SecretFilter{
		Metadata: map[string]string{secretsif.MetadataKeySecretType: accountSecretType},
	})
	if err != nil {
		return nil, fmt.Errorf("list accounts: %w", err)
	}

	var entries []AuthorizedWebAuthnCredential
	for _, meta := range metas {
		username := meta.Metadata["username"]
		if username == "" {
			continue
		}
		acct, err := s.getAccount(ctx, username)
		if err != nil || acct == nil {
			continue
		}
		for _, credential := range acct.Credentials {
			entries = append(entries, AuthorizedWebAuthnCredential{
				Kind:         AuthorizedWebAuthnCredentialKind,
				CredentialID: credential.ID,
				PublicKey:    credential.PublicKey,
			})
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		return bytes.Compare(entries[i].CredentialID, entries[j].CredentialID) < 0
	})
	return entries, nil
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

	webauthnCreds, err := s.buildAuthorizedWebAuthnCredentials(r.Context())
	if err != nil {
		s.logger.Error("Failed to build authorized WebAuthn credentials", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to build revocation manifest", "INTERNAL_ERROR")
		return
	}
	manifest.AuthorizedWebAuthnCredentials = webauthnCreds

	sig, err := signRevocationManifest(s.certManager, manifest)
	if err != nil {
		s.logger.Error("Failed to sign revocation manifest", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to sign revocation manifest", "INTERNAL_ERROR")
		return
	}

	// Issue #3697: fetched a second time (cheap in-memory store lookup, not the
	// signing path) solely to embed the PEM a caller with no other side channel to the
	// current signing certificate needs to independently chain-verify Signature.
	signingCert, err := s.certManager.GetCurrentCertForPurpose(cert.PurposeSigning)
	if err != nil {
		s.logger.Error("Failed to load signing certificate for manifest response", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to sign revocation manifest", "INTERNAL_ERROR")
		return
	}

	s.writeSuccessResponse(w, SignedRevocationManifest{
		Manifest:             *manifest,
		Signature:            sig,
		SignerCertificatePEM: string(signingCert.CertificatePEM),
	})
}
