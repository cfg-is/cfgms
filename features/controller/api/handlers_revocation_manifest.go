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
	"time"

	"github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// terminalStewardManifestStatuses are the ControllerService steward statuses that must
// never reach the manifest, mirroring the terminal set EnsureSteward already refuses to
// promote out of (controller_service.go, Issue #3403). A steward's mTLS certificate is
// never revoked or removed on decommission (handleDecommissionSteward tombstones the
// durable record and best-effort updates this in-memory Status, but issues no
// certManager.Revoke call and never deletes the registry entry), so a decommissioned
// device keeps a fully chain-valid client certificate indefinitely. Without this check,
// TenantForDevice's existence-only test would keep answering "known" for that
// certificate forever, handing a decommissioned steward the live WebAuthn operator
// roster for its former tenant on every subsequent request.
var terminalStewardManifestStatuses = map[string]struct{}{
	string(business.StewardStatusDeregistered): {},
	string(business.StewardStatusRevoked):      {},
	string(business.StewardStatusArchived):     {},
	string(business.StewardStatusDormant):      {},
}

// RevocationManifestKind identifies RevocationManifest's payload shape. It exists
// so a manifest can never be confused with a signed config/DNA payload — both are
// signed with the same PurposeSigning certificate, but only a revocation manifest
// carries this Kind (Issue #3691).
const RevocationManifestKind = "operator-cert-revocation"

// AuthorizedWebAuthnCredentialKind discriminates AuthorizedWebAuthnCredential from any
// future manifest entry type sitting alongside RevokedSerials — a Kind-discriminated
// sibling entry type (Issue #3697).
const AuthorizedWebAuthnCredentialKind = "webauthn-credential"

// OperatorPayloadSignGrant is the permission ID whose presence in
// AuthorizedWebAuthnCredential.Grants authorizes the credential to sign an operator
// payload. It is the same string requirePermission("operator-payload", "sign") builds
// (buildPermissionID), so the roster's authority predicate and the signing ceremony's
// own route gate are decided by one value, not by two that could drift apart.
const OperatorPayloadSignGrant = "operator-payload:sign"

// AuthorizedWebAuthnCredential is a CA-signed roster entry (Issue #3697) naming one
// registered WebAuthn credential's COSE public key, keyed by credential ID, so a
// steward verifying a WebAuthn-signed operator payload can resolve the signer's public
// key from a source it independently trusts rather than an unsigned, live controller
// claim. CredentialID and PublicKey mirror WebAuthnCredential.ID/.PublicKey exactly.
//
// The entry carries the authority the owning account actually holds, because roster
// membership is not authorization: a passkey exists on an account so its owner can log
// in, which says nothing about whether that owner may execute a script as SYSTEM on a
// steward. TenantID/RootScope and Grants are the two predicates the steward re-checks
// against a manifest it has chain-verified for itself:
//
//   - Grants lists the permission IDs the owning account holds that are meaningful to a
//     verifying steward. An entry without OperatorPayloadSignGrant is present for
//     completeness (a steward may resolve a key for another purpose later) but
//     authorizes no execution.
//   - TenantID is the owning account's tenant path, and RootScope is true only for an
//     unscoped platform-administrator account (TenantID == "" by explicit grant). A
//     steward accepts an entry only when RootScope is set or its own tenant path is the
//     entry's tenant or a descendant of it — without this the roster's fleet-wide reach
//     would let a credential registered in one tenant authorize execution in another.
type AuthorizedWebAuthnCredential struct {
	Kind         string   `json:"kind"`
	CredentialID []byte   `json:"credential_id"`
	PublicKey    []byte   `json:"public_key"`
	TenantID     string   `json:"tenant_id"`
	RootScope    bool     `json:"root_scope"`
	Grants       []string `json:"grants"`
}

// WebAuthnRelyingParty carries the controller's WebAuthn relying-party binding in the
// signed manifest (Issue #3697) so a steward can perform the W3C WebAuthn §7.2 checks
// that need it — rpIdHash against sha256(ID), and clientDataJSON.origin against Origins
// — for which it has no other trustworthy source. Both are copied verbatim from the
// configured webauthn.Config the signing ceremony itself runs under.
type WebAuthnRelyingParty struct {
	ID      string   `json:"id"`
	Origins []string `json:"origins"`
}

// RevocationManifest is the compact, signable set of currently revoked
// operator-certificate serials, plus (Issue #3697) the fleet-wide roster of authorized
// WebAuthn credential public keys. RevokedSerials is always sorted, and
// AuthorizedWebAuthnCredentials is always sorted by CredentialID, so the same
// underlying state serializes to identical bytes before signing.
//
// IssuedAt (Issue #3697) is the freshness anchor. Version counts revoked serials only,
// so it does not move when a credential leaves the roster — on its own it would make an
// older manifest listing a de-registered credential indistinguishable from the current
// one, and de-registering a compromised passkey would never take effect on any steward.
// IssuedAt advances on every issuance regardless of which part of the content changed,
// so a consumer can both bound a manifest's age and refuse one older than the newest it
// has already accepted.
type RevocationManifest struct {
	Kind                          string                         `json:"kind"`
	Version                       int64                          `json:"version"`
	IssuedAt                      time.Time                      `json:"issued_at"`
	RevokedSerials                []string                       `json:"revoked_serials"`
	AuthorizedWebAuthnCredentials []AuthorizedWebAuthnCredential `json:"authorized_webauthn_credentials,omitempty"`
	WebAuthnRelyingParty          *WebAuthnRelyingParty          `json:"webauthn_relying_party,omitempty"`
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
// never regresses. IssuedAt is stamped here, at second resolution, so it is
// identical in the signed bytes and in the served response.
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
		IssuedAt:       time.Now().UTC().Truncate(time.Second),
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

// accountHoldsOperatorPayloadSigning reports whether acct's own authority allows it to
// sign an operator payload, deciding roster membership the same way requirePermission
// decides the signing route (middleware.go hasPermission): a root-scope account is a
// platform administrator holding every permission, and any other account holds exactly
// the permissions configured on it. A disabled account holds none — Disabled is a login
// gate that leaves credentials and role assignments in place (Issue #3126), so the
// credentials of a disabled account are still enumerable here and must be excluded
// explicitly rather than assumed gone.
func accountHoldsOperatorPayloadSigning(acct *account) bool {
	if acct == nil || acct.Disabled {
		return false
	}
	if acct.RootScope {
		return true
	}
	for _, permission := range acct.Permissions {
		if permission == OperatorPayloadSignGrant {
			return true
		}
	}
	return false
}

// buildAuthorizedWebAuthnCredentials flattens the WebAuthn credentials of every account
// that actually holds operator-payload signing authority into CA-signed manifest entries
// keyed by credential ID (Issue #3697), so a steward can resolve a WebAuthn credential's
// public key from a source it independently trusts instead of an unsigned, live
// controller claim.
//
// The roster is an allow-list, so it is built from the accounts' authority, not from the
// mere existence of a passkey: accountHoldsOperatorPayloadSigning excludes disabled and
// zero-privilege accounts, and each surviving entry carries the owning account's tenant
// and granted permission so the steward can re-check both against a manifest it verified
// itself. Enumeration is still fleet-wide — a manifest cannot be tenant-scoped without
// making Version incomparable across callers, and the endpoint is closed to
// tenant-scoped callers for that reason (handleGetRevocationManifest) — but a fleet-wide
// allow-list is only safe because each entry states the tenant it is valid for.
//
// Entries are sorted by CredentialID so the manifest serializes to identical bytes
// regardless of account enumeration order. A nil secretStore (e.g. some test servers)
// yields an empty roster, not an error — a manifest with no WebAuthn credentials is a
// valid, signable state.
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
		if !accountHoldsOperatorPayloadSigning(acct) {
			continue
		}
		for _, credential := range acct.Credentials {
			entries = append(entries, AuthorizedWebAuthnCredential{
				Kind:         AuthorizedWebAuthnCredentialKind,
				CredentialID: credential.ID,
				PublicKey:    credential.PublicKey,
				TenantID:     acct.TenantID,
				RootScope:    acct.RootScope,
				Grants:       []string{OperatorPayloadSignGrant},
			})
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		return bytes.Compare(entries[i].CredentialID, entries[j].CredentialID) < 0
	})
	return entries, nil
}

// webAuthnRelyingPartyBinding returns the configured relying-party ID and origins for
// the manifest, or nil when WebAuthn is not configured on this controller. Nil is the
// correct state rather than an error: with no relying party there can be no assertion to
// verify, and a steward that finds a roster entry without this binding refuses the
// assertion instead of guessing which origin to expect.
func (s *Server) webAuthnRelyingPartyBinding() *WebAuthnRelyingParty {
	wa := s.getWebAuthn()
	if wa == nil || wa.Config == nil || wa.Config.RPID == "" || len(wa.Config.RPOrigins) == 0 {
		return nil
	}
	origins := make([]string, len(wa.Config.RPOrigins))
	copy(origins, wa.Config.RPOrigins)
	sort.Strings(origins)
	return &WebAuthnRelyingParty{ID: wa.Config.RPID, Origins: origins}
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
	callerTenant := callerTenantFilter(r.Context())
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
	manifest.WebAuthnRelyingParty = s.webAuthnRelyingPartyBinding()

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

// stewardTenantFromPeerCertificate resolves the tenant path of the steward whose mTLS
// certificate authenticated this request (handleGetStewardRevocationManifest), the
// non-admin counterpart to extractAdminPrincipal. By the time this runs, the TLS layer
// (VerifyClientCertIfGiven + ClientCAs, server.go) has already chain-verified
// r.TLS.PeerCertificates[0] against the controller's own CA — but chain trust alone is
// not identity: an admin certificate, or a steward certificate for a different,
// unregistered or decommissioned device, would also chain-verify. Three additional bars
// are applied here.
//
// First, the presented certificate must not be REVOKED. The TLS handshake cannot decide
// this — VerifyClientCertIfGiven checks the chain only and CFGMS publishes no CRL or OCSP
// responder, so the controller's own revocation store is the sole authority, and it is
// consulted per request exactly as every other certificate-authenticated path in this
// package does (extractAdminPrincipal for admin mTLS, hardened fail-closed by Issue
// #3852; verifyOperatorSigningCertificate for operator certs). This gate is what makes
// revoking a stolen steward key actually stop that key: without it a revoked certificate
// would keep collecting its tenant subtree's operator WebAuthn roster and the fleet
// revocation list on every poll, indefinitely — the stolen-steward-key scenario this
// endpoint exists to mitigate. The terminal-status check below does not cover it:
// handleRevokeCertificate records the serial in the revocation store and never writes
// StewardStatusRevoked to the steward registry record. A revocation-store read error
// fails closed (deny), never falls through as "not revoked", matching Manager.IsRevoked's
// documented contract.
//
// Second, the certificate's CommonName must resolve via the steward registry
// (controllerService.GetStewardInfo) to a known device — the same "known identity, not
// just a valid chain" bar pkg/transport/quic.PeerStewardID applies on the gRPC control
// plane. Third, that device's Status must not be one of the terminal states
// (terminalStewardManifestStatuses). The status check is required because decommissioning
// a steward never revokes its mTLS certificate or removes its registry entry (see
// terminalStewardManifestStatuses), so certificate validity and chain trust alone would
// keep a decommissioned device "known" forever. A revoked certificate, an unknown
// CommonName, or a known one in a terminal status is refused even though its certificate
// chain is genuine — none of those has any legitimate call to see any part of this
// manifest.
func (s *Server) stewardTenantFromPeerCertificate(r *http.Request) (tenantID string, ok bool) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", false
	}
	peerCert := r.TLS.PeerCertificates[0]
	stewardID := peerCert.Subject.CommonName
	if stewardID == "" || s.controllerService == nil {
		return "", false
	}
	// certManager may be nil in deployments that have not initialised certificate
	// management; the caller refuses such a request with 503 before serving anything,
	// so there is no path where a revocation check is skipped and a manifest is served.
	if s.certManager != nil {
		serial := peerCert.SerialNumber.String()
		revoked, err := s.certManager.IsRevoked(serial)
		if err != nil {
			s.logger.Error("Steward certificate revocation check failed; failing closed",
				"cert_serial", logging.SanitizeLogValue(serial),
				"steward_id", logging.SanitizeLogValue(stewardID),
				"error", logging.SanitizeLogValue(err.Error()))
			return "", false
		}
		if revoked {
			s.logger.Warn("Refused revocation manifest request from a revoked steward certificate",
				"cert_serial", logging.SanitizeLogValue(serial),
				"steward_id", logging.SanitizeLogValue(stewardID))
			return "", false
		}
	}
	info, known := s.controllerService.GetStewardInfo(stewardID)
	if !known {
		return "", false
	}
	if _, terminal := terminalStewardManifestStatuses[info.Status]; terminal {
		return "", false
	}
	return info.TenantID, true
}

// filterWebAuthnCredentialsForSteward narrows creds to the entries a requesting steward
// in stewardTenant is allowed to see (Issue #4400). This mirrors, byte for byte, the
// rule the steward itself applies once it has independently verified the manifest
// (commands.entryAuthorizedForTenant) and that
// docs/architecture/steward-operating-model.md documents; applying it server-side here
// means a compromised steward never receives another tenant's operator credentials in
// the first place.
//
// The rule is fail-closed on every unset tenant, deliberately: an entry with
// TenantID == "" and RootScope == false can still come from an account record written
// before Issue #4665 (handleCreateAccount then accepted root_scope:false with no
// tenant_id; it now assigns the caller's own tenant), and treating that
// unset tenant as "unrestricted" — which is what the general-purpose
// isWithinTenantScope("") does for an *mTLS admin caller* — would disclose that entry's
// credential ID, public key and existence to every steward in the fleet. The unset
// state here is a roster entry with no declared authority, not an unrestricted caller,
// so it authorizes nothing. This is the same fail-closed direction isAuthorizedForTenant
// (middleware.go, Issue #4316) takes for the request-scoped three-state TenantScope.
//
// RevokedSerials is deliberately never filtered this way — see
// handleGetStewardRevocationManifest's doc comment for why a narrower WebAuthn roster
// is safe where a narrower revocation list would not be.
func filterWebAuthnCredentialsForSteward(creds []AuthorizedWebAuthnCredential, stewardTenant string) []AuthorizedWebAuthnCredential {
	if len(creds) == 0 {
		return creds
	}
	filtered := make([]AuthorizedWebAuthnCredential, 0, len(creds))
	for _, credential := range creds {
		if webauthnCredentialAuthorizedForSteward(credential, stewardTenant) {
			filtered = append(filtered, credential)
		}
	}
	return filtered
}

// webauthnCredentialAuthorizedForSteward reports whether credential's owning tenant
// covers a steward at stewardTenant. A root-scope entry is a fleet-wide platform
// administrator and covers every steward, but only when it carries no tenant path —
// a root-scope entry that also names a tenant is self-contradictory and authorizes
// nothing. Any other entry covers only its own tenant path and that path's
// descendants, and an entry or steward with no tenant path at all covers nothing.
//
// Kept identical to the steward-side entryAuthorizedForTenant
// (features/steward/commands/webauthn_credential_verifier.go): the steward re-checks
// this after verifying the manifest signature, and a server filter that admitted more
// than the steward accepts would be a disclosure with no corresponding capability.
func webauthnCredentialAuthorizedForSteward(credential AuthorizedWebAuthnCredential, stewardTenant string) bool {
	if credential.RootScope {
		return credential.TenantID == ""
	}
	if credential.TenantID == "" || stewardTenant == "" {
		return false
	}
	return isWithinTenantScope(credential.TenantID, stewardTenant) //architecture:allow-root-scope -- compares a roster entry with a steward, not a caller
}

// handleGetStewardRevocationManifest handles GET /api/v1/public/steward-revocation-manifest
// (Issue #4400). Registered on the base router (server.go), like the public
// steward-binary download, because a steward's mTLS certificate carries no CFGMS admin
// marker and therefore produces no principal via extractAdminPrincipal/
// authenticationMiddleware — the fleet-wide GET /api/v1/certificates/revocation-manifest
// above is simply unreachable by a steward. Authorization here is the steward's own
// peer certificate, resolved to a registered device by stewardTenantFromPeerCertificate;
// certificate:list is never widened to steward principals, and stewards are never
// issued the admin marker.
//
// The response is filtered per steward, unlike the fleet-wide admin manifest:
//   - RevokedSerials is served in full. Serials are opaque and non-identifying, and a
//     steward's RevocationVerifier only ever unions RevokedSerials into what it already
//     believed revoked (never replaces it), so a narrower list could only reduce
//     coverage — the opposite of what a per-steward-filtered response must do here.
//   - AuthorizedWebAuthnCredentials is narrowed to operators whose tenant scope covers
//     this steward's tenant path (filterWebAuthnCredentialsForSteward) — the fleet
//     admin inventory a steward, which the threat model treats as a host that may be
//     compromised, has no legitimate need to see beyond its own chain of tenants.
//   - WebAuthnRelyingParty is served unchanged; rp_id and origins are not sensitive.
//
// Each response is signed fresh with the controller's current PurposeSigning
// certificate (signRevocationManifest) rather than reusing a previously-signed
// fleet-wide manifest, because the filtered content differs per caller — an unsigned or
// re-signed-by-a-relay payload would defeat the steward's own chain verification
// (operatorroster.RevocationVerifier.VerifyManifest, strict mode).
func (s *Server) handleGetStewardRevocationManifest(w http.ResponseWriter, r *http.Request) {
	stewardTenant, ok := s.stewardTenantFromPeerCertificate(r)
	if !ok {
		s.writeErrorResponse(w, http.StatusForbidden,
			"A registered steward mTLS certificate is required", "FORBIDDEN")
		return
	}

	if s.certManager == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Certificate manager not available", "SERVICE_UNAVAILABLE")
		return
	}

	manifest, err := buildRevocationManifest(s.certManager)
	if err != nil {
		s.logger.Error("Failed to build steward revocation manifest", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to build revocation manifest", "INTERNAL_ERROR")
		return
	}

	webauthnCreds, err := s.buildAuthorizedWebAuthnCredentials(r.Context())
	if err != nil {
		s.logger.Error("Failed to build authorized WebAuthn credentials", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to build revocation manifest", "INTERNAL_ERROR")
		return
	}
	manifest.AuthorizedWebAuthnCredentials = filterWebAuthnCredentialsForSteward(webauthnCreds, stewardTenant)
	manifest.WebAuthnRelyingParty = s.webAuthnRelyingPartyBinding()

	sig, err := signRevocationManifest(s.certManager, manifest)
	if err != nil {
		s.logger.Error("Failed to sign steward revocation manifest", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to sign revocation manifest", "INTERNAL_ERROR")
		return
	}

	// Issue #3697: fetched a second time (cheap in-memory store lookup, not the signing
	// path) solely to embed the PEM a caller with no other side channel to the current
	// signing certificate needs to independently chain-verify Signature.
	signingCert, err := s.certManager.GetCurrentCertForPurpose(cert.PurposeSigning)
	if err != nil {
		s.logger.Error("Failed to load signing certificate for steward manifest response", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to sign revocation manifest", "INTERNAL_ERROR")
		return
	}

	// Written raw, not via writeSuccessResponse's {"data": ...} envelope: the consumer
	// is operatorroster.FetchAndVerify (features/steward/operatorroster/revocation.go),
	// which unmarshals the response body directly as signedRevocationManifest — the
	// same un-enveloped, steward-consumed wire-contract pattern used by the
	// registration and registration-status endpoints (handlers_registration.go), not
	// the admin-API envelope convention the fleet-wide manifest above uses.
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(SignedRevocationManifest{
		Manifest:             *manifest,
		Signature:            sig,
		SignerCertificatePEM: string(signingCert.CertificatePEM),
	}); err != nil {
		s.logger.Error("Failed to encode steward revocation manifest response", "error", logging.SanitizeLogValue(err.Error()))
	}
}
