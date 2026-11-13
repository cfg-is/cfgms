// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #6227: server-verified TPM attestation for a root agent account's software
// authenticator (ADR-021 Amendment 12).
//
// An account is a root agent account when rootAgentSession(acct) is true: root scope
// and the AllowSoftwareAuthenticator flag. The trigger is the account, never the
// credential's AAGUID (self-asserted) and never the root_agent_accounts setting (turning
// it off must not relax the requirement). Every credential registered on such an account
// must carry a TPM attestation the controller verified itself, or registration is
// refused and nothing is stored.
//
// Mechanism: an endorsement-key-bound attestation key, activated by a software
// MakeCredential, carried in the WebAuthn "tpm" attestation format.
//
//   - Begin (both registration routes). The client posts its EK certificate chain and the
//     public area of its attestation key (AK). The controller chains the EK certificate
//     to a root configured in controller.cfg, checks the AK template, generates a random
//     secret and wraps it with credactivation.Generate for the AK name and the EK public
//     key. Only a TPM holding that EK and that AK can recover the secret. The response
//     is the usual creation options plus a top-level "cfgmsTpm" member, and direct
//     attestation is requested for this ceremony only.
//   - Finish. After the library verified the attestation statement's structure (public
//     area matches the credential key, certInfo binds the ceremony's challenge, the
//     signature verifies under x5c[0]), the controller requires format "tpm", x5c[0]
//     holding the AK sent at begin, the recovered secret in attStmt["cfgmsActivation"],
//     and a certified key that is fixedTPM, fixedParent, sensitiveDataOrigin and sign-only.
//
// The library never verifies the x5c chain (no metadata provider is configured), and
// x5c[0] is a client-built carrier certificate that only satisfies the library's profile
// check, so the controller ignores everything in it except its public key.
//
// Both begin handlers and both finish handlers call the helpers in this file.

package api

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/webauthn"
	legacytpm "github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/legacy/tpm2/credactivation"
	"github.com/google/go-tpm/tpm2"

	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
)

// Error codes of a refused root agent registration.
const (
	errCodeTPMAttestationRequired = "TPM_ATTESTATION_REQUIRED"
	errCodeTPMAttestationRefused  = "TPM_ATTESTATION_REFUSED"
)

// Reasons recorded on a refused root agent registration (the "reason" audit detail).
const (
	reasonTPMAttestationRequired = "tpm_attestation_required"
	reasonTPMNoTrustedRoots      = "tpm_no_trusted_roots"
	reasonTPMEKChain             = "tpm_ek_chain"
	reasonTPMAKTemplate          = "tpm_ak_template"
	reasonTPMAttestationFormat   = "tpm_attestation_format"
	reasonTPMAttestationInvalid  = "tpm_attestation_invalid"
	reasonTPMAKMismatch          = "tpm_ak_mismatch"
	reasonTPMActivationFailed    = "tpm_activation_failed"
	reasonTPMKeyNotFixed         = "tpm_key_not_fixed"
)

const (
	// tpmBeginBodyLimit caps the begin request body of a root agent registration.
	tpmBeginBodyLimit = 64 << 10
	// tpmMaxEKChain bounds the EK certificate chain a client may send.
	tpmMaxEKChain = 8
	// tpmSecretLen is the length of the activation secret (TPM2 Part 1 recommends 32).
	tpmSecretLen = 32
	// tpmSymBlockSize is the AES block size of the storage symmetric algorithm the EK
	// protects the credential blob with, in bytes.
	tpmSymBlockSize = 16
	// tpmActivationStmtKey is the extra attStmt member carrying the recovered secret.
	tpmActivationStmtKey = "cfgmsActivation"
	// tpmAttestationFormat is the WebAuthn attestation statement format required.
	tpmAttestationFormat = "tpm"
)

// TCG object identifiers: the endorsement certificate's device attributes
// (TPMv2-EK-Profile 3.2.9) in its subject alternative name.
var (
	oidTCGDeviceManufacturer = asn1.ObjectIdentifier{2, 23, 133, 2, 1}
	oidTCGDeviceModel        = asn1.ObjectIdentifier{2, 23, 133, 2, 2}
	oidTCGDeviceFirmware     = asn1.ObjectIdentifier{2, 23, 133, 2, 3}
	oidSubjectAltNameExt     = asn1.ObjectIdentifier{2, 5, 29, 17}
)

// tpmBeginRequest is the optional begin body of a root agent registration.
type tpmBeginRequest struct {
	TPM *struct {
		// EKCertChain is the DER EK certificate followed by any intermediates (std base64).
		EKCertChain [][]byte `json:"ek_cert_chain"`
		// AKPublic is the marshalled TPMT_PUBLIC of the attestation key (std base64).
		AKPublic []byte `json:"ak_public"`
	} `json:"tpm"`
}

// tpmChallenge is the "cfgmsTpm" member of the creation options: the marshalled
// TPM2B_ID_OBJECT and TPM2B_ENCRYPTED_SECRET for TPM2_ActivateCredential.
type tpmChallenge struct {
	CredentialBlob  []byte `json:"credential_blob"`
	EncryptedSecret []byte `json:"encrypted_secret"`
}

// tpmActivationState is what a root agent registration's pending session keeps until
// finish: the attestation key the activation was made for, the EK identity and a digest
// of the one-time secret. The secret itself is not kept, so a copy of the session store
// does not reveal what the TPM must return; finish compares the digest in constant time.
type tpmActivationState struct {
	SecretSHA256 []byte               `json:"secret_sha256"`
	AKPublic     []byte               `json:"ak_public"`
	EK           TPMAttestationRecord `json:"ek"`
}

// tpmRegistration is the result of a root agent registration begin.
type tpmRegistration struct {
	state     tpmActivationState
	challenge tpmChallenge
}

// SetRootAgentTPMRoots installs the TPM manufacturer endorsement-key roots from
// controller.cfg (webauthn.allow_software_authenticators.root_agent_tpm_roots). Call
// after New() and before Start(). A nil or empty pool refuses every root agent
// registration (reason tpm_no_trusted_roots). The roots have no API writer.
func (s *Server) SetRootAgentTPMRoots(pool *x509.CertPool) {
	if pool != nil && pool.Equal(&x509.CertPool{}) {
		pool = nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rootAgentTPMRoots = pool
}

// RootAgentTPMRootsConfigured reports whether any TPM root is installed. With none,
// every root agent registration is refused.
func (s *Server) RootAgentTPMRootsConfigured() bool {
	return s.getRootAgentTPMRoots() != nil
}

func (s *Server) getRootAgentTPMRoots() *x509.CertPool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rootAgentTPMRoots
}

// tpmRegistrationOptions is the per-ceremony option that requests direct attestation.
// It is applied to a root agent account's registration only; every other registration
// keeps the library default and the global attestation preference is untouched.
func tpmRegistrationOptions() []webauthn.RegistrationOption {
	return []webauthn.RegistrationOption{webauthn.WithConveyancePreference(protocol.PreferDirectAttestation)}
}

// beginRegistration runs wa.BeginRegistration for acct with the options both
// registration routes share (userVerification required, discoverable credential, the
// account's existing credentials excluded). For a root agent account it also verifies
// the TPM material in the request body, requests direct attestation and returns the
// activation state the pending session must carry. It returns the response object, the
// session data and that state (nil for any other account); on refusal it audits,
// writes the response and returns ok == false.
func (s *Server) beginRegistration(w http.ResponseWriter, r *http.Request, wa *webauthn.WebAuthn, acct *account, user *webauthnUser) (resp any, session *webauthn.SessionData, activation *tpmActivationState, ok bool) {
	opts := []webauthn.RegistrationOption{
		// userVerification: "required" for the initial enrollment ceremony: the
		// human-presence gesture is cheap at registration time. ADR-021 Decision 3
		// relaxes this only for ongoing continuity checks, not the one-time enrollment.
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			UserVerification: protocol.VerificationRequired,
			// Passkey login is usernameless (BeginDiscoverableLogin, empty
			// allowCredentials), so only a discoverable credential can ever sign in.
			// Without this, authenticators that default to non-discoverable register a
			// passkey that login can never find (Issue #4505).
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: protocol.ResidentKeyRequired(),
		}),
		// Prevent re-registering an authenticator already enrolled for this account.
		webauthn.WithExclusions(webauthn.Credentials(user.credentials).CredentialDescriptors()),
	}

	var tpm *tpmRegistration
	if rootAgentSession(acct) {
		if tpm, ok = s.prepareTPMRegistration(w, r, acct); !ok {
			return nil, nil, nil, false
		}
		opts = append(opts, tpmRegistrationOptions()...)
	}

	creation, sessionData, err := wa.BeginRegistration(user, opts...)
	if err != nil {
		s.logger.Error("WebAuthn BeginRegistration failed",
			"account_id", logging.SanitizeLogValue(acct.ID),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError,
			"Failed to begin WebAuthn registration", "WEBAUTHN_BEGIN_ERROR")
		return nil, nil, nil, false
	}
	if tpm == nil {
		return creation, sessionData, nil, true
	}
	body, err := tpm.responseBody(creation)
	if err != nil {
		s.logger.Error("WebAuthn registration options could not be encoded",
			"account_id", logging.SanitizeLogValue(acct.ID),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError,
			"Failed to begin WebAuthn registration", "WEBAUTHN_BEGIN_ERROR")
		return nil, nil, nil, false
	}
	return body, sessionData, &tpm.state, true
}

// responseBody is the creation options JSON object with one extra top-level member,
// "cfgmsTpm". A browser-style consumer ignores unknown members.
func (t *tpmRegistration) responseBody(creation *protocol.CredentialCreation) (map[string]json.RawMessage, error) {
	raw, err := json.Marshal(creation)
	if err != nil {
		return nil, err
	}
	body := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, err
	}
	if body["cfgmsTpm"], err = json.Marshal(t.challenge); err != nil {
		return nil, err
	}
	return body, nil
}

// prepareTPMRegistration reads and verifies the TPM material a root agent account's
// begin request must carry and builds the activation challenge. Any failure is audited
// with its reason, answered and returns ok == false; nothing is stored.
func (s *Server) prepareTPMRegistration(w http.ResponseWriter, r *http.Request, acct *account) (*tpmRegistration, bool) {
	req, err := readTPMBeginRequest(w, r)
	if err != nil {
		s.refuseTPMRegistration(w, r, acct, reasonTPMAttestationRequired, http.StatusBadRequest, errCodeTPMAttestationRequired)
		return nil, false
	}
	reg, reason := newTPMRegistration(req, s.getRootAgentTPMRoots(), time.Now())
	if reason != "" {
		s.refuseTPMRegistration(w, r, acct, reason, http.StatusForbidden, errCodeTPMAttestationRefused)
		return nil, false
	}
	return reg, true
}

// readTPMBeginRequest decodes the begin body, capped at tpmBeginBodyLimit. A missing,
// oversized or malformed body, or one without the tpm member, is an error.
func readTPMBeginRequest(w http.ResponseWriter, r *http.Request) (*tpmBeginRequest, error) {
	if r.Body == nil {
		return nil, errors.New("no body")
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, tpmBeginBodyLimit))
	if err != nil {
		return nil, err
	}
	var req tpmBeginRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	if req.TPM == nil || len(req.TPM.EKCertChain) == 0 || len(req.TPM.AKPublic) == 0 {
		return nil, errors.New("tpm member is incomplete")
	}
	return &req, nil
}

// newTPMRegistration verifies req against roots and builds the activation challenge. It
// returns a reason (and a nil registration) for every refusal; it fails closed on no
// roots, an unknown root, an invalid attestation key and any construction error.
func newTPMRegistration(req *tpmBeginRequest, roots *x509.CertPool, now time.Time) (*tpmRegistration, string) {
	if roots == nil {
		return nil, reasonTPMNoTrustedRoots
	}
	ek, err := verifyEKChain(req.TPM.EKCertChain, roots, now)
	if err != nil {
		return nil, reasonTPMEKChain
	}
	ak, _, err := parseAttestationKey(req.TPM.AKPublic)
	if err != nil {
		return nil, reasonTPMAKTemplate
	}
	secret := make([]byte, tpmSecretLen)
	if _, err := rand.Read(secret); err != nil {
		return nil, reasonTPMAttestationInvalid
	}
	challenge, err := activationChallenge(ak, ek.PublicKey, secret)
	if err != nil {
		return nil, reasonTPMEKChain
	}
	digest := sha256.Sum256(secret)
	identity, err := ekIdentity(ek)
	if err != nil {
		return nil, reasonTPMEKChain
	}
	return &tpmRegistration{
		state: tpmActivationState{
			SecretSHA256: digest[:],
			AKPublic:     tpm2.Marshal(*ak),
			EK:           identity,
		},
		challenge: *challenge,
	}, ""
}

// verifyEKChain chains the first certificate of chain (the endorsement key
// certificate) to roots, using the others as intermediates, at time now. EK
// certificates carry the TCG EK extended key usage and a critical subject alternative
// name holding only a directoryName, neither of which crypto/x509 accepts as a standard
// profile, so any key usage is allowed and the SAN's critical flag is cleared on a copy
// (as tpmParseAIKAttCA in go-webauthn's protocol/attestation_tpm.go does for the AIK
// certificate); every other unhandled critical extension still fails the chain. Roots
// may hold intermediate CA certificates: a certificate in roots is a trust anchor.
func verifyEKChain(chain [][]byte, roots *x509.CertPool, now time.Time) (*x509.Certificate, error) {
	if len(chain) == 0 || len(chain) > tpmMaxEKChain {
		return nil, errors.New("endorsement certificate chain has an invalid length")
	}
	if roots == nil {
		return nil, errors.New("no trusted TPM roots")
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return nil, fmt.Errorf("endorsement certificate: %w", err)
	}
	intermediates, err := intermediatePool(chain[1:])
	if err != nil {
		return nil, err
	}
	checked := *leaf
	checked.UnhandledCriticalExtensions = withoutOID(leaf.UnhandledCriticalExtensions, oidSubjectAltNameExt)
	if _, err := checked.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, fmt.Errorf("endorsement certificate chain: %w", err)
	}
	return leaf, nil
}

// intermediatePool builds the intermediate pool from DER certificates; nil when there are none.
func intermediatePool(ders [][]byte) (*x509.CertPool, error) {
	if len(ders) == 0 {
		return nil, nil
	}
	var pemChain []byte
	for _, der := range ders {
		if _, err := x509.ParseCertificate(der); err != nil {
			return nil, fmt.Errorf("intermediate certificate: %w", err)
		}
		pemChain = append(pemChain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	pool, err := cert.CertPoolFromPEM(pemChain)
	if err != nil {
		return nil, fmt.Errorf("intermediate certificates: %w", err)
	}
	return pool, nil
}

// withoutOID returns oids without drop.
func withoutOID(oids []asn1.ObjectIdentifier, drop asn1.ObjectIdentifier) []asn1.ObjectIdentifier {
	var out []asn1.ObjectIdentifier
	for _, oid := range oids {
		if !oid.Equal(drop) {
			out = append(out, oid)
		}
	}
	return out
}

// parseAttestationKey decodes a marshalled TPMT_PUBLIC and requires the attestation key
// template: ECC NIST P-256, ECDSA with SHA-256, SHA-256 name algorithm, restricted
// signing, fixedTPM, fixedParent and sensitiveDataOrigin. Its attributes are authenticated
// by the activation, because MakeCredential binds the challenge to the AK's TPM name.
func parseAttestationKey(raw []byte) (*tpm2.TPMTPublic, *ecdsa.PublicKey, error) {
	pub, err := tpm2.Unmarshal[tpm2.TPMTPublic](raw)
	if err != nil {
		return nil, nil, fmt.Errorf("attestation key public area: %w", err)
	}
	if !bytes.Equal(tpm2.Marshal(*pub), raw) {
		return nil, nil, errors.New("attestation key public area is not canonical")
	}
	if err := checkAttestationKeyAttributes(pub); err != nil {
		return nil, nil, err
	}
	parms, err := pub.Parameters.ECCDetail()
	if err != nil {
		return nil, nil, fmt.Errorf("attestation key parameters: %w", err)
	}
	if err := checkAttestationKeyScheme(parms); err != nil {
		return nil, nil, err
	}
	key, err := attestationKeyPoint(pub, parms)
	if err != nil {
		return nil, nil, err
	}
	return pub, key, nil
}

// checkAttestationKeyAttributes requires an ECC key with a SHA-256 name that is a
// restricted signing key, TPM-generated and fixed to its TPM and parent.
func checkAttestationKeyAttributes(pub *tpm2.TPMTPublic) error {
	if pub.Type != tpm2.TPMAlgECC || pub.NameAlg != tpm2.TPMAlgSHA256 {
		return errors.New("attestation key must be ECC with a SHA-256 name")
	}
	a := pub.ObjectAttributes
	if !a.Restricted || !a.SignEncrypt || a.Decrypt || !a.FixedTPM || !a.FixedParent || !a.SensitiveDataOrigin {
		return errors.New("attestation key must be a restricted signing key fixed to its TPM and parent")
	}
	return nil
}

// checkAttestationKeyScheme requires ECDSA with SHA-256 on NIST P-256.
func checkAttestationKeyScheme(parms *tpm2.TPMSECCParms) error {
	if parms.CurveID != tpm2.TPMECCNistP256 || parms.Scheme.Scheme != tpm2.TPMAlgECDSA {
		return errors.New("attestation key must be ECDSA on NIST P-256")
	}
	scheme, err := parms.Scheme.Details.ECDSA()
	if err != nil || scheme.HashAlg != tpm2.TPMAlgSHA256 {
		return errors.New("attestation key must sign with SHA-256")
	}
	return nil
}

// attestationKeyPoint returns the attestation key's public key, which must be a point on the curve.
func attestationKeyPoint(pub *tpm2.TPMTPublic, parms *tpm2.TPMSECCParms) (*ecdsa.PublicKey, error) {
	point, err := pub.Unique.ECC()
	if err != nil {
		return nil, fmt.Errorf("attestation key point: %w", err)
	}
	key, err := tpm2.ECDSAPub(parms, point)
	if err != nil {
		return nil, fmt.Errorf("attestation key point: %w", err)
	}
	if _, err := key.ECDH(); err != nil {
		return nil, errors.New("attestation key is not a point on the curve")
	}
	return key, nil
}

// activationChallenge wraps secret for the attestation key ak and the endorsement key
// ekPub with TPM2_MakeCredential's software form. No TPM is needed here.
func activationChallenge(ak *tpm2.TPMTPublic, ekPub crypto.PublicKey, secret []byte) (*tpmChallenge, error) {
	switch ekPub.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey:
	default:
		return nil, errors.New("unsupported endorsement key type")
	}
	name, err := tpm2.ObjectName(ak)
	if err != nil || len(name.Buffer) <= 2 {
		return nil, errors.New("attestation key name")
	}
	// The name is the 2-byte hash algorithm identifier followed by the digest.
	hv := &legacytpm.HashValue{Alg: legacytpm.AlgSHA256, Value: name.Buffer[2:]}
	blob, enc, err := credactivation.Generate(hv, ekPub, tpmSymBlockSize, secret)
	if err != nil {
		return nil, fmt.Errorf("make credential: %w", err)
	}
	return &tpmChallenge{CredentialBlob: blob, EncryptedSecret: enc}, nil
}

// ekIdentity records who issued the endorsement certificate and which key it certifies,
// plus the manufacturer, model and firmware from its TCG device attributes when present.
func ekIdentity(ek *x509.Certificate) (TPMAttestationRecord, error) {
	der, err := x509.MarshalPKIXPublicKey(ek.PublicKey)
	if err != nil {
		return TPMAttestationRecord{}, err
	}
	keyHash := sha256.Sum256(der)
	rec := TPMAttestationRecord{
		EKIssuer:       ek.Issuer.String(),
		EKSerial:       ek.SerialNumber.Text(16),
		EKPublicSHA256: hex.EncodeToString(keyHash[:]),
	}
	for _, name := range sanDirectoryNames(ek) {
		for _, rdn := range name {
			for _, atv := range rdn {
				rec.setDeviceAttribute(atv)
			}
		}
	}
	return rec, nil
}

// setDeviceAttribute stores atv when it is a TCG manufacturer, model or firmware string.
func (r *TPMAttestationRecord) setDeviceAttribute(atv pkix.AttributeTypeAndValue) {
	v, ok := atv.Value.(string)
	if !ok {
		return
	}
	switch {
	case atv.Type.Equal(oidTCGDeviceManufacturer):
		r.EKManufacturer = v
	case atv.Type.Equal(oidTCGDeviceModel):
		r.EKModel = v
	case atv.Type.Equal(oidTCGDeviceFirmware):
		r.EKFirmware = v
	}
}

// sanDirectoryNames returns the directoryName entries of the certificate's subject
// alternative name, where an endorsement certificate carries its TCG device attributes.
func sanDirectoryNames(c *x509.Certificate) []pkix.RDNSequence {
	var out []pkix.RDNSequence
	for _, ext := range c.Extensions {
		if !ext.Id.Equal(oidSubjectAltNameExt) {
			continue
		}
		var names []asn1.RawValue
		if _, err := asn1.Unmarshal(ext.Value, &names); err != nil {
			continue
		}
		for _, n := range names {
			var rdns pkix.RDNSequence
			if n.Class != asn1.ClassContextSpecific || n.Tag != 4 { // directoryName
				continue
			}
			if _, err := asn1.Unmarshal(n.Bytes, &rdns); err == nil {
				out = append(out, rdns)
			}
		}
	}
	return out
}

// refuseTPMRegistration audits and answers a root agent registration refused at begin.
// The reason goes to the audit event only; the response never says which check failed.
func (s *Server) refuseTPMRegistration(w http.ResponseWriter, r *http.Request, acct *account, reason string, status int, code string) {
	s.auditRegistrationDenied(r.Context(), registrationBeginDeniedAction, acct, nil, reason)
	s.logger.Warn("Root agent authenticator registration refused at begin",
		"account_id", logging.SanitizeLogValue(acct.ID),
		"reason", logging.SanitizeLogValue(reason))
	msg := "A verified TPM attestation is required to register an authenticator for this account"
	if code == errCodeTPMAttestationRefused {
		msg = "The TPM attestation was refused"
	}
	s.writeErrorResponse(w, status, msg, code)
}

// auditRegistrationVerifyFailure records a FinishRegistration failure for a ceremony
// that required a TPM attestation (an attestation replayed from another ceremony fails
// the library's extraData check, for example). Any other ceremony is not audited here.
func (s *Server) auditRegistrationVerifyFailure(ctx context.Context, acct *account, pending *webAuthnPendingSession) {
	if pending == nil || pending.tpmActivation == nil {
		return
	}
	s.auditSoftwareAuthenticatorRefused(ctx, acct, nil, reasonTPMAttestationInvalid)
}

// applyTPMAttestation verifies the TPM attestation of a just-finished registration
// whose begin required one, and records the result on stored. A ceremony that did not
// require one is left to the policy check on the reloaded account
// (enforceSoftwareAuthenticatorPolicy), which refuses a root agent credential with no
// recorded attestation. On refusal it audits, answers and returns false; the caller must
// not persist anything.
func (s *Server) applyTPMAttestation(w http.ResponseWriter, r *http.Request, acct *account, pending *webAuthnPendingSession, credential *webauthn.Credential, stored *WebAuthnCredential) bool {
	if pending.tpmActivation == nil {
		return true
	}
	rec, reason := checkTPMAttestation(credential, pending.tpmActivation, time.Now().UTC())
	if reason != "" {
		s.auditSoftwareAuthenticatorRefused(r.Context(), acct, stored, reason)
		s.logger.Warn("Root agent authenticator registration refused",
			"account_id", logging.SanitizeLogValue(acct.ID),
			"reason", logging.SanitizeLogValue(reason))
		s.writeErrorResponse(w, http.StatusForbidden, "The TPM attestation was refused", errCodeTPMAttestationRefused)
		return false
	}
	stored.TPMAttestation = rec
	return true
}

// checkTPMAttestation decides whether credential, which the library has already
// verified (public area matches the credential key, certInfo binds this ceremony's
// challenge, the signature verifies under x5c[0]), meets the controller's requirements
// for a root agent account, in order: format "tpm"; x5c[0] holds the attestation key sent
// at begin; the recovered activation secret matches; the certified key is fixedTPM,
// fixedParent, sensitiveDataOrigin and sign-only. It returns the record to store, or the
// reason for the refusal.
func checkTPMAttestation(credential *webauthn.Credential, state *tpmActivationState, now time.Time) (*TPMAttestationRecord, string) {
	if credential.AttestationFormat != tpmAttestationFormat {
		return nil, reasonTPMAttestationFormat
	}
	var obj protocol.AttestationObject
	if err := webauthncbor.Unmarshal(credential.Attestation.Object, &obj); err != nil || obj.Format != tpmAttestationFormat {
		return nil, reasonTPMAttestationInvalid
	}
	if reason := checkCarrierKey(&obj, state); reason != "" {
		return nil, reason
	}
	if reason := checkActivationSecret(&obj, state); reason != "" {
		return nil, reason
	}
	if reason := checkCertifiedKey(&obj); reason != "" {
		return nil, reason
	}
	rec := state.EK
	rec.VerifiedAt = now
	return &rec, ""
}

// checkCarrierKey requires x5c[0] to hold the attestation key the begin request named.
func checkCarrierKey(obj *protocol.AttestationObject, state *tpmActivationState) string {
	_, wantKey, err := parseAttestationKey(state.AKPublic)
	if err != nil {
		return reasonTPMAttestationInvalid
	}
	x5c, _ := obj.AttStatement["x5c"].([]any)
	if len(x5c) == 0 {
		return reasonTPMAttestationInvalid
	}
	carrierDER, _ := x5c[0].([]byte)
	carrier, err := x509.ParseCertificate(carrierDER)
	if err != nil {
		return reasonTPMAttestationInvalid
	}
	if gotKey, ok := carrier.PublicKey.(*ecdsa.PublicKey); !ok || gotKey.Curve != elliptic.P256() || !wantKey.Equal(gotKey) {
		return reasonTPMAKMismatch
	}
	return ""
}

// checkActivationSecret requires the secret the TPM recovered to match the one this
// ceremony's challenge carried, compared by digest in constant time.
func checkActivationSecret(obj *protocol.AttestationObject, state *tpmActivationState) string {
	activation, _ := obj.AttStatement[tpmActivationStmtKey].([]byte)
	digest := sha256.Sum256(activation)
	if len(activation) == 0 || subtle.ConstantTimeCompare(digest[:], state.SecretSHA256) != 1 {
		return reasonTPMActivationFailed
	}
	return ""
}

// checkCertifiedKey requires the certified public area to be a TPM-generated sign-only
// key fixed to its TPM and parent.
func checkCertifiedKey(obj *protocol.AttestationObject) string {
	pubArea, _ := obj.AttStatement["pubArea"].([]byte)
	area, err := tpm2.Unmarshal[tpm2.TPMTPublic](pubArea)
	if err != nil {
		return reasonTPMAttestationInvalid
	}
	a := area.ObjectAttributes
	if !a.FixedTPM || !a.FixedParent || !a.SensitiveDataOrigin || !a.SignEncrypt || a.Decrypt {
		return reasonTPMKeyNotFixed
	}
	return ""
}

// enforceRootAgentTPM refuses a credential for a root agent account that carries no
// recorded TPM attestation. It is called on the reloaded account, whatever the
// credential's AAGUID, after the software-authenticator policy. On refusal it audits,
// answers 403 and returns false.
func (s *Server) enforceRootAgentTPM(w http.ResponseWriter, r *http.Request, acct *account, cred *WebAuthnCredential) bool {
	if !rootAgentSession(acct) || cred.tpmAttested() {
		return true
	}
	s.auditSoftwareAuthenticatorRefused(r.Context(), acct, cred, reasonTPMAttestationRequired)
	s.logger.Warn("Root agent authenticator registration refused",
		"account_id", logging.SanitizeLogValue(acct.ID),
		"reason", logging.SanitizeLogValue(reasonTPMAttestationRequired))
	s.writeErrorResponse(w, http.StatusForbidden,
		"A verified TPM attestation is required to register an authenticator for this account", errCodeTPMAttestationRequired)
	return false
}

// tpmAuditDetails adds the endorsement certificate identity of a TPM-attested
// credential to an audit event's details, so an auditor can tell which TPM holds each
// root agent key.
func tpmAuditDetails(details map[string]interface{}, rec *TPMAttestationRecord) {
	details["tpm_attested"] = true
	details["ek_manufacturer"] = rec.EKManufacturer
	details["ek_model"] = rec.EKModel
	details["ek_firmware"] = rec.EKFirmware
	details["ek_issuer"] = rec.EKIssuer
	details["ek_serial"] = rec.EKSerial
	details["ek_public_sha256"] = rec.EKPublicSHA256
}

// tpmUnusable reports whether cred must not be used on acct: a root agent account's
// credential without a recorded TPM attestation, whatever its AAGUID.
func tpmUnusable(acct *account, cred *WebAuthnCredential) bool {
	return rootAgentSession(acct) && !cred.tpmAttested()
}
