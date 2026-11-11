// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package softauthn is a software WebAuthn authenticator core. Given a P-256
// crypto.Signer it produces standards-conformant registration (attestation
// "none") and assertion responses for a single relying party. It stores no key
// material and talks to no controller: the caller owns key storage and
// transport. See README.md for the limits of what a response from this package
// proves.
package softauthn

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"strings"
	"sync"

	"github.com/go-webauthn/webauthn/protocol"
)

// AAGUID is the fixed CFGMS software-authenticator identifier
// (50669e9d-c34a-453b-9701-ebe87092fa00). It is self-asserted: the controller
// requests no attestation, so any client can claim it.
var AAGUID = [16]byte{
	0x50, 0x66, 0x9e, 0x9d, 0xc3, 0x4a, 0x45, 0x3b,
	0x97, 0x01, 0xeb, 0xe8, 0x70, 0x92, 0xfa, 0x00,
}

const (
	// coseAlgES256 is the COSE algorithm identifier for ECDSA P-256 with SHA-256.
	coseAlgES256 = -7

	flagUP = 0x01
	flagUV = 0x04
	flagAT = 0x40

	// signCount is always 0. The controller accepts a stored/response counter of
	// 0/0 (signCountAdvances in features/controller/api), and the package has no
	// storage in which to persist an advancing counter. A fixed 0 keeps every
	// response consistent with that rule.
	signCount uint32 = 0

	maxCredentialIDLen = 1023
)

// Refusal errors. None of them carry key material.
var (
	ErrRPIDMismatch         = errors.New("softauthn: options rpId does not match the authenticator's relying party")
	ErrOriginInvalid        = errors.New("softauthn: origin must be an https origin whose host is the RP ID or a subdomain of it")
	ErrNoES256              = errors.New("softauthn: pubKeyCredParams does not include ES256 (-7)")
	ErrCredentialExcluded   = errors.New("softauthn: excludeCredentials contains this authenticator's credential")
	ErrCredentialNotAllowed = errors.New("softauthn: allowCredentials does not include this authenticator's credential")
)

// Config configures an Authenticator.
type Config struct {
	// Signer holds the credential private key. Its public key must be ECDSA
	// P-256. A non-exportable signer can be supplied; the key is never read.
	Signer crypto.Signer
	// RPID is the relying party ID the authenticator is bound to.
	RPID string
	// Origin is the single origin written into clientDataJSON.
	Origin string
	// CredentialID is the credential ID the authenticator registers and asserts.
	CredentialID []byte
	// UserHandle is returned as userHandle in assertions (needed for
	// discoverable login). Optional: Register records the handle from the
	// creation options when this is empty.
	UserHandle []byte
	// AAGUID overrides the CFGMS AAGUID. nil means AAGUID. Only tests set it, to
	// model a non-CFGMS authenticator; the shipped cfg tool must never set it
	// (ADR-021 Amendment 10).
	AAGUID *[16]byte
}

// Authenticator signs WebAuthn ceremonies for one RP ID, one origin and one
// credential.
type Authenticator struct {
	signer       crypto.Signer
	rpID         string
	origin       string
	credentialID []byte
	aaguid       [16]byte
	cosePubKey   []byte

	mu         sync.Mutex
	userHandle []byte
}

// validateConfig checks cfg and returns the signer's P-256 public key.
func validateConfig(cfg Config) (*ecdsa.PublicKey, error) {
	if cfg.Signer == nil {
		return nil, errors.New("softauthn: signer is required")
	}
	pub, ok := cfg.Signer.Public().(*ecdsa.PublicKey)
	if !ok || pub == nil || pub.Curve != elliptic.P256() {
		return nil, errors.New("softauthn: signer public key must be ECDSA P-256")
	}
	if cfg.RPID == "" {
		return nil, errors.New("softauthn: rp id is required")
	}
	if err := checkOrigin(cfg.Origin, cfg.RPID); err != nil {
		return nil, err
	}
	if len(cfg.CredentialID) == 0 || len(cfg.CredentialID) > maxCredentialIDLen {
		return nil, fmt.Errorf("softauthn: credential id must be 1..%d bytes", maxCredentialIDLen)
	}
	return pub, nil
}

// New validates cfg and returns an Authenticator.
func New(cfg Config) (*Authenticator, error) {
	pub, err := validateConfig(cfg)
	if err != nil {
		return nil, err
	}
	a := &Authenticator{
		signer:       cfg.Signer,
		rpID:         cfg.RPID,
		origin:       cfg.Origin,
		credentialID: append([]byte(nil), cfg.CredentialID...),
		aaguid:       AAGUID,
		cosePubKey:   encodeCOSEKey(pub),
		userHandle:   append([]byte(nil), cfg.UserHandle...),
	}
	if cfg.AAGUID != nil {
		a.aaguid = *cfg.AAGUID
	}
	return a, nil
}

// checkOrigin refuses an origin that is not a valid https origin for rpID: the
// host must equal the RP ID or be a subdomain of it (WebAuthn §5.1.3 step 7).
// The options carry no origin, so this is where a different origin is refused.
func checkOrigin(origin, rpID string) error {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil ||
		u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return ErrOriginInvalid
	}
	host := u.Hostname()
	if host != rpID && !strings.HasSuffix(host, "."+rpID) {
		return ErrOriginInvalid
	}
	return nil
}

// CredentialID returns a copy of the credential ID.
func (a *Authenticator) CredentialID() []byte {
	return append([]byte(nil), a.credentialID...)
}

// Register answers the begin-registration options (a JSON
// protocol.CredentialCreation, the controller's begin payload with any API
// envelope already removed) and returns the JSON body the finish endpoint
// expects.
func (a *Authenticator) Register(creationJSON []byte) ([]byte, error) {
	var creation protocol.CredentialCreation
	if err := json.Unmarshal(creationJSON, &creation); err != nil {
		return nil, errors.New("softauthn: malformed registration options")
	}
	opts := creation.Response
	if err := a.checkCreation(opts); err != nil {
		return nil, err
	}

	clientData, err := a.clientDataJSON("webauthn.create", opts.Challenge)
	if err != nil {
		return nil, err
	}

	authData := a.authData(flagUP|flagUV|flagAT, true)
	attObj := encodeAttestationNone(authData)

	a.rememberUser(opts.User.ID)

	resp := protocol.CredentialCreationResponse{
		PublicKeyCredential: protocol.PublicKeyCredential{
			Credential: protocol.Credential{
				ID:   protocol.URLEncodedBase64(a.credentialID).String(),
				Type: string(protocol.PublicKeyCredentialType),
			},
			RawID: a.credentialID,
		},
		AttestationResponse: protocol.AuthenticatorAttestationResponse{
			AuthenticatorResponse: protocol.AuthenticatorResponse{ClientDataJSON: clientData},
			Transports:            []string{"internal"},
			AuthenticatorData:     authData,
			PublicKey:             a.cosePubKey,
			PublicKeyAlgorithm:    coseAlgES256,
			AttestationObject:     attObj,
		},
	}
	return json.Marshal(resp)
}

// Assert answers the begin-login options (a JSON protocol.CredentialAssertion,
// with any API envelope already removed) and returns the JSON body the finish
// endpoint expects.
func (a *Authenticator) Assert(requestJSON []byte) ([]byte, error) {
	var req protocol.CredentialAssertion
	if err := json.Unmarshal(requestJSON, &req); err != nil {
		return nil, errors.New("softauthn: malformed assertion options")
	}
	opts := req.Response
	if err := a.checkRequest(opts); err != nil {
		return nil, err
	}

	clientData, err := a.clientDataJSON("webauthn.get", opts.Challenge)
	if err != nil {
		return nil, err
	}
	authData := a.authData(flagUP|flagUV, false)

	cdHash := sha256.Sum256(clientData)
	signed := append(append([]byte(nil), authData...), cdHash[:]...)
	digest := sha256.Sum256(signed)
	sig, err := a.signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return nil, errors.New("softauthn: signing failed")
	}

	resp := protocol.CredentialAssertionResponse{
		PublicKeyCredential: protocol.PublicKeyCredential{
			Credential: protocol.Credential{
				ID:   protocol.URLEncodedBase64(a.credentialID).String(),
				Type: string(protocol.PublicKeyCredentialType),
			},
			RawID: a.credentialID,
		},
		AssertionResponse: protocol.AuthenticatorAssertionResponse{
			AuthenticatorResponse: protocol.AuthenticatorResponse{ClientDataJSON: clientData},
			AuthenticatorData:     authData,
			Signature:             sig,
			UserHandle:            a.getUserHandle(),
		},
	}
	return json.Marshal(resp)
}

// checkCreation refuses registration options this authenticator must not sign.
func (a *Authenticator) checkCreation(opts protocol.PublicKeyCredentialCreationOptions) error {
	if opts.RelyingParty.ID != "" && opts.RelyingParty.ID != a.rpID {
		return ErrRPIDMismatch
	}
	if !hasES256(opts.Parameters) {
		return ErrNoES256
	}
	if a.listed(opts.CredentialExcludeList) {
		return ErrCredentialExcluded
	}
	if len(opts.Challenge) == 0 {
		return errors.New("softauthn: registration options carry no challenge")
	}
	return nil
}

// checkRequest refuses assertion options this authenticator must not sign.
func (a *Authenticator) checkRequest(opts protocol.PublicKeyCredentialRequestOptions) error {
	if opts.RelyingPartyID != "" && opts.RelyingPartyID != a.rpID {
		return ErrRPIDMismatch
	}
	if len(opts.AllowedCredentials) > 0 && !a.listed(opts.AllowedCredentials) {
		return ErrCredentialNotAllowed
	}
	if len(opts.Challenge) == 0 {
		return errors.New("softauthn: assertion options carry no challenge")
	}
	return nil
}

// listed reports whether this authenticator's credential ID is in list.
func (a *Authenticator) listed(list []protocol.CredentialDescriptor) bool {
	for _, d := range list {
		if bytes.Equal(d.CredentialID, a.credentialID) {
			return true
		}
	}
	return false
}

// rememberUser keeps the base64url-encoded user id from the creation options as
// the handle for later assertions, unless one was configured.
func (a *Authenticator) rememberUser(id any) {
	enc, ok := id.(string)
	if !ok {
		return
	}
	h, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil || len(h) == 0 {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.userHandle) == 0 {
		a.userHandle = h
	}
}

func (a *Authenticator) getUserHandle() []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]byte(nil), a.userHandle...)
}

func hasES256(params []protocol.CredentialParameter) bool {
	for _, p := range params {
		if p.Algorithm == coseAlgES256 {
			return true
		}
	}
	return false
}

// clientDataJSON builds the collected client data for the ceremony, binding it
// to the authenticator's single origin.
func (a *Authenticator) clientDataJSON(ceremony string, challenge protocol.URLEncodedBase64) ([]byte, error) {
	cd := struct {
		Type        string `json:"type"`
		Challenge   string `json:"challenge"`
		Origin      string `json:"origin"`
		CrossOrigin bool   `json:"crossOrigin"`
	}{ceremony, challenge.String(), a.origin, false}
	out, err := json.Marshal(cd)
	if err != nil {
		return nil, errors.New("softauthn: encoding client data failed")
	}
	return out, nil
}

// authData assembles authenticator data: rpIdHash || flags || signCount, plus
// attested credential data (AAGUID, credential ID, COSE key) when withAttested.
func (a *Authenticator) authData(flags byte, withAttested bool) []byte {
	rpHash := sha256.Sum256([]byte(a.rpID))
	out := make([]byte, 0, 37+16+2+len(a.credentialID)+len(a.cosePubKey))
	out = append(out, rpHash[:]...)
	out = append(out, flags)
	var ctr [4]byte
	binary.BigEndian.PutUint32(ctr[:], signCount)
	out = append(out, ctr[:]...)
	if withAttested {
		out = append(out, a.aaguid[:]...)
		out = binary.BigEndian.AppendUint16(out, uint16(len(a.credentialID)&0xffff))
		out = append(out, a.credentialID...)
		out = append(out, a.cosePubKey...)
	}
	return out
}

// --- minimal deterministic CBOR (only the shapes WebAuthn registration needs) ---

func cborHead(major byte, n uint64) []byte {
	m := major << 5
	switch {
	case n < 24:
		return []byte{m | byte(n&0x1f)}
	case n <= math.MaxUint8:
		return []byte{m | 24, byte(n & 0xff)}
	case n <= math.MaxUint16:
		return binary.BigEndian.AppendUint16([]byte{m | 25}, uint16(n&0xffff))
	default:
		return binary.BigEndian.AppendUint32([]byte{m | 26}, uint32(n&0xffffffff))
	}
}

func cborInt(v int64) []byte {
	if v >= 0 {
		return cborHead(0, uint64(v))
	}
	return cborHead(1, uint64(-1-v))
}

func cborBytes(b []byte) []byte { return append(cborHead(2, uint64(len(b))), b...) }
func cborText(s string) []byte  { return append(cborHead(3, uint64(len(s))), s...) }

// encodeCOSEKey encodes an EC2 P-256 ES256 COSE_Key (RFC 9053).
func encodeCOSEKey(pub *ecdsa.PublicKey) []byte {
	var x, y [32]byte
	pub.X.FillBytes(x[:])
	pub.Y.FillBytes(y[:])
	var b []byte
	b = append(b, cborHead(5, 5)...)
	b = append(b, cborInt(1)...)
	b = append(b, cborInt(2)...) // kty: EC2
	b = append(b, cborInt(3)...)
	b = append(b, cborInt(coseAlgES256)...)
	b = append(b, cborInt(-1)...)
	b = append(b, cborInt(1)...) // crv: P-256
	b = append(b, cborInt(-2)...)
	b = append(b, cborBytes(x[:])...)
	b = append(b, cborInt(-3)...)
	b = append(b, cborBytes(y[:])...)
	return b
}

// encodeAttestationNone encodes {"fmt":"none","attStmt":{},"authData":h'..'}.
func encodeAttestationNone(authData []byte) []byte {
	var b []byte
	b = append(b, cborHead(5, 3)...)
	b = append(b, cborText("fmt")...)
	b = append(b, cborText("none")...)
	b = append(b, cborText("attStmt")...)
	b = append(b, cborHead(5, 0)...)
	b = append(b, cborText("authData")...)
	b = append(b, cborBytes(authData)...)
	return b
}
