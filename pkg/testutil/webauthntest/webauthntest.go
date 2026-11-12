// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package webauthntest is the one test-support builder for WebAuthn
// registration and assertion bodies. It sits on top of pkg/softauthn: every
// response starts as a softauthn response, and an option that softauthn refuses
// to produce (UP only, a different origin or RP ID, a chosen sign count, a
// corrupted signature) patches that response and, when a signed byte changed,
// signs it again with the caller's key.
//
// The package exists so a test can move exactly one property away from a valid
// ceremony. It is test support, not a provider: product code must not import it,
// and nothing in it is a statement about what a real authenticator does.
//
// Default registrations carry a zero AAGUID so a migrated fixture is not
// mistaken for a CFGMS software authenticator; WithCFGMSAAGUID opts in.
package webauthntest

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
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/softauthn"
)

// Authenticator-data flag bits (WebAuthn §6.1).
const (
	FlagUP byte = 0x01 // user present
	FlagUV byte = 0x04 // user verified
	FlagAT byte = 0x40 // attested credential data included
)

// Ceremony types written into clientDataJSON.
const (
	CeremonyGet    = "webauthn.get"
	CeremonyCreate = "webauthn.create"
)

const (
	flagsOffset     = 32
	signCountOffset = 33
	authDataMinLen  = 37
)

// defaultUserHandle is the user handle a registration records when none is chosen.
var defaultUserHandle = []byte("webauthntest-user")

// options is the resolved option set. A nil pointer means "leave what softauthn
// produced".
type options struct {
	flags      *byte
	signCount  *uint32
	origin     *string
	rpID       *string
	ceremony   *string
	userHandle []byte
	aaguid     [16]byte
	corruptSig bool
}

// Option moves one property of a ceremony away from the valid default.
type Option func(*options)

// WithFlags replaces the authenticator-data flags byte of an assertion.
func WithFlags(flags byte) Option { return func(o *options) { o.flags = &flags } }

// UserPresenceOnly sets the flags to UP alone: user verification is clear.
func UserPresenceOnly() Option { return WithFlags(FlagUP) }

// WithSignCount sets the signature counter an assertion reports. softauthn
// always reports 0.
func WithSignCount(n uint32) Option { return func(o *options) { o.signCount = &n } }

// WithOrigin sets the origin written into clientDataJSON, whether or not it is
// valid for the RP ID. The origin argument of Assert/Register stays the one the
// relying party is expected to accept.
func WithOrigin(origin string) Option { return func(o *options) { o.origin = &origin } }

// WithRPID sets the RP ID the authenticator hashes into authenticatorData,
// whether or not it matches the RP ID the relying party expects.
func WithRPID(rpID string) Option { return func(o *options) { o.rpID = &rpID } }

// WithCeremonyType sets the clientDataJSON type ("webauthn.get" /
// "webauthn.create").
func WithCeremonyType(typ string) Option { return func(o *options) { o.ceremony = &typ } }

// WithUserHandle sets the userHandle an assertion returns and the user id a
// registration records.
func WithUserHandle(handle []byte) Option {
	return func(o *options) { o.userHandle = append([]byte(nil), handle...) }
}

// WithAAGUID sets the AAGUID a registration carries. The default is all zero.
func WithAAGUID(aaguid [16]byte) Option { return func(o *options) { o.aaguid = aaguid } }

// WithCFGMSAAGUID sets the registration AAGUID to softauthn.AAGUID, the
// identifier of the CFGMS software authenticator.
func WithCFGMSAAGUID() Option { return WithAAGUID(softauthn.AAGUID) }

// WithCorruptSignature flips bits of the final signature byte so it no longer
// verifies. The result is still a well-formed ASN.1 signature.
func WithCorruptSignature() Option { return func(o *options) { o.corruptSig = true } }

func resolve(opts []Option) options {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

// NewKey returns a fresh P-256 key and its COSE-encoded public key, in the
// format a stored credential's public key takes.
func NewKey(t testing.TB) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pub, err := COSEPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	return priv, pub
}

// COSEPublicKey encodes pub as an EC2 / ES256 / P-256 COSE_Key.
func COSEPublicKey(pub *ecdsa.PublicKey) ([]byte, error) {
	var x, y [32]byte
	pub.X.FillBytes(x[:])
	pub.Y.FillBytes(y[:])
	return webauthncbor.Marshal(webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{
			KeyType:   int64(webauthncose.EllipticKey),
			Algorithm: int64(webauthncose.AlgES256),
		},
		Curve:  int64(webauthncose.P256),
		XCoord: x[:],
		YCoord: y[:],
	})
}

// Assertion is one assertion response, split into the byte fields a verifier
// consumes.
type Assertion struct {
	CredentialID      []byte
	AuthenticatorData []byte
	ClientDataJSON    []byte
	Signature         []byte
	UserHandle        []byte
}

// Body returns the JSON PublicKeyCredential body a finish endpoint accepts.
func (a *Assertion) Body() []byte {
	return RawAssertionBody(a.CredentialID, a.AuthenticatorData, a.ClientDataJSON, a.Signature, a.UserHandle)
}

// Reader returns Body as a reader, for httptest requests.
func (a *Assertion) Reader() *bytes.Reader { return bytes.NewReader(a.Body()) }

// Assert builds an assertion over challenge (the base64url challenge string the
// relying party issued) with key for the credential credID. rpID and origin are
// the values the relying party expects; options move the response away from them.
func Assert(t testing.TB, key *ecdsa.PrivateKey, credID []byte, rpID, origin, challenge string, opts ...Option) *Assertion {
	t.Helper()
	o := resolve(opts)
	effRPID := o.rpIDOr(rpID)
	wantOrigin := o.originOr(origin)

	chBytes, canonical := decodeCanonical(challenge)
	if !canonical {
		// Not a canonical base64url string: softauthn gets a placeholder and the
		// string is written into clientDataJSON by patching.
		chBytes = []byte{0}
	}
	authn := newAuthenticator(t, key, credID, effRPID, wantOrigin, o.userHandle, nil)
	request, err := json.Marshal(protocol.CredentialAssertion{Response: protocol.PublicKeyCredentialRequestOptions{
		Challenge:      chBytes,
		RelyingPartyID: effRPID,
	}})
	require.NoError(t, err)
	raw, err := authn.Assert(request)
	require.NoError(t, err)

	var resp protocol.CredentialAssertionResponse
	require.NoError(t, json.Unmarshal(raw, &resp))
	authData, clientData, sig, changed := o.patchAssertion(t, resp.AssertionResponse, challenge, wantOrigin)
	if changed {
		sig = sign(t, key, authData, clientData)
	}
	if o.corruptSig {
		sig = corrupt(sig)
	}

	return &Assertion{
		CredentialID:      authn.CredentialID(),
		AuthenticatorData: authData,
		ClientDataJSON:    clientData,
		Signature:         sig,
		UserHandle:        []byte(resp.AssertionResponse.UserHandle),
	}
}

func (o *options) rpIDOr(def string) string {
	if o.rpID != nil {
		return *o.rpID
	}
	return def
}

func (o *options) originOr(def string) string {
	if o.origin != nil {
		return *o.origin
	}
	return def
}

func (o *options) ceremonyOr(def string) string {
	if o.ceremony != nil {
		return *o.ceremony
	}
	return def
}

// patchAssertion applies the flags, sign count and clientDataJSON options to
// softauthn's response and reports whether a signed byte changed, so the caller
// must sign again.
func (o *options) patchAssertion(t testing.TB, resp protocol.AuthenticatorAssertionResponse, challenge, origin string) (authData, clientData, sig []byte, changed bool) {
	t.Helper()
	authData = append([]byte(nil), resp.AuthenticatorData...)
	require.GreaterOrEqual(t, len(authData), authDataMinLen)
	if o.flags != nil && authData[flagsOffset] != *o.flags {
		authData[flagsOffset] = *o.flags
		changed = true
	}
	if o.signCount != nil && *o.signCount != 0 {
		binary.BigEndian.PutUint32(authData[signCountOffset:], *o.signCount)
		changed = true
	}
	clientData, did := patchClientData(t, resp.ClientDataJSON, o.ceremonyOr(CeremonyGet), challenge, origin)
	return authData, clientData, resp.Signature, changed || did
}

// Registration is one registration response.
type Registration struct {
	CredentialID []byte
	// PublicKey is the COSE-encoded public key the response carries.
	PublicKey []byte
	body      []byte
}

// Body returns the JSON PublicKeyCredential body a finish-registration endpoint accepts.
func (r *Registration) Body() []byte { return r.body }

// Reader returns Body as a reader, for httptest requests.
func (r *Registration) Reader() *bytes.Reader { return bytes.NewReader(r.body) }

// Register builds an attestation-"none" registration over challenge (the
// base64url challenge string the relying party issued) for the credential
// credID held by key. The default AAGUID is zero.
func Register(t testing.TB, key *ecdsa.PrivateKey, credID []byte, rpID, origin, challenge string, opts ...Option) *Registration {
	t.Helper()
	o := resolve(opts)

	effRPID := o.rpIDOr(rpID)
	wantOrigin := o.originOr(origin)
	wantCeremony := o.ceremonyOr(CeremonyCreate)
	user := o.userHandle
	if len(user) == 0 {
		user = defaultUserHandle
	}

	chBytes, canonical := decodeCanonical(challenge)
	if !canonical {
		chBytes = []byte{0}
	}
	aaguid := o.aaguid
	authn := newAuthenticator(t, key, credID, effRPID, wantOrigin, nil, &aaguid)

	var creation protocol.CredentialCreation
	creation.Response.Challenge = chBytes
	creation.Response.RelyingParty.ID = effRPID
	creation.Response.User.ID = base64.RawURLEncoding.EncodeToString(user)
	creation.Response.Parameters = []protocol.CredentialParameter{{
		Type:      protocol.PublicKeyCredentialType,
		Algorithm: webauthncose.AlgES256,
	}}
	request, err := json.Marshal(creation)
	require.NoError(t, err)
	raw, err := authn.Register(request)
	require.NoError(t, err)

	var resp protocol.CredentialCreationResponse
	require.NoError(t, json.Unmarshal(raw, &resp))
	if patched, did := patchClientData(t, resp.AttestationResponse.ClientDataJSON, wantCeremony, challenge, wantOrigin); did {
		resp.AttestationResponse.ClientDataJSON = patched
	}
	body, err := json.Marshal(resp)
	require.NoError(t, err)
	return &Registration{CredentialID: authn.CredentialID(), PublicKey: resp.AttestationResponse.PublicKey, body: body}
}

// RawAssertionBody wraps already-built assertion byte fields (a recorded
// authenticator vector, for example) in the JSON body a finish endpoint
// accepts. userHandle may be nil.
func RawAssertionBody(credID, authData, clientDataJSON, signature, userHandle []byte) []byte {
	resp := protocol.CredentialAssertionResponse{
		PublicKeyCredential: protocol.PublicKeyCredential{
			Credential: protocol.Credential{
				ID:   protocol.URLEncodedBase64(credID).String(),
				Type: string(protocol.PublicKeyCredentialType),
			},
			RawID: credID,
		},
		AssertionResponse: protocol.AuthenticatorAssertionResponse{
			AuthenticatorResponse: protocol.AuthenticatorResponse{ClientDataJSON: clientDataJSON},
			AuthenticatorData:     authData,
			Signature:             signature,
			UserHandle:            userHandle,
		},
	}
	body, err := json.Marshal(resp)
	if err != nil {
		// Marshalling byte slices and strings cannot fail.
		panic("webauthntest: " + err.Error())
	}
	return body
}

// newAuthenticator returns a softauthn authenticator for rpID. softauthn refuses
// an origin that is not an https origin for the RP ID; the caller's origin is
// then written by patching, so the authenticator is built on the RP ID's own
// https origin instead.
func newAuthenticator(t testing.TB, key *ecdsa.PrivateKey, credID []byte, rpID, origin string, userHandle []byte, aaguid *[16]byte) *softauthn.Authenticator {
	t.Helper()
	cfg := softauthn.Config{
		Signer:       key,
		RPID:         rpID,
		Origin:       origin,
		CredentialID: credID,
		UserHandle:   userHandle,
		AAGUID:       aaguid,
	}
	a, err := softauthn.New(cfg)
	if errors.Is(err, softauthn.ErrOriginInvalid) {
		cfg.Origin = "https://" + rpID
		a, err = softauthn.New(cfg)
	}
	require.NoError(t, err)
	return a
}

// decodeCanonical decodes a base64url challenge and reports whether re-encoding
// it gives the same string.
func decodeCanonical(challenge string) ([]byte, bool) {
	b, err := base64.RawURLEncoding.DecodeString(challenge)
	if err != nil || len(b) == 0 || base64.RawURLEncoding.EncodeToString(b) != challenge {
		return nil, false
	}
	return b, true
}

// patchClientData rewrites clientDataJSON when its type, challenge or origin
// differs from what the caller wants, and reports whether it did.
func patchClientData(t testing.TB, clientData []byte, ceremony, challenge, origin string) ([]byte, bool) {
	t.Helper()
	var cd struct {
		Type        string `json:"type"`
		Challenge   string `json:"challenge"`
		Origin      string `json:"origin"`
		CrossOrigin bool   `json:"crossOrigin"`
	}
	require.NoError(t, json.Unmarshal(clientData, &cd))
	if cd.Type == ceremony && cd.Challenge == challenge && cd.Origin == origin {
		return clientData, false
	}
	cd.Type, cd.Challenge, cd.Origin = ceremony, challenge, origin
	out, err := json.Marshal(cd)
	require.NoError(t, err)
	return out, true
}

// sign signs authData || SHA-256(clientDataJSON), the bytes an assertion covers.
func sign(t testing.TB, key *ecdsa.PrivateKey, authData, clientData []byte) []byte {
	t.Helper()
	cdHash := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(append([]byte(nil), authData...), cdHash[:]...))
	sig, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)
	return sig
}

// corrupt flips the bits of the last signature byte.
func corrupt(sig []byte) []byte {
	out := append([]byte(nil), sig...)
	out[len(out)-1] ^= 0xff
	return out
}
