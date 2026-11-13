// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build linux && cgo

package tpmkey_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"strings"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	legacy "github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/legacy/tpm2/credactivation"
	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/softauthn"
	"github.com/cfgis/cfgms/pkg/softauthn/tpmkey"
	"github.com/cfgis/cfgms/pkg/softauthn/tpmkey/tpmkeytest"
)

const (
	rpID   = "controller.example.test"
	origin = "https://controller.example.test"
)

// challenge makes the controller's credential challenge for the attestation key
// in p and the EK certificate it holds, the way the server does.
func challenge(t *testing.T, p *tpmkey.Prepared, secret []byte) (credentialBlob, encryptedSecret []byte) {
	t.Helper()
	cert, err := x509.ParseCertificate(p.EKCertChain[0])
	require.NoError(t, err)
	ak, err := tpm2.Unmarshal[tpm2.TPMTPublic](p.AKPublic)
	require.NoError(t, err)
	name, err := tpm2.ObjectName(ak)
	require.NoError(t, err)
	require.Greater(t, len(name.Buffer), 2)
	hv := &legacy.HashValue{Alg: legacy.AlgSHA256, Value: name.Buffer[2:]}
	credentialBlob, encryptedSecret, err = credactivation.Generate(hv, cert.PublicKey, 16, secret)
	require.NoError(t, err)
	return credentialBlob, encryptedSecret
}

func newSecret(t *testing.T) []byte {
	t.Helper()
	s := make([]byte, 32)
	_, err := rand.Read(s)
	require.NoError(t, err)
	return s
}

func transientHandles(t *testing.T, tpm *tpmkeytest.TPM) int {
	t.Helper()
	rsp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapHandles,
		Property:      uint32(tpm2.TPMHTTransient) << 24,
		PropertyCount: 32,
	}.Execute(tpm)
	require.NoError(t, err)
	h, err := rsp.CapabilityData.Data.Handles()
	require.NoError(t, err)
	return len(h.Handle)
}

func keyAttributes(t *testing.T, publicBlob []byte) tpm2.TPMAObject {
	t.Helper()
	p2b, err := tpm2.Unmarshal[tpm2.TPM2BPublic](publicBlob)
	require.NoError(t, err)
	pt, err := p2b.Contents()
	require.NoError(t, err)
	return pt.ObjectAttributes
}

func TestCreateOpenSign(t *testing.T) {
	tpm := tpmkeytest.Start(t, tpmkeytest.Options{})
	blobs, pub, err := tpmkey.Create(tpm)
	require.NoError(t, err)
	assert.Equal(t, "P-256", pub.Curve.Params().Name)

	attrs := keyAttributes(t, blobs.Public)
	assert.True(t, attrs.FixedTPM, "credential key must be fixedTPM")
	assert.True(t, attrs.FixedParent, "credential key must be fixedParent")
	assert.True(t, attrs.SensitiveDataOrigin, "credential key must be TPM-generated")
	assert.True(t, attrs.SignEncrypt)
	assert.False(t, attrs.Restricted)

	fromBlob, err := tpmkey.PublicKey(blobs.Public)
	require.NoError(t, err)
	assert.True(t, pub.Equal(fromBlob))

	signer, err := tpmkey.Open(tpm, blobs)
	require.NoError(t, err)
	assert.True(t, pub.Equal(signer.Public()))

	digest := sha256.Sum256([]byte("message"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)
	assert.True(t, ecdsa.VerifyASN1(pub, digest[:], sig), "TPM signature verifies under the public key")
	other := sha256.Sum256([]byte("other"))
	assert.False(t, ecdsa.VerifyASN1(pub, other[:], sig))

	assert.Zero(t, transientHandles(t, tpm), "every transient handle must be flushed")
}

func TestSignerRefusesWrongDigest(t *testing.T) {
	tpm := tpmkeytest.Start(t, tpmkeytest.Options{})
	blobs, _, err := tpmkey.Create(tpm)
	require.NoError(t, err)
	signer, err := tpmkey.Open(tpm, blobs)
	require.NoError(t, err)

	_, err = signer.Sign(rand.Reader, []byte("short"), crypto.SHA256)
	require.Error(t, err)
	digest := sha256.Sum256([]byte("m"))
	_, err = signer.Sign(rand.Reader, digest[:], crypto.SHA512)
	require.Error(t, err)
	_, err = signer.Sign(rand.Reader, digest[:], nil)
	require.Error(t, err)
}

func TestOpenRefusesBadBlobs(t *testing.T) {
	tpm := tpmkeytest.Start(t, tpmkeytest.Options{})
	_, err := tpmkey.Open(tpm, tpmkey.Blobs{Public: []byte("garbage")})
	require.Error(t, err)

	blobs, _, err := tpmkey.Create(tpm)
	require.NoError(t, err)
	signer, err := tpmkey.Open(tpm, tpmkey.Blobs{Public: blobs.Public, Private: []byte{0, 4, 1, 2, 3, 4}})
	require.NoError(t, err, "the public half alone is enough to open")
	digest := sha256.Sum256([]byte("m"))
	_, err = signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.Error(t, err, "a private blob this TPM did not wrap cannot sign")
}

func TestPrepareReturnsEKChainAndAKPublicArea(t *testing.T) {
	tpm := tpmkeytest.Start(t, tpmkeytest.Options{})
	p, err := tpmkey.Prepare(tpm)
	require.NoError(t, err)

	require.Len(t, p.EKCertChain, 1)
	assert.Equal(t, tpm.EKCertificate, p.EKCertChain[0])
	ekCert, err := x509.ParseCertificate(p.EKCertChain[0])
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(tpm.CA)
	// A real EK certificate has an empty subject and so a critical subject
	// alternative name holding only a directoryName, which crypto/x509 reports
	// as an unhandled critical extension; a verifier clears it before chaining.
	ekCert.UnhandledCriticalExtensions = nil
	_, err = ekCert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	require.NoError(t, err, "the EK certificate chains to the test CA")

	ak, err := tpm2.Unmarshal[tpm2.TPMTPublic](p.AKPublic)
	require.NoError(t, err)
	assert.Equal(t, tpm2.TPMAlgECC, ak.Type)
	a := ak.ObjectAttributes
	assert.True(t, a.FixedTPM)
	assert.True(t, a.FixedParent)
	assert.True(t, a.SensitiveDataOrigin)
	assert.True(t, a.Restricted)
	assert.True(t, a.SignEncrypt)
	assert.False(t, a.Decrypt)
	parms, err := ak.Parameters.ECCDetail()
	require.NoError(t, err)
	assert.Equal(t, tpm2.TPMECCNistP256, parms.CurveID)
	assert.Equal(t, tpm2.TPMAlgECDSA, parms.Scheme.Scheme)

	// The AK is re-derived from a fixed template: a second Prepare is identical
	// and nothing stays loaded.
	again, err := tpmkey.Prepare(tpm)
	require.NoError(t, err)
	assert.Equal(t, p.AKPublic, again.AKPublic)
	assert.Zero(t, transientHandles(t, tpm))
}

func TestPrepareRefusesTPMWithoutEKCertificate(t *testing.T) {
	tpm := tpmkeytest.Start(t, tpmkeytest.Options{NoEKCertificate: true})
	_, err := tpmkey.Prepare(tpm)
	require.ErrorIs(t, err, tpmkey.ErrNoEKCertificate)
	assert.Contains(t, err.Error(), "endorsement key certificate")
	require.ErrorIs(t, tpmkey.HasEKCertificate(tpm), tpmkey.ErrNoEKCertificate)
}

func TestActivateRecoversSecret(t *testing.T) {
	tpm := tpmkeytest.Start(t, tpmkeytest.Options{})
	p, err := tpmkey.Prepare(tpm)
	require.NoError(t, err)
	secret := newSecret(t)
	blob, enc := challenge(t, p, secret)

	got, err := tpmkey.Activate(tpm, p, blob, enc)
	require.NoError(t, err)
	assert.Equal(t, secret, got)
	assert.Zero(t, transientHandles(t, tpm))
}

func TestActivateRefusals(t *testing.T) {
	tpm := tpmkeytest.Start(t, tpmkeytest.Options{})
	p, err := tpmkey.Prepare(tpm)
	require.NoError(t, err)
	blob, enc := challenge(t, p, newSecret(t))

	_, err = tpmkey.Activate(tpm, nil, blob, enc)
	require.Error(t, err)
	_, err = tpmkey.Activate(tpm, p, []byte{0xff}, enc)
	require.Error(t, err)
	_, err = tpmkey.Activate(tpm, p, blob, []byte{0xff})
	require.Error(t, err)

	// A challenge made for a different attestation key does not activate.
	wrong := *p
	otherAK := append([]byte(nil), p.AKPublic...)
	otherAK[len(otherAK)-1] ^= 0x01
	wrong.AKPublic = otherAK
	wrongBlob, wrongEnc := challenge(t, &wrong, newSecret(t))
	_, err = tpmkey.Activate(tpm, p, wrongBlob, wrongEnc)
	require.Error(t, err, "the TPM must refuse a challenge that names another AK")

	tampered := append([]byte(nil), blob...)
	tampered[len(tampered)-1] ^= 0x01
	_, err = tpmkey.Activate(tpm, p, tampered, enc)
	require.Error(t, err, "a modified credential blob fails integrity")
	assert.Zero(t, transientHandles(t, tpm))
}

// registered runs a registration with a TPM-held key and returns the parsed
// response and the pieces VerifyAttestation needs.
type registered struct {
	obj            protocol.AttestationObject
	clientDataHash []byte
	authData       []byte
	pub            *ecdsa.PublicKey
	parsed         *protocol.ParsedCredentialCreationData
}

func creationOptions(t *testing.T) []byte {
	t.Helper()
	wa, err := webauthn.New(&webauthn.Config{RPID: rpID, RPDisplayName: "CFGMS test", RPOrigins: []string{origin}})
	require.NoError(t, err)
	creation, _, err := wa.BeginRegistration(&testUser{},
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			UserVerification:   protocol.VerificationRequired,
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: protocol.ResidentKeyRequired(),
		}))
	require.NoError(t, err)
	raw, err := json.Marshal(creation)
	require.NoError(t, err)
	return raw
}

type testUser struct{}

func (testUser) WebAuthnID() []byte                         { return []byte("user-handle-0123456789") }
func (testUser) WebAuthnName() string                       { return "agent" }
func (testUser) WebAuthnDisplayName() string                { return "Agent" }
func (testUser) WebAuthnCredentials() []webauthn.Credential { return nil }

func registerWith(t *testing.T, blobs tpmkey.Blobs, pub *ecdsa.PublicKey, attester softauthn.Attester, signer crypto.Signer) registered {
	t.Helper()
	credID := newSecret(t)
	a, err := softauthn.New(softauthn.Config{
		Signer: signer, RPID: rpID, Origin: origin, CredentialID: credID, Attester: attester,
	})
	require.NoError(t, err)
	resp, err := a.Register(creationOptions(t))
	require.NoError(t, err)
	parsed, err := protocol.ParseCredentialCreationResponseBytes(resp)
	require.NoError(t, err)
	cdHash := sha256.Sum256(parsed.Raw.AttestationResponse.ClientDataJSON)
	return registered{
		obj:            parsed.Response.AttestationObject,
		clientDataHash: cdHash[:],
		authData:       parsed.Raw.AttestationResponse.AuthenticatorData,
		pub:            pub,
		parsed:         parsed,
	}
}

// verify runs go-webauthn's tpm verification with no metadata provider, the way
// the controller does.
func verify(t *testing.T, obj protocol.AttestationObject, clientDataHash []byte) error {
	t.Helper()
	return obj.VerifyAttestation(clientDataHash, nil, protocol.AttestationPolicy{}, protocol.SignaturePolicy{})
}

// ceremony makes a key, prepares, activates a controller challenge and registers.
func ceremony(t *testing.T, tpm *tpmkeytest.TPM) (registered, []byte, tpmkey.Blobs) {
	t.Helper()
	blobs, pub, err := tpmkey.Create(tpm)
	require.NoError(t, err)
	p, err := tpmkey.Prepare(tpm)
	require.NoError(t, err)
	secret := newSecret(t)
	blob, enc := challenge(t, p, secret)
	recovered, err := tpmkey.Activate(tpm, p, blob, enc)
	require.NoError(t, err)
	require.Equal(t, secret, recovered)
	signer, err := tpmkey.Open(tpm, blobs)
	require.NoError(t, err)
	return registerWith(t, blobs, pub, tpmkey.NewAttester(tpm, blobs, recovered), signer), secret, blobs
}

func TestAttestationPassesVerifyAttestation(t *testing.T) {
	for name, opts := range map[string]tpmkeytest.Options{
		"ecc EK":                        {},
		"ecc EK without TCG attributes": {NoEKAttributes: true},
	} {
		t.Run(name, func(t *testing.T) {
			tpm := tpmkeytest.Start(t, opts)
			reg, secret, _ := ceremony(t, tpm)

			assert.Equal(t, "tpm", reg.obj.Format)
			assert.Equal(t, softauthn.AAGUID[:], reg.obj.AuthData.AttData.AAGUID)
			assert.Equal(t, secret, reg.obj.AttStatement["cfgmsActivation"])
			require.NoError(t, verify(t, reg.obj, reg.clientDataHash))
			assert.Zero(t, transientHandles(t, tpm))
		})
	}
}

func TestAttestationWithRSAEK(t *testing.T) {
	tpm := tpmkeytest.Start(t, tpmkeytest.Options{RSAEK: true})
	reg, _, _ := ceremony(t, tpm)
	require.NoError(t, verify(t, reg.obj, reg.clientDataHash))
}

func TestAttestationFailsWhenBindingDiffersByOneByte(t *testing.T) {
	tpm := tpmkeytest.Start(t, tpmkeytest.Options{})
	reg, _, _ := ceremony(t, tpm)
	require.NoError(t, verify(t, reg.obj, reg.clientDataHash))

	badHash := append([]byte(nil), reg.clientDataHash...)
	badHash[0] ^= 0x01
	require.Error(t, verify(t, reg.obj, badHash), "clientDataHash differing by one byte must fail")

	badAuth := reg.obj
	badAuth.RawAuthData = append([]byte(nil), reg.obj.RawAuthData...)
	badAuth.RawAuthData[len(badAuth.RawAuthData)-1] ^= 0x01
	require.Error(t, verify(t, badAuth, reg.clientDataHash), "authData differing by one byte must fail")
}

func TestAttestationCarrierCertificate(t *testing.T) {
	tpm := tpmkeytest.Start(t, tpmkeytest.Options{})
	reg, _, _ := ceremony(t, tpm)
	x5c, ok := reg.obj.AttStatement["x5c"].([]any)
	require.True(t, ok)
	require.Len(t, x5c, 1)
	cert, err := x509.ParseCertificate(x5c[0].([]byte))
	require.NoError(t, err)

	p, err := tpmkey.Prepare(tpm)
	require.NoError(t, err)
	ak, err := tpm2.Unmarshal[tpm2.TPMTPublic](p.AKPublic)
	require.NoError(t, err)
	point, err := ak.Unique.ECC()
	require.NoError(t, err)
	certKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	require.True(t, ok)
	assert.Equal(t, point.X.Buffer, certKey.X.FillBytes(make([]byte, 32)), "the carrier carries the AK public key")
	assert.Equal(t, point.Y.Buffer, certKey.Y.FillBytes(make([]byte, 32)))
	assert.Empty(t, cert.Subject.String())
	assert.False(t, cert.IsCA)
	assert.Equal(t, 3, cert.Version)

	// A second ceremony gets a different carrier signing key: nothing is reused.
	reg2, _, _ := ceremony(t, tpm)
	x5c2 := reg2.obj.AttStatement["x5c"].([]any)
	cert2, err := x509.ParseCertificate(x5c2[0].([]byte))
	require.NoError(t, err)
	assert.NotEqual(t, cert.Signature, cert2.Signature)
	assert.NotEqual(t, cert.SerialNumber, cert2.SerialNumber)
}

func TestCredentialKeyMustBeTheCertifiedKey(t *testing.T) {
	tpm := tpmkeytest.Start(t, tpmkeytest.Options{})
	blobs, pub, err := tpmkey.Create(tpm)
	require.NoError(t, err)
	otherBlobs, _, err := tpmkey.Create(tpm)
	require.NoError(t, err)
	signer, err := tpmkey.Open(tpm, blobs)
	require.NoError(t, err)

	reg := registerWith(t, blobs, pub, tpmkeytest.OtherKeyAttester(tpm, otherBlobs, newSecret(t)), signer)
	require.Error(t, verify(t, reg.obj, reg.clientDataHash), "certifying a different key must fail verification")
}

func TestKeyWithoutFixedTPMIsVisibleToAVerifier(t *testing.T) {
	tpm := tpmkeytest.Start(t, tpmkeytest.Options{})
	blobs, err := tpmkeytest.KeyWithoutFixedTPM(tpm)
	require.NoError(t, err)
	attrs := keyAttributes(t, blobs.Public)
	assert.False(t, attrs.FixedTPM)

	pub, err := tpmkey.PublicKey(blobs.Public)
	require.NoError(t, err)
	signer, err := tpmkey.Open(tpm, blobs)
	require.NoError(t, err)
	reg := registerWith(t, blobs, pub, tpmkey.NewAttester(tpm, blobs, newSecret(t)), signer)

	pubArea, ok := reg.obj.AttStatement["pubArea"].([]byte)
	require.True(t, ok)
	area, err := tpm2.Unmarshal[tpm2.TPMTPublic](pubArea)
	require.NoError(t, err)
	assert.False(t, area.ObjectAttributes.FixedTPM, "the attested pubArea reports the missing fixedTPM")
	require.NoError(t, verify(t, reg.obj, reg.clientDataHash), "the format check passes; refusing the key is the verifier's policy")
}

func TestTamperedActivationChangesOnlyTheSecret(t *testing.T) {
	tpm := tpmkeytest.Start(t, tpmkeytest.Options{})
	blobs, _, err := tpmkey.Create(tpm)
	require.NoError(t, err)
	secret := newSecret(t)
	inner := tpmkey.NewAttester(tpm, blobs, secret)
	authData := bytes.Repeat([]byte{1}, 40)
	cdHash := bytes.Repeat([]byte{2}, 32)

	clean, err := inner.AttestTPM(authData, cdHash)
	require.NoError(t, err)
	tampered, err := tpmkeytest.TamperedActivation(inner).AttestTPM(authData, cdHash)
	require.NoError(t, err)
	assert.Equal(t, secret, clean.Activation)
	assert.NotEqual(t, secret, tampered.Activation)
	assert.Len(t, tampered.Activation, len(secret))
	assert.Equal(t, clean.PubArea, tampered.PubArea)
}

func TestAttestRefusesMissingInputs(t *testing.T) {
	tpm := tpmkeytest.Start(t, tpmkeytest.Options{})
	blobs, _, err := tpmkey.Create(tpm)
	require.NoError(t, err)
	for name, args := range map[string][3][]byte{
		"no authData": {nil, {1}, {1}},
		"no hash":     {{1}, nil, {1}},
		"no secret":   {{1}, {1}, nil},
	} {
		_, err := tpmkey.Attest(tpm, blobs, args[0], args[1], args[2])
		require.Error(t, err, name)
	}
	_, err = tpmkey.Attest(tpm, tpmkey.Blobs{Public: []byte("x")}, []byte{1}, []byte{1}, []byte{1})
	require.Error(t, err)
}

// The production API exports exactly the documented surface and no wrong-output
// option; those live in tpmkeytest.
func TestProductionAPIHasNoWrongOutputKnobs(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	require.NoError(t, err)
	pkg, ok := pkgs["tpmkey"]
	require.True(t, ok)

	exported := map[string]bool{}
	for _, f := range pkg.Files {
		for name, obj := range f.Scope.Objects {
			if ast.IsExported(name) && obj.Kind != ast.Pkg {
				exported[name] = true
			}
		}
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && ast.IsExported(fd.Name.Name) {
				exported[fd.Name.Name] = true
			}
		}
	}
	want := []string{"Activate", "Attest", "Blobs", "Create", "ErrNoEKCertificate", "ErrUnsupported",
		"HasEKCertificate", "NewAttester", "Open", "OpenDevice", "Prepare", "Prepared", "PublicKey"}
	var got []string
	for name := range exported {
		got = append(got, name)
	}
	assert.ElementsMatch(t, want, got, "a new export must be reviewed: the production API has no wrong-output knobs")
}
