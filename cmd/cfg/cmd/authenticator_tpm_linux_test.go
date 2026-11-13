// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build linux && cgo

package cmd

// These tests drive a "tpm" authenticator through the CLI against a software TPM
// (pkg/softauthn/tpmkey/tpmkeytest) and the fake controllers of
// authenticator_enroll_test.go and webauthn_test.go, which check the TPM wire
// contract and run go-webauthn's real attestation verification. The parts that
// need no TPM are in the untagged test files and run on every OS.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/softauthn"
	"github.com/cfgis/cfgms/pkg/softauthn/tpmkey/tpmkeytest"
)

// startSimTPM starts a software TPM and makes cfg open it.
func startSimTPM(t *testing.T, opts tpmkeytest.Options) *tpmkeytest.TPM {
	t.Helper()
	sim := tpmkeytest.Start(t, opts)
	useTPMOpener(t, func() (transport.TPMCloser, error) { return sim, nil })
	return sim
}

// createTPMAuthenticator creates a "tpm" authenticator bound to es.
func createTPMAuthenticator(t *testing.T, es *enrollTestServer, name string) *CredentialStore {
	t.Helper()
	_, store := authTestStore(t)
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: es.srv.Certificate().Raw})
	require.NoError(t, os.WriteFile(caPath, caPEM, 0o600))
	out, err := runAuthenticator(t, "", "create", "--key-provider", "tpm", name, "--url", es.srv.URL,
		"--rp-id", testAuthRPID, "--origin", es.origin, "--ca-cert", caPath)
	require.NoError(t, err, out)
	return store
}

func TestAuthenticatorCreate_TPMKeyHoldsBlobsAndNoKeyBytes(t *testing.T) {
	startSimTPM(t, tpmkeytest.Options{})
	dir, store := authTestStore(t)

	out, err := runAuthenticator(t, "", "create", "agent-1", "--url", testAuthURL, "--key-provider", "tpm")
	require.NoError(t, err, out)
	assert.Contains(t, out, "Protection:    tpm")
	assert.Contains(t, out, "TPM-wrapped blobs")

	rec, err := loadAuthenticatorRecord(context.Background(), store, "agent-1")
	require.NoError(t, err)
	assert.Equal(t, authenticatorProtectionTPM, rec.Protection)
	assert.NotEmpty(t, rec.KeyPublicBlob)
	assert.NotEmpty(t, rec.KeyPrivateBlob)
	assert.Empty(t, rec.KeyPKCS8, "no key bytes are stored")

	raw, err := store.Load(context.Background(), authenticatorCredentialName("agent-1"))
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "key_pkcs8")
	assert.Contains(t, string(raw), "key_public_blob")
	assert.FileExists(t, filepath.Join(dir, "authenticator.agent-1.enc"))

	listed, err := runAuthenticator(t, "", "list")
	require.NoError(t, err)
	assert.Contains(t, listed, "tpm")

	// The TPM signs, and the signature verifies under the key in the record.
	signer, err := rec.signer()
	require.NoError(t, err)
	digest := sha256.Sum256([]byte("challenge"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)
	assert.True(t, ecdsa.VerifyASN1(signer.Public().(*ecdsa.PublicKey), digest[:], sig))

	// delete needs no TPM: the key is only wrapped blobs.
	useTPMOpener(t, noTPM)
	out, err = runAuthenticator(t, "", "delete", "agent-1", "--force")
	require.NoError(t, err, out)
	assert.NoFileExists(t, filepath.Join(dir, "authenticator.agent-1.enc"))
}

// A TPM with no EK certificate in NV is refused, and nothing is created.
func TestAuthenticatorCreate_TPMWithoutEKCertificateRefused(t *testing.T) {
	startSimTPM(t, tpmkeytest.Options{NoEKCertificate: true})
	dir := filepath.Join(t.TempDir(), "creds")
	overrideCredentialsDir(t, dir)

	_, err := runAuthenticator(t, "", "create", "agent-1", "--url", testAuthURL, "--key-provider", "tpm")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "endorsement key certificate")
	assert.Contains(t, err.Error(), "root agent account requires a key held in a TPM")
	assert.NoDirExists(t, dir)
}

// A name that already exists is refused, as for every provider.
func TestAuthenticatorCreate_TPMExistingNameRefused(t *testing.T) {
	startSimTPM(t, tpmkeytest.Options{})
	authTestStore(t)
	out, err := runAuthenticator(t, "", "create", "agent-1", "--url", testAuthURL, "--key-provider", "tpm")
	require.NoError(t, err, out)
	_, err = runAuthenticator(t, "", "create", "agent-1", "--url", testAuthURL, "--key-provider", "tpm")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

// Required: with a "tpm" record and a controller that requires a TPM, enroll sends the
// TPM begin body, handles the cfgmsTpm challenge and sends a TPM attestation; the
// controller's real verification accepts it.
func TestAuthenticatorEnroll_TPMRecordProvesTheKeyIsInTheTPM(t *testing.T) {
	sim := startSimTPM(t, tpmkeytest.Options{})
	es := newEnrollTestServer(t)
	es.tpm = &tpmPolicy{require: true, ca: sim.CA}
	store := createTPMAuthenticator(t, es, "agent-1")

	out, err := runEnroll(t, "", "agent-1", "--link-file", writeLinkFile(t, enrollLink(es)))
	require.NoError(t, err, out)

	rec, err := loadAuthenticatorRecord(context.Background(), store, "agent-1")
	require.NoError(t, err)
	assert.True(t, rec.Registered)

	bodies := es.tpm.beginBodies()
	require.Len(t, bodies, 1)
	var wire struct {
		TPM struct {
			EKCertChain []string `json:"ek_cert_chain"`
			AKPublic    string   `json:"ak_public"`
		} `json:"tpm"`
	}
	require.NoError(t, json.Unmarshal(bodies[0], &wire))
	require.Len(t, wire.TPM.EKCertChain, 1)
	assert.NotEmpty(t, wire.TPM.AKPublic)

	format, activation, secret, finishes := es.tpm.finishResult()
	assert.Equal(t, 1, finishes)
	assert.Equal(t, "tpm", format)
	require.NotEmpty(t, secret)
	assert.Equal(t, secret, activation, "cfgmsActivation is the secret the controller generated")

	es.mu.Lock()
	defer es.mu.Unlock()
	require.NotNil(t, es.registered, "the controller's real verification accepted the TPM attestation")
	assert.Equal(t, "tpm", es.registered.AttestationFormat)
	assert.Equal(t, softauthn.AAGUID[:], es.registered.Authenticator.AAGUID)
	assert.Equal(t, rec.CredentialID, es.registered.ID)
}

// A controller that sends no cfgmsTpm gets the begin body but registers with none.
func TestAuthenticatorEnroll_TPMRecordWithoutChallengeRegistersWithNone(t *testing.T) {
	sim := startSimTPM(t, tpmkeytest.Options{})
	es := newEnrollTestServer(t)
	es.tpm = &tpmPolicy{noChallenge: true, ca: sim.CA}
	store := createTPMAuthenticator(t, es, "agent-1")

	out, err := runEnroll(t, "", "agent-1", "--link-file", writeLinkFile(t, enrollLink(es)))
	require.NoError(t, err, out)

	assert.Len(t, es.tpm.beginBodies(), 1)
	assert.NotEmpty(t, es.tpm.beginBodies()[0], "a tpm record always offers its proof")
	format, activation, _, _ := es.tpm.finishResult()
	assert.Equal(t, "none", format)
	assert.Empty(t, activation)
	rec, err := loadAuthenticatorRecord(context.Background(), store, "agent-1")
	require.NoError(t, err)
	assert.True(t, rec.Registered)
}

// A TPM whose EK certificate has gone cannot offer a proof: refused before any request.
func TestAuthenticatorEnroll_TPMRecordOnTPMWithoutEKCertificateRefusedBeforeNetwork(t *testing.T) {
	sim := startSimTPM(t, tpmkeytest.Options{})
	es := newEnrollTestServer(t)
	es.tpm = &tpmPolicy{require: true, ca: sim.CA}
	store := createTPMAuthenticator(t, es, "agent-1")
	sim.UndefineEKCertificate(t)

	_, err := runEnroll(t, "", "agent-1", "--link-file", writeLinkFile(t, enrollLink(es)))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "endorsement key certificate")
	assert.Zero(t, es.requestCount(), "no request may reach the server")
	rec, err := loadAuthenticatorRecord(context.Background(), store, "agent-1")
	require.NoError(t, err)
	assert.False(t, rec.Registered)
}

// A challenge the TPM cannot open (made for another endorsement key) fails the
// registration without registering.
func TestAuthenticatorEnroll_TPMRecordRejectsChallengeForAnotherTPM(t *testing.T) {
	sim := startSimTPM(t, tpmkeytest.Options{})
	es := newEnrollTestServer(t)
	es.tpm = &tpmPolicy{require: true, ca: sim.CA}
	store := createTPMAuthenticator(t, es, "agent-1")

	// The controller makes its challenge for a different AK name.
	es.tpm.corruptChallenge = true

	_, err := runEnroll(t, "", "agent-1", "--link-file", writeLinkFile(t, enrollLink(es)))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not activate")
	rec, err := loadAuthenticatorRecord(context.Background(), store, "agent-1")
	require.NoError(t, err)
	assert.False(t, rec.Registered)
}

// Required: cfg webauthn register --authenticator does the same through the admin
// register routes.
func TestWebAuthnRegisterAuthenticator_TPMRecordProvesTheKeyIsInTheTPM(t *testing.T) {
	sim := startSimTPM(t, tpmkeytest.Options{})
	rs := newRegisterTestServer(t)
	rs.tpm = &tpmPolicy{require: true, ca: sim.CA}
	restore := saveWebAuthnFlags(t)
	defer restore()
	_, store := authTestStore(t)
	out, err := runAuthenticator(t, "", "create", "agent-1", "--url", testAuthURL, "--key-provider", "tpm")
	require.NoError(t, err, out)

	bundlePath = writeBundleFile(t, generateWebAuthnBundle(t), rs.srv.URL)
	webAuthnUsername = "alice"
	webAuthnAuthenticator = "agent-1"
	webAuthnLabel = ""
	var buf bytes.Buffer
	webAuthnRegisterCmd.SetOut(&buf)
	t.Cleanup(func() { webAuthnRegisterCmd.SetOut(nil) })

	require.NoError(t, runWebAuthnRegister(webAuthnRegisterCmd, nil))

	rec, err := loadAuthenticatorRecord(context.Background(), store, "agent-1")
	require.NoError(t, err)
	assert.True(t, rec.Registered)

	bodies := rs.tpm.beginBodies()
	require.Len(t, bodies, 1)
	assert.Contains(t, string(bodies[0]), `"ek_cert_chain"`)
	assert.Contains(t, string(bodies[0]), `"ak_public"`)
	format, activation, secret, _ := rs.tpm.finishResult()
	assert.Equal(t, "tpm", format)
	assert.Equal(t, secret, activation)

	rs.mu.Lock()
	defer rs.mu.Unlock()
	require.NotNil(t, rs.registered)
	assert.Equal(t, "tpm", rs.registered.AttestationFormat)
	assert.Equal(t, softauthn.AAGUID[:], rs.registered.Authenticator.AAGUID)
}

// A registered tpm authenticator signs later assertions through the TPM.
func TestTPMAuthenticatorSignsAssertions(t *testing.T) {
	startSimTPM(t, tpmkeytest.Options{})
	_, store := authTestStore(t)
	out, err := runAuthenticator(t, "", "create", "agent-1", "--url", testAuthURL, "--key-provider", "tpm")
	require.NoError(t, err, out)
	rec, err := loadAuthenticatorRecord(context.Background(), store, "agent-1")
	require.NoError(t, err)

	auth, err := rec.authenticator()
	require.NoError(t, err)
	opts, err := json.Marshal(map[string]any{"publicKey": map[string]any{
		"challenge": "AAECAwQFBgcICQoLDA0ODw", "rpId": testAuthRPID,
	}})
	require.NoError(t, err)
	resp, err := auth.Assert(opts)
	require.NoError(t, err)

	var parsed struct {
		Response struct {
			ClientDataJSON    string `json:"clientDataJSON"`
			AuthenticatorData string `json:"authenticatorData"`
			Signature         string `json:"signature"`
		} `json:"response"`
	}
	require.NoError(t, json.Unmarshal(resp, &parsed))
	clientData, err := base64.RawURLEncoding.DecodeString(parsed.Response.ClientDataJSON)
	require.NoError(t, err)
	authData, err := base64.RawURLEncoding.DecodeString(parsed.Response.AuthenticatorData)
	require.NoError(t, err)
	sig, err := base64.RawURLEncoding.DecodeString(parsed.Response.Signature)
	require.NoError(t, err)

	cdHash := sha256.Sum256(clientData)
	signed := sha256.Sum256(append(append([]byte(nil), authData...), cdHash[:]...))
	signer, err := rec.signer()
	require.NoError(t, err)
	assert.True(t, ecdsa.VerifyASN1(signer.Public().(*ecdsa.PublicKey), signed[:], sig),
		"the assertion was signed by the TPM key in the record")
}
