// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"unsafe"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"

	"github.com/cfgis/cfgms/pkg/registration/identity"
)

// The checks below call ncrypt.dll directly rather than through the identity
// package, so they observe the key the way any other program on the host would.
var (
	testNCrypt                    = windows.NewLazySystemDLL("ncrypt.dll")
	testNCryptOpenStorageProvider = testNCrypt.NewProc("NCryptOpenStorageProvider")
	testNCryptOpenKey             = testNCrypt.NewProc("NCryptOpenKey")
	testNCryptExportKey           = testNCrypt.NewProc("NCryptExportKey")
	testNCryptFreeObject          = testNCrypt.NewProc("NCryptFreeObject")
)

const (
	testNCryptSilentFlag     = 0x00000040 // NCRYPT_SILENT_FLAG
	testNCryptMachineKeyFlag = 0x00000020 // NCRYPT_MACHINE_KEY_FLAG
	testNTEBadKeyset         = 0x80090016 // NTE_BAD_KEYSET
)

func testUTF16(t *testing.T, s string) *uint16 {
	t.Helper()
	p, err := windows.UTF16PtrFromString(s)
	require.NoError(t, err)
	return p
}

// openCNGKey opens keyName in provider with flags and returns the handle (0 on
// failure) and the SECURITY_STATUS. The caller frees a non-zero handle.
func openCNGKey(t *testing.T, provider, keyName string, flags uintptr) (prov, key uintptr, status uint32) {
	t.Helper()
	r, _, _ := testNCryptOpenStorageProvider.Call(uintptr(unsafe.Pointer(&prov)), uintptr(unsafe.Pointer(testUTF16(t, provider))), 0)
	require.Zero(t, uint32(r), "open %s", provider) //#nosec G115 -- SECURITY_STATUS is 32-bit
	r, _, _ = testNCryptOpenKey.Call(prov, uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(testUTF16(t, keyName))), 0, flags)
	return prov, key, uint32(r) //#nosec G115 -- SECURITY_STATUS is 32-bit
}

func freeCNG(handles ...uintptr) {
	for _, h := range handles {
		if h != 0 {
			_, _, _ = testNCryptFreeObject.Call(h)
		}
	}
}

// exportStatus tries to export key as blobType and returns the SECURITY_STATUS.
func exportStatus(t *testing.T, key uintptr, blobType string) uint32 {
	t.Helper()
	var n uint32
	r, _, _ := testNCryptExportKey.Call(key, 0, uintptr(unsafe.Pointer(testUTF16(t, blobType))), 0, 0, 0, uintptr(unsafe.Pointer(&n)), testNCryptSilentFlag)
	return uint32(r) //#nosec G115 -- SECURITY_STATUS is 32-bit
}

// createPlatformAuth runs create with no --key-provider and returns the stored
// record. The platform key is deleted when the test ends.
func createPlatformAuth(t *testing.T, store *CredentialStore, name string, extra ...string) (*authenticatorRecord, string) {
	t.Helper()
	out, err := runAuthenticator(t, "", append([]string{"create", name, "--url", testAuthURL}, extra...)...)
	require.NoError(t, err, out)
	rec, err := loadAuthenticatorRecord(context.Background(), store, name)
	require.NoError(t, err)
	if rec.Protection == authenticatorProtectionPlatform {
		t.Cleanup(func() { assert.NoError(t, identity.DeleteUserKey(rec.KeyProvider, rec.KeyName)) })
	}
	return rec, out
}

// withPlatformKeyUnavailable makes create's platform key step report what
// CreateUserKey reports on a host where no provider can hold a key.
func withPlatformKeyUnavailable(t *testing.T) {
	t.Helper()
	orig := createUserKey
	createUserKey = func() (*identity.UserKeySigner, error) {
		return nil, fmt.Errorf("%w: test host has no usable provider", identity.ErrUserKeyUnavailable)
	}
	t.Cleanup(func() { createUserKey = orig })
}

// With no --key-provider, a host with no usable platform provider falls back
// to the encrypted store and says so.
func TestAuthenticatorCreate_WindowsDefaultFallsBackToStore(t *testing.T) {
	withPlatformKeyUnavailable(t)
	_, store := authTestStore(t)
	out, err := runAuthenticator(t, "", "create", "agent-fb", "--url", testAuthURL)
	require.NoError(t, err, out)
	assert.Contains(t, out, "No platform key provider is available")
	assert.Contains(t, out, "Protection:    store")

	rec, err := loadAuthenticatorRecord(context.Background(), store, "agent-fb")
	require.NoError(t, err)
	assert.Equal(t, authenticatorProtectionStore, rec.Protection)
	assert.NotEmpty(t, rec.KeyPKCS8)
	assert.Empty(t, rec.KeyName)
	assert.Empty(t, rec.KeyProvider)
}

// An explicit --key-provider platform never falls back: create fails and
// stores nothing.
func TestAuthenticatorCreate_WindowsExplicitPlatformDoesNotFallBack(t *testing.T) {
	withPlatformKeyUnavailable(t)
	_, store := authTestStore(t)
	out, err := runAuthenticator(t, "", "create", "agent-nofb", "--url", testAuthURL, "--key-provider", "platform")
	require.Error(t, err, out)
	assert.True(t, errors.Is(err, identity.ErrUserKeyUnavailable), "got %v", err)

	exists, err := authenticatorExists(context.Background(), store, "agent-nofb")
	require.NoError(t, err)
	assert.False(t, exists, "no record is stored when the platform key cannot be made")
}

var platformProviders = []string{"Microsoft Platform Crypto Provider", "Microsoft Software Key Storage Provider"}

// On Windows, create defaults to a platform key; the record and list show it.
func TestAuthenticatorCreate_WindowsDefaultsToPlatformKey(t *testing.T) {
	_, store := authTestStore(t)
	rec, out := createPlatformAuth(t, store, "agent-1")

	assert.Equal(t, authenticatorProtectionPlatform, rec.Protection)
	assert.Contains(t, platformProviders, rec.KeyProvider)
	assert.NotEmpty(t, rec.KeyName)
	assert.Contains(t, out, "Protection:    platform")
	assert.Contains(t, out, rec.KeyProvider)
	t.Logf("platform key provider on this host: %s", rec.KeyProvider)

	listOut, err := runAuthenticator(t, "", "list")
	require.NoError(t, err)
	assert.Contains(t, listOut, "platform")
	jsonOut, err := runAuthenticator(t, "", "list", "--json")
	require.NoError(t, err)
	var summaries []authenticatorSummary
	require.NoError(t, json.Unmarshal([]byte(jsonOut), &summaries))
	require.Len(t, summaries, 1)
	assert.Equal(t, authenticatorProtectionPlatform, summaries[0].Protection)
	assert.Equal(t, rec.KeyProvider, summaries[0].KeyProvider, "list shows which provider holds the key")
	assert.Contains(t, listOut, rec.KeyProvider)
	if rec.KeyProvider == softwareKeyProviderName {
		assert.Contains(t, out, "the TPM could not hold the key")
	} else {
		assert.NotContains(t, out, "the TPM could not hold the key")
	}
}

// An explicit --key-provider store on Windows keeps the key in the credential store.
func TestAuthenticatorCreate_WindowsExplicitStore(t *testing.T) {
	_, store := authTestStore(t)
	rec, out := createPlatformAuth(t, store, "agent-1", "--key-provider", "store")
	assert.Equal(t, authenticatorProtectionStore, rec.Protection)
	assert.NotEmpty(t, rec.KeyPKCS8)
	assert.Empty(t, rec.KeyName)
	assert.Empty(t, rec.KeyProvider)
	assert.Contains(t, out, "Protection:    store")
}

// Required: a platform key signs, and a WebAuthn registration and assertion made
// with it verify in the real go-webauthn library.
func TestAuthenticatorPlatformKey_RegistrationAndAssertionVerify(t *testing.T) {
	_, store := authTestStore(t)
	createPlatformAuth(t, store, "agent-1", "--key-provider", "platform")
	rec, err := loadAuthenticatorRecord(context.Background(), store, "agent-1")
	require.NoError(t, err)
	require.Equal(t, authenticatorProtectionPlatform, rec.Protection)
	a, err := rec.authenticator()
	require.NoError(t, err)

	wa, err := webauthn.New(&webauthn.Config{
		RPID:          testAuthRPID,
		RPDisplayName: "CFGMS test",
		RPOrigins:     []string{testAuthOrigin},
	})
	require.NoError(t, err)
	user := &platformTestUser{}
	creation, regSession, err := wa.BeginRegistration(user,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			UserVerification:   protocol.VerificationRequired,
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: protocol.ResidentKeyRequired(),
		}))
	require.NoError(t, err)
	creationJSON, err := json.Marshal(creation)
	require.NoError(t, err)
	regResp, err := a.Register(creationJSON)
	require.NoError(t, err)
	cred, err := wa.FinishRegistration(user, *regSession, finishRequest(regResp))
	require.NoError(t, err)
	assert.Equal(t, rec.CredentialID, cred.ID)
	user.creds = []webauthn.Credential{*cred}

	// The registered public key is the platform key's public key.
	signer, err := rec.signer()
	require.NoError(t, err)
	assert.IsType(t, &identity.UserKeySigner{}, signer)

	assertion, loginSession, err := wa.BeginLogin(user, webauthn.WithUserVerification(protocol.VerificationRequired))
	require.NoError(t, err)
	assertionJSON, err := json.Marshal(assertion)
	require.NoError(t, err)
	loginResp, err := a.Assert(assertionJSON)
	require.NoError(t, err)
	got, err := wa.FinishLogin(user, *loginSession, finishRequest(loginResp))
	require.NoError(t, err)
	assert.Equal(t, rec.CredentialID, got.ID)
}

// Required: the key is a user key (created without the machine-key flag), its
// private key cannot be exported, and the stored record carries no key bytes.
func TestAuthenticatorPlatformKey_IsUserKeyAndNotExportable(t *testing.T) {
	_, store := authTestStore(t)
	rec, _ := createPlatformAuth(t, store, "agent-1", "--key-provider", "platform")
	require.Equal(t, authenticatorProtectionPlatform, rec.Protection)

	prov, key, status := openCNGKey(t, rec.KeyProvider, rec.KeyName, testNCryptSilentFlag)
	defer freeCNG(key, prov)
	require.Zero(t, status, "the key opens in the user key store")
	assert.Zero(t, exportStatus(t, key, "ECCPUBLICBLOB"), "the public key exports")
	for _, blob := range []string{"ECCPRIVATEBLOB", "PKCS8_PRIVATEKEY"} {
		assert.NotZero(t, exportStatus(t, key, blob), "%s export must fail (export policy none)", blob)
	}

	mprov, mkey, mstatus := openCNGKey(t, rec.KeyProvider, rec.KeyName, testNCryptSilentFlag|testNCryptMachineKeyFlag)
	defer freeCNG(mkey, mprov)
	assert.Equal(t, uint32(testNTEBadKeyset), mstatus, "the key must not be in the machine key store")

	raw, err := store.Load(context.Background(), authenticatorCredentialName("agent-1"))
	require.NoError(t, err)
	var fields map[string]any
	require.NoError(t, json.Unmarshal(raw, &fields))
	assert.NotContains(t, fields, "key_pkcs8", "a platform record holds no key bytes")
	assert.Empty(t, rec.KeyPKCS8)
	assert.False(t, bytes.Contains(raw, []byte("PRIVATE KEY")))
	assert.Equal(t, rec.KeyName, fields["key_name"])
	assert.Equal(t, rec.KeyProvider, fields["key_provider"])
}

// Required: delete removes the CNG key as well as the record.
func TestAuthenticatorDelete_RemovesPlatformKey(t *testing.T) {
	_, store := authTestStore(t)
	rec, _ := createPlatformAuth(t, store, "agent-1", "--key-provider", "platform")
	require.Equal(t, authenticatorProtectionPlatform, rec.Protection)

	out, err := runAuthenticator(t, "", "delete", "agent-1", "--force")
	require.NoError(t, err, out)

	prov, key, status := openCNGKey(t, rec.KeyProvider, rec.KeyName, testNCryptSilentFlag)
	defer freeCNG(key, prov)
	assert.Equal(t, uint32(testNTEBadKeyset), status, "the CNG key must be gone")
	exists, err := authenticatorExists(context.Background(), store, "agent-1")
	require.NoError(t, err)
	assert.False(t, exists)

	// The record is gone, so the key cannot be opened through cfg either.
	_, err = identity.OpenUserKey(rec.KeyProvider, rec.KeyName)
	require.Error(t, err)
}

func finishRequest(body []byte) *http.Request {
	return httptest.NewRequest(http.MethodPost, "/finish", bytes.NewReader(body))
}

type platformTestUser struct{ creds []webauthn.Credential }

func (u *platformTestUser) WebAuthnID() []byte                         { return []byte("user-handle-0123456789") }
func (u *platformTestUser) WebAuthnName() string                       { return "operator" }
func (u *platformTestUser) WebAuthnDisplayName() string                { return "Operator" }
func (u *platformTestUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }
