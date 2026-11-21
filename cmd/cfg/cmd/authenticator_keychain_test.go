// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

// These tests cover where `cfg authenticator create` puts the key with no
// --key-provider on Linux and macOS: the OS keychain when there is no TPM, a
// refusal when there is neither, and the encrypted file store only when named.
// The keychain is the in-memory SecretStore the session tests inject
// (authenticatorKeychainFn is the same kind of seam as sessionStoreFn); the
// real-backend assertion that the kernel keyring is never used lives in
// pkg/secrets/providers/oskeychain. The TPM-first selection runs against a
// software TPM in authenticator_tpm_linux_test.go.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

// useAuthenticatorKeychain makes cfg see store as the OS keychain.
func useAuthenticatorKeychain(t *testing.T, store interfaces.SecretStore) {
	t.Helper()
	orig := authenticatorKeychainFn
	authenticatorKeychainFn = func() (interfaces.SecretStore, error) { return store, nil }
	t.Cleanup(func() { authenticatorKeychainFn = orig })
}

// useHostOS makes cfg behave as it does on goos for the key-provider checks.
func useHostOS(t *testing.T, goos string) {
	t.Helper()
	orig := authenticatorHostOS
	authenticatorHostOS = goos
	t.Cleanup(func() { authenticatorHostOS = orig })
}

// useUnixDefaultSelection makes cfg choose the key store as it does on goos
// (linux or darwin) with no --key-provider, on any host: the platform user key
// that is the Windows default is reported as absent. Without it the no-flag
// create on Windows takes the CNG path, which these tests do not cover.
func useUnixDefaultSelection(t *testing.T, goos string) {
	t.Helper()
	useHostOS(t, goos)
	orig := authenticatorUserKeysSupportedFn
	authenticatorUserKeysSupportedFn = func() bool { return false }
	t.Cleanup(func() { authenticatorUserKeysSupportedFn = orig })
}

// runAuthenticatorSplit is runAuthenticator with stdout and stderr kept apart.
func runAuthenticatorSplit(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	c := newAuthenticatorCmd()
	var out, errOut bytes.Buffer
	c.SetOut(&out)
	c.SetErr(&errOut)
	c.SetIn(strings.NewReader(""))
	c.SetArgs(args)
	err = c.Execute()
	return out.String(), errOut.String(), err
}

// failingStore wraps a SecretStore and runs hook after each successful write.
type failingStore struct {
	interfaces.SecretStore
	afterStore func()
}

func (s *failingStore) StoreSecret(ctx context.Context, req *interfaces.SecretRequest) error {
	if err := s.SecretStore.StoreSecret(ctx, req); err != nil {
		return err
	}
	if s.afterStore != nil {
		s.afterStore()
	}
	return nil
}

// secretCount returns how many items the in-memory keychain holds.
func secretCount(s *testSessionStore) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.secrets)
}

// Required: with no TPM and an available keychain, create with no --key-provider
// writes the key to the keychain; the record holds no key bytes; login-style
// signing works from it; list shows keychain; delete removes the item.
func TestAuthenticatorCreate_DefaultsToKeychainWithoutTPM(t *testing.T) {
	useUnixDefaultSelection(t, "linux")
	useTPMOpener(t, noTPM)
	kc := newTestSessionStore()
	useAuthenticatorKeychain(t, kc)
	dir, store := authTestStore(t)

	out, err := runAuthenticator(t, "", "create", "agent-1", "--url", testAuthURL)
	require.NoError(t, err, out)
	assert.Contains(t, out, "Protection:    keychain")
	assert.Contains(t, out, "OS keychain")

	ctx := context.Background()
	rec, err := loadAuthenticatorRecord(ctx, store, "agent-1")
	require.NoError(t, err)
	assert.Equal(t, authenticatorProtectionKeychain, rec.Protection)
	assert.Empty(t, rec.KeyPKCS8, "the record holds no key bytes")
	assert.Equal(t, authenticatorKeychainKeyPrefix+base64.RawURLEncoding.EncodeToString(rec.CredentialID), rec.KeychainKey,
		"the item is named from the credential id, not the authenticator name")

	raw, err := store.Load(ctx, authenticatorCredentialName("agent-1"))
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "key_pkcs8")
	assert.Contains(t, string(raw), "keychain_key")

	// The key is in the keychain and nowhere in the credentials directory.
	item, err := kc.GetSecret(ctx, rec.KeychainKey)
	require.NoError(t, err)
	der, err := base64.StdEncoding.DecodeString(item.Value)
	require.NoError(t, err)
	require.NoError(t, filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		require.NoError(t, err)
		if fi.IsDir() {
			return nil
		}
		data, err := os.ReadFile(p)
		require.NoError(t, err)
		assert.False(t, bytes.Contains(data, der), "key bytes found in %s", fi.Name())
		assert.False(t, bytes.Contains(data, []byte(item.Value)), "encoded key found in %s", fi.Name())
		return nil
	}))
	assert.NotContains(t, out, item.Value)

	// Signing works from the keychain key: an assertion verifies under the record's key.
	signer, err := rec.signer()
	require.NoError(t, err)
	digest := sha256.Sum256([]byte("challenge"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)
	assert.True(t, ecdsa.VerifyASN1(signer.Public().(*ecdsa.PublicKey), digest[:], sig))
	assertAuthenticatorAsserts(t, rec)

	listed, err := runAuthenticator(t, "", "list")
	require.NoError(t, err)
	assert.Contains(t, listed, "keychain")
	assert.NotContains(t, listed, "file store")
	jsonOut, err := runAuthenticator(t, "", "list", "--json")
	require.NoError(t, err)
	var sums []authenticatorSummary
	require.NoError(t, json.Unmarshal([]byte(jsonOut), &sums))
	require.Len(t, sums, 1)
	assert.Equal(t, authenticatorProtectionKeychain, sums[0].Protection)

	out, err = runAuthenticator(t, "", "delete", "agent-1", "--force")
	require.NoError(t, err, out)
	assert.Zero(t, secretCount(kc), "delete removes the keychain item")
	assert.NoFileExists(t, filepath.Join(dir, "authenticator.agent-1.enc"))
}

// assertAuthenticatorAsserts runs a WebAuthn assertion through the record's authenticator.
func assertAuthenticatorAsserts(t *testing.T, rec *authenticatorRecord) {
	t.Helper()
	a, err := rec.authenticator()
	require.NoError(t, err)
	opts, err := json.Marshal(map[string]any{"publicKey": map[string]any{
		"challenge": "AAECAwQFBgcICQoLDA0ODw", "rpId": testAuthRPID,
	}})
	require.NoError(t, err)
	resp, err := a.Assert(opts)
	require.NoError(t, err)
	assert.Contains(t, string(resp), "signature")
}

// Two authenticators have two items; deleting one never touches the other's.
func TestAuthenticatorKeychain_ItemsAreIndependent(t *testing.T) {
	useUnixDefaultSelection(t, "linux")
	useTPMOpener(t, noTPM)
	kc := newTestSessionStore()
	useAuthenticatorKeychain(t, kc)
	authTestStore(t)

	for _, n := range []string{"a", "b"} {
		out, err := runAuthenticator(t, "", "create", n, "--url", testAuthURL)
		require.NoError(t, err, out)
	}
	require.Equal(t, 2, secretCount(kc))
	out, err := runAuthenticator(t, "", "delete", "a", "--force")
	require.NoError(t, err, out)
	assert.Equal(t, 1, secretCount(kc))

	out, err = runAuthenticator(t, "", "create", "a", "--url", testAuthURL)
	require.NoError(t, err, out)
	assert.Equal(t, 2, secretCount(kc), "re-creating the name makes a new item")
}

// Required: with no TPM and no keychain, create with no --key-provider exits
// non-zero, writes no record and no key, and names the ways forward.
func TestAuthenticatorCreate_RefusesWithNoTPMAndNoKeychain(t *testing.T) {
	useUnixDefaultSelection(t, "linux")
	useTPMOpener(t, noTPM)
	useAuthenticatorKeychain(t, nil)
	dir := filepath.Join(t.TempDir(), "creds")
	overrideCredentialsDir(t, dir)

	out, err := runAuthenticator(t, "", "create", "agent-1", "--url", testAuthURL)
	require.Error(t, err)
	msg := err.Error()
	assert.Contains(t, msg, "no TPM and no OS keychain")
	assert.Contains(t, msg, "Enable a TPM or virtual TPM")
	assert.Contains(t, msg, "Secret Service")
	assert.Contains(t, msg, "--key-provider store")
	assert.NotContains(t, out, `Authenticator "agent-1" created`)
	assert.NoDirExists(t, dir, "a refused create writes no record and opens no credential store")
}

// On macOS there is no TPM to suggest: the refusal names the Keychain and store.
func TestAuthenticatorCreate_RefusesOnMacOSWithoutKeychain(t *testing.T) {
	useUnixDefaultSelection(t, "darwin")
	useTPMOpener(t, func() (transport.TPMCloser, error) {
		t.Error("macOS has no TPM path; it must not be opened")
		return nil, errors.New("unreachable")
	})
	useAuthenticatorKeychain(t, nil)
	dir := filepath.Join(t.TempDir(), "creds")
	overrideCredentialsDir(t, dir)

	_, err := runAuthenticator(t, "", "create", "agent-1", "--url", testAuthURL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "macOS login Keychain")
	assert.Contains(t, err.Error(), "--key-provider store")
	assert.NoDirExists(t, dir)
}

// A keychain that cannot be opened, or whose write fails, refuses and never
// falls back to the file store.
func TestAuthenticatorCreate_KeychainFailureNeverFallsBackToFileStore(t *testing.T) {
	useUnixDefaultSelection(t, "linux")
	useTPMOpener(t, noTPM)

	t.Run("open fails", func(t *testing.T) {
		orig := authenticatorKeychainFn
		authenticatorKeychainFn = func() (interfaces.SecretStore, error) { return nil, errors.New("bus gone") }
		t.Cleanup(func() { authenticatorKeychainFn = orig })
		dir := filepath.Join(t.TempDir(), "creds")
		overrideCredentialsDir(t, dir)
		_, err := runAuthenticator(t, "", "create", "a", "--url", testAuthURL)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--key-provider store")
		assert.NoDirExists(t, dir)
	})

	t.Run("write fails", func(t *testing.T) {
		useAuthenticatorKeychain(t, writeFailStore{newTestSessionStore()})
		dir, store := authTestStore(t)
		_, err := runAuthenticator(t, "", "create", "a", "--url", testAuthURL)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--key-provider store")
		exists, err := authenticatorExists(context.Background(), store, "a")
		require.NoError(t, err)
		assert.False(t, exists, "no record is written when the key could not be")
		assert.NoFileExists(t, filepath.Join(dir, "authenticator.a.enc"))
	})
}

type writeFailStore struct{ *testSessionStore }

func (writeFailStore) StoreSecret(context.Context, *interfaces.SecretRequest) error {
	return errors.New("keychain is locked")
}

// A name that exists is refused before any keychain item is written.
func TestAuthenticatorCreate_KeychainExistingNameLeavesNoItem(t *testing.T) {
	useUnixDefaultSelection(t, "linux")
	useTPMOpener(t, noTPM)
	kc := newTestSessionStore()
	useAuthenticatorKeychain(t, kc)
	authTestStore(t)
	out, err := runAuthenticator(t, "", "create", "a", "--url", testAuthURL)
	require.NoError(t, err, out)
	require.Equal(t, 1, secretCount(kc))

	_, err = runAuthenticator(t, "", "create", "a", "--url", testAuthURL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
	assert.Equal(t, 1, secretCount(kc), "the refused create wrote no second item")
}

// Required: when the record cannot be saved after the item was written, the item is
// deleted again.
func TestAuthenticatorCreate_SaveFailureRemovesKeychainItem(t *testing.T) {
	useUnixDefaultSelection(t, "linux")
	useTPMOpener(t, noTPM)
	kc := newTestSessionStore()
	dir, _ := authTestStore(t)
	useAuthenticatorKeychain(t, &failingStore{SecretStore: kc, afterStore: func() {
		// A directory where the record file goes makes the rename of the record fail.
		require.NoError(t, os.Mkdir(filepath.Join(dir, "authenticator.a.enc"), 0o700))
	}})

	_, err := runAuthenticator(t, "", "create", "a", "--url", testAuthURL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to store authenticator")
	assert.Zero(t, secretCount(kc), "the rollback removes the keychain item")
}

// delete keeps the record when the item cannot be deleted, unless --force; a
// missing item is not an error.
func TestAuthenticatorDelete_KeychainItemHandling(t *testing.T) {
	useUnixDefaultSelection(t, "linux")
	useTPMOpener(t, noTPM)
	kc := newTestSessionStore()
	useAuthenticatorKeychain(t, kc)
	dir, _ := authTestStore(t)
	path := filepath.Join(dir, "authenticator.a.enc")
	out, err := runAuthenticator(t, "", "create", "a", "--url", testAuthURL)
	require.NoError(t, err, out)

	// Keychain unavailable now: the record is kept, --force deletes it with a warning.
	useAuthenticatorKeychain(t, nil)
	_, err = runAuthenticator(t, "y\n", "delete", "a")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--force")
	assert.FileExists(t, path)
	out, err = runAuthenticator(t, "", "delete", "a", "--force")
	require.NoError(t, err, out)
	assert.Contains(t, out, "Warning: the keychain item could not be deleted")
	assert.NoFileExists(t, path)
	assert.Equal(t, 1, secretCount(kc), "the item was left in the keychain")

	// An item that is already gone is not an error.
	useAuthenticatorKeychain(t, kc)
	out, err = runAuthenticator(t, "", "create", "b", "--url", testAuthURL)
	require.NoError(t, err, out)
	kc.mu.Lock()
	kc.secrets = map[string]string{}
	kc.mu.Unlock()
	out, err = runAuthenticator(t, "", "delete", "b", "--force")
	require.NoError(t, err, out)
	assert.NotContains(t, out, "Warning")
}

// Signing from a keychain record fails clearly when the item is gone or the
// keychain is unavailable, and never invents a key.
func TestAuthenticatorKeychainRecord_SigningFailures(t *testing.T) {
	useUnixDefaultSelection(t, "linux")
	useTPMOpener(t, noTPM)
	kc := newTestSessionStore()
	useAuthenticatorKeychain(t, kc)
	_, store := authTestStore(t)
	out, err := runAuthenticator(t, "", "create", "a", "--url", testAuthURL)
	require.NoError(t, err, out)
	rec, err := loadAuthenticatorRecord(context.Background(), store, "a")
	require.NoError(t, err)

	useAuthenticatorKeychain(t, nil)
	_, err = rec.signer()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not available")

	useAuthenticatorKeychain(t, newTestSessionStore())
	_, err = rec.signer()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing from the OS keychain")
	assert.Contains(t, err.Error(), "cfg authenticator delete a --force")

	bad := newTestSessionStore()
	require.NoError(t, bad.StoreSecret(context.Background(), &interfaces.SecretRequest{Key: rec.KeychainKey, Value: "!!not base64!!"}))
	useAuthenticatorKeychain(t, bad)
	_, err = rec.signer()
	require.Error(t, err)

	rec.KeychainKey = ""
	_, err = rec.signer()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "names no keychain item")
}

// Required: --key-provider store with no TPM and no keychain succeeds, warns on
// stderr about same-user recovery, and list labels the record as the file store;
// the key signs.
func TestAuthenticatorCreate_NamedFileStoreWarnsAndIsLabelled(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			useHostOS(t, goos)
			useTPMOpener(t, noTPM)
			useAuthenticatorKeychain(t, nil)
			_, store := authTestStore(t)

			stdout, stderr, err := runAuthenticatorSplit(t, "create", "agent-1", "--url", testAuthURL, "--key-provider", "store")
			require.NoError(t, err, stdout)
			assert.Contains(t, stderr, "Warning")
			assert.Contains(t, stderr, "any process running as your user can read")
			assert.Contains(t, stderr, "code running as your user can recover the key")
			assert.NotContains(t, stdout, "any process running as your user")
			assert.Contains(t, stdout, "Protection:    store")

			rec, err := loadAuthenticatorRecord(context.Background(), store, "agent-1")
			require.NoError(t, err)
			assert.Equal(t, authenticatorProtectionStore, rec.Protection)
			assert.NotEmpty(t, rec.KeyPKCS8)
			assertAuthenticatorAsserts(t, rec)

			listed, err := runAuthenticator(t, "", "list")
			require.NoError(t, err)
			assert.Contains(t, listed, "store (file store)")
			jsonOut, err := runAuthenticator(t, "", "list", "--json")
			require.NoError(t, err)
			var sums []authenticatorSummary
			require.NoError(t, json.Unmarshal([]byte(jsonOut), &sums))
			require.Len(t, sums, 1)
			assert.Equal(t, "store", sums[0].Protection, "the protection value stays store")
		})
	}
}

// The warning is for Linux and macOS only.
func TestAuthenticatorCreate_FileStoreWarningNotOnWindows(t *testing.T) {
	useHostOS(t, "windows")
	authTestStore(t)
	_, stderr, err := runAuthenticatorSplit(t, "create", "agent-1", "--url", testAuthURL, "--key-provider", "store")
	require.NoError(t, err)
	assert.Empty(t, stderr)
}

// Required: the old silent default is gone. With no flag the choice is the
// automatic selection on Linux and macOS, never store.
func TestResolveAuthenticatorKeyProvider_NoFlagIsNeverStoreOnLinuxOrMacOS(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		// The Windows default is covered by authenticator_keystore_windows_test.go.
		useUnixDefaultSelection(t, goos)
		c, err := resolveAuthenticatorKeyProvider("")
		require.NoError(t, err)
		assert.Equal(t, authenticatorKeyChoice{protection: authenticatorProtectionAuto}, c)
		assert.NotEqual(t, authenticatorProtectionStore, c.protection)
	}
}

// Required: a record written before this change (version 1, protection store)
// still signs, lists as the file store and deletes.
func TestAuthenticatorKeychain_VersionOneStoreRecordStillWorks(t *testing.T) {
	useAuthenticatorKeychain(t, nil)
	_, store := authTestStore(t)
	ctx := context.Background()

	old, err := newAuthenticatorRecord("old")
	require.NoError(t, err)
	old.RPID, old.Origin, old.ControllerURL = testAuthRPID, testAuthOrigin, testAuthURL
	raw, err := json.Marshal(map[string]any{
		"version": 1, "name": "old", "credential_id": old.CredentialID, "key_pkcs8": old.KeyPKCS8,
		"rp_id": testAuthRPID, "origin": testAuthOrigin, "controller_url": testAuthURL,
		"user_handle": []byte{}, "registered": false, "protection": "store",
	})
	require.NoError(t, err)
	require.NoError(t, store.Store(ctx, authenticatorCredentialName("old"), raw))

	rec, err := loadAuthenticatorRecord(ctx, store, "old")
	require.NoError(t, err)
	assertAuthenticatorAsserts(t, rec)

	listed, err := runAuthenticator(t, "", "list")
	require.NoError(t, err)
	assert.Contains(t, listed, "store (file store)")

	out, err := runAuthenticator(t, "", "delete", "old", "--force")
	require.NoError(t, err, out)
}

// A keychain record read by a cfg that predates the protection is refused through
// the existing unknown-protection error; the same check holds here for any
// protection this cfg does not know.
func TestAuthenticatorKeychain_ProtectionConstantsAreDistinct(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range []string{authenticatorProtectionStore, authenticatorProtectionPlatform,
		authenticatorProtectionTPM, authenticatorProtectionKeychain} {
		assert.False(t, seen[p], p)
		seen[p] = true
	}
	assert.Equal(t, authenticatorRecordVersion, 1, "a keychain record is still version 1")
}

// The real keychain opener hands out no store when only the Linux kernel session
// keyring remains (the provider's native_only option), so create refuses instead
// of writing an authenticator key that logout would lose.
func TestOpenAuthenticatorKeychain_NeverReturnsSessionKeyringStore(t *testing.T) {
	if runtime.GOOS != "linux" {
		return // other platforms have only their native store; nothing to exclude
	}
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "")
	store, err := openAuthenticatorKeychain()
	require.NoError(t, err)
	assert.Nil(t, store, "with no Secret Service the opener returns no store, not the kernel keyring")
}

// The authenticator command text describes the default order and the refusal.
func TestAuthenticatorHelp_DescribesDefaultOrderAndRefusal(t *testing.T) {
	var create *cobra.Command
	parent := newAuthenticatorCmd()
	for _, c := range parent.Commands() {
		if c.Name() == "create" {
			create = c
		}
	}
	require.NotNil(t, create)
	for name, text := range map[string]string{"authenticator": parent.Long, "create": create.Long} {
		assert.Contains(t, text, "OS keychain", name)
		assert.Contains(t, text, "never falls back", name)
		assert.Contains(t, text, "--key-provider store", name)
		assert.NotContains(t, text, "the default on other", name)
		assert.NotContains(t, text, "Elsewhere,\nor with --key-provider store", name)
	}
	flag := create.Flags().Lookup("key-provider")
	require.NotNil(t, flag)
	assert.NotContains(t, flag.Usage, "store elsewhere")
}
