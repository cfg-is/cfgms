// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/fs"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/registration/identity"
	"github.com/cfgis/cfgms/pkg/softauthn"
)

const (
	testAuthURL    = "https://controller.example.test"
	testAuthRPID   = "controller.example.test"
	testAuthOrigin = "https://controller.example.test"
)

// runAuthenticator executes `authenticator <args...>` on a fresh command tree and
// returns its combined output.
func runAuthenticator(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	c := newAuthenticatorCmd()
	var out bytes.Buffer
	c.SetOut(&out)
	c.SetErr(&out)
	c.SetIn(strings.NewReader(stdin))
	c.SetArgs(args)
	err := c.Execute()
	return out.String(), err
}

// authTestStore points the credential store at a fresh directory and returns the
// directory and an opened store.
func authTestStore(t *testing.T) (string, *CredentialStore) {
	t.Helper()
	dir := t.TempDir()
	overrideCredentialsDir(t, dir)
	store, err := newCredentialStore()
	require.NoError(t, err)
	return dir, store
}

func createAuth(t *testing.T, name string, extra ...string) string {
	t.Helper()
	args := []string{"create", name, "--url", testAuthURL}
	if !hasFlag(extra, "--key-provider") {
		// These tests inspect the store-held key; platform keys have their own tests.
		args = append(args, "--key-provider", "store")
	}
	out, err := runAuthenticator(t, "", append(args, extra...)...)
	require.NoError(t, err, out)
	return out
}

// storedKeyMaterial returns the PKCS#8 DER and the raw private scalar of a stored authenticator.
func storedKeyMaterial(t *testing.T, store *CredentialStore, name string) (der, scalar []byte) {
	t.Helper()
	rec, err := loadAuthenticatorRecord(context.Background(), store, name)
	require.NoError(t, err)
	key, err := x509.ParsePKCS8PrivateKey(rec.KeyPKCS8)
	require.NoError(t, err)
	return rec.KeyPKCS8, key.(*ecdsa.PrivateKey).D.FillBytes(make([]byte, 32))
}

func TestAuthenticatorCommandsRegisteredOnRoot(t *testing.T) {
	var found bool
	for _, c := range rootCmd.Commands() {
		if c.Name() == "authenticator" {
			found = true
		}
	}
	require.True(t, found, "authenticator must be registered on the root command")

	verbs := map[string]bool{}
	for _, c := range authenticatorCmd.Commands() {
		verbs[c.Name()] = true
	}
	assert.Equal(t, map[string]bool{"create": true, "list": true, "delete": true, "enroll": true}, verbs)
}

// Required: after create the credentials directory holds authenticator.<name>.enc and
// no file in it contains the PKCS#8 PEM header or the key bytes.
func TestAuthenticatorCreate_KeyOnlyInEncryptedStore(t *testing.T) {
	dir, store := authTestStore(t)
	createAuth(t, "agent-1")

	_, err := os.Stat(filepath.Join(dir, "authenticator.agent-1.enc"))
	require.NoError(t, err)

	der, scalar := storedKeyMaterial(t, store, "agent-1")
	needles := map[string][]byte{
		"PEM header":         []byte("-----BEGIN"),
		"PRIVATE KEY":        []byte("PRIVATE KEY"),
		"PKCS#8 DER":         der,
		"raw scalar":         scalar,
		"base64 DER":         []byte(base64.StdEncoding.EncodeToString(der)),
		"base64url DER":      []byte(base64.URLEncoding.EncodeToString(der)),
		"base64 scalar":      []byte(base64.StdEncoding.EncodeToString(scalar)),
		"key_pkcs8 JSON key": []byte("key_pkcs8"),
	}
	var files int
	require.NoError(t, filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		require.NoError(t, err)
		if d.IsDir() {
			return nil
		}
		files++
		raw, err := os.ReadFile(p)
		require.NoError(t, err)
		for what, n := range needles {
			assert.False(t, bytes.Contains(raw, n), "%s found in %s", what, d.Name())
		}
		return nil
	}))
	assert.GreaterOrEqual(t, files, 2, "expected the credential and the salt to have been scanned")
}

// Required: http:// refuses before any file is written, and no flag disables TLS verification
// or exports a key.
func TestAuthenticatorCreate_RefusesHTTPBeforeWritingAnything(t *testing.T) {
	cases := map[string][]string{
		"http url":    {"create", "a", "--url", "http://controller.example.test"},
		"http origin": {"create", "a", "--url", testAuthURL, "--origin", "http://controller.example.test"},
		"no scheme":   {"create", "a", "--url", "controller.example.test"},
		"userinfo":    {"create", "a", "--url", "https://user:pw@controller.example.test"},
		"missing url": {"create", "a"},
		"bad rp id":   {"create", "a", "--url", testAuthURL, "--rp-id", "other.example.test"},
		"origin path": {"create", "a", "--url", testAuthURL, "--origin", "https://controller.example.test/x"},
		"missing ca":  {"create", "a", "--url", testAuthURL, "--ca-cert", filepath.Join(t.TempDir(), "nope.pem")},
		"bad name":    {"create", "a/b", "--url", testAuthURL},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			overrideCredentialsDir(t, dir)
			_, err := runAuthenticator(t, "", args...)
			require.Error(t, err)
			entries, rerr := os.ReadDir(dir)
			require.NoError(t, rerr)
			assert.Empty(t, entries, "a refused create must write nothing")
		})
	}
}

func TestAuthenticatorCreate_HTTPErrorSaysHTTPS(t *testing.T) {
	overrideCredentialsDir(t, t.TempDir())
	_, err := runAuthenticator(t, "", "create", "a", "--url", "http://controller.example.test")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "https")
}

func TestAuthenticatorCreate_NoTLSSkipOrKeyExportFlag(t *testing.T) {
	c := newAuthenticatorCmd()
	create, _, err := c.Find([]string{"create"})
	require.NoError(t, err)

	var help bytes.Buffer
	create.SetOut(&help)
	require.NoError(t, create.Help())

	forbidden := []string{"plaintext", "export", "insecure", "skip", "no-verify", "key-out", "private-key", "cleartext"}
	text := strings.ToLower(help.String())
	create.Flags().VisitAll(func(f *pflag.Flag) {
		for _, w := range forbidden {
			assert.NotContains(t, strings.ToLower(f.Name), w, "flag --%s", f.Name)
		}
	})
	for _, w := range forbidden {
		assert.NotContains(t, text, w, "create --help must not mention %q", w)
	}
	assert.Nil(t, create.Flags().Lookup("tls-insecure"))

	// Passing one anyway is an unknown flag, and the environment cannot enable it.
	t.Setenv("CFGMS_TLS_INSECURE", "true")
	overrideCredentialsDir(t, t.TempDir())
	_, err = runAuthenticator(t, "", "create", "a", "--url", testAuthURL, "--export-plaintext-key")
	require.Error(t, err)
	_, err = runAuthenticator(t, "", "create", "a", "--url", testAuthURL, "--tls-insecure")
	require.Error(t, err)
}

// Required: the record has no AAGUID field, and a registration made from a stored
// record carries softauthn.AAGUID.
func TestAuthenticatorRecord_NoAAGUIDAndRegistrationCarriesCFGMSAAGUID(t *testing.T) {
	_, store := authTestStore(t)
	t.Setenv("CFGMS_AAGUID", "00000000-0000-0000-0000-000000000001")
	createAuth(t, "agent-1")
	ctx := context.Background()

	raw, err := store.Load(ctx, "authenticator.agent-1")
	require.NoError(t, err)
	var fields map[string]any
	require.NoError(t, json.Unmarshal(raw, &fields))
	for k := range fields {
		assert.NotContains(t, strings.ToLower(k), "aaguid", "record field %q", k)
	}
	assert.Equal(t, float64(authenticatorRecordVersion), fields["version"])
	assert.Equal(t, "store", fields["protection"])
	assert.Equal(t, false, fields["registered"])

	rec, err := loadAuthenticatorRecord(ctx, store, "agent-1")
	require.NoError(t, err)
	a, err := rec.authenticator()
	require.NoError(t, err)

	wa, err := webauthn.New(&webauthn.Config{
		RPID:          testAuthRPID,
		RPDisplayName: "CFGMS test",
		RPOrigins:     []string{testAuthOrigin},
	})
	require.NoError(t, err)
	user := &authTestUser{}
	creation, session, err := wa.BeginRegistration(user,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			UserVerification:   protocol.VerificationRequired,
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: protocol.ResidentKeyRequired(),
		}))
	require.NoError(t, err)
	opts, err := json.Marshal(creation)
	require.NoError(t, err)

	resp, err := a.Register(opts)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/finish", bytes.NewReader(resp))
	cred, err := wa.FinishRegistration(user, *session, req)
	require.NoError(t, err)

	assert.Equal(t, softauthn.AAGUID[:], cred.Authenticator.AAGUID)
	assert.Equal(t, rec.CredentialID, cred.ID)
}

// The AAGUID is not configurable from this package: it never sets softauthn.Config.AAGUID.
func TestAuthenticatorSources_NeverSetAAGUID(t *testing.T) {
	for _, f := range []string{"authenticator.go", "authenticator_store.go"} {
		src, err := os.ReadFile(f)
		require.NoError(t, err)
		// Code lines only: comments may mention the AAGUID.
		assert.NotRegexp(t, regexp.MustCompile(`(?m)^[^/\n]*\bAAGUID\s*[:=]`), string(src), f)
	}
}

type authTestUser struct{}

func (u *authTestUser) WebAuthnID() []byte                         { return []byte("user-handle-0123456789") }
func (u *authTestUser) WebAuthnName() string                       { return "operator" }
func (u *authTestUser) WebAuthnDisplayName() string                { return "Operator" }
func (u *authTestUser) WebAuthnCredentials() []webauthn.Credential { return nil }

// Required: list and list --json never contain key material, and create output never prints it.
func TestAuthenticator_OutputNeverContainsKeyMaterial(t *testing.T) {
	_, store := authTestStore(t)
	createOut := createAuth(t, "agent-1", "--label", "ci agent")
	createAuth(t, "agent-2")
	listOut, err := runAuthenticator(t, "", "list")
	require.NoError(t, err)
	jsonOut, err := runAuthenticator(t, "", "list", "--json")
	require.NoError(t, err)

	for _, name := range []string{"agent-1", "agent-2"} {
		der, scalar := storedKeyMaterial(t, store, name)
		for label, out := range map[string]string{"create": createOut, "list": listOut, "list --json": jsonOut} {
			for what, n := range map[string][]byte{
				"DER": der, "scalar": scalar,
				"base64 DER":    []byte(base64.StdEncoding.EncodeToString(der)),
				"base64url DER": []byte(base64.RawURLEncoding.EncodeToString(der)),
				"hex scalar":    []byte(strings.ToLower(hexOf(scalar))),
			} {
				assert.NotContains(t, out, string(n), "%s: %s of %s", label, what, name)
			}
			assert.NotContains(t, out, "PRIVATE KEY", label)
			assert.NotContains(t, out, "key_pkcs8", label)
		}
	}
	assert.Contains(t, createOut, "authenticator.agent-1")
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	var sb strings.Builder
	for _, x := range b {
		sb.WriteByte(digits[x>>4])
		sb.WriteByte(digits[x&0xf])
	}
	return sb.String()
}

func TestAuthenticatorList_ShowsFieldsAndJSON(t *testing.T) {
	_, store := authTestStore(t)

	emptyOut, err := runAuthenticator(t, "", "list")
	require.NoError(t, err)
	assert.Contains(t, emptyOut, "No software authenticators")
	emptyJSON, err := runAuthenticator(t, "", "list", "--json")
	require.NoError(t, err)
	assert.Equal(t, "[]", strings.TrimSpace(emptyJSON))

	createAuth(t, "b-agent", "--label", "second")
	createAuth(t, "a-agent", "--origin", "https://controller.example.test:8443")
	rec, err := loadAuthenticatorRecord(context.Background(), store, "a-agent")
	require.NoError(t, err)
	wantID := base64.RawURLEncoding.EncodeToString(rec.CredentialID)

	out, err := runAuthenticator(t, "", "list")
	require.NoError(t, err)
	for _, want := range []string{"NAME", "RP ID", "ORIGIN", "CREDENTIAL ID", "REGISTERED", "PROTECTION",
		"a-agent", "b-agent", testAuthRPID, "https://controller.example.test:8443", wantID, "false", "store"} {
		assert.Contains(t, out, want)
	}
	assert.Less(t, strings.Index(out, "a-agent"), strings.Index(out, "b-agent"), "sorted by name")

	jsonOut, err := runAuthenticator(t, "", "list", "--json")
	require.NoError(t, err)
	var got []authenticatorSummary
	require.NoError(t, json.Unmarshal([]byte(jsonOut), &got))
	require.Len(t, got, 2)
	assert.Equal(t, "a-agent", got[0].Name)
	assert.Equal(t, wantID, got[0].CredentialID)
	assert.Equal(t, "https://controller.example.test:8443", got[0].Origin)
	assert.Equal(t, "store", got[0].Protection)
	assert.False(t, got[0].Registered)
	assert.Equal(t, "second", got[1].Label)
}

func TestAuthenticatorCreate_DefaultsAndOverrides(t *testing.T) {
	_, store := authTestStore(t)
	ctx := context.Background()

	createAuth(t, "def")
	def, err := loadAuthenticatorRecord(ctx, store, "def")
	require.NoError(t, err)
	assert.Equal(t, testAuthRPID, def.RPID)
	assert.Equal(t, testAuthOrigin, def.Origin)
	assert.Equal(t, testAuthURL, def.ControllerURL)
	assert.Equal(t, authenticatorRecordVersion, def.Version)
	assert.Len(t, def.CredentialID, authenticatorCredentialIDLen)
	assert.Empty(t, def.UserHandle)
	assert.False(t, def.Registered)
	assert.Empty(t, def.CACertPEM)

	out, err := runAuthenticator(t, "", "create", "port", "--url", "https://controller.example.test:8443/", "--key-provider", "store")
	require.NoError(t, err, out)
	port, err := loadAuthenticatorRecord(ctx, store, "port")
	require.NoError(t, err)
	assert.Equal(t, testAuthRPID, port.RPID, "RP ID has no port")
	assert.Equal(t, "https://controller.example.test:8443", port.Origin)
	assert.Equal(t, "https://controller.example.test:8443", port.ControllerURL)

	out, err = runAuthenticator(t, "", "create", "ov", "--url", "https://10.0.0.5:8443", "--key-provider", "store",
		"--rp-id", "controller.example.test", "--origin", "https://sub.controller.example.test")
	require.NoError(t, err, out)
	ov, err := loadAuthenticatorRecord(ctx, store, "ov")
	require.NoError(t, err)
	assert.Equal(t, "controller.example.test", ov.RPID)
	assert.Equal(t, "https://sub.controller.example.test", ov.Origin)

	// Two authenticators never share a key or credential ID.
	assert.NotEqual(t, def.KeyPKCS8, port.KeyPKCS8)
	assert.NotEqual(t, def.CredentialID, port.CredentialID)
}

func TestAuthenticatorCreate_PinsCACert(t *testing.T) {
	_, store := authTestStore(t)
	ctx := context.Background()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(caFile, caPEM, 0o600))

	createAuth(t, "pinned", "--ca-cert", caFile)
	rec, err := loadAuthenticatorRecord(ctx, store, "pinned")
	require.NoError(t, err)
	assert.Equal(t, string(caPEM), rec.CACertPEM)

	notCert := filepath.Join(t.TempDir(), "junk.pem")
	require.NoError(t, os.WriteFile(notCert, []byte("not a certificate"), 0o600))
	_, err = runAuthenticator(t, "", "create", "junk", "--url", testAuthURL, "--ca-cert", notCert)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no PEM certificate")
	ok, err := store.Exists(ctx, "authenticator.junk")
	require.NoError(t, err)
	assert.False(t, ok)
}

// Required: create with an existing name fails and leaves the original byte-identical.
func TestAuthenticatorCreate_ExistingNameRefusedAndUntouched(t *testing.T) {
	dir, _ := authTestStore(t)
	createAuth(t, "agent-1")
	path := filepath.Join(dir, "authenticator.agent-1.enc")
	before, err := os.ReadFile(path)
	require.NoError(t, err)

	out, err := runAuthenticator(t, "", "create", "agent-1", "--url", "https://other.example.test")
	require.Error(t, err, out)
	assert.Contains(t, err.Error(), "already exists")

	after, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, before, after, "the original record must be byte-identical")
}

// Required: an unknown version makes list and later loads fail naming the version and the remedy.
func TestAuthenticator_UnknownVersionFailsWithRemedy(t *testing.T) {
	_, store := authTestStore(t)
	ctx := context.Background()
	for _, doc := range map[string]string{
		"future": `{"version":2,"name":"old"}`,
		"none":   `{"name":"old"}`,
	} {
		require.NoError(t, store.Store(ctx, "authenticator.old", []byte(doc)))

		_, err := runAuthenticator(t, "", "list")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "version")
		assert.Contains(t, err.Error(), "cfg authenticator delete old")
		assert.Contains(t, err.Error(), "create it again")

		_, err = runAuthenticator(t, "", "list", "--json")
		require.Error(t, err)

		_, err = loadAuthenticatorRecord(ctx, store, "old")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "version")
	}

	require.NoError(t, store.Store(ctx, "authenticator.old", []byte(`{"version":7,"name":"old"}`)))
	_, err := loadAuthenticatorRecord(ctx, store, "old")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "version 7")

	// The remedy works: an unreadable record can still be deleted.
	_, err = runAuthenticator(t, "", "delete", "old", "--force")
	require.NoError(t, err)
	out, err := runAuthenticator(t, "", "list")
	require.NoError(t, err)
	assert.Contains(t, out, "No software authenticators")
}

func TestAuthenticator_CorruptRecordFailsWithRemedy(t *testing.T) {
	_, store := authTestStore(t)
	ctx := context.Background()
	require.NoError(t, store.Store(ctx, "authenticator.bad", []byte("not json")))
	_, err := runAuthenticator(t, "", "list")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cfg authenticator delete bad")

	require.NoError(t, store.Store(ctx, "authenticator.bad", []byte(`{"version":1,"name":"other"}`)))
	_, err = loadAuthenticatorRecord(ctx, store, "bad")
	require.Error(t, err)
}

func TestAuthenticatorRecord_RejectsUnusableKey(t *testing.T) {
	rec, err := newAuthenticatorRecord("x")
	require.NoError(t, err)
	rec.RPID, rec.Origin = testAuthRPID, testAuthOrigin

	rec.KeyPKCS8 = []byte("garbage")
	_, err = rec.authenticator()
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "garbage")

	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	rec.KeyPKCS8, err = x509.MarshalPKCS8PrivateKey(p384)
	require.NoError(t, err)
	_, err = rec.authenticator()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "P-256")
}

// Required: delete --force removes the file; delete of a missing name errors; path
// separators are rejected.
func TestAuthenticatorDelete(t *testing.T) {
	dir, _ := authTestStore(t)
	createAuth(t, "agent-1")
	createAuth(t, "agent-2")
	path := filepath.Join(dir, "authenticator.agent-1.enc")
	require.FileExists(t, path)

	out, err := runAuthenticator(t, "", "delete", "agent-1", "--force")
	require.NoError(t, err, out)
	assert.NoFileExists(t, path)
	assert.FileExists(t, filepath.Join(dir, "authenticator.agent-2.enc"))
	assert.Contains(t, out, "still lists")
	assert.Contains(t, out, "cfg webauthn revoke")

	_, err = runAuthenticator(t, "", "delete", "agent-1", "--force")
	require.Error(t, err)
	assert.ErrorIs(t, err, errAuthenticatorNotFound)

	for _, bad := range []string{"../agent-2", "a/b", `a\b`, "..", "", ".hidden", "x y"} {
		_, err = runAuthenticator(t, "", "delete", bad, "--force")
		require.Error(t, err, "name %q", bad)
		_, err = runAuthenticator(t, "", "create", bad, "--url", testAuthURL)
		require.Error(t, err, "name %q", bad)
	}
	assert.FileExists(t, filepath.Join(dir, "authenticator.agent-2.enc"))
}

// A platform record whose key cannot be deleted (here a reference CreateUserKey
// never makes, as a hand-edited record would hold) keeps the record unless
// --force is given; --force deletes the record and warns.
func TestAuthenticatorDelete_UndeletablePlatformKeyNeedsForce(t *testing.T) {
	dir, store := authTestStore(t)
	createAuth(t, "agent-1")
	path := filepath.Join(dir, "authenticator.agent-1.enc")
	ctx := context.Background()
	rec, err := loadAuthenticatorRecord(ctx, store, "agent-1")
	require.NoError(t, err)
	rec.Protection = authenticatorProtectionPlatform
	rec.KeyPKCS8, rec.KeyProvider, rec.KeyName = nil, "Microsoft Software Key Storage Provider", "cfgms-device-key-0"
	require.NoError(t, saveAuthenticatorRecord(ctx, store, rec))

	out, err := runAuthenticator(t, "y\n", "delete", "agent-1")
	require.Error(t, err, out)
	assert.Contains(t, err.Error(), "--force")
	assert.FileExists(t, path, "the record that locates the key is kept")

	out, err = runAuthenticator(t, "", "delete", "agent-1", "--force")
	require.NoError(t, err, out)
	assert.Contains(t, out, "Warning: the platform key could not be deleted")
	assert.NoFileExists(t, path)
}

func TestAuthenticatorDelete_PromptsWithoutForce(t *testing.T) {
	dir, _ := authTestStore(t)
	createAuth(t, "agent-1")
	path := filepath.Join(dir, "authenticator.agent-1.enc")

	out, err := runAuthenticator(t, "n\n", "delete", "agent-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "aborted")
	assert.Contains(t, out, "[y/N]")
	assert.FileExists(t, path)

	out, err = runAuthenticator(t, "y\n", "delete", "agent-1")
	require.NoError(t, err, out)
	assert.NoFileExists(t, path)
}

func TestAuthenticatorDelete_MissingNameDoesNotPrompt(t *testing.T) {
	authTestStore(t)
	out, err := runAuthenticator(t, "y\n", "delete", "ghost")
	require.Error(t, err)
	assert.NotContains(t, out, "[y/N]")
}

// hasFlag reports whether args contains flag, as "--flag value" or "--flag=value".
func hasFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag || strings.HasPrefix(a, flag+"=") {
			return true
		}
	}
	return false
}

// An unknown --key-provider is refused before anything is written.
func TestAuthenticatorCreate_UnknownKeyProviderRefusedBeforeWriting(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "creds")
	overrideCredentialsDir(t, dir)
	_, err := runAuthenticator(t, "", "create", "a", "--url", testAuthURL, "--key-provider", "hsm")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--key-provider")
	assert.NoDirExists(t, dir, "a refused create must not create the credentials directory")
}

// Where the OS has no platform user keys, the default is the credential store and
// --key-provider platform is refused, before anything is written, with an error
// that names the OS and the alternative. Windows behaviour is covered by
// authenticator_keystore_windows_test.go.
func TestAuthenticatorCreate_KeyProviderWithoutPlatformSupport(t *testing.T) {
	if identity.UserKeysSupported() {
		t.Skip("this OS supports platform user keys; see authenticator_keystore_windows_test.go")
	}
	dir := filepath.Join(t.TempDir(), "creds")
	overrideCredentialsDir(t, dir)
	_, err := runAuthenticator(t, "", "create", "a", "--url", testAuthURL, "--key-provider", "platform")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not supported on "+runtime.GOOS)
	assert.Contains(t, err.Error(), "--key-provider store")
	assert.NoDirExists(t, dir, "a refused create must not create the credentials directory")

	out, err := runAuthenticator(t, "", "create", "b", "--url", testAuthURL)
	require.NoError(t, err, out)
	store, err := newCredentialStore()
	require.NoError(t, err)
	rec, err := loadAuthenticatorRecord(context.Background(), store, "b")
	require.NoError(t, err)
	assert.Equal(t, authenticatorProtectionStore, rec.Protection, "the default elsewhere is the credential store")
	assert.NotEmpty(t, rec.KeyPKCS8)
	assert.Empty(t, rec.KeyName)
	assert.Contains(t, out, "Protection:    store")
}

// A record whose protection is not one this cfg knows is refused with the remedy.
func TestAuthenticatorRecord_UnknownProtectionRefused(t *testing.T) {
	rec, err := newAuthenticatorRecord("x")
	require.NoError(t, err)
	rec.RPID, rec.Origin = testAuthRPID, testAuthOrigin
	rec.Protection = "hsm"
	_, err = rec.authenticator()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown protection")
	assert.Contains(t, err.Error(), "cfg authenticator delete x --force")
}

// cfg never reaches the identity package's device-key paths (Open, the file key
// store and its ed25519 fallback): it uses only the user-key signer.
func TestAuthenticatorSources_DoNotUseDeviceIdentityKeyStore(t *testing.T) {
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	forbidden := regexp.MustCompile(`identity\.(Open|NewFileKeyStore\w*|RemoveAllStoredKeys|RemoveStoredKey|StoredKeyFileName|AlgorithmEd25519)\b`)
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		require.NoError(t, err)
		assert.NotRegexp(t, forbidden, string(src), f)
	}
}

// --key-provider tpm on a host whose TPM cannot be opened is refused with a message
// that names the requirement, and creates no record and no file.
func TestAuthenticatorCreate_TPMProviderRefusedWithoutUsableTPM(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "creds")
	overrideCredentialsDir(t, dir)
	useTPMOpener(t, noTPM)

	out, err := runAuthenticator(t, "", "create", "agent-1", "--url", testAuthURL, "--key-provider", "tpm")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--key-provider tpm")
	assert.Contains(t, err.Error(), "root agent account requires a key held in a TPM")
	assert.Contains(t, err.Error(), "no software key was created")
	assert.NotContains(t, out, `Authenticator "agent-1" created`)
	assert.NoDirExists(t, dir, "a refused create must not create the credentials directory or any record")
}

// On macOS --key-provider tpm is refused as unsupported before the TPM is touched.
func TestAuthenticatorCreate_TPMProviderUnsupportedOnMacOS(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "creds")
	overrideCredentialsDir(t, dir)
	orig := authenticatorHostOS
	authenticatorHostOS = "darwin"
	t.Cleanup(func() { authenticatorHostOS = orig })
	useTPMOpener(t, func() (transport.TPMCloser, error) {
		t.Error("the TPM must not be opened when the provider is unsupported")
		return nil, errors.New("unreachable")
	})

	_, err := runAuthenticator(t, "", "create", "agent-1", "--url", testAuthURL, "--key-provider", "tpm")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not supported on macOS")
	assert.Contains(t, err.Error(), "root agent account")
	assert.NoDirExists(t, dir)
}

// tpm is an additional provider: store and platform selection, the default and the
// unknown-value refusal are unchanged.
func TestResolveAuthenticatorKeyProvider_TPMAndUnchangedChoices(t *testing.T) {
	c, err := resolveAuthenticatorKeyProvider("tpm")
	require.NoError(t, err)
	assert.Equal(t, authenticatorKeyChoice{protection: authenticatorProtectionTPM}, c, "tpm never falls back")

	c, err = resolveAuthenticatorKeyProvider("store")
	require.NoError(t, err)
	assert.Equal(t, authenticatorKeyChoice{protection: authenticatorProtectionStore}, c)

	c, err = resolveAuthenticatorKeyProvider("")
	require.NoError(t, err)
	if identity.UserKeysSupported() {
		assert.Equal(t, authenticatorKeyChoice{protection: authenticatorProtectionPlatform, fallback: true}, c,
			"the Windows default is unchanged")
	} else {
		assert.Equal(t, authenticatorKeyChoice{protection: authenticatorProtectionStore}, c)
	}

	_, err = resolveAuthenticatorKeyProvider("platform")
	if identity.UserKeysSupported() {
		require.NoError(t, err)
	} else {
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not supported on "+runtime.GOOS)
	}

	_, err = resolveAuthenticatorKeyProvider("hsm")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"tpm"`)
}

// A tpm record whose blobs are missing is refused with the remedy; one with blobs
// signs only through the TPM.
func TestAuthenticatorRecord_TPMBlobsRequired(t *testing.T) {
	rec, err := newAuthenticatorRecord("x")
	require.NoError(t, err)
	rec.RPID, rec.Origin = testAuthRPID, testAuthOrigin
	rec.KeyPKCS8 = nil
	rec.Protection = authenticatorProtectionTPM

	_, err = rec.authenticator()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TPM key blobs are missing")
	assert.Contains(t, err.Error(), "cfg authenticator delete x --force")

	rec.KeyPublicBlob, rec.KeyPrivateBlob = tpmTestPublicBlob(t), []byte("blob")
	signer, err := rec.signer()
	require.NoError(t, err)
	assert.NotNil(t, signer.Public())

	rec.KeyPublicBlob = []byte("garbage")
	_, err = rec.signer()
	require.Error(t, err)
}
