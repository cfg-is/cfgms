// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #3582: tests for cfg account commands.
//
// All tests use real HTTP test servers (no mocks) and real admin bundle material
// generated via generateWebAuthnBundle / writeBundleFile. Plain HTTP is used
// intentionally: the client TLS config is constructed (exercising cert/key validation
// via tls.X509KeyPair) but no TLS handshake fires, so we test CLI logic without
// needing a matching server certificate chain.
//
// Coverage:
//   - AccountCreate: happy path (201), unauthenticated (no bundle → error)
//   - AccountList: happy path, JSON output mode
//   - AccountGet: happy path, not-found error
//   - AccountUpdate: permissions update, disabled=true, disabled=false
//   - AccountDelete: destructive guard without --force → error; --force proceeds
//   - AccountBindCert: happy path
//   - AccountCerts: happy path, empty list
//   - AccountRevokeCert: destructive guard without --force → error; --force proceeds
//   - AccountRotateCert: happy path; destructive guard (declined → no request sent,
//     confirmed → request sent)
//   - Cobra flag wiring: every documented flag is registered, and create/rotate-cert
//     are driven through rootCmd.Execute() so argv → pflag → handler is covered
package cmd

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- test server helpers ---

// accountServerConfig controls which responses the account test server emits.
type accountServerConfig struct {
	accounts     []apiAccountInfo
	certs        []apiCertBindingInfo
	capturedBody *[]byte // when non-nil, the server stores the last request body here
}

// newAccountTestServer creates a plain-HTTP test server that handles all
// /api/v1/accounts... endpoints used by cfg account subcommands.
func newAccountTestServer(t *testing.T, cfg accountServerConfig) *httptest.Server {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		path := r.URL.Path

		switch {
		// POST /api/v1/accounts/{username}/certs/bind
		case r.Method == http.MethodPost && strings.Contains(path, "/certs/bind"):
			var req apiBindCertRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			binding := apiCertBindingInfo{
				Serial:  req.Serial,
				Label:   req.Label,
				BoundAt: "2026-08-01T00:00:00Z",
			}
			w.WriteHeader(http.StatusCreated)
			writeEnvelope(w, binding)

		// POST /api/v1/accounts/{username}/certs/revoke/{serial}
		case r.Method == http.MethodPost && strings.Contains(path, "/certs/revoke/"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":{"revoked":true}}`))

		// POST /api/v1/accounts/{username}/certs/rotate/{old_serial}
		case r.Method == http.MethodPost && strings.Contains(path, "/certs/rotate/"):
			if cfg.capturedBody != nil {
				body, _ := io.ReadAll(r.Body)
				*cfg.capturedBody = body
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":{"rotated":true}}`))

		// GET /api/v1/accounts/{username}/certs
		case r.Method == http.MethodGet && strings.Contains(path, "/certs"):
			writeEnvelope(w, cfg.certs)

		// DELETE /api/v1/accounts/{username}
		case r.Method == http.MethodDelete && strings.Contains(path, "/accounts/"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":{"deleted":true}}`))

		// PUT /api/v1/accounts/{username}
		case r.Method == http.MethodPut && strings.Contains(path, "/accounts/"):
			if cfg.capturedBody != nil {
				body, _ := io.ReadAll(r.Body)
				*cfg.capturedBody = body
			}
			var acct apiAccountInfo
			if len(cfg.accounts) > 0 {
				acct = cfg.accounts[0]
			}
			resp := apiAccountCreateResponse{apiAccountInfo: acct}
			writeEnvelope(w, resp)

		// GET /api/v1/accounts/{username}
		case r.Method == http.MethodGet && countPathSegmentsAfter(path, "accounts") == 1:
			username := extractPathSegmentAfter(path, "accounts")
			for _, a := range cfg.accounts {
				if a.Username == username {
					writeEnvelope(w, a)
					return
				}
			}
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":{"code":"ACCOUNT_NOT_FOUND","message":"account not found"}}`))

		// POST /api/v1/accounts
		case r.Method == http.MethodPost && strings.HasSuffix(path, "/accounts"):
			var req apiAccountCreateRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			created := apiAccountCreateResponse{
				apiAccountInfo: apiAccountInfo{
					ID:          "test-id-001",
					Username:    req.Username,
					TenantID:    req.TenantID,
					RootScope:   req.RootScope,
					Permissions: req.Permissions,
					CreatedAt:   "2026-08-01T00:00:00Z",
				},
				EnrollmentMagicLink: "deadbeefcafe1234",
			}
			if created.Permissions == nil {
				created.Permissions = []string{}
			}
			w.WriteHeader(http.StatusCreated)
			writeEnvelope(w, created)

		// GET /api/v1/accounts (list)
		case r.Method == http.MethodGet && strings.HasSuffix(path, "/accounts"):
			writeEnvelope(w, cfg.accounts)

		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"not found"}`))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// writeEnvelope marshals v into the standard {"data": v} envelope and writes it.
func writeEnvelope(w http.ResponseWriter, v interface{}) {
	type envelope struct {
		Data interface{} `json:"data"`
	}
	_ = json.NewEncoder(w).Encode(envelope{Data: v})
}

// countPathSegmentsAfter counts how many non-empty segments follow marker in path.
func countPathSegmentsAfter(path, marker string) int {
	parts := strings.Split(path, "/")
	found := false
	count := 0
	for _, p := range parts {
		if found && p != "" {
			count++
		}
		if p == marker {
			found = true
		}
	}
	return count
}

// saveAccountFlags snapshots account-related global flags and returns a restore func.
func saveAccountFlags(t *testing.T) func() {
	t.Helper()
	origAPIURL := accountAPIURL
	origUsername := accountUsername
	origTenantID := accountTenantID
	origRootScope := accountRootScope
	origPermissions := accountPermissions
	origDisabled := accountDisabled
	origJSONOutput := accountJSONOutput
	origForce := accountForce
	origCertSerial := accountCertSerial
	origCertFingerprint := accountCertFingerprint
	origCertLabel := accountCertLabel
	origCertNewSerial := accountCertNewSerial
	origBundlePath := bundlePath
	origNoBundle := noBundle

	return func() {
		accountAPIURL = origAPIURL
		accountUsername = origUsername
		accountTenantID = origTenantID
		accountRootScope = origRootScope
		accountPermissions = origPermissions
		accountDisabled = origDisabled
		accountJSONOutput = origJSONOutput
		accountForce = origForce
		accountCertSerial = origCertSerial
		accountCertFingerprint = origCertFingerprint
		accountCertLabel = origCertLabel
		accountCertNewSerial = origCertNewSerial
		bundlePath = origBundlePath
		noBundle = origNoBundle
	}
}

// setupAccountTest creates the test server, generates a bundle, wires bundlePath,
// and returns a restore function.
func setupAccountTest(t *testing.T, cfg accountServerConfig) (*httptest.Server, func()) {
	t.Helper()
	srv := newAccountTestServer(t, cfg)
	restore := saveAccountFlags(t)
	b := generateWebAuthnBundle(t)
	bundlePath = writeBundleFile(t, b, srv.URL)
	return srv, restore
}

// --- AC: account lifecycle ---

func TestAccountCreateHappyPath(t *testing.T) {
	_, restore := setupAccountTest(t, accountServerConfig{})
	defer restore()

	accountUsername = "alice"
	accountTenantID = "acme-corp"

	var out bytes.Buffer
	accountCreateCmd.SetOut(&out)
	t.Cleanup(func() { accountCreateCmd.SetOut(nil) })

	err := runAccountCreate(accountCreateCmd, nil)
	require.NoError(t, err)
	assert.Contains(t, out.String(), "alice")
	assert.Contains(t, out.String(), "Enrollment link", "output should include the enrollment magic link")
}

func TestAccountCreateNoBundle(t *testing.T) {
	restore := saveAccountFlags(t)
	defer restore()

	origUserConfigDirFn := userConfigDirFn
	origSystemBundlePathFn := systemBundlePathFn
	t.Cleanup(func() {
		userConfigDirFn = origUserConfigDirFn
		systemBundlePathFn = origSystemBundlePathFn
	})
	userConfigDirFn = func() (string, error) { return t.TempDir(), nil }
	systemBundlePathFn = func() string { return "/nonexistent/admin.bundle.yaml" }

	noBundle = true
	accountUsername = "alice"

	err := runAccountCreate(accountCreateCmd, nil)
	require.Error(t, err, "create must fail when no client can be resolved")
}

func TestAccountCreateMissingUsername(t *testing.T) {
	restore := saveAccountFlags(t)
	defer restore()
	accountUsername = ""

	err := runAccountCreate(accountCreateCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--username")
}

func TestAccountCreateRootScopeAndTenantID(t *testing.T) {
	restore := saveAccountFlags(t)
	defer restore()
	accountUsername = "alice"
	accountRootScope = true
	accountTenantID = "acme-corp"

	err := runAccountCreate(accountCreateCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mutually exclusive")
}

func TestAccountCreateJSONOutput(t *testing.T) {
	_, restore := setupAccountTest(t, accountServerConfig{})
	defer restore()

	accountUsername = "alice"
	accountJSONOutput = true

	var out bytes.Buffer
	accountCreateCmd.SetOut(&out)
	t.Cleanup(func() {
		accountCreateCmd.SetOut(nil)
		accountJSONOutput = false
	})

	err := runAccountCreate(accountCreateCmd, nil)
	require.NoError(t, err)

	var result apiAccountCreateResponse
	require.NoError(t, json.NewDecoder(&out).Decode(&result))
	assert.Equal(t, "alice", result.Username)
	assert.Equal(t, "deadbeefcafe1234", result.EnrollmentMagicLink)
}

func TestAccountListHappyPath(t *testing.T) {
	cfg := accountServerConfig{
		accounts: []apiAccountInfo{
			{ID: "id-1", Username: "alice", TenantID: "acme-corp", CreatedAt: "2026-08-01T00:00:00Z"},
			{ID: "id-2", Username: "bob", TenantID: "acme-corp", CreatedAt: "2026-08-02T00:00:00Z"},
		},
	}
	_, restore := setupAccountTest(t, cfg)
	defer restore()

	var out bytes.Buffer
	accountListCmd.SetOut(&out)
	t.Cleanup(func() { accountListCmd.SetOut(nil) })

	err := runAccountList(accountListCmd, nil)
	require.NoError(t, err)
	assert.Contains(t, out.String(), "alice")
	assert.Contains(t, out.String(), "bob")
}

func TestAccountListEmpty(t *testing.T) {
	_, restore := setupAccountTest(t, accountServerConfig{accounts: []apiAccountInfo{}})
	defer restore()

	var out bytes.Buffer
	accountListCmd.SetOut(&out)
	t.Cleanup(func() { accountListCmd.SetOut(nil) })

	err := runAccountList(accountListCmd, nil)
	require.NoError(t, err)
	assert.Contains(t, out.String(), "No accounts")
}

func TestAccountListJSONOutput(t *testing.T) {
	cfg := accountServerConfig{
		accounts: []apiAccountInfo{
			{ID: "id-1", Username: "alice", TenantID: "acme-corp", CreatedAt: "2026-08-01T00:00:00Z"},
		},
	}
	_, restore := setupAccountTest(t, cfg)
	defer restore()
	accountJSONOutput = true

	var out bytes.Buffer
	accountListCmd.SetOut(&out)
	t.Cleanup(func() {
		accountListCmd.SetOut(nil)
		accountJSONOutput = false
	})

	err := runAccountList(accountListCmd, nil)
	require.NoError(t, err)

	var accounts []apiAccountInfo
	require.NoError(t, json.NewDecoder(&out).Decode(&accounts))
	require.Len(t, accounts, 1)
	assert.Equal(t, "alice", accounts[0].Username)
}

func TestAccountGetHappyPath(t *testing.T) {
	cfg := accountServerConfig{
		accounts: []apiAccountInfo{
			{ID: "id-1", Username: "alice", TenantID: "acme-corp", CreatedAt: "2026-08-01T00:00:00Z", Permissions: []string{"account:list"}},
		},
	}
	_, restore := setupAccountTest(t, cfg)
	defer restore()

	var out bytes.Buffer
	accountGetCmd.SetOut(&out)
	t.Cleanup(func() { accountGetCmd.SetOut(nil) })

	err := runAccountGet(accountGetCmd, []string{"alice"})
	require.NoError(t, err)
	assert.Contains(t, out.String(), "alice")
	assert.Contains(t, out.String(), "acme-corp")
}

func TestAccountGetNotFound(t *testing.T) {
	_, restore := setupAccountTest(t, accountServerConfig{})
	defer restore()

	err := runAccountGet(accountGetCmd, []string{"nonexistent"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestAccountGetJSONOutput(t *testing.T) {
	cfg := accountServerConfig{
		accounts: []apiAccountInfo{
			{ID: "id-1", Username: "alice", TenantID: "acme-corp", CreatedAt: "2026-08-01T00:00:00Z"},
		},
	}
	_, restore := setupAccountTest(t, cfg)
	defer restore()
	accountJSONOutput = true

	var out bytes.Buffer
	accountGetCmd.SetOut(&out)
	t.Cleanup(func() {
		accountGetCmd.SetOut(nil)
		accountJSONOutput = false
	})

	err := runAccountGet(accountGetCmd, []string{"alice"})
	require.NoError(t, err)

	var acct apiAccountInfo
	require.NoError(t, json.NewDecoder(&out).Decode(&acct))
	assert.Equal(t, "alice", acct.Username)
}

func TestAccountUpdatePermissions(t *testing.T) {
	cfg := accountServerConfig{
		accounts: []apiAccountInfo{
			{ID: "id-1", Username: "alice", TenantID: "acme-corp", Permissions: []string{"account:list"}, CreatedAt: "2026-08-01T00:00:00Z"},
		},
	}
	_, restore := setupAccountTest(t, cfg)
	defer restore()

	accountPermissions = []string{"account:list", "account:get"}

	var out bytes.Buffer
	accountUpdateCmd.SetOut(&out)
	t.Cleanup(func() { accountUpdateCmd.SetOut(nil) })

	err := runAccountUpdate(accountUpdateCmd, []string{"alice"})
	require.NoError(t, err)
	assert.Contains(t, out.String(), "updated")
}

func TestAccountUpdateDisabledTrue(t *testing.T) {
	var captured []byte
	cfg := accountServerConfig{
		accounts: []apiAccountInfo{
			{ID: "id-1", Username: "alice", TenantID: "acme-corp", CreatedAt: "2026-08-01T00:00:00Z"},
		},
		capturedBody: &captured,
	}
	_, restore := setupAccountTest(t, cfg)
	defer restore()

	accountDisabled = "true"

	var out bytes.Buffer
	accountUpdateCmd.SetOut(&out)
	t.Cleanup(func() { accountUpdateCmd.SetOut(nil) })

	err := runAccountUpdate(accountUpdateCmd, []string{"alice"})
	require.NoError(t, err)
	require.NotNil(t, captured, "test server must have captured the request body")
	var sent apiAccountUpdateRequest
	require.NoError(t, json.Unmarshal(captured, &sent))
	require.NotNil(t, sent.Disabled, "disabled field must be present in the request")
	assert.True(t, *sent.Disabled, "disabled must be true in the serialized request")
}

func TestAccountUpdateDisabledFalse(t *testing.T) {
	var captured []byte
	cfg := accountServerConfig{
		accounts: []apiAccountInfo{
			{ID: "id-1", Username: "alice", TenantID: "acme-corp", Disabled: true, CreatedAt: "2026-08-01T00:00:00Z"},
		},
		capturedBody: &captured,
	}
	_, restore := setupAccountTest(t, cfg)
	defer restore()

	accountDisabled = "false"

	var out bytes.Buffer
	accountUpdateCmd.SetOut(&out)
	t.Cleanup(func() { accountUpdateCmd.SetOut(nil) })

	err := runAccountUpdate(accountUpdateCmd, []string{"alice"})
	require.NoError(t, err)
	require.NotNil(t, captured, "test server must have captured the request body")
	var sent apiAccountUpdateRequest
	require.NoError(t, json.Unmarshal(captured, &sent))
	require.NotNil(t, sent.Disabled, "disabled field must be present in the request")
	assert.False(t, *sent.Disabled, "disabled must be false in the serialized request")
}

func TestAccountUpdateInvalidDisabled(t *testing.T) {
	restore := saveAccountFlags(t)
	defer restore()
	accountDisabled = "maybe"

	err := runAccountUpdate(accountUpdateCmd, []string{"alice"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--disabled must be 'true' or 'false'")
}

// --- AC: account delete — destructive guard ---

func TestAccountDeleteRequiresForce(t *testing.T) {
	_, restore := setupAccountTest(t, accountServerConfig{})
	defer restore()

	accountForce = false

	// confirmDestructive reads the answer from cmd.InOrStdin(), so the declined
	// answer is fed deterministically rather than depending on the test binary's
	// stdin happening to be empty.
	accountDeleteCmd.SetIn(strings.NewReader("n\n"))
	t.Cleanup(func() { accountDeleteCmd.SetIn(nil) })

	err := runAccountDelete(accountDeleteCmd, []string{"alice"})
	require.Error(t, err, "delete without --force must fail when confirmation is not given")
	assert.Contains(t, err.Error(), "aborted")
}

func TestAccountDeleteWithForce(t *testing.T) {
	_, restore := setupAccountTest(t, accountServerConfig{})
	defer restore()

	accountForce = true

	var out bytes.Buffer
	accountDeleteCmd.SetOut(&out)
	t.Cleanup(func() { accountDeleteCmd.SetOut(nil) })

	err := runAccountDelete(accountDeleteCmd, []string{"alice"})
	require.NoError(t, err, "delete with --force must succeed")
	assert.Contains(t, out.String(), "deleted")
}

// --- AC: cert binding ---

func TestAccountBindCertHappyPath(t *testing.T) {
	_, restore := setupAccountTest(t, accountServerConfig{})
	defer restore()

	accountCertSerial = "abc123"
	accountCertLabel = "primary laptop"

	var out bytes.Buffer
	accountBindCertCmd.SetOut(&out)
	t.Cleanup(func() { accountBindCertCmd.SetOut(nil) })

	err := runAccountBindCert(accountBindCertCmd, []string{"alice"})
	require.NoError(t, err)
	assert.Contains(t, out.String(), "abc123")
	assert.Contains(t, out.String(), "primary laptop")
}

func TestAccountCertsHappyPath(t *testing.T) {
	cfg := accountServerConfig{
		certs: []apiCertBindingInfo{
			{Serial: "abc123", Label: "primary laptop", BoundAt: "2026-08-01T00:00:00Z"},
			{Serial: "def456", BoundAt: "2026-08-02T00:00:00Z"},
		},
	}
	_, restore := setupAccountTest(t, cfg)
	defer restore()

	var out bytes.Buffer
	accountCertsCmd.SetOut(&out)
	t.Cleanup(func() { accountCertsCmd.SetOut(nil) })

	err := runAccountCerts(accountCertsCmd, []string{"alice"})
	require.NoError(t, err)
	assert.Contains(t, out.String(), "abc123")
	assert.Contains(t, out.String(), "def456")
}

// TestAccountCertsShowsLastUsed verifies that a binding with a recorded last-used
// timestamp displays it, and a binding that has never authenticated (LastUsedAt empty —
// the server omits last_used_at for it) renders an explicit "never" value rather than a
// blank line (Issue #3715).
func TestAccountCertsShowsLastUsed(t *testing.T) {
	cfg := accountServerConfig{
		certs: []apiCertBindingInfo{
			{Serial: "abc123", Label: "primary laptop", BoundAt: "2026-08-01T00:00:00Z", LastUsedAt: "2026-08-20T12:30:00Z"},
			{Serial: "def456", BoundAt: "2026-08-02T00:00:00Z"},
		},
	}
	_, restore := setupAccountTest(t, cfg)
	defer restore()

	var out bytes.Buffer
	accountCertsCmd.SetOut(&out)
	t.Cleanup(func() { accountCertsCmd.SetOut(nil) })

	err := runAccountCerts(accountCertsCmd, []string{"alice"})
	require.NoError(t, err)
	assert.Contains(t, out.String(), "Last used: 2026-08-20T12:30:00Z",
		"a binding with a recorded use must display its timestamp")
	assert.Contains(t, out.String(), "Last used: never",
		"a binding that has never authenticated must render an explicit never-used value")
}

func TestAccountCertsEmpty(t *testing.T) {
	_, restore := setupAccountTest(t, accountServerConfig{certs: []apiCertBindingInfo{}})
	defer restore()

	var out bytes.Buffer
	accountCertsCmd.SetOut(&out)
	t.Cleanup(func() { accountCertsCmd.SetOut(nil) })

	err := runAccountCerts(accountCertsCmd, []string{"alice"})
	require.NoError(t, err)
	assert.Contains(t, out.String(), "No certificate bindings")
}

func TestAccountCertsJSONOutput(t *testing.T) {
	cfg := accountServerConfig{
		certs: []apiCertBindingInfo{
			{Serial: "abc123", BoundAt: "2026-08-01T00:00:00Z"},
		},
	}
	_, restore := setupAccountTest(t, cfg)
	defer restore()
	accountJSONOutput = true

	var out bytes.Buffer
	accountCertsCmd.SetOut(&out)
	t.Cleanup(func() {
		accountCertsCmd.SetOut(nil)
		accountJSONOutput = false
	})

	err := runAccountCerts(accountCertsCmd, []string{"alice"})
	require.NoError(t, err)

	var bindings []apiCertBindingInfo
	require.NoError(t, json.NewDecoder(&out).Decode(&bindings))
	require.Len(t, bindings, 1)
	assert.Equal(t, "abc123", bindings[0].Serial)
}

// --- AC: revoke-cert — destructive guard ---

func TestAccountRevokeCertRequiresForce(t *testing.T) {
	_, restore := setupAccountTest(t, accountServerConfig{})
	defer restore()

	accountForce = false

	accountRevokeCertCmd.SetIn(strings.NewReader("n\n"))
	t.Cleanup(func() { accountRevokeCertCmd.SetIn(nil) })

	err := runAccountRevokeCert(accountRevokeCertCmd, []string{"alice", "abc123"})
	require.Error(t, err, "revoke-cert without --force must fail when confirmation is not given")
	assert.Contains(t, err.Error(), "aborted")
}

func TestAccountRevokeCertWithForce(t *testing.T) {
	_, restore := setupAccountTest(t, accountServerConfig{})
	defer restore()

	accountForce = true

	var out bytes.Buffer
	accountRevokeCertCmd.SetOut(&out)
	t.Cleanup(func() { accountRevokeCertCmd.SetOut(nil) })

	err := runAccountRevokeCert(accountRevokeCertCmd, []string{"alice", "abc123"})
	require.NoError(t, err, "revoke-cert with --force must succeed")
	assert.Contains(t, out.String(), "revoked")
}

// --- AC: rotate-cert — destructive guard ---

func TestAccountRotateCertHappyPath(t *testing.T) {
	_, restore := setupAccountTest(t, accountServerConfig{})
	defer restore()

	accountCertNewSerial = "newserial789"
	accountForce = true

	var out bytes.Buffer
	accountRotateCertCmd.SetOut(&out)
	t.Cleanup(func() { accountRotateCertCmd.SetOut(nil) })

	err := runAccountRotateCert(accountRotateCertCmd, []string{"alice", "oldserial123"})
	require.NoError(t, err)
	assert.Contains(t, out.String(), "oldserial123")
	assert.Contains(t, out.String(), "newserial789")
}

// TestAccountRotateCertRequiresForce covers the destructive guard: rotation revokes
// the old serial through the CA, so it must not run unconfirmed.
func TestAccountRotateCertRequiresForce(t *testing.T) {
	var captured []byte
	_, restore := setupAccountTest(t, accountServerConfig{capturedBody: &captured})
	defer restore()

	accountCertNewSerial = "newserial789"
	accountForce = false

	var out bytes.Buffer
	accountRotateCertCmd.SetOut(&out)
	accountRotateCertCmd.SetIn(strings.NewReader("n\n"))
	t.Cleanup(func() {
		accountRotateCertCmd.SetOut(nil)
		accountRotateCertCmd.SetIn(nil)
	})

	err := runAccountRotateCert(accountRotateCertCmd, []string{"alice", "oldserial123"})
	require.Error(t, err, "rotate-cert without --force must abort when confirmation is declined")
	assert.Contains(t, err.Error(), "aborted")
	assert.Contains(t, out.String(), "oldserial123", "prompt must name the certificate being revoked")
	assert.Contains(t, out.String(), "newserial789", "prompt must name the replacement certificate")
	assert.Nil(t, captured, "no rotate request may reach the controller when confirmation is declined")
}

// TestAccountRotateCertConfirmationAccepted proves the prompt path (not just --force)
// reaches the controller when the operator confirms.
func TestAccountRotateCertConfirmationAccepted(t *testing.T) {
	var captured []byte
	_, restore := setupAccountTest(t, accountServerConfig{capturedBody: &captured})
	defer restore()

	accountCertNewSerial = "newserial789"
	accountForce = false

	var out bytes.Buffer
	accountRotateCertCmd.SetOut(&out)
	accountRotateCertCmd.SetIn(strings.NewReader("y\n"))
	t.Cleanup(func() {
		accountRotateCertCmd.SetOut(nil)
		accountRotateCertCmd.SetIn(nil)
	})

	err := runAccountRotateCert(accountRotateCertCmd, []string{"alice", "oldserial123"})
	require.NoError(t, err)

	var req apiRotateCertRequest
	require.NoError(t, json.Unmarshal(captured, &req))
	assert.Equal(t, "newserial789", req.Serial)
}

// --- AC: cobra flag wiring (Execute()-level) ---
//
// The handler-level tests above assign the package-level flag variables directly,
// which cannot observe a flag that was never registered on its command. These tests
// drive the real rootCmd through Execute() so that argv → pflag → handler is covered.

// resetAccountFlagChanged clears pflag's per-flag "Changed" bit across the account
// command tree and the root command. Cobra commands are package-level singletons, so
// a flag parsed by one Execute() would otherwise still count as set for the next one —
// which would silently satisfy a MarkFlagRequired assertion.
func resetAccountFlagChanged() {
	clear := func(fs *pflag.FlagSet) {
		fs.VisitAll(func(f *pflag.Flag) { f.Changed = false })
	}
	clear(rootCmd.Flags())
	clear(rootCmd.PersistentFlags())
	clear(accountCmd.PersistentFlags())
	for _, sub := range accountCmd.Commands() {
		clear(sub.Flags())
	}
}

// executeAccountCommand runs the real root command with argv and returns its output.
func executeAccountCommand(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	resetAccountFlagChanged()

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	rootCmd.SetIn(strings.NewReader(stdin))
	rootCmd.SetArgs(args)
	t.Cleanup(func() {
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		rootCmd.SetIn(nil)
		rootCmd.SetArgs([]string{})
		resetAccountFlagChanged()
	})

	err := rootCmd.Execute()
	return out.String(), err
}

// TestAccountSubcommandFlagsAreRegistered asserts every flag the handlers read (and the
// commands-reference documents) is actually registered, so no handler branch is
// unreachable from argv.
func TestAccountSubcommandFlagsAreRegistered(t *testing.T) {
	cases := map[string][]string{
		"create":      {"username", "tenant-id", "root-scope", "permission", "json"},
		"list":        {"json"},
		"get":         {"json"},
		"update":      {"permission", "disabled", "json"},
		"delete":      {"force"},
		"bind-cert":   {"serial", "fingerprint", "label"},
		"certs":       {"json"},
		"revoke-cert": {"force"},
		"rotate-cert": {"new-serial", "fingerprint", "force"},
	}

	subcommands := make(map[string]*cobra.Command)
	for _, sub := range accountCmd.Commands() {
		subcommands[sub.Name()] = sub
	}

	for name, flags := range cases {
		sub, ok := subcommands[name]
		require.True(t, ok, "cfg account %s must be registered on accountCmd", name)
		for _, flagName := range flags {
			assert.NotNilf(t, sub.Flags().Lookup(flagName),
				"cfg account %s must register --%s", name, flagName)
		}
	}

	// --username is mandatory: cobra, not just the handler's empty-string guard, rejects it.
	usernameFlag := subcommands["create"].Flags().Lookup("username")
	require.NotNil(t, usernameFlag)
	assert.Equal(t, []string{"true"}, usernameFlag.Annotations[cobra.BashCompOneRequiredFlag],
		"--username must be marked required on cfg account create")
}

func TestAccountCreateUsernameFlagReachesHandler(t *testing.T) {
	srv, restore := setupAccountTest(t, accountServerConfig{})
	defer restore()

	out, err := executeAccountCommand(t, "",
		"account", "create",
		"--username", "flag-wired-user",
		"--tenant-id", "acme-corp",
		"--api-url", srv.URL)
	require.NoError(t, err, "cfg account create --username must parse and run")
	assert.Equal(t, "flag-wired-user", accountUsername, "--username must bind to accountUsername")
	assert.Contains(t, out, "flag-wired-user")
	assert.Contains(t, out, "Enrollment link")
}

func TestAccountCreateWithoutUsernameFlagIsRejected(t *testing.T) {
	srv, restore := setupAccountTest(t, accountServerConfig{})
	defer restore()

	_, err := executeAccountCommand(t, "", "account", "create", "--api-url", srv.URL)
	require.Error(t, err, "cfg account create must fail when --username is omitted")
	assert.Contains(t, err.Error(), "username")
}

func TestAccountRotateCertFlagsReachHandler(t *testing.T) {
	var captured []byte
	srv, restore := setupAccountTest(t, accountServerConfig{capturedBody: &captured})
	defer restore()

	out, err := executeAccountCommand(t, "",
		"account", "rotate-cert", "alice", "oldserial123",
		"--new-serial", "newserial789",
		"--fingerprint", "aabbccdd",
		"--force",
		"--api-url", srv.URL)
	require.NoError(t, err)
	assert.Contains(t, out, "newserial789")

	var req apiRotateCertRequest
	require.NoError(t, json.Unmarshal(captured, &req))
	assert.Equal(t, "newserial789", req.Serial)
	assert.Equal(t, "aabbccdd", req.Fingerprint, "--fingerprint must reach the rotate request body")
}

// TestAccountRotateCertPromptsWithoutForce is the Execute()-level counterpart of the
// destructive guard: with --force omitted and a declined answer on stdin, no request
// reaches the controller.
func TestAccountRotateCertPromptsWithoutForce(t *testing.T) {
	var captured []byte
	srv, restore := setupAccountTest(t, accountServerConfig{capturedBody: &captured})
	defer restore()

	accountForce = false

	out, err := executeAccountCommand(t, "n\n",
		"account", "rotate-cert", "alice", "oldserial123",
		"--new-serial", "newserial789",
		"--api-url", srv.URL)
	require.Error(t, err, "rotate-cert must prompt when --force is omitted")
	assert.Contains(t, err.Error(), "aborted")
	assert.Contains(t, out, "irreversible")
	assert.Nil(t, captured, "declining the prompt must not send a rotate request")
}
