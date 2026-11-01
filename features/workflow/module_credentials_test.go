// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package workflow

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/features/controller/modules/cache"
	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/features/workflow/modules/m365/auth"
	"github.com/cfgis/cfgms/features/workflow/modules/m365/moduleset"
	"github.com/cfgis/cfgms/features/workflow/runtime"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/modules/bundle"
	"github.com/cfgis/cfgms/pkg/modules/trust"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	_ "github.com/cfgis/cfgms/pkg/secrets/providers/sops"
)

const (
	testClientSecret = "very-secret-client-secret-9f3a"
	testMintedToken  = "minted-graph-access-token-77c1"
	testCFGMSTenant  = "client-tenant-1"
	testM365Tenant   = "11111111-2222-3333-4444-555555555555"
)

// newSOPSStoreAt opens a real sops secret store (flatfile root, temp key file)
// under base, the shape api.NewSecretStore builds for the controller.
func newSOPSStoreAt(t *testing.T, base string) (secretsif.SecretStore, string, string) {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	keyPath := filepath.Join(base, "secrets.key")
	require.NoError(t, os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(key)), 0o600))
	root := filepath.Join(base, "data")
	store, err := secretsif.CreateSecretStoreFromConfig("sops", map[string]interface{}{
		"storage_provider": "flatfile",
		"storage_config":   map[string]interface{}{"root": root},
		"cache_enabled":    false,
		"key_file":         keyPath,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store, root, keyPath
}

type credRewrite struct{ target *url.URL }

func (r credRewrite) RoundTrip(req *http.Request) (*http.Response, error) {
	c := req.Clone(req.Context())
	c.URL.Scheme, c.URL.Host, c.Host = r.target.Scheme, r.target.Host, r.target.Host
	return http.DefaultTransport.RoundTrip(c)
}

// tokenEndpoint is an httptest OAuth2 token endpoint that counts requests.
type tokenEndpoint struct {
	hits atomic.Int64
	srv  *httptest.Server
	cl   *http.Client
}

func newTokenEndpoint(t *testing.T) *tokenEndpoint {
	t.Helper()
	te := &tokenEndpoint{}
	te.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		te.hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": testMintedToken, "token_type": "Bearer", "expires_in": 3600})
	}))
	t.Cleanup(te.srv.Close)
	u, err := url.Parse(te.srv.URL)
	require.NoError(t, err)
	te.cl = &http.Client{Transport: credRewrite{target: u}}
	return te
}

// credFixture is a factory over a real module cache, a real runtime and a real
// sops secret store, with one approved bundle published.
type credFixture struct {
	factory    *WorkflowModuleFactory
	rt         *runtime.ModuleRuntime
	runtimeDir string
	store      secretsif.SecretStore
	storeRoot  string
	token      *tokenEndpoint
}

// breakStore closes the store and corrupts what it persisted, so the next read
// fails with a store error rather than a clean not-found. Closing alone leaves
// the flatfile-backed sops store readable.
func (fx *credFixture) breakStore(t *testing.T) {
	t.Helper()
	require.NoError(t, fx.store.Close())
	var n int
	require.NoError(t, filepath.Walk(fx.storeRoot, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		n++
		return os.WriteFile(p, []byte("corrupt"), 0o600)
	}))
	require.NotZero(t, n, "the store persisted nothing to corrupt")
}

func newCredFixture(t *testing.T, name, publisher, binary string) *credFixture {
	t.Helper()
	return newCredFixtureSigned(t, name, publisher, binary, nil, nil)
}

// newCredFixtureSigned is newCredFixture with the bundle's signatures and the
// factory's CFGMS publisher identity chosen by the test. A nil identityFn keeps
// the build's own identity (the placeholder in a test binary).
func newCredFixtureSigned(t *testing.T, name, publisher, binary string, sign func(contentHash string) []bundle.BundleSignature, identityFn func() trust.PublisherIdentity) *credFixture {
	t.Helper()
	b := newControllerBundle(t, name, publisher, "0.1.0", binary, sign)
	c, err := cache.New(t.TempDir())
	require.NoError(t, err)
	require.NoError(t, c.Put(b))
	require.NoError(t, c.SetApprovalStatus(b.ContentAddress(), cache.ApprovalStatusApproved))

	runtimeDir := shortRuntimeDir(t)
	rt := runtime.NewModuleRuntime(runtimeDir)

	store, storeRoot, _ := newSOPSStoreAt(t, t.TempDir())
	te := newTokenEndpoint(t)
	f := NewWorkflowModuleFactory(c, rt).(*WorkflowModuleFactory)
	f.identityFn = identityFn
	f.useSecretStore(store)
	f.credentials.SetHTTPClient(te.cl)
	return &credFixture{factory: f, rt: rt, runtimeDir: runtimeDir, store: store, storeRoot: storeRoot, token: te}
}

func (fx *credFixture) storeConnection(t *testing.T, tenant string) {
	t.Helper()
	require.NoError(t, auth.NewSecretStoreCredentialStore(fx.store).StoreConfig(tenant, &auth.OAuth2Config{
		ClientID: "client-id", ClientSecret: testClientSecret, TenantID: testM365Tenant, UseClientCredentials: true,
	}))
}

// assertNoProcessStarted asserts the runtime never allocated a socket, which it
// does before fork/exec.
func (fx *credFixture) assertNoProcessStarted(t *testing.T) {
	t.Helper()
	entries, err := os.ReadDir(fx.runtimeDir)
	require.NoError(t, err)
	assert.Empty(t, entries, "no process may be started: runtime dir must stay untouched")
}

func dummyBinary(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "never-run")
	require.NoError(t, os.WriteFile(p, []byte("not executable"), 0o600))
	return p
}

// [REQUIRED TEST] Issue #4891
func TestM365Credential_UnreachableStoreFailsClosedNoEnvFallback(t *testing.T) {
	fx := newCredFixture(t, "m365-entra-user", "cfgms", dummyBinary(t))
	fx.storeConnection(t, testCFGMSTenant)

	// A populated store reachable only through the retired environment settings,
	// holding a connection for the same tenant.
	envStore, envRoot, envKey := newSOPSStoreAt(t, t.TempDir())
	require.NoError(t, auth.NewSecretStoreCredentialStore(envStore).StoreConfig(testCFGMSTenant, &auth.OAuth2Config{
		ClientID: "env-client", ClientSecret: "env-secret", TenantID: testM365Tenant, UseClientCredentials: true,
	}))
	t.Setenv("CFGMS_M365_SECRETS_PROVIDER", "sops")
	t.Setenv("CFGMS_M365_SECRETS_DIR", envRoot)
	t.Setenv("CFGMS_M365_SECRETS_KEY_FILE", envKey)

	fx.breakStore(t)

	mod, err := fx.factory.CreateTenantModuleInstance(context.Background(), "m365-entra-user", testCFGMSTenant)
	require.Error(t, err)
	assert.Nil(t, mod)
	assert.Contains(t, err.Error(), "m365-entra-user")
	assert.Contains(t, err.Error(), testCFGMSTenant)
	assert.NotContains(t, err.Error(), testClientSecret)
	assert.Zero(t, fx.token.hits.Load(), "no token may be issued from the environment-supplied store")
	fx.assertNoProcessStarted(t)
}

// [REQUIRED TEST] Issue #4891
func TestM365Credential_NoConnectionFailsClosed(t *testing.T) {
	fx := newCredFixture(t, "m365-entra-user", "cfgms", dummyBinary(t))

	_, err := fx.factory.CreateTenantModuleInstance(context.Background(), "m365-entra-user", "tenant-without-connection")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "m365-entra-user")
	assert.Contains(t, err.Error(), "tenant-without-connection")
	assert.Contains(t, err.Error(), "cfg tenant m365 set")
	assert.Contains(t, err.Error(), "cfg tenant m365 gdap-link")
	assert.Zero(t, fx.token.hits.Load())
	fx.assertNoProcessStarted(t)
}

// [REQUIRED TEST] Issue #4891
func TestM365Credential_RefusedWithoutTenantOrStore(t *testing.T) {
	fx := newCredFixture(t, "m365-entra-user", "cfgms", dummyBinary(t))
	fx.storeConnection(t, testCFGMSTenant)

	t.Run("empty tenant", func(t *testing.T) {
		_, err := fx.factory.CreateTenantModuleInstance(context.Background(), "m365-entra-user", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "m365-entra-user")
	})
	t.Run("tenant-less CreateModuleInstance", func(t *testing.T) {
		_, err := fx.factory.CreateModuleInstance("m365-entra-user")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "m365-entra-user")
	})
	t.Run("engine without secret store", func(t *testing.T) {
		f := NewWorkflowModuleFactory(fx.factory.cache, fx.rt)
		_ = NewEngine(f, logging.NewNoopLogger(), nil, nil, nil, nil, nil)
		_, err := f.(TenantModuleLoader).CreateTenantModuleInstance(context.Background(), "m365-entra-user", testCFGMSTenant)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "m365-entra-user")
		assert.Contains(t, err.Error(), testCFGMSTenant)
		assert.Contains(t, err.Error(), "no secret store")
	})
	assert.Zero(t, fx.token.hits.Load())
	fx.assertNoProcessStarted(t)
}

// [REQUIRED TEST] Issue #4891
func TestM365Credential_NonCFGMSPublisherGetsNoToken(t *testing.T) {
	if integrationEchoModuleBin == "" {
		t.Skip("echo_module binary not available")
	}
	fx := newCredFixture(t, "m365-entra-user", "vendor-a", integrationEchoModuleBin)
	fx.storeConnection(t, testCFGMSTenant)

	mod, err := fx.factory.CreateTenantModuleInstance(context.Background(), "m365-entra-user", testCFGMSTenant)
	require.NoError(t, err)
	handle := mod.(*runtime.ModuleHandle)
	t.Cleanup(func() { _ = handle.Stop() })

	state, err := mod.Get(context.Background(), "handshake")
	require.NoError(t, err)
	assert.Equal(t, "tenant="+testCFGMSTenant+";token=", state.AsMap()["config_data"],
		"a non-cfgms bundle gets the tenant and an empty auth_token")
	assert.Zero(t, fx.token.hits.Load(), "no token may be minted for a non-cfgms publisher")
}

func TestM365Credential_CredentialedModuleReceivesMintedToken(t *testing.T) {
	if integrationEchoModuleBin == "" {
		t.Skip("echo_module binary not available")
	}
	// The echo module stands in for the process: it records what the handshake carried.
	fx := newCredFixture(t, "m365-entra-user", "cfgms", integrationEchoModuleBin)
	fx.storeConnection(t, testCFGMSTenant)

	mod, err := fx.factory.CreateTenantModuleInstance(context.Background(), "m365-entra-user", testCFGMSTenant)
	require.NoError(t, err)
	handle := mod.(*runtime.ModuleHandle)
	t.Cleanup(func() { _ = handle.Stop() })

	state, err := mod.Get(context.Background(), "handshake")
	require.NoError(t, err)
	data := state.AsMap()["config_data"].(string)
	assert.True(t, strings.HasPrefix(data, "tenant="+testCFGMSTenant+";token="))
	payload := strings.TrimPrefix(data, "tenant="+testCFGMSTenant+";token=")

	var tok auth.AccessToken
	require.NoError(t, json.Unmarshal([]byte(payload), &tok))
	assert.Equal(t, testMintedToken, tok.Token)
	assert.Equal(t, testM365Tenant, tok.TenantID)
	assert.Empty(t, tok.RefreshToken)
	assert.NotContains(t, payload, testClientSecret)
	assert.NotContains(t, payload, "client-id")
	assert.NotContains(t, payload, "refresh_token")
}

// [REQUIRED TEST] Issue #4891
func TestM365ModuleSet_MatchesShippedModules(t *testing.T) {
	mains, err := filepath.Glob("modules/m365/*/cmd/main.go")
	require.NoError(t, err)
	require.Len(t, mains, len(moduleset.Names()), "every M365 module main.go must be in the issuer set")

	seen := map[string]bool{}
	for _, mainPath := range mains {
		manifestPath := filepath.Join(filepath.Dir(filepath.Dir(mainPath)), "module.yaml")
		raw, err := os.ReadFile(manifestPath) //#nosec G304 -- fixed repo-relative glob result
		require.NoError(t, err, manifestPath)
		var m struct {
			Name      string `yaml:"name"`
			Publisher string `yaml:"publisher"`
		}
		require.NoError(t, yaml.Unmarshal(raw, &m))
		assert.True(t, moduleset.Contains(m.Name), "%s: manifest name %q is not in the issuer set", manifestPath, m.Name)
		assert.Equal(t, cfgmsPublisher, m.Publisher, manifestPath)
		seen[m.Name] = true

		src, err := os.ReadFile(mainPath) //#nosec G304 -- fixed repo-relative glob result
		require.NoError(t, err)
		assert.Contains(t, string(src), "moduleserver.Run(", "%s must use the shared moduleserver bootstrap", mainPath)
	}
	for _, name := range moduleset.Names() {
		assert.True(t, seen[name], "issuer set names %q but no shipped module has that manifest", name)
	}

	// No non-test Go file under modules/m365 may read the retired settings.
	retired := "CFGMS_M365_" + "SECRETS_"
	require.NoError(t, filepath.Walk("modules/m365", func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return err
		}
		b, readErr := os.ReadFile(p) //#nosec G304 -- walking the repo tree
		require.NoError(t, readErr)
		assert.NotContains(t, string(b), retired, p)
		return nil
	}))
}

// stopRecorder wraps the real factory and remembers the handle it returned.
type stopRecorder struct {
	f      *WorkflowModuleFactory
	mu     sync.Mutex
	handle *runtime.ModuleHandle
}

func (s *stopRecorder) CreateModuleInstance(name string) (modules.Module, error) {
	return s.f.CreateModuleInstance(name)
}

func (s *stopRecorder) CreateTenantModuleInstance(ctx context.Context, name, tenant string) (modules.Module, error) {
	m, err := s.f.CreateTenantModuleInstance(ctx, name, tenant)
	if h, ok := m.(*runtime.ModuleHandle); ok {
		s.mu.Lock()
		s.handle = h
		s.mu.Unlock()
	}
	return m, err
}

// [REQUIRED TEST] Issue #4891
func TestExecuteTaskStep_StopsModuleProcess(t *testing.T) {
	if integrationEchoModuleBin == "" {
		t.Skip("echo_module binary not available")
	}
	run := func(t *testing.T, ctx context.Context, wantErr bool) {
		fx := newCredFixture(t, "echo", "test", integrationEchoModuleBin)
		rec := &stopRecorder{f: fx.factory}
		e := NewEngine(rec, logging.NewNoopLogger(), nil, nil, nil, nil, nil)
		exec := &WorkflowExecution{Variables: map[string]interface{}{}}

		err := e.executeTaskStep(ctx, Step{Name: "s1", Module: "echo", Config: map[string]interface{}{"k": "v"}}, exec)
		if wantErr {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
		}

		rec.mu.Lock()
		h := rec.handle
		rec.mu.Unlock()
		require.NotNil(t, h)
		assert.Equal(t, runtime.StateStopped, h.GetState(), "module process must be stopped when the step ends")
		var sockets []string
		_ = filepath.Walk(fx.runtimeDir, func(p string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() {
				sockets = append(sockets, p)
			}
			return nil
		})
		assert.Empty(t, sockets, "module socket must be removed")
	}

	t.Run("success", func(t *testing.T) {
		run(t, context.WithValue(context.Background(), ctxkeys.TenantID, testCFGMSTenant), false)
	})
	t.Run("error", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.WithValue(context.Background(), ctxkeys.TenantID, testCFGMSTenant))
		cancel() // Set fails on the cancelled context
		run(t, ctx, true)
	})
}

// captureOutput runs fn while collecting everything written to stdout, stderr
// and the standard logger.
func captureOutput(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = w, w
	log.SetOutput(w)
	var buf bytes.Buffer
	done := make(chan struct{})
	go func() { _, _ = io.Copy(&buf, r); close(done) }()
	func() {
		defer func() {
			os.Stdout, os.Stderr = oldOut, oldErr
			log.SetOutput(oldErr)
			_ = w.Close()
		}()
		fn()
	}()
	<-done
	return buf.String()
}

// [REQUIRED TEST] Issue #4891
func TestM365Credential_SecretAndTokenNeverLogged(t *testing.T) {
	if integrationEchoModuleBin == "" {
		t.Skip("echo_module binary not available")
	}
	fx := newCredFixture(t, "m365-entra-user", "cfgms", integrationEchoModuleBin)
	fx.storeConnection(t, testCFGMSTenant)

	// A token endpoint that fails, echoing nothing secret, for the error paths.
	failSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer failSrv.Close()
	failURL, _ := url.Parse(failSrv.URL)

	var msgs []string
	out := captureOutput(t, func() {
		ctx := context.WithValue(context.Background(), ctxkeys.TenantID, testCFGMSTenant)
		e := NewEngine(&stopRecorder{f: fx.factory}, logging.ForModule("workflow-test"), nil, nil, nil, nil, nil)
		_ = e
		mod, err := fx.factory.CreateTenantModuleInstance(ctx, "m365-entra-user", testCFGMSTenant)
		require.NoError(t, err)
		h := mod.(*runtime.ModuleHandle)
		_, getErr := h.Get(ctx, "handshake")
		require.NoError(t, getErr)
		require.NoError(t, h.Stop())

		// Failing token endpoint.
		fx.factory.credentials.SetHTTPClient(&http.Client{Transport: credRewrite{target: failURL}})
		_, err = fx.factory.CreateTenantModuleInstance(ctx, "m365-entra-user", testCFGMSTenant)
		require.Error(t, err)
		msgs = append(msgs, err.Error())

		// Missing connection and unreadable store.
		_, err = fx.factory.CreateTenantModuleInstance(ctx, "m365-entra-user", "nobody")
		require.Error(t, err)
		msgs = append(msgs, err.Error())
		fx.breakStore(t)
		_, err = fx.factory.CreateTenantModuleInstance(ctx, "m365-entra-user", testCFGMSTenant)
		require.Error(t, err)
		msgs = append(msgs, err.Error())
	})

	for _, m := range msgs {
		assert.NotContains(t, m, testClientSecret)
		assert.NotContains(t, m, testMintedToken)
	}
	assert.NotContains(t, out, testClientSecret)
	assert.NotContains(t, out, testMintedToken)
}

func testIdentity(pub ed25519.PublicKey) func() trust.PublisherIdentity {
	return func() trust.PublisherIdentity {
		return trust.PublisherIdentity{Name: cfgmsPublisher, PublicKey: pub, Algorithm: "ed25519"}
	}
}

// signOver returns a signer that signs the bundle's real content hash.
func signOver(priv ed25519.PrivateKey, publisher string) func(string) []bundle.BundleSignature {
	return func(hash string) []bundle.BundleSignature {
		return []bundle.BundleSignature{signHash(priv, publisher, hash)}
	}
}

func signHash(priv ed25519.PrivateKey, publisher, hash string) bundle.BundleSignature {
	return bundle.BundleSignature{Publisher: publisher, Algorithm: "ed25519", Signature: ed25519.Sign(priv, []byte(hash))}
}

// [REQUIRED TEST] Issue #4913
func TestM365Credential_SignedBuildRequiresCFGMSSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	for name, sign := range map[string]func(string) []bundle.BundleSignature{
		"no signature":             nil,
		"signature from other key": signOver(otherPriv, cfgmsPublisher),
		"signature over other hash": func(string) []bundle.BundleSignature {
			return []bundle.BundleSignature{signHash(priv, cfgmsPublisher, "sha256-something-else")}
		},
		"valid signature, other publisher name": signOver(priv, "vendor-a"),
	} {
		t.Run(name, func(t *testing.T) {
			fx := newCredFixtureSigned(t, "m365-entra-user", "cfgms", dummyBinary(t), sign, testIdentity(pub))
			fx.storeConnection(t, testCFGMSTenant)

			mod, err := fx.factory.CreateTenantModuleInstance(context.Background(), "m365-entra-user", testCFGMSTenant)
			require.Error(t, err)
			assert.Nil(t, mod)
			assert.Contains(t, err.Error(), "m365-entra-user")
			assert.Contains(t, err.Error(), testCFGMSTenant)
			assert.Zero(t, fx.token.hits.Load(), "no token may be minted")
			fx.assertNoProcessStarted(t)
		})
	}

	t.Run("one valid among invalid signatures gets a token", func(t *testing.T) {
		if integrationEchoModuleBin == "" {
			t.Skip("echo_module binary not available")
		}
		sign := func(hash string) []bundle.BundleSignature {
			return []bundle.BundleSignature{signHash(otherPriv, cfgmsPublisher, hash), signHash(priv, cfgmsPublisher, hash)}
		}
		fx := newCredFixtureSigned(t, "m365-entra-user", "cfgms", integrationEchoModuleBin, sign, testIdentity(pub))
		fx.storeConnection(t, testCFGMSTenant)

		mod, err := fx.factory.CreateTenantModuleInstance(context.Background(), "m365-entra-user", testCFGMSTenant)
		require.NoError(t, err)
		handle := mod.(*runtime.ModuleHandle)
		t.Cleanup(func() { _ = handle.Stop() })
		assert.EqualValues(t, 1, fx.token.hits.Load())
	})

	t.Run("checked on every issue", func(t *testing.T) {
		if integrationEchoModuleBin == "" {
			t.Skip("echo_module binary not available")
		}
		fx := newCredFixtureSigned(t, "m365-entra-user", "cfgms", integrationEchoModuleBin,
			signOver(priv, cfgmsPublisher), testIdentity(pub))
		fx.storeConnection(t, testCFGMSTenant)
		for i := 0; i < 2; i++ {
			mod, err := fx.factory.CreateTenantModuleInstance(context.Background(), "m365-entra-user", testCFGMSTenant)
			require.NoError(t, err)
			require.NoError(t, mod.(*runtime.ModuleHandle).Stop())
		}
		// Rotate the anchor: the earlier-approved bundle no longer verifies.
		otherPub, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		fx.factory.identityFn = testIdentity(otherPub)
		_, err = fx.factory.CreateTenantModuleInstance(context.Background(), "m365-entra-user", testCFGMSTenant)
		require.Error(t, err)
	})
}

// [REQUIRED TEST] Issue #4913
func TestM365Credential_PlaceholderKeyWarnsOnce(t *testing.T) {
	require.False(t, trust.IsUsableIdentityKey(trust.CFGMSPublisherIdentity()), "test binary carries the placeholder key")

	rec := &recordingLogger{Logger: logging.NewNoopLogger()}
	f := NewWorkflowModuleFactory(nil, nil).(*WorkflowModuleFactory)
	f.warnUnboundCredentials(rec)
	f.warnUnboundCredentials(rec)
	assert.Equal(t, 1, rec.warns, "the warning is logged once")
	assert.Contains(t, rec.msg, "not signature-bound")

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signed := NewWorkflowModuleFactory(nil, nil).(*WorkflowModuleFactory)
	signed.identityFn = testIdentity(pub)
	rec2 := &recordingLogger{Logger: logging.NewNoopLogger()}
	signed.warnUnboundCredentials(rec2)
	assert.Zero(t, rec2.warns, "a build with a real key does not warn")
}

type recordingLogger struct {
	logging.Logger
	warns int
	msg   string
}

func (r *recordingLogger) Warn(msg string, _ ...interface{}) {
	r.warns++
	r.msg = msg
}
