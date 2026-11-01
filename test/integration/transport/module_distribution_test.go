// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/test/bufconn"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	stewardtypes "github.com/cfgis/cfgms/features/config/stewardtypes"
	"github.com/cfgis/cfgms/features/controller/modules/approval"
	"github.com/cfgis/cfgms/features/controller/modules/cache"
	"github.com/cfgis/cfgms/features/controller/modules/resolution"
	gitresolver "github.com/cfgis/cfgms/features/controller/modules/sources/git"
	"github.com/cfgis/cfgms/features/controller/service"
	controllertransport "github.com/cfgis/cfgms/features/controller/transport"
	"github.com/cfgis/cfgms/features/steward/discovery"
	"github.com/cfgis/cfgms/features/steward/execution"
	"github.com/cfgis/cfgms/features/steward/factory"
	"github.com/cfgis/cfgms/features/steward/modules/install"
	moduleruntime "github.com/cfgis/cfgms/features/steward/modules/runtime"
	stewardtrust "github.com/cfgis/cfgms/features/steward/modules/trust"
	cfgcert "github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/modules/bundle"
	pkgtrust "github.com/cfgis/cfgms/pkg/modules/trust"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
	"github.com/cfgis/cfgms/pkg/testutil"
)

// Module distribution, publish to execute (Issue #4990, epic #4654).
//
// One real chain, no mocks and no re-implemented signing:
//
//	cfg module keygen / cfg module bundle build   (the shipped binary, built here)
//	  -> git repository tagged with the version, served over https (git http-backend)
//	  -> controller: GitSourceResolver, ApprovalWorkflow, ModuleCache, trust store
//	  -> push gate (resolution.ResolveCfgRequiredModules, as the config push handler runs it)
//	  -> admin approval (ApprovalWorkflow.Approve, the reviewer behind the REST route)
//	  -> the REAL FetchModuleBundle handler over gRPC
//	  -> steward: install.Installer, Executor.ApplyConfiguration, module runtime, real module process
//
// The REST approve route itself needs a WebAuthn presence ceremony and is covered
// end to end in test/integration/controller/module_routes_test.go; this test
// drives the workflow that route calls. A hostile channel is a hook on the REAL
// handler's stream (and request) that alters what the steward receives.

const (
	distStewardID = "steward-distribution"
	distTenant    = "tenant-dist"
	distModule    = "widget"
	distPublisher = "acme-corp"
)

// ---------------------------------------------------------------------------
// Tools built once: the shipped cfg binary and a real runnable module.
// ---------------------------------------------------------------------------

type distTools struct {
	cfgBin    string
	moduleBin string
	otherBin  string // bytes standing in for another platform's binary
}

func exeName(name string) string {
	if goruntime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}

func buildDistTools(t *testing.T) distTools {
	t.Helper()
	dir := t.TempDir()
	tools := distTools{
		cfgBin:    filepath.Join(dir, exeName("cfg")),
		moduleBin: filepath.Join(dir, exeName("yaml_module")),
		otherBin:  filepath.Join(dir, "other-platform-binary"),
	}
	for out, pkg := range map[string]string{
		tools.cfgBin:    "github.com/cfgis/cfgms/cmd/cfg",
		tools.moduleBin: "github.com/cfgis/cfgms/features/steward/execution/testdata/yaml_module",
	} {
		// #nosec G204 -- fixed go binary; the output path is test-owned and the package is a constant.
		cmd := exec.Command("go", "build", "-o", out, pkg)
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("go build %s: %v\n%s", pkg, err, b)
		}
	}
	require.NoError(t, os.WriteFile(tools.otherBin, []byte("binary of another platform, not runnable here"), 0o600))
	return tools
}

func ownPlatformKey() string { return goruntime.GOOS + "-" + goruntime.GOARCH }

func otherPlatformKey() string {
	if ownPlatformKey() == "linux-amd64" {
		return "windows-amd64"
	}
	return "linux-amd64"
}

// publisher is a publisher identity created by `cfg module keygen`.
type publisher struct {
	name string
	seed string
	pub  ed25519.PublicKey
}

func (tl distTools) cfg(t *testing.T, stdin string, args ...string) string {
	t.Helper()
	// #nosec G204 -- the binary is the cfg build made by this test; arguments are test constants and test-owned paths.
	cmd := exec.Command(tl.cfgBin, args...)
	cmd.Env = append(filteredEnv("CFGMS_PUBLISHER_SEED"), "HOME="+t.TempDir())
	cmd.Stdin = strings.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	require.NoError(t, cmd.Run(), "cfg %s: %s", strings.Join(args, " "), stderr.String())
	return stdout.String()
}

func filteredEnv(drop string) []string {
	var out []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, drop+"=") {
			out = append(out, kv)
		}
	}
	return out
}

func (tl distTools) keygen(t *testing.T, name string) publisher {
	t.Helper()
	out := tl.cfg(t, "", "module", "keygen")
	p := publisher{name: name}
	for _, line := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(line, "seed: "); ok {
			p.seed = strings.TrimSpace(v)
		}
		if v, ok := strings.CutPrefix(line, "public key: "); ok {
			raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v))
			require.NoError(t, err)
			p.pub = raw
		}
	}
	require.NotEmpty(t, p.seed, "keygen printed a seed")
	require.Len(t, p.pub, ed25519.PublicKeySize, "keygen printed a public key")
	return p
}

func manifestYAML(pubName, name, version string) string {
	return fmt.Sprintf("name: %s\nversion: %s\ndescription: distribution test module\npublisher: %s\nexecutors:\n  - steward\n", name, version, pubName)
}

// buildBundle runs `cfg module bundle build` and returns the installation root it
// wrote. The own platform carries the real module binary, the other platform
// carries different bytes.
func (tl distTools) buildBundle(t *testing.T, p publisher, name, version string) string {
	t.Helper()
	work := t.TempDir()
	manifest := filepath.Join(work, "module.yaml")
	require.NoError(t, os.WriteFile(manifest, []byte(manifestYAML(p.name, name, version)), 0o600))
	out := filepath.Join(work, "bundle-root")
	tl.cfg(t, p.seed+"\n", "module", "bundle", "build", "--seed-stdin",
		"--manifest", manifest,
		"--binary", ownPlatformKey()+"="+tl.moduleBin,
		"--binary", otherPlatformKey()+"="+tl.otherBin,
		"--out", out)
	return out
}

// buildUnsignedBundle assembles a bundle with the production assembler and never
// signs it (the shipped tool always signs), writing the same installation root.
func (tl distTools) buildUnsignedBundle(t *testing.T, pubName, name, version string) string {
	t.Helper()
	work := t.TempDir()
	manifest := filepath.Join(work, "module.yaml")
	require.NoError(t, os.WriteFile(manifest, []byte(manifestYAML(pubName, name, version)), 0o600))
	binName := func(platform string) string {
		n := "cfgms-module-" + name
		if strings.HasPrefix(platform, "windows-") {
			n += ".exe"
		}
		return n
	}
	b, err := bundle.Assemble(bundle.AssembleSpec{ManifestPath: manifest, Binaries: map[string]bundle.PlatformBinary{
		ownPlatformKey():   {FileName: binName(ownPlatformKey()), SourcePath: tl.moduleBin},
		otherPlatformKey(): {FileName: binName(otherPlatformKey()), SourcePath: tl.otherBin},
	}})
	require.NoError(t, err)
	require.Empty(t, b.Signatures)
	out := filepath.Join(work, "bundle-root")
	require.NoError(t, bundle.WriteInstalled(b, out, bundle.WriteOptions{}))
	return out
}

// ---------------------------------------------------------------------------
// Git publishing
// ---------------------------------------------------------------------------

func distGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	full := append([]string{"-C", dir,
		"-c", "user.name=cfgms-test", "-c", "user.email=test@example.invalid",
		"-c", "commit.gpgsign=false", "-c", "core.autocrlf=false", "-c", "init.defaultBranch=main"}, args...)
	// #nosec G204 -- fixed git binary; arguments are test-controlled constants and test-owned paths.
	out, err := testutil.GitCommand(t, "", full...).CombinedOutput()
	require.NoError(t, err, "git %s: %s", strings.Join(args, " "), out)
	return strings.TrimSpace(string(out))
}

// commitBundleRoot makes the bundle installation root the root of repoDir at tag
// version. tamper, when set, runs on the repository working tree before the commit.
func commitBundleRoot(t *testing.T, bundleRoot, repoDir, version string, tamper func(repoDir string)) {
	t.Helper()
	require.NoError(t, os.MkdirAll(repoDir, 0o750))
	if _, err := os.Stat(filepath.Join(repoDir, ".git")); err != nil {
		distGit(t, repoDir, "init", "-q")
	}
	old, err := os.ReadDir(repoDir)
	require.NoError(t, err)
	for _, e := range old {
		if e.Name() != ".git" {
			require.NoError(t, os.RemoveAll(filepath.Join(repoDir, e.Name())))
		}
	}
	entries, err := os.ReadDir(bundleRoot)
	require.NoError(t, err)
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(bundleRoot, e.Name())) // #nosec G304 -- test-owned bundle root
		require.NoError(t, err)
		info, err := e.Info()
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(repoDir, e.Name()), data, info.Mode().Perm())) // #nosec G703 -- name comes from the bundle root listing
	}
	if tamper != nil {
		tamper(repoDir)
	}
	distGit(t, repoDir, "add", "-A")
	distGit(t, repoDir, "commit", "-q", "--allow-empty", "-m", "publish "+version)
	distGit(t, repoDir, "tag", version)
}

// ---------------------------------------------------------------------------
// Controller side
// ---------------------------------------------------------------------------

type hostileHooks struct {
	mu         sync.Mutex
	rewriteReq func(*transportpb.FetchModuleBundleRequest)
	mutate     func(*transportpb.ModuleBundleChunk) bool // false drops the chunk
}

type distService struct {
	transportpb.UnimplementedStewardTransportServer
	f *distFixture
}

type mutatingModuleStream struct {
	grpc.ServerStreamingServer[transportpb.ModuleBundleChunk]
	ctx    context.Context
	mutate func(*transportpb.ModuleBundleChunk) bool
}

func (s *mutatingModuleStream) Context() context.Context { return s.ctx }
func (s *mutatingModuleStream) Send(c *transportpb.ModuleBundleChunk) error {
	if s.mutate != nil && !s.mutate(c) {
		return nil
	}
	return s.ServerStreamingServer.Send(c)
}

func (d *distService) FetchModuleBundle(req *transportpb.FetchModuleBundleRequest, stream grpc.ServerStreamingServer[transportpb.ModuleBundleChunk]) error {
	d.f.hooks.mu.Lock()
	rewrite, mutate := d.f.hooks.rewriteReq, d.f.hooks.mutate
	d.f.hooks.mu.Unlock()
	if rewrite != nil {
		rewrite(req)
	}
	return d.f.handler.HandleGRPC(d.f.peerCtx, req, &mutatingModuleStream{ServerStreamingServer: stream, ctx: d.f.peerCtx, mutate: mutate})
}

// distFixture is a controller (module cache, approval workflow, trust store, git
// source resolver, FetchModuleBundle handler) plus the git server publishing to it.
type distFixture struct {
	t         *testing.T
	tools     distTools
	reposRoot string
	cache     *cache.ModuleCache
	workflow  *approval.ApprovalWorkflow
	trust     *pkgtrust.InMemoryTrustStore
	resolver  *gitresolver.GitSourceResolver
	cfgSvc    *service.ConfigurationServiceV2
	handler   *controllertransport.ModuleBundleHandler
	peerCtx   context.Context
	client    transportpb.StewardTransportClient
	root      string // the steward's module discovery root
	hooks     hostileHooks
}

// newDistFixture wires the controller. controllerTrusted lists the publishers in
// module_trust; sourcePublishers lists the publishers in module_sources.
func newDistFixture(t *testing.T, tools distTools, controllerTrusted []publisher, sourcePublishers ...string) *distFixture {
	t.Helper()
	f := &distFixture{t: t, tools: tools, reposRoot: t.TempDir(), root: filepath.Join(t.TempDir(), "modules")}

	baseURL, caFile := testutil.NewGitServer(t, f.reposRoot)
	t.Setenv("GIT_SSL_CAINFO", caFile)
	sources := map[string]gitresolver.SourceConfig{}
	for _, name := range sourcePublishers {
		sources[name] = gitresolver.SourceConfig{Type: "git", Base: baseURL}
	}
	resolver, err := gitresolver.New(sources, t.TempDir(), logging.NewNoopLogger())
	require.NoError(t, err)
	f.resolver = resolver

	f.trust = pkgtrust.NewInMemoryTrustStore()
	for _, p := range controllerTrusted {
		require.NoError(t, f.trust.AddPublisher(pkgtrust.PublisherIdentity{Name: p.name, PublicKey: p.pub, Algorithm: "ed25519"}))
	}

	sm := pkgtesting.SetupTestStorage(t)
	ctrl := service.NewControllerService(logging.NewNoopLogger())
	f.cfgSvc = service.NewConfigurationServiceV2(logging.NewNoopLogger(), sm, ctrl)
	require.NoError(t, sm.GetTenantStore().CreateTenant(ctxkeys.WithSystem(context.Background()),
		&business.TenantData{ID: distTenant, Name: distTenant, Status: business.TenantStatusActive}))

	f.cache, err = cache.New(filepath.Join(t.TempDir(), "module-cache"))
	require.NoError(t, err)
	f.cache.SetApprovalStore(pkgtesting.SetupTestModuleApprovalStore())
	f.workflow = approval.New(f.cache)

	ca, err := cfgcert.NewCA(&cfgcert.CAConfig{Organization: "CFGMS Distribution Test", Country: "US", ValidityDays: 1, KeySize: 2048})
	require.NoError(t, err)
	require.NoError(t, ca.Initialize(nil))
	cert, err := ca.GenerateClientCertificate(&cfgcert.ClientCertConfig{CommonName: distStewardID, ValidityDays: 1, KeySize: 2048})
	require.NoError(t, err)
	block, _ := pem.Decode(cert.CertificatePEM)
	require.NotNil(t, block)
	x509Cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	f.peerCtx = peer.NewContext(ctxkeys.WithSystem(context.Background()), &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{x509Cert}, VerifiedChains: [][]*x509.Certificate{{x509Cert}}, HandshakeComplete: true,
	}}})

	f.handler = controllertransport.NewModuleBundleHandler(f.cache, f.cfgSvc, ctrl, controllertransport.NewTenantQueue(), logging.NewNoopLogger())
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	transportpb.RegisterStewardTransportServer(srv, &distService{f: f})
	go func() { _ = srv.Serve(lis) }()
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close(); srv.Stop() })
	f.client = transportpb.NewStewardTransportClient(conn)

	require.NoError(t, ctrl.RegisterSteward(distStewardID, distTenant, "localhost:4433", "connected"))
	t.Setenv(install.BundleDirEnvVar, f.root)
	return f
}

func (f *distFixture) stewardConfig(required ...stewardtypes.RequiredModule) *stewardtypes.StewardConfig {
	return &stewardtypes.StewardConfig{
		Steward: stewardtypes.StewardSettings{
			ID:      distStewardID,
			Logging: stewardtypes.LoggingConfig{Level: "info"},
			ErrorHandling: stewardtypes.ErrorHandlingConfig{
				ModuleLoadFailure: stewardtypes.ActionContinue, ResourceFailure: stewardtypes.ActionWarn, ConfigurationError: stewardtypes.ActionFail,
			},
		},
		Modules:         map[string]string{"directory": "directory"},
		Resources:       []stewardtypes.ResourceConfig{{Name: "d", Module: "directory", Config: map[string]interface{}{"path": "/tmp/x", "permissions": "755"}}},
		RequiredModules: required,
	}
}

// storeConfig records the steward's configuration without the push gate.
func (f *distFixture) storeConfig(required ...stewardtypes.RequiredModule) {
	f.t.Helper()
	require.NoError(f.t, f.cfgSvc.SetConfiguration(ctxkeys.WithSystem(context.Background()), distTenant, distStewardID, f.stewardConfig(required...)))
}

// push is the config push: required_modules are resolved against the cache and
// the git source, and the configuration is stored only when every module is
// approved (resolution.ResolveCfgRequiredModules is the call the push handler makes).
func (f *distFixture) push(required ...stewardtypes.RequiredModule) error {
	f.t.Helper()
	if err := resolution.ResolveCfgRequiredModules(context.Background(), required, f.cache, f.resolver, f.workflow, f.trust); err != nil {
		return err
	}
	f.storeConfig(required...)
	return nil
}

func (f *distFixture) cacheStatus(name, version string) (cache.ApprovalStatus, bundle.ContentAddress) {
	f.t.Helper()
	entries, err := f.cache.List()
	require.NoError(f.t, err)
	for _, e := range entries {
		if e.Addr.Name == name && e.Addr.Version == version {
			return e.Status, e.Addr
		}
	}
	return "", bundle.ContentAddress{}
}

func (f *distFixture) requireCacheEmpty() {
	f.t.Helper()
	entries, err := f.cache.List()
	require.NoError(f.t, err)
	assert.Empty(f.t, entries, "nothing reached the controller cache")
}

func (f *distFixture) setHostile(rewrite func(*transportpb.FetchModuleBundleRequest), mutate func(*transportpb.ModuleBundleChunk) bool) {
	f.hooks.mu.Lock()
	defer f.hooks.mu.Unlock()
	f.hooks.rewriteReq, f.hooks.mutate = rewrite, mutate
}

func requireModule(publisherName, name, version string) stewardtypes.RequiredModule {
	return stewardtypes.RequiredModule{Name: publisherName + "/" + name, Version: version}
}

// ---------------------------------------------------------------------------
// Steward side
// ---------------------------------------------------------------------------

// stewardTrust builds the steward's trust enforcer. known holds the publisher keys
// the steward binary was built with (the compiled-in additional publisher registry
// of Issue #4988, which strict mode resolves by name).
func stewardTrust(t *testing.T, known ...publisher) *stewardtrust.StewardTrustEnforcer {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	ids := map[string]pkgtrust.PublisherIdentity{}
	for _, p := range known {
		ids[p.name] = pkgtrust.PublisherIdentity{Name: p.name, PublicKey: p.pub, Algorithm: "ed25519"}
	}
	return stewardtrust.NewStewardTrustEnforcerWithKnownPublishers(func() pkgtrust.PublisherIdentity {
		return pkgtrust.PublisherIdentity{Name: "cfgms", PublicKey: pub, Algorithm: "ed25519"}
	}, ids)
}

func shortDistRuntimeDir(t *testing.T) string {
	t.Helper()
	if goruntime.GOOS == "windows" {
		return t.TempDir()
	}
	base, err := os.MkdirTemp("/tmp", "cfgms-dist-rt-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	return base
}

type distSteward struct {
	installer *install.Installer
	executor  *execution.Executor
}

func (f *distFixture) newSteward(mode stewardtypes.ModuleTrustMode, enforcer *stewardtrust.StewardTrustEnforcer, additional ...string) *distSteward {
	f.t.Helper()
	inst := &install.Installer{
		Root: f.root, Mode: mode, AdditionalPublisherNames: additional,
		Enforcer: enforcer, Client: f.client, Logger: logging.NewNoopLogger(),
	}
	errCfg := stewardtypes.ErrorHandlingConfig{
		ModuleLoadFailure: stewardtypes.ActionContinue, ResourceFailure: stewardtypes.ActionWarn, ConfigurationError: stewardtypes.ActionFail,
	}
	// The factory is the one NewExecutor builds by default; it is created here only so
	// the test can stop the module processes it starts.
	mf := factory.New(discovery.ModuleRegistry{}, errCfg, logging.NewNoopLogger())
	mf.SetModuleRuntime(moduleruntime.NewModuleRuntimeWithEnforcer(shortDistRuntimeDir(f.t), enforcer), mode, additional)
	f.t.Cleanup(mf.UnloadAllModules)
	ex, err := execution.NewExecutor(&execution.ExecutorConfig{
		Logger:        logging.NewNoopLogger(),
		Factory:       mf,
		ErrorHandling: errCfg,
	})
	require.NoError(f.t, err)
	ex.SetModuleInstaller(inst)
	return &distSteward{installer: inst, executor: ex}
}

// applyBytes is the configuration the steward applies: the pushed required_modules
// and one resource of the pulled module.
func applyBytes(t *testing.T, module string, required ...stewardtypes.RequiredModule) []byte {
	t.Helper()
	data, err := json.Marshal(map[string]interface{}{
		"steward": map[string]interface{}{"id": "s", "logging": map[string]string{"level": "info"}},
		"resources": []map[string]interface{}{
			{"name": "uses-module", "module": module, "config": map[string]interface{}{"key": "value"}},
		},
		"required_modules": required,
	})
	require.NoError(t, err)
	return data
}

// treeSnapshot maps every path under root to the SHA-256 of its content ("dir" for directories).
func treeSnapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	snap := map[string]string{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if errors.Is(err, os.ErrNotExist) && path == root {
				return nil
			}
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if info.IsDir() {
			snap[rel] = "dir"
			return nil
		}
		data, rerr := os.ReadFile(path) // #nosec G304 -- walks the test-owned discovery root
		if rerr != nil {
			return rerr
		}
		sum := sha256.Sum256(data)
		snap[rel] = hex.EncodeToString(sum[:])
		return nil
	})
	require.NoError(t, err)
	delete(snap, ".")
	return snap
}

func requireNothingInstalled(t *testing.T, root string) {
	t.Helper()
	assert.Empty(t, treeSnapshot(t, root), "the steward's installed root holds neither a module nor a staging directory")
}

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

func TestModuleDistribution(t *testing.T) {
	tools := buildDistTools(t)
	req := requireModule(distPublisher, distModule, "1.0.0")

	// publish builds and tags a signed two-platform bundle of the module.
	publish := func(t *testing.T, f *distFixture, p publisher, version string, tamper func(string)) {
		t.Helper()
		commitBundleRoot(t, tools.buildBundle(t, p, distModule, version), filepath.Join(f.reposRoot, distModule), version, tamper)
	}

	// pullAndRun walks the steward half: apply, then assert the module ran.
	pullAndRun := func(t *testing.T, f *distFixture, s *distSteward, version string) {
		t.Helper()
		report, err := s.executor.ApplyConfiguration(context.Background(), applyBytes(t, distModule, requireModule(distPublisher, distModule, version)), "v1")
		require.NoError(t, err)
		require.Contains(t, report.Modules, distModule)
		assert.Equal(t, "OK", report.Modules[distModule].Status, "the pulled module ran: %v", report.Modules[distModule].Details)
		assert.Equal(t, 1, report.Modules[distModule].Details["success_count"])
		assert.Equal(t, "OK", report.Status)
		assertOwnPlatformTree(t, f.root, distPublisher, version)
	}

	t.Run("controller mode: publish, fetch, verify, approve, pull, install, execute", func(t *testing.T) {
		p := tools.keygen(t, distPublisher)
		f := newDistFixture(t, tools, []publisher{p}, distPublisher)
		publish(t, f, p, "1.0.0", nil)

		// Push is blocked: the module is fetched from the git source, verified
		// against the trusted publisher key and queued, not approved.
		err := f.push(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "requires approval")
		status, addr := f.cacheStatus(distModule, "1.0.0")
		assert.Equal(t, cache.ApprovalStatusPending, status)

		// A pending bundle cannot be fetched, even by a steward whose config names it.
		f.storeConfig(req)
		s := f.newSteward(stewardtypes.ModuleTrustModeController, stewardtrust.NewStewardTrustEnforcer())
		_, err = s.installer.Install(context.Background(), distPublisher, distModule, "1.0.0")
		require.ErrorIs(t, err, install.ErrFetchFailed)
		requireNothingInstalled(t, f.root)

		// The admin approves, push succeeds, the steward pulls, installs and runs it.
		require.NoError(t, f.workflow.Approve(addr))
		require.NoError(t, f.push(req))
		pullAndRun(t, f, s, "1.0.0")

		// The approved status is what the controller now serves.
		status, _ = f.cacheStatus(distModule, "1.0.0")
		assert.Equal(t, cache.ApprovalStatusApproved, status)
	})

	t.Run("strict mode: the supplied publisher key runs the module", func(t *testing.T) {
		p := tools.keygen(t, distPublisher)
		f := newDistFixture(t, tools, []publisher{p}, distPublisher)
		publish(t, f, p, "1.0.0", nil)
		require.Error(t, f.push(req))
		_, addr := f.cacheStatus(distModule, "1.0.0")
		require.NoError(t, f.workflow.Approve(addr))
		require.NoError(t, f.push(req))

		s := f.newSteward(stewardtypes.ModuleTrustModeStrict, stewardTrust(t, p), distPublisher)
		pullAndRun(t, f, s, "1.0.0")
	})

	t.Run("strict mode: a publisher the steward lacks fails closed though the controller approved it", func(t *testing.T) {
		p := tools.keygen(t, distPublisher)
		f := newDistFixture(t, tools, []publisher{p}, distPublisher)
		publish(t, f, p, "1.0.0", nil)
		require.Error(t, f.push(req))
		_, addr := f.cacheStatus(distModule, "1.0.0")
		require.NoError(t, f.workflow.Approve(addr))
		require.NoError(t, f.push(req))

		// The steward was built without this publisher's key, and names no additional publisher.
		s := f.newSteward(stewardtypes.ModuleTrustModeStrict, stewardTrust(t))
		_, err := s.installer.Install(context.Background(), distPublisher, distModule, "1.0.0")
		require.ErrorIs(t, err, install.ErrTrustRefused)
		requireNothingInstalled(t, f.root)

		// Through the executor: the dependent resource fails as a security failure.
		report, err := s.executor.ApplyConfiguration(context.Background(), applyBytes(t, distModule, req), "v1")
		require.NoError(t, err)
		assert.Equal(t, "ERROR", report.Modules[distModule].Status)
		assert.Contains(t, fmt.Sprint(report.Modules[distModule].Details["errors"]), "security failure")
		requireNothingInstalled(t, f.root)
	})

	t.Run("untrusted publisher approved by an admin is queued, unfetchable until approved, and refused by a strict steward", func(t *testing.T) {
		vendor := tools.keygen(t, "vendor-b")
		trusted := tools.keygen(t, distPublisher)
		f := newDistFixture(t, tools, []publisher{trusted}, "vendor-b")
		publish(t, f, vendor, "1.0.0", nil)
		vreq := requireModule("vendor-b", distModule, "1.0.0")

		err := f.push(vreq)
		require.Error(t, err)
		status, addr := f.cacheStatus(distModule, "1.0.0")
		assert.Equal(t, cache.ApprovalStatusPending, status, "an unknown publisher is queued, not rejected")

		f.storeConfig(vreq)
		strict := f.newSteward(stewardtypes.ModuleTrustModeStrict, stewardTrust(t, trusted), distPublisher)
		_, err = strict.installer.Install(context.Background(), "vendor-b", distModule, "1.0.0")
		require.ErrorIs(t, err, install.ErrFetchFailed, "not fetchable until approved")
		requireNothingInstalled(t, f.root)

		require.NoError(t, f.workflow.Approve(addr))
		_, err = strict.installer.Install(context.Background(), "vendor-b", distModule, "1.0.0")
		require.ErrorIs(t, err, install.ErrTrustRefused, "the controller approved it; the strict steward does not trust the publisher")
		requireNothingInstalled(t, f.root)
	})

	t.Run("an unsigned bundle is rejected at ingest, cannot be approved, and forced approved is refused by a strict steward", func(t *testing.T) {
		p := tools.keygen(t, distPublisher)
		f := newDistFixture(t, tools, []publisher{p}, distPublisher)
		commitBundleRoot(t, tools.buildUnsignedBundle(t, distPublisher, distModule, "1.0.0"), filepath.Join(f.reposRoot, distModule), "1.0.0", nil)

		require.Error(t, f.push(req), "a zero-signature bundle blocks the push")
		status, addr := f.cacheStatus(distModule, "1.0.0")
		assert.Equal(t, cache.ApprovalStatusRejected, status, "rejected at ingest")
		require.ErrorIs(t, f.workflow.Approve(addr), approval.ErrNoSignature)
		status, _ = f.cacheStatus(distModule, "1.0.0")
		assert.Equal(t, cache.ApprovalStatusRejected, status, "the failed approval changed nothing")

		// Forced past the workflow, the controller serves it; the steward is the last gate.
		ok, err := f.cache.CompareAndSetApprovalStatus(addr, cache.ApprovalStatusRejected, cache.ApprovalStatusApproved)
		require.NoError(t, err)
		require.True(t, ok)
		require.NoError(t, f.push(req))

		s := f.newSteward(stewardtypes.ModuleTrustModeStrict, stewardTrust(t, p), distPublisher)
		_, err = s.installer.Install(context.Background(), distPublisher, distModule, "1.0.0")
		require.ErrorIs(t, err, install.ErrTrustRefused)
		requireNothingInstalled(t, f.root)

		report, err := s.executor.ApplyConfiguration(context.Background(), applyBytes(t, distModule, req), "v1")
		require.NoError(t, err)
		assert.Equal(t, "ERROR", report.Modules[distModule].Status)
		requireNothingInstalled(t, f.root)
	})

	t.Run("bytes tampered after signing never reach the cache or the steward", func(t *testing.T) {
		tampers := map[string]func(repoDir string){
			"binary": func(repoDir string) {
				name := "cfgms-module-" + distModule
				if goruntime.GOOS == "windows" {
					name += ".exe"
				}
				path := filepath.Join(repoDir, name)
				data, err := os.ReadFile(path) // #nosec G304 -- test-owned repository
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(path, append(data, []byte("tampered")...), 0o755)) // #nosec G306 -- executable module fixture
			},
			"manifest": func(repoDir string) {
				path := filepath.Join(repoDir, "module.yaml")
				data, err := os.ReadFile(path) // #nosec G304 -- test-owned repository
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(path, append(data, []byte("# changed after signing\n")...), 0o600))
			},
		}
		for name, tamper := range tampers {
			t.Run(name, func(t *testing.T) {
				p := tools.keygen(t, distPublisher)
				f := newDistFixture(t, tools, []publisher{p}, distPublisher)
				publish(t, f, p, "1.0.0", tamper)

				_, err := f.resolver.Resolve(context.Background(), "acme-corp/widget@1.0.0")
				require.Error(t, err, "the resolver refuses bytes that do not match what was signed")
				err = f.push(req)
				require.Error(t, err)
				assert.Contains(t, err.Error(), "resolve module")
				f.requireCacheEmpty()

				f.storeConfig(req)
				s := f.newSteward(stewardtypes.ModuleTrustModeController, stewardtrust.NewStewardTrustEnforcer())
				_, err = s.installer.Install(context.Background(), distPublisher, distModule, "1.0.0")
				require.ErrorIs(t, err, install.ErrFetchFailed)
				requireNothingInstalled(t, f.root)
			})
		}
	})

	t.Run("hostile channel: what the steward receives is checked against what it asked for", func(t *testing.T) {
		own, other := ownPlatformKey(), otherPlatformKey()
		otherBytes, err := os.ReadFile(tools.otherBin) // #nosec G304 -- test-owned file
		require.NoError(t, err)

		cases := []struct {
			name    string
			rewrite func(*transportpb.FetchModuleBundleRequest)
			mutate  func() func(*transportpb.ModuleBundleChunk) bool
			// controllerRequires is the version the controller-side configuration lists; the
			// controller serves what that configuration requires, not what the steward asked.
			controllerRequires string
			want               error
		}{
			{
				name:               "a different validly signed version than requested",
				rewrite:            func(r *transportpb.FetchModuleBundleRequest) { r.Version = "2.0.0" },
				controllerRequires: "2.0.0",
				want:               install.ErrIdentityMismatch,
			},
			{
				name: "a different platform's binary",
				mutate: func() func(*transportpb.ModuleBundleChunk) bool {
					swapped := false
					return func(c *transportpb.ModuleBundleChunk) bool {
						if h := c.GetHeader(); h != nil {
							h.FileSize = int64(len(otherBytes))
							swapped = false // a new stream starts with its header
							return true
						}
						if !swapped {
							// The real binary spans several chunks; the other platform's bytes replace them all.
							c.Data, c.Final = otherBytes, true
							swapped = true
							return true
						}
						return false
					}
				},
				want: install.ErrBinaryDigestMismatch,
			},
			{
				name: "swapped digests",
				mutate: func() func(*transportpb.ModuleBundleChunk) bool {
					return func(c *transportpb.ModuleBundleChunk) bool {
						if h := c.GetHeader(); h != nil {
							h.BinaryDigests[own], h.BinaryDigests[other] = h.BinaryDigests[other], h.BinaryDigests[own]
						}
						return true
					}
				},
				want: install.ErrBinaryDigestMismatch,
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				p := tools.keygen(t, distPublisher)
				f := newDistFixture(t, tools, []publisher{p}, distPublisher)
				publish(t, f, p, "1.0.0", nil)
				publish(t, f, p, "2.0.0", nil)
				for _, v := range []string{"1.0.0", "2.0.0"} {
					require.Error(t, f.push(requireModule(distPublisher, distModule, v)))
					_, addr := f.cacheStatus(distModule, v)
					require.NoError(t, f.workflow.Approve(addr))
				}
				if tc.controllerRequires == "" {
					tc.controllerRequires = "1.0.0"
				}
				require.NoError(t, f.push(requireModule(distPublisher, distModule, tc.controllerRequires)))

				before := treeSnapshot(t, f.root)
				var mutate func(*transportpb.ModuleBundleChunk) bool
				if tc.mutate != nil {
					mutate = tc.mutate()
				}
				f.setHostile(tc.rewrite, mutate)

				s := f.newSteward(stewardtypes.ModuleTrustModeController, stewardtrust.NewStewardTrustEnforcer())
				_, err := s.installer.Install(context.Background(), distPublisher, distModule, "1.0.0")
				require.ErrorIs(t, err, tc.want)
				assert.NotContains(t, err.Error(), f.root, "errors carry no filesystem path")
				assert.Equal(t, before, treeSnapshot(t, f.root), "the installed root is unchanged")
				requireNothingInstalled(t, f.root)

				// The same channel through the executor: a security failure, nothing installed.
				report, err := s.executor.ApplyConfiguration(context.Background(), applyBytes(t, distModule, req), "v1")
				require.NoError(t, err)
				assert.Equal(t, "ERROR", report.Modules[distModule].Status)
				assert.Contains(t, fmt.Sprint(report.Modules[distModule].Details["errors"]), "security failure")
				requireNothingInstalled(t, f.root)
			})
		}
	})

	t.Run("a binary modified after install does not run", func(t *testing.T) {
		p := tools.keygen(t, distPublisher)
		f := newDistFixture(t, tools, []publisher{p}, distPublisher)
		publish(t, f, p, "1.0.0", nil)
		require.Error(t, f.push(req))
		_, addr := f.cacheStatus(distModule, "1.0.0")
		require.NoError(t, f.workflow.Approve(addr))
		require.NoError(t, f.push(req))

		s := f.newSteward(stewardtypes.ModuleTrustModeController, stewardtrust.NewStewardTrustEnforcer())
		_, err := s.installer.Install(context.Background(), distPublisher, distModule, "1.0.0")
		require.NoError(t, err)

		// An attacker with write access replaces the installed binary before the module starts.
		ran := filepath.Join(t.TempDir(), "ran")
		binPath := filepath.Join(f.root, distModule, exeName("cfgms-module-"+distModule))
		require.NoError(t, os.Chmod(binPath, 0o700)) // #nosec G302 -- test-owned file, made writable to model tampering
		require.NoError(t, os.WriteFile(binPath, []byte("#!/bin/sh\ntouch '"+ran+"'\n"), 0o700))

		// A restarted steward that cannot reach the controller finds the module installed
		// and starts it: the pre-exec verification refuses the modified binary.
		offline := f.newSteward(stewardtypes.ModuleTrustModeController, stewardtrust.NewStewardTrustEnforcer())
		offline.executor.SetModuleInstaller(nil)
		report, err := offline.executor.ApplyConfiguration(context.Background(), applyBytes(t, distModule, req), "v1")
		require.NoError(t, err)
		// The module fails to load, so its resource is skipped rather than converged.
		assert.Equal(t, 0, report.Modules[distModule].Details["success_count"], "a modified binary is not started: %v", report.Modules[distModule].Details)
		assert.NoFileExists(t, ran, "the modified binary never executed")

		// With the controller reachable the tree no longer verifies, so it is replaced by
		// the verified bundle and the module runs from the restored binary.
		healed := f.newSteward(stewardtypes.ModuleTrustModeController, stewardtrust.NewStewardTrustEnforcer())
		report, err = healed.executor.ApplyConfiguration(context.Background(), applyBytes(t, distModule, req), "v1")
		require.NoError(t, err)
		assert.Equal(t, 1, report.Modules[distModule].Details["success_count"], "%v", report.Modules[distModule].Details)
		assert.NoFileExists(t, ran, "the modified binary never executed")
		assertOwnPlatformTree(t, f.root, distPublisher, "1.0.0")
		assert.NoError(t, bundle.VerifyInstalled(filepath.Join(f.root, distModule), ownPlatformKey()))
	})
}

// assertOwnPlatformTree requires that the installed tree is exactly the steward's
// own platform binary plus the manifest and the sidecar, and that the sidecar still
// carries the digest of every platform.
func assertOwnPlatformTree(t *testing.T, root, publisherName, version string) {
	t.Helper()
	dir := filepath.Join(root, distModule)
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	wantBin := "cfgms-module-" + distModule
	if goruntime.GOOS == "windows" {
		wantBin += ".exe"
	}
	want := []string{"bundle.yaml", "module.yaml", wantBin}
	sort.Strings(want)
	assert.Equal(t, want, names, "the installed tree holds only the own platform's binary")

	b, err := bundle.ReadInstalled(dir)
	require.NoError(t, err)
	assert.Equal(t, publisherName, b.Manifest.Publisher)
	assert.Equal(t, version, b.Manifest.Version)
	assert.Len(t, b.BinaryDigests, 2, "the full digest list is kept")
	assert.Contains(t, b.BinaryDigests, ownPlatformKey())
	assert.Contains(t, b.BinaryDigests, otherPlatformKey())
	assert.Contains(t, b.Binaries, ownPlatformKey())
	assert.NotContains(t, b.Binaries, otherPlatformKey(), "the other platform's binary is not installed")
}
