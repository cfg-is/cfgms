// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package execution_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"sync"
	"sync/atomic"
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
	"github.com/cfgis/cfgms/features/controller/service"
	controllertransport "github.com/cfgis/cfgms/features/controller/transport"
	"github.com/cfgis/cfgms/features/steward/execution"
	"github.com/cfgis/cfgms/features/steward/modules/install"
	moduleruntime "github.com/cfgis/cfgms/features/steward/modules/runtime"
	stewardtrust "github.com/cfgis/cfgms/features/steward/modules/trust"
	cfgcert "github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	pkgtrust "github.com/cfgis/cfgms/pkg/modules/trust"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
	"github.com/cfgis/cfgms/pkg/testutil"
)

const rmStewardID = "steward-required-modules"

var (
	moduleBuildOnce sync.Once
	moduleBinPath   string
	moduleBuildErr  error
)

// requiredModuleBytes builds (once) the real yaml_module test binary and
// returns its bytes, so the published bundle carries a runnable module.
func requiredModuleBytes(t *testing.T) []byte {
	t.Helper()
	moduleBuildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "exec-required-modules-*")
		if err != nil {
			moduleBuildErr = err
			return
		}
		moduleBinPath = filepath.Join(dir, "yaml_module")
		if goruntime.GOOS == "windows" {
			moduleBinPath += ".exe"
		}
		if out, err := exec.Command("go", "build", "-o", moduleBinPath, "./testdata/yaml_module").CombinedOutput(); err != nil {
			moduleBuildErr = fmt.Errorf("build yaml_module: %s: %w", out, err)
		}
	})
	require.NoError(t, moduleBuildErr)
	data, err := os.ReadFile(moduleBinPath)
	require.NoError(t, err)
	return data
}

// rmFixture serves the REAL FetchModuleBundle handler over a real ModuleCache
// loaded through ApprovalWorkflow, in-process over gRPC.
type rmFixture struct {
	t        *testing.T
	workflow *approval.ApprovalWorkflow
	cfgSvc   *service.ConfigurationServiceV2
	client   transportpb.StewardTransportClient
	root     string
	fetches  atomic.Int32
}

type countingService struct {
	transportpb.UnimplementedStewardTransportServer
	f       *rmFixture
	handler *controllertransport.ModuleBundleHandler
	ctx     context.Context
}

func (s *countingService) FetchModuleBundle(req *transportpb.FetchModuleBundleRequest, stream grpc.ServerStreamingServer[transportpb.ModuleBundleChunk]) error {
	s.f.fetches.Add(1)
	return s.handler.HandleGRPC(s.ctx, req, &ctxStream{ServerStreamingServer: stream, ctx: s.ctx})
}

type ctxStream struct {
	grpc.ServerStreamingServer[transportpb.ModuleBundleChunk]
	ctx context.Context
}

func (s *ctxStream) Context() context.Context { return s.ctx }

func newRMFixture(t *testing.T) *rmFixture {
	t.Helper()
	sm := pkgtesting.SetupTestStorage(t)
	ctrl := service.NewControllerService(logging.NewNoopLogger())
	cfgSvc := service.NewConfigurationServiceV2(logging.NewNoopLogger(), sm, ctrl)
	require.NoError(t, sm.GetTenantStore().CreateTenant(ctxkeys.WithSystem(context.Background()),
		&business.TenantData{ID: "tenant-x", Name: "tenant-x", Status: business.TenantStatusActive}))

	mc, err := cache.New(filepath.Join(t.TempDir(), "module-cache"))
	require.NoError(t, err)
	mc.SetApprovalStore(pkgtesting.SetupTestModuleApprovalStore())

	ca, err := cfgcert.NewCA(&cfgcert.CAConfig{Organization: "CFGMS Required Modules Test", Country: "US", ValidityDays: 1, KeySize: 2048})
	require.NoError(t, err)
	require.NoError(t, ca.Initialize(nil))
	cert, err := ca.GenerateClientCertificate(&cfgcert.ClientCertConfig{CommonName: rmStewardID, ValidityDays: 1, KeySize: 2048})
	require.NoError(t, err)
	block, _ := pem.Decode(cert.CertificatePEM)
	require.NotNil(t, block)
	x509Cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	peerCtx := peer.NewContext(ctxkeys.WithSystem(context.Background()), &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{x509Cert}, VerifiedChains: [][]*x509.Certificate{{x509Cert}}, HandshakeComplete: true,
	}}})

	f := &rmFixture{t: t, workflow: approval.New(mc), cfgSvc: cfgSvc, root: filepath.Join(t.TempDir(), "modules")}
	svc := &countingService{
		f:       f,
		ctx:     peerCtx,
		handler: controllertransport.NewModuleBundleHandler(mc, cfgSvc, ctrl, controllertransport.NewTenantQueue(), logging.NewNoopLogger()),
	}
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	transportpb.RegisterStewardTransportServer(srv, svc)
	go func() { _ = srv.Serve(lis) }()
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close(); srv.Stop() })
	f.client = transportpb.NewStewardTransportClient(conn)
	require.NoError(t, ctrl.RegisterSteward(rmStewardID, "tenant-x", "localhost:4433", "connected"))

	t.Setenv(install.BundleDirEnvVar, f.root)
	return f
}

// publish signs, ingests and approves a bundle of the real echo module, and
// records it as required by the steward's configuration.
func (f *rmFixture) publish(publisher, name, version string) {
	f.t.Helper()
	own := goruntime.GOOS + "-" + goruntime.GOARCH
	sb := testutil.NewSignedBundle(f.t, testutil.BundleOptions{
		Publisher: publisher, Name: name, Version: version,
		BinaryContent: map[string][]byte{own: requiredModuleBytes(f.t)},
	})
	_, err := f.workflow.EvaluateAndStore(sb.Bundle, pkgtrust.NewInMemoryTrustStore())
	require.NoError(f.t, err)
	require.NoError(f.t, f.workflow.Approve(sb.ContentAddress()))
	cfg := &stewardtypes.StewardConfig{
		Steward: stewardtypes.StewardSettings{
			ID: rmStewardID, Logging: stewardtypes.LoggingConfig{Level: "info"},
			ErrorHandling: stewardtypes.ErrorHandlingConfig{
				ModuleLoadFailure: stewardtypes.ActionContinue, ResourceFailure: stewardtypes.ActionWarn, ConfigurationError: stewardtypes.ActionFail,
			},
		},
		Modules:         map[string]string{"directory": "directory"},
		Resources:       []stewardtypes.ResourceConfig{{Name: "d", Module: "directory", Config: map[string]interface{}{"path": "/tmp/x", "permissions": "755"}}},
		RequiredModules: []stewardtypes.RequiredModule{{Name: publisher + "/" + name, Version: version}},
	}
	require.NoError(f.t, f.cfgSvc.SetConfiguration(ctxkeys.WithSystem(context.Background()), "tenant-x", rmStewardID, cfg))
}

func (f *rmFixture) installer(mode stewardtypes.ModuleTrustMode) *install.Installer {
	return &install.Installer{Root: f.root, Mode: mode, Enforcer: stewardtrust.NewStewardTrustEnforcer(), Client: f.client}
}

func shortRuntimeDir(t *testing.T) string {
	t.Helper()
	if goruntime.GOOS == "windows" {
		return t.TempDir()
	}
	base, err := os.MkdirTemp("/tmp", "cfgms-exec-rt-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	return base
}

func newRMExecutor(t *testing.T, mode stewardtypes.ModuleTrustMode, installer execution.ModuleInstaller) *execution.Executor {
	t.Helper()
	ex, err := execution.NewExecutor(&execution.ExecutorConfig{
		Logger:          logging.NewNoopLogger(),
		ModuleRuntime:   moduleruntime.NewModuleRuntime(shortRuntimeDir(t)),
		ModuleTrustMode: mode,
	})
	require.NoError(t, err)
	t.Cleanup(func() { execution.ExecutorFactory(ex).UnloadAllModules() })
	if installer != nil {
		ex.SetModuleInstaller(installer)
	}
	return ex
}

// rmConfig builds a config with the given required modules, one resource using
// module `used` and a sibling directory resource.
func rmConfig(t *testing.T, siblingDir string, used string, required ...stewardtypes.RequiredModule) []byte {
	t.Helper()
	siblingCfg := map[string]interface{}{
		"type": "directory", "allowed_base_path": filepath.Dir(siblingDir), "path": siblingDir,
	}
	if goruntime.GOOS != "windows" {
		// NTFS has no Unix permission bits; the directory module rejects them there.
		siblingCfg["permissions"] = 493
	}
	cfg := map[string]interface{}{
		"steward": map[string]interface{}{"id": "s", "logging": map[string]string{"level": "info"}},
		"resources": []map[string]interface{}{
			{"name": "uses-module", "module": used, "config": map[string]interface{}{"key": "value"}},
			{"name": "sibling", "module": "directory", "config": siblingCfg},
		},
		"required_modules": required,
	}
	data, err := json.Marshal(cfg)
	require.NoError(t, err)
	return data
}

func TestApplyConfiguration_PullsMissingRequiredModule(t *testing.T) {
	f := newRMFixture(t)
	f.publish("acme-corp", "widget", "1.0.0")
	req := stewardtypes.RequiredModule{Name: "acme-corp/widget", Version: "1.0.0"}
	ex := newRMExecutor(t, stewardtypes.ModuleTrustModeController, f.installer(stewardtypes.ModuleTrustModeController))
	sibling := filepath.Join(t.TempDir(), "sibling")
	cfgBytes := rmConfig(t, sibling, "widget", req)

	report, err := ex.ApplyConfiguration(context.Background(), cfgBytes, "v1")
	require.NoError(t, err)
	assert.Equal(t, int32(1), f.fetches.Load(), "the missing module is fetched once")
	require.Contains(t, report.Modules, "widget")
	assert.Equal(t, "OK", report.Modules["widget"].Status, "the pulled module's resource converges in the same apply: %v", report.Modules["widget"].Details)
	assert.Equal(t, "OK", report.Status)
	assert.DirExists(t, sibling)

	// Applying again with the module present performs no fetch.
	report, err = ex.ApplyConfiguration(context.Background(), cfgBytes, "v1")
	require.NoError(t, err)
	assert.Equal(t, int32(1), f.fetches.Load(), "an installed module is not fetched again")
	assert.Equal(t, "OK", report.Status)
}

func TestApplyConfiguration_FailedPullFailsOnlyDependentResources(t *testing.T) {
	f := newRMFixture(t)
	f.publish("acme-corp", "widget", "1.0.0")
	// Version 2.0.0 was never published.
	req := stewardtypes.RequiredModule{Name: "acme-corp/widget", Version: "2.0.0"}
	ex := newRMExecutor(t, stewardtypes.ModuleTrustModeController, f.installer(stewardtypes.ModuleTrustModeController))
	sibling := filepath.Join(t.TempDir(), "sibling")

	report, err := ex.ApplyConfiguration(context.Background(), rmConfig(t, sibling, "widget", req), "v1")
	require.NoError(t, err)
	assert.Equal(t, "ERROR", report.Status)
	assert.Equal(t, "ERROR", report.Modules["widget"].Status)
	assert.Contains(t, fmt.Sprint(report.Modules["widget"].Details["errors"]), "acme-corp/widget@2.0.0")
	assert.Equal(t, "OK", report.Modules["directory"].Status, "sibling resources still converge")
	assert.DirExists(t, sibling)
}

func TestApplyConfiguration_StrictUntrustedPublisherFailsDependentOnly(t *testing.T) {
	f := newRMFixture(t)
	f.publish("acme-corp", "widget", "1.0.0")
	req := stewardtypes.RequiredModule{Name: "acme-corp/widget", Version: "1.0.0"}
	// Strict mode, acme-corp is not an additional trusted publisher.
	ex := newRMExecutor(t, stewardtypes.ModuleTrustModeStrict, f.installer(stewardtypes.ModuleTrustModeStrict))
	sibling := filepath.Join(t.TempDir(), "sibling")
	cfgBytes := rmConfig(t, sibling, "widget", req)

	report, err := ex.ApplyConfiguration(context.Background(), cfgBytes, "v1")
	require.NoError(t, err)
	assert.Equal(t, "ERROR", report.Modules["widget"].Status)
	assert.Contains(t, fmt.Sprint(report.Modules["widget"].Details["errors"]), "security failure")
	assert.Equal(t, "OK", report.Modules["directory"].Status)
	assert.DirExists(t, sibling)
	entries, _ := os.ReadDir(f.root)
	assert.Empty(t, entries, "nothing is installed")

	// Not retried by a convergence re-run of the same configuration.
	fetched := f.fetches.Load()
	_, err = ex.ApplyConfiguration(context.Background(), cfgBytes, "v1")
	require.NoError(t, err)
	assert.Equal(t, fetched, f.fetches.Load(), "a security refusal is not retried until the next config apply")
}

func TestApplyConfiguration_StdlibRequiredModuleIsNotFetched(t *testing.T) {
	f := newRMFixture(t)
	req := stewardtypes.RequiredModule{Name: "acme-corp/file", Version: "1.0.0"}
	ex := newRMExecutor(t, stewardtypes.ModuleTrustModeController, f.installer(stewardtypes.ModuleTrustModeController))
	sibling := filepath.Join(t.TempDir(), "sibling")

	report, err := ex.ApplyConfiguration(context.Background(), rmConfig(t, sibling, "file", req), "v1")
	require.NoError(t, err)
	assert.Equal(t, int32(0), f.fetches.Load(), "a stdlib name triggers no fetch")
	assert.Equal(t, "ERROR", report.Modules["file"].Status)
	assert.Contains(t, fmt.Sprint(report.Modules["file"].Details["errors"]), "provided by the installer, not by required_modules")
	assert.Equal(t, "OK", report.Modules["directory"].Status)
}

func TestApplyConfiguration_RequiredModuleInstalledByOtherPublisherFails(t *testing.T) {
	f := newRMFixture(t)
	f.publish("acme-corp", "widget", "1.0.0")
	ex := newRMExecutor(t, stewardtypes.ModuleTrustModeController, f.installer(stewardtypes.ModuleTrustModeController))
	sibling := filepath.Join(t.TempDir(), "sibling")
	good := stewardtypes.RequiredModule{Name: "acme-corp/widget", Version: "1.0.0"}
	_, err := ex.ApplyConfiguration(context.Background(), rmConfig(t, sibling, "widget", good), "v1")
	require.NoError(t, err)

	other := stewardtypes.RequiredModule{Name: "vendor-a/widget", Version: "1.0.0"}
	report, err := ex.ApplyConfiguration(context.Background(), rmConfig(t, sibling, "widget", other), "v2")
	require.NoError(t, err)
	assert.Equal(t, "ERROR", report.Modules["widget"].Status, "a module installed under another publisher is a failure, not skipped")
}

func TestApplyConfiguration_NoInstallerLeavesBehaviourUnchanged(t *testing.T) {
	_ = newRMFixture(t) // sets an empty bundle dir
	ex := newRMExecutor(t, stewardtypes.ModuleTrustModeController, nil)
	sibling := filepath.Join(t.TempDir(), "sibling")
	req := stewardtypes.RequiredModule{Name: "acme-corp/widget", Version: "1.0.0"}

	report, err := ex.ApplyConfiguration(context.Background(), rmConfig(t, sibling, "widget", req), "v1")
	require.NoError(t, err)
	assert.NotContains(t, fmt.Sprint(report.Modules["widget"].Details["errors"]), "required module")
	entries, _ := os.ReadDir(os.Getenv(install.BundleDirEnvVar))
	assert.Empty(t, entries, "nothing is installed without an installer")
	assert.Equal(t, "OK", report.Modules["directory"].Status)
}
