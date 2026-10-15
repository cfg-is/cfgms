// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package install

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"runtime"
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
	"github.com/cfgis/cfgms/features/controller/service"
	controllertransport "github.com/cfgis/cfgms/features/controller/transport"
	"github.com/cfgis/cfgms/features/steward/modules/trust"
	cfgcert "github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/modules/bundle"
	pkgtrust "github.com/cfgis/cfgms/pkg/modules/trust"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
	"github.com/cfgis/cfgms/pkg/testutil"
)

const testStewardID = "steward-install"

// ---------------------------------------------------------------------------
// Fixture: the REAL FetchModuleBundle handler over a real ModuleCache loaded
// through ApprovalWorkflow, served in-process over gRPC. A hostile channel is a
// hook that mutates the real handler's stream in transit.
// ---------------------------------------------------------------------------

type fixture struct {
	t        *testing.T
	cache    *cache.ModuleCache
	workflow *approval.ApprovalWorkflow
	ctrl     *service.ControllerService
	cfgSvc   *service.ConfigurationServiceV2
	handler  *controllertransport.ModuleBundleHandler
	peerCtx  context.Context
	client   transportpb.StewardTransportClient
	root     string

	mu sync.Mutex
	// rewriteReq, when set, changes the request before the real handler sees it.
	rewriteReq func(*transportpb.FetchModuleBundleRequest)
	// mutate, when set, changes each chunk in transit; returning false drops it.
	mutate func(*transportpb.ModuleBundleChunk) bool
}

type hostileService struct {
	transportpb.UnimplementedStewardTransportServer
	f *fixture
}

type mutatingStream struct {
	grpc.ServerStreamingServer[transportpb.ModuleBundleChunk]
	ctx    context.Context
	mutate func(*transportpb.ModuleBundleChunk) bool
}

func (s *mutatingStream) Context() context.Context { return s.ctx }
func (s *mutatingStream) Send(c *transportpb.ModuleBundleChunk) error {
	if s.mutate != nil && !s.mutate(c) {
		return nil
	}
	return s.ServerStreamingServer.Send(c)
}

func (h *hostileService) FetchModuleBundle(req *transportpb.FetchModuleBundleRequest, stream grpc.ServerStreamingServer[transportpb.ModuleBundleChunk]) error {
	h.f.mu.Lock()
	rewrite, mutate := h.f.rewriteReq, h.f.mutate
	h.f.mu.Unlock()
	if rewrite != nil {
		rewrite(req)
	}
	ctx := h.f.peerCtx
	return h.f.handler.HandleGRPC(ctx, req, &mutatingStream{ServerStreamingServer: stream, ctx: ctx, mutate: mutate})
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	sm := pkgtesting.SetupTestStorage(t)
	ctrl := service.NewControllerService(logging.NewNoopLogger())
	cfgSvc := service.NewConfigurationServiceV2(logging.NewNoopLogger(), sm, ctrl)
	require.NoError(t, sm.GetTenantStore().CreateTenant(ctxkeys.WithSystem(context.Background()),
		&business.TenantData{ID: "tenant-x", Name: "tenant-x", Status: business.TenantStatusActive}))

	mc, err := cache.New(filepath.Join(t.TempDir(), "module-cache"))
	require.NoError(t, err)
	mc.SetApprovalStore(pkgtesting.SetupTestModuleApprovalStore())

	ca, err := cfgcert.NewCA(&cfgcert.CAConfig{Organization: "CFGMS Install Test", Country: "US", ValidityDays: 1, KeySize: 2048})
	require.NoError(t, err)
	require.NoError(t, ca.Initialize(nil))
	cert, err := ca.GenerateClientCertificate(&cfgcert.ClientCertConfig{CommonName: testStewardID, ValidityDays: 1, KeySize: 2048})
	require.NoError(t, err)
	block, _ := pem.Decode(cert.CertificatePEM)
	require.NotNil(t, block)
	x509Cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	peerCtx := peer.NewContext(ctxkeys.WithSystem(context.Background()), &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{x509Cert}, VerifiedChains: [][]*x509.Certificate{{x509Cert}}, HandshakeComplete: true,
	}}})

	f := &fixture{
		t: t, cache: mc, workflow: approval.New(mc), ctrl: ctrl, cfgSvc: cfgSvc, peerCtx: peerCtx,
		handler: controllertransport.NewModuleBundleHandler(mc, cfgSvc, ctrl, controllertransport.NewTenantQueue(), logging.NewNoopLogger()),
		root:    filepath.Join(t.TempDir(), "modules"),
	}

	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	transportpb.RegisterStewardTransportServer(srv, &hostileService{f: f})
	go func() { _ = srv.Serve(lis) }()
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close(); srv.Stop() })
	f.client = transportpb.NewStewardTransportClient(conn)

	require.NoError(t, ctrl.RegisterSteward(testStewardID, "tenant-x", "localhost:4433", "connected"))
	return f
}

// ingest puts a signed two-platform bundle through the real ApprovalWorkflow and
// approves it. The own platform is always one of the two.
func (f *fixture) ingest(opts testutil.BundleOptions) *testutil.SignedBundle {
	f.t.Helper()
	sb := f.ingestPending(opts)
	require.NoError(f.t, f.workflow.Approve(sb.ContentAddress()))
	return sb
}

func otherPlatform() string {
	if ownPlatform() == "linux-amd64" {
		return "windows-amd64"
	}
	return "linux-amd64"
}

func (f *fixture) ingestPending(opts testutil.BundleOptions) *testutil.SignedBundle {
	f.t.Helper()
	if opts.Publisher == "" {
		opts.Publisher = "acme-corp"
	}
	if opts.Name == "" {
		opts.Name = "widget"
	}
	if opts.Platforms == nil {
		opts.Platforms = []string{ownPlatform(), otherPlatform()}
	}
	sb := testutil.NewSignedBundle(f.t, opts)
	_, err := f.workflow.EvaluateAndStore(sb.Bundle, pkgtrust.NewInMemoryTrustStore())
	require.NoError(f.t, err)
	return sb
}

// forceApprove sets approved through CompareAndSetApprovalStatus (never Approve),
// whatever status EvaluateAndStore recorded.
func (f *fixture) forceApprove(sb *testutil.SignedBundle) {
	f.t.Helper()
	cur, err := f.cache.GetApprovalStatus(sb.ContentAddress())
	require.NoError(f.t, err)
	if cur == cache.ApprovalStatusApproved {
		return
	}
	ok, err := f.cache.CompareAndSetApprovalStatus(sb.ContentAddress(), cur, cache.ApprovalStatusApproved)
	require.NoError(f.t, err)
	require.True(f.t, ok)
}

// require records the modules the steward's configuration requires.
func (f *fixture) require(mods ...stewardtypes.RequiredModule) {
	f.t.Helper()
	cfg := &stewardtypes.StewardConfig{
		Steward: stewardtypes.StewardSettings{
			ID:      testStewardID,
			Logging: stewardtypes.LoggingConfig{Level: "info"},
			ErrorHandling: stewardtypes.ErrorHandlingConfig{
				ModuleLoadFailure: stewardtypes.ActionContinue, ResourceFailure: stewardtypes.ActionWarn, ConfigurationError: stewardtypes.ActionFail,
			},
		},
		Modules:         map[string]string{"directory": "directory"},
		Resources:       []stewardtypes.ResourceConfig{{Name: "d", Module: "directory", Config: map[string]interface{}{"path": "/tmp/x", "permissions": "755"}}},
		RequiredModules: mods,
	}
	require.NoError(f.t, f.cfgSvc.SetConfiguration(ctxkeys.WithSystem(context.Background()), "tenant-x", testStewardID, cfg))
}

func (f *fixture) setMutate(fn func(*transportpb.ModuleBundleChunk) bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mutate = fn
}

// onHeader mutates only the header frame.
func onHeader(fn func(*transportpb.ModuleBundleHeader)) func(*transportpb.ModuleBundleChunk) bool {
	return func(c *transportpb.ModuleBundleChunk) bool {
		if c.GetHeader() != nil {
			fn(c.GetHeader())
		}
		return true
	}
}

func (f *fixture) installer(mode stewardtypes.ModuleTrustMode, enforcer *trust.StewardTrustEnforcer, additional ...string) *Installer {
	if enforcer == nil {
		enforcer = trust.NewStewardTrustEnforcer()
	}
	return &Installer{Root: f.root, Mode: mode, AdditionalPublisherNames: additional, Enforcer: enforcer, Client: f.client}
}

func widget(version string) stewardtypes.RequiredModule {
	return stewardtypes.RequiredModule{Name: "acme-corp/widget", Version: version}
}

// assertNothingInstalled requires that no module tree and no staging directory
// exists under the root.
func assertNothingInstalled(t *testing.T, root string) {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		require.ErrorIs(t, err, os.ErrNotExist)
		return
	}
	assert.Empty(t, entries, "discovery root must hold neither a module nor a staging directory")
}

func assertNoPath(t *testing.T, err error, root string) {
	t.Helper()
	require.Error(t, err)
	assert.NotContains(t, err.Error(), root, "errors carry no filesystem path")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// [REQUIRED TEST] fixture provenance + the happy path: the installed root is one
// binary that ReadInstalledPayload and DiscoverInstalled accept.
func TestInstall_InstallsOwnPlatformOnly(t *testing.T) {
	f := newFixture(t)
	sb := f.ingest(testutil.BundleOptions{Version: "1.0.0"})
	f.require(widget("1.0.0"))

	res, err := f.installer(stewardtypes.ModuleTrustModeController, nil).Install(context.Background(), "acme-corp", "widget", "1.0.0")
	require.NoError(t, err)
	assert.True(t, res.Changed)
	assert.Equal(t, sb.ContentHash, res.ContentHash)

	dir := filepath.Join(f.root, "widget")
	got, err := bundle.ReadInstalledPayload(dir, bundle.ReadOptions{Platform: ownPlatform()})
	require.NoError(t, err)
	assert.Equal(t, sb.ContentHash, got.ContentHash)
	assert.Equal(t, sb.BinaryContent[ownPlatform()], got.BinaryContent[ownPlatform()])
	assert.Len(t, got.BinaryContent, 1, "only the own platform's binary is installed")

	found, err := bundle.DiscoverInstalled(f.root)
	require.NoError(t, err)
	require.Contains(t, found, "widget")

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Len(t, entries, 3, "module.yaml, bundle.yaml and one binary")
	rootEntries, err := os.ReadDir(f.root)
	require.NoError(t, err)
	assert.Len(t, rootEntries, 1, "no staging leftovers")

	require.NoError(t, CheckProtectedTree(f.root))
}

// [REQUIRED TEST] hostile channel, every case in controller mode (the content
// hash is recomputed in all modes) and nothing is installed.
func TestInstall_HostileChannel(t *testing.T) {
	own, other := ownPlatform(), otherPlatform()
	cases := []struct {
		name    string
		mutate  func(f *fixture, sb *testutil.SignedBundle) func(*transportpb.ModuleBundleChunk) bool
		rewrite func(*transportpb.FetchModuleBundleRequest)
		require string // version the configuration requires; default 1.0.0
		want    error
	}{
		{
			name: "controller sends a different platform's binary",
			mutate: func(f *fixture, sb *testutil.SignedBundle) func(*transportpb.ModuleBundleChunk) bool {
				swapped := false
				return func(c *transportpb.ModuleBundleChunk) bool {
					if h := c.GetHeader(); h != nil {
						h.FileSize = int64(len(sb.BinaryContent[other]))
						return true
					}
					if !swapped {
						c.Data = sb.BinaryContent[other]
						swapped = true
						return true
					}
					return false
				}
			},
			want: ErrBinaryDigestMismatch,
		},
		{
			name: "digests swapped between two platforms",
			mutate: func(*fixture, *testutil.SignedBundle) func(*transportpb.ModuleBundleChunk) bool {
				return onHeader(func(h *transportpb.ModuleBundleHeader) {
					h.BinaryDigests[own], h.BinaryDigests[other] = h.BinaryDigests[other], h.BinaryDigests[own]
				})
			},
			want: ErrBinaryDigestMismatch,
		},
		{
			name: "tampered bytes",
			mutate: func(*fixture, *testutil.SignedBundle) func(*transportpb.ModuleBundleChunk) bool {
				return func(c *transportpb.ModuleBundleChunk) bool {
					if len(c.GetData()) > 0 {
						c.Data[0] ^= 0xff
					}
					return true
				}
			},
			want: ErrBinaryDigestMismatch,
		},
		{
			name: "tampered manifest",
			mutate: func(*fixture, *testutil.SignedBundle) func(*transportpb.ModuleBundleChunk) bool {
				return onHeader(func(h *transportpb.ModuleBundleHeader) { h.Manifest = append(h.Manifest, '#') })
			},
			want: ErrContentHashMismatch,
		},
		{
			name: "header hash disagrees with the recomputed hash",
			mutate: func(*fixture, *testutil.SignedBundle) func(*transportpb.ModuleBundleChunk) bool {
				return onHeader(func(h *transportpb.ModuleBundleHeader) { h.ContentHash = strings.Repeat("0", 64) })
			},
			want: ErrContentHashMismatch,
		},
		{
			name:    "a different validly signed version than requested",
			rewrite: func(r *transportpb.FetchModuleBundleRequest) { r.Version = "2.0.0" },
			require: "2.0.0", // the controller serves what the steward's config requires, not what was asked
			want:    ErrIdentityMismatch,
		},
		{
			name: "digest list without the own platform",
			mutate: func(*fixture, *testutil.SignedBundle) func(*transportpb.ModuleBundleChunk) bool {
				return onHeader(func(h *transportpb.ModuleBundleHeader) { delete(h.BinaryDigests, own) })
			},
			want: ErrDigestListInvalid,
		},
		{
			name: "digest list with a key outside the allowlist",
			mutate: func(*fixture, *testutil.SignedBundle) func(*transportpb.ModuleBundleChunk) bool {
				return onHeader(func(h *transportpb.ModuleBundleHeader) { h.BinaryDigests["plan9-386"] = h.BinaryDigests[own] })
			},
			want: ErrDigestListInvalid,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			sb := f.ingest(testutil.BundleOptions{Version: "1.0.0"})
			f.ingest(testutil.BundleOptions{Version: "2.0.0"})
			if tc.require == "" {
				tc.require = "1.0.0"
			}
			f.require(widget(tc.require))
			if tc.mutate != nil {
				f.setMutate(tc.mutate(f, sb))
			}
			f.rewriteReq = tc.rewrite

			_, err := f.installer(stewardtypes.ModuleTrustModeController, nil).Install(context.Background(), "acme-corp", "widget", "1.0.0")
			require.ErrorIs(t, err, tc.want)
			assertNoPath(t, err, f.root)
			assertNothingInstalled(t, f.root)
		})
	}
}

// [REQUIRED TEST] strict mode is the only gate: no controller attestation is read.
func TestInstall_StrictMode(t *testing.T) {
	t.Run("unsigned bundle is refused", func(t *testing.T) {
		f := newFixture(t)
		sb := f.ingestPending(testutil.BundleOptions{})
		f.forceApprove(sb)
		f.require(widget("1.0.0"))
		f.setMutate(onHeader(func(h *transportpb.ModuleBundleHeader) { h.Signatures = nil }))

		_, err := f.installer(stewardtypes.ModuleTrustModeStrict, nil).Install(context.Background(), "acme-corp", "widget", "1.0.0")
		require.ErrorIs(t, err, ErrTrustRefused)
		assertNothingInstalled(t, f.root)
	})

	t.Run("untrusted publisher is refused though the controller approved it", func(t *testing.T) {
		f := newFixture(t)
		sb := f.ingestPending(testutil.BundleOptions{})
		f.forceApprove(sb)
		f.require(widget("1.0.0"))

		_, err := f.installer(stewardtypes.ModuleTrustModeStrict, nil).Install(context.Background(), "acme-corp", "widget", "1.0.0")
		require.ErrorIs(t, err, ErrTrustRefused)
		assertNothingInstalled(t, f.root)
	})

	t.Run("tampered bundle is refused", func(t *testing.T) {
		f := newFixture(t)
		sb := f.ingest(testutil.BundleOptions{})
		f.require(widget("1.0.0"))
		f.setMutate(func(c *transportpb.ModuleBundleChunk) bool {
			if len(c.GetData()) > 0 {
				c.Data[0] ^= 0xff
			}
			return true
		})
		enforcer := trust.NewStewardTrustEnforcerWithIdentity(func() pkgtrust.PublisherIdentity {
			return pkgtrust.PublisherIdentity{Name: "acme-corp", PublicKey: sb.PublicKey, Algorithm: "ed25519"}
		})
		_, err := f.installer(stewardtypes.ModuleTrustModeStrict, enforcer).Install(context.Background(), "acme-corp", "widget", "1.0.0")
		require.Error(t, err)
		assertNothingInstalled(t, f.root)
	})

	t.Run("header hash that disagrees is refused even for a trusted publisher", func(t *testing.T) {
		f := newFixture(t)
		sb := f.ingest(testutil.BundleOptions{})
		f.require(widget("1.0.0"))
		f.setMutate(onHeader(func(h *transportpb.ModuleBundleHeader) { h.ContentHash = strings.Repeat("a", 64) }))
		enforcer := trust.NewStewardTrustEnforcerWithIdentity(func() pkgtrust.PublisherIdentity {
			return pkgtrust.PublisherIdentity{Name: "acme-corp", PublicKey: sb.PublicKey, Algorithm: "ed25519"}
		})
		_, err := f.installer(stewardtypes.ModuleTrustModeStrict, enforcer).Install(context.Background(), "acme-corp", "widget", "1.0.0")
		require.ErrorIs(t, err, ErrContentHashMismatch)
		assertNothingInstalled(t, f.root)
	})

	t.Run("baked-in publisher installs", func(t *testing.T) {
		f := newFixture(t)
		sb := f.ingest(testutil.BundleOptions{Publisher: "cfgms", Name: "widget"})
		f.require(stewardtypes.RequiredModule{Name: "cfgms/widget", Version: "1.0.0"})
		enforcer := trust.NewStewardTrustEnforcerWithIdentity(func() pkgtrust.PublisherIdentity {
			return pkgtrust.PublisherIdentity{Name: "cfgms", PublicKey: sb.PublicKey, Algorithm: "ed25519"}
		})
		_, err := f.installer(stewardtypes.ModuleTrustModeStrict, enforcer).Install(context.Background(), "cfgms", "widget", "1.0.0")
		require.NoError(t, err)
		found, err := bundle.DiscoverInstalled(f.root)
		require.NoError(t, err)
		assert.Contains(t, found, "widget")
	})

	t.Run("additional publisher installs", func(t *testing.T) {
		f := newFixture(t)
		sb := f.ingest(testutil.BundleOptions{})
		f.require(widget("1.0.0"))
		enforcer := trust.NewStewardTrustEnforcerWithKnownPublishers(pkgtrust.CFGMSPublisherIdentity,
			map[string]pkgtrust.PublisherIdentity{
				"acme-corp": {Name: "acme-corp", PublicKey: sb.PublicKey, Algorithm: "ed25519"},
			})
		_, err := f.installer(stewardtypes.ModuleTrustModeStrict, enforcer, "acme-corp").Install(context.Background(), "acme-corp", "widget", "1.0.0")
		require.NoError(t, err)
	})

	t.Run("unresolvable additional publisher name writes nothing", func(t *testing.T) {
		f := newFixture(t)
		f.ingest(testutil.BundleOptions{})
		f.require(widget("1.0.0"))
		_, err := f.installer(stewardtypes.ModuleTrustModeStrict, nil, "vendor-a").Install(context.Background(), "acme-corp", "widget", "1.0.0")
		require.ErrorIs(t, err, trust.ErrAdditionalPublisherUnresolvable)
		assertNothingInstalled(t, f.root)
	})
}

// [REQUIRED TEST] received file names that must never reach the filesystem.
func TestInstall_RefusesHostileFileNames(t *testing.T) {
	names := []string{
		"..", "../evil", "/etc/passwd", `C:\x`, "a:b", "NUL", "nul.exe", "trailing.", "trailing ", "a/b", `a\b`,
		"BUNDLE.YAML", "Module.Yaml", "link -> /etc/passwd", "", "\x00x",
	}
	f := newFixture(t)
	f.ingest(testutil.BundleOptions{})
	f.require(widget("1.0.0"))
	for _, n := range names {
		f.setMutate(onHeader(func(h *transportpb.ModuleBundleHeader) { h.FileName = n }))
		_, err := f.installer(stewardtypes.ModuleTrustModeController, nil).Install(context.Background(), "acme-corp", "widget", "1.0.0")
		require.ErrorIs(t, err, ErrStreamInvalid, "file name %q", n)
		assertNothingInstalled(t, f.root)
	}
}

// [REQUIRED TEST] truncated and oversize streams leave nothing behind.
func TestInstall_TruncatedAndOversizeStreams(t *testing.T) {
	big := make([]byte, 700_000) // several chunks
	for i := range big {
		big[i] = byte(i)
	}
	setup := func(t *testing.T) *fixture {
		f := newFixture(t)
		f.ingest(testutil.BundleOptions{BinaryContent: map[string][]byte{ownPlatform(): big}})
		f.require(widget("1.0.0"))
		return f
	}

	t.Run("truncated: final frame dropped", func(t *testing.T) {
		f := setup(t)
		f.setMutate(func(c *transportpb.ModuleBundleChunk) bool { return !c.GetFinal() })
		_, err := f.installer(stewardtypes.ModuleTrustModeController, nil).Install(context.Background(), "acme-corp", "widget", "1.0.0")
		require.ErrorIs(t, err, ErrStreamInvalid)
		assertNothingInstalled(t, f.root)
	})
	t.Run("truncated: declared size larger than delivered", func(t *testing.T) {
		f := setup(t)
		f.setMutate(onHeader(func(h *transportpb.ModuleBundleHeader) { h.FileSize++ }))
		_, err := f.installer(stewardtypes.ModuleTrustModeController, nil).Install(context.Background(), "acme-corp", "widget", "1.0.0")
		require.ErrorIs(t, err, ErrStreamInvalid)
		assertNothingInstalled(t, f.root)
	})
	t.Run("oversize: declared size above the file cap", func(t *testing.T) {
		f := setup(t)
		f.setMutate(onHeader(func(h *transportpb.ModuleBundleHeader) { h.FileSize = bundle.MaxBundleFileBytes + 1 }))
		_, err := f.installer(stewardtypes.ModuleTrustModeController, nil).Install(context.Background(), "acme-corp", "widget", "1.0.0")
		require.ErrorIs(t, err, ErrStreamInvalid)
		assertNothingInstalled(t, f.root)
	})
	t.Run("oversize: more bytes than declared", func(t *testing.T) {
		f := setup(t)
		f.setMutate(onHeader(func(h *transportpb.ModuleBundleHeader) { h.FileSize = 10 }))
		_, err := f.installer(stewardtypes.ModuleTrustModeController, nil).Install(context.Background(), "acme-corp", "widget", "1.0.0")
		require.ErrorIs(t, err, ErrStreamInvalid)
		assertNothingInstalled(t, f.root)
	})
}

// [REQUIRED TEST] replace procedure: a new version over an existing one, the same
// bundle again as a no-op, a forced failure on the second rename restoring the
// old tree, and no half-written tree ever discoverable.
func TestInstall_ReplaceProcedure(t *testing.T) {
	f := newFixture(t)
	f.ingest(testutil.BundleOptions{Version: "1.0.0"})
	f.ingest(testutil.BundleOptions{Version: "2.0.0"})
	f.require(widget("1.0.0"))
	ctx := context.Background()

	in := f.installer(stewardtypes.ModuleTrustModeController, nil)
	_, err := in.Install(ctx, "acme-corp", "widget", "1.0.0")
	require.NoError(t, err)

	res, err := in.Install(ctx, "acme-corp", "widget", "1.0.0")
	require.NoError(t, err)
	assert.False(t, res.Changed, "same publisher, name, version and hash is a no-op")

	// Forced failure on the second rename: the old tree is restored, and at every
	// rename the root holds only discoverable-or-skipped entries.
	calls := 0
	in.renameHook = func(oldPath, newPath string) error {
		calls++
		found, derr := bundle.DiscoverInstalled(f.root)
		assert.NoError(t, derr, "a half-written tree is never discoverable (rename %d)", calls)
		if calls == 1 {
			require.Contains(t, found, "widget")
		} else {
			assert.Empty(t, found, "while the old tree is aside nothing is discoverable, and nothing is half-written")
		}
		if calls == 2 {
			return os.ErrPermission
		}
		return os.Rename(oldPath, newPath)
	}
	f.require(widget("2.0.0"))
	_, err = in.Install(ctx, "acme-corp", "widget", "2.0.0")
	require.ErrorIs(t, err, ErrInstallFailed)
	assertNoPath(t, err, f.root)
	found, err := bundle.DiscoverInstalled(f.root)
	require.NoError(t, err)
	assert.Equal(t, "1.0.0", found["widget"].Bundle.Manifest.Version, "old tree restored")
	rootEntries, err := os.ReadDir(f.root)
	require.NoError(t, err)
	assert.Len(t, rootEntries, 1, "no staging leftovers after a failed replace")

	// The real replace succeeds.
	in.renameHook = nil
	res, err = in.Install(ctx, "acme-corp", "widget", "2.0.0")
	require.NoError(t, err)
	assert.True(t, res.Changed)
	found, err = bundle.DiscoverInstalled(f.root)
	require.NoError(t, err)
	assert.Equal(t, "2.0.0", found["widget"].Bundle.Manifest.Version)
	rootEntries, err = os.ReadDir(f.root)
	require.NoError(t, err)
	assert.Len(t, rootEntries, 1)
	require.NoError(t, CheckProtectedTree(f.root))
}

// [REQUIRED TEST] a first-rename failure (what a held-open binary causes on
// Windows) returns ErrModuleInUse and leaves the old tree intact. This variant
// forces the failure and runs everywhere.
func TestInstall_ModuleInUse_ForcedRename(t *testing.T) {
	f := newFixture(t)
	f.ingest(testutil.BundleOptions{Version: "1.0.0"})
	f.ingest(testutil.BundleOptions{Version: "2.0.0"})
	f.require(widget("1.0.0"))
	in := f.installer(stewardtypes.ModuleTrustModeController, nil)
	_, err := in.Install(context.Background(), "acme-corp", "widget", "1.0.0")
	require.NoError(t, err)
	f.require(widget("2.0.0"))

	in.renameHook = func(string, string) error { return os.ErrPermission }
	_, err = in.Install(context.Background(), "acme-corp", "widget", "2.0.0")
	require.ErrorIs(t, err, ErrModuleInUse)
	assertNoPath(t, err, f.root)
	assertOldIntact(t, f.root)
}

func assertOldIntact(t *testing.T, root string) {
	t.Helper()
	found, err := bundle.DiscoverInstalled(root)
	require.NoError(t, err)
	require.Contains(t, found, "widget")
	assert.Equal(t, "1.0.0", found["widget"].Bundle.Manifest.Version)
	_, err = bundle.ReadInstalledPayload(filepath.Join(root, "widget"), bundle.ReadOptions{Platform: ownPlatform()})
	require.NoError(t, err, "old tree still loadable")
	entries, err := os.ReadDir(root)
	require.NoError(t, err)
	assert.Len(t, entries, 1, "no staging leftovers")
}

// [REQUIRED TEST] with an open handle held in the old tree, replacement fails
// with ErrModuleInUse and the old tree stays loadable. Only Windows refuses to
// rename a directory that contains an open file, so other platforms skip.
func TestInstall_ModuleInUse_OpenHandle(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("directory rename with an open file handle only fails on Windows; TestInstall_ModuleInUse_ForcedRename covers the path elsewhere")
	}
	f := newFixture(t)
	f.ingest(testutil.BundleOptions{Version: "1.0.0"})
	f.ingest(testutil.BundleOptions{Version: "2.0.0"})
	f.require(widget("1.0.0"))
	in := f.installer(stewardtypes.ModuleTrustModeController, nil)
	_, err := in.Install(context.Background(), "acme-corp", "widget", "1.0.0")
	require.NoError(t, err)
	f.require(widget("2.0.0"))

	held, err := os.Open(filepath.Join(f.root, "widget", testutil.BinaryFileName("widget", ownPlatform())))
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, held.Close()) })

	_, err = in.Install(context.Background(), "acme-corp", "widget", "2.0.0")
	require.ErrorIs(t, err, ErrModuleInUse)
	assertOldIntact(t, f.root)
}

// [REQUIRED TEST] a name installed by another publisher is refused; every stdlib
// name is refused for a non-cfgms publisher.
func TestInstall_NameRules(t *testing.T) {
	t.Run("same name, different publisher", func(t *testing.T) {
		f := newFixture(t)
		f.ingest(testutil.BundleOptions{Publisher: "acme-corp"})
		f.ingest(testutil.BundleOptions{Publisher: "other-corp"})
		f.require(widget("1.0.0"))
		in := f.installer(stewardtypes.ModuleTrustModeController, nil)
		_, err := in.Install(context.Background(), "acme-corp", "widget", "1.0.0")
		require.NoError(t, err)
		f.require(stewardtypes.RequiredModule{Name: "other-corp/widget", Version: "1.0.0"})
		_, err = in.Install(context.Background(), "other-corp", "widget", "1.0.0")
		require.ErrorIs(t, err, ErrPublisherMismatch)
		found, err := bundle.DiscoverInstalled(f.root)
		require.NoError(t, err)
		assert.Equal(t, "acme-corp", found["widget"].Bundle.Manifest.Publisher)
	})

	t.Run("unreadable tree of a different publisher is not replaced", func(t *testing.T) {
		f := newFixture(t)
		f.ingest(testutil.BundleOptions{Publisher: "other-corp"})
		f.require(stewardtypes.RequiredModule{Name: "other-corp/widget", Version: "1.0.0"})
		in := f.installer(stewardtypes.ModuleTrustModeController, nil)
		_, err := in.Install(context.Background(), "other-corp", "widget", "1.0.0")
		require.NoError(t, err)
		// Corrupt the installed binary so the tree no longer reads as a bundle.
		bin := filepath.Join(f.root, "widget", testutil.BinaryFileName("widget", ownPlatform()))
		require.NoError(t, os.WriteFile(bin, []byte("corrupt"), 0o755)) // #nosec G306 -- test fixture
		f.ingest(testutil.BundleOptions{Publisher: "acme-corp"})
		f.require(widget("1.0.0"))
		_, err = in.Install(context.Background(), "acme-corp", "widget", "1.0.0")
		require.ErrorIs(t, err, ErrPublisherMismatch)
	})

	t.Run("stdlib names", func(t *testing.T) {
		f := newFixture(t)
		for _, n := range StdlibModuleNames() {
			in := f.installer(stewardtypes.ModuleTrustModeController, nil)
			_, err := in.Install(context.Background(), "acme-corp", n, "1.0.0")
			require.ErrorIs(t, err, ErrStdlibName, n)
			_, err = in.Install(context.Background(), "acme-corp", strings.ToUpper(n), "1.0.0")
			require.ErrorIs(t, err, ErrStdlibName, n)
		}
		assertNothingInstalled(t, f.root)
	})

	t.Run("invalid request components", func(t *testing.T) {
		f := newFixture(t)
		in := f.installer(stewardtypes.ModuleTrustModeController, nil)
		for _, c := range [][3]string{{"acme-corp", "../x", "1.0.0"}, {"a/b", "widget", "1.0.0"}, {"acme-corp", "widget", "^1.0"}, {"acme-corp", "NUL", "1.0.0"}} {
			_, err := in.Install(context.Background(), c[0], c[1], c[2])
			require.ErrorIs(t, err, ErrInvalidRequest, "%v", c)
		}
	})

	t.Run("misconfigured installer", func(t *testing.T) {
		_, err := (&Installer{}).Install(context.Background(), "acme-corp", "widget", "1.0.0")
		require.ErrorIs(t, err, ErrInstallerMisconfigured)
		f := newFixture(t)
		_, err = f.installer("bogus", nil).Install(context.Background(), "acme-corp", "widget", "1.0.0")
		require.ErrorIs(t, err, ErrInstallerMisconfigured)
	})
}

func TestDefaultRoot(t *testing.T) {
	t.Setenv(BundleDirEnvVar, "")
	if runtime.GOOS == "windows" {
		assert.Equal(t, installedModulesWindowsRoot, DefaultRoot())
	} else {
		assert.Equal(t, installedModulesUnixRoot, DefaultRoot())
	}
	t.Setenv(BundleDirEnvVar, "/override")
	assert.Equal(t, "/override", DefaultRoot())
}
