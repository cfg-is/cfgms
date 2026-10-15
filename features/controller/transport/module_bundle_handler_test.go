// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v3"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	stewardtypes "github.com/cfgis/cfgms/features/config/stewardtypes"
	"github.com/cfgis/cfgms/features/controller/modules/approval"
	"github.com/cfgis/cfgms/features/controller/modules/cache"
	"github.com/cfgis/cfgms/features/controller/service"
	modules "github.com/cfgis/cfgms/features/modules"
	cfgcert "github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/modules/bundle"
	"github.com/cfgis/cfgms/pkg/modules/trust"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
	"github.com/cfgis/cfgms/pkg/testutil"
)

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

// failableApprovalStore is a real in-memory ModuleApprovalStore whose reads can
// be made to fail, to exercise the "store error counts as not approved" path.
type failableApprovalStore struct {
	business.ModuleApprovalStore
	failReads atomic.Bool
}

func (s *failableApprovalStore) GetApprovalStatus(ctx context.Context, addr string) (business.ModuleApprovalStatus, bool, error) {
	if s.failReads.Load() {
		return "", false, errors.New("approval store unavailable: /var/secret/path")
	}
	return s.ModuleApprovalStore.GetApprovalStatus(ctx, addr)
}

type moduleStream struct {
	ctx    context.Context
	mu     sync.Mutex
	chunks []*transportpb.ModuleBundleChunk
	onSend func()
}

func (s *moduleStream) Send(c *transportpb.ModuleBundleChunk) error {
	if s.onSend != nil {
		s.onSend()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.chunks = append(s.chunks, c)
	return nil
}
func (s *moduleStream) SetHeader(metadata.MD) error  { return nil }
func (s *moduleStream) SendHeader(metadata.MD) error { return nil }
func (s *moduleStream) SetTrailer(metadata.MD)       {}
func (s *moduleStream) Context() context.Context     { return s.ctx }
func (s *moduleStream) SendMsg(interface{}) error    { return nil }
func (s *moduleStream) RecvMsg(interface{}) error    { return nil }

var _ grpc.ServerStreamingServer[transportpb.ModuleBundleChunk] = (*moduleStream)(nil)

type moduleFixture struct {
	t        *testing.T
	ca       *cfgcert.CA
	cfgSvc   *service.ConfigurationServiceV2
	ctrl     *service.ControllerService
	cache    *cache.ModuleCache
	workflow *approval.ApprovalWorkflow
	store    *failableApprovalStore
	queue    *TenantQueue
	h        *ModuleBundleHandler
}

func newModuleFixture(t *testing.T) *moduleFixture {
	t.Helper()
	sm := pkgtesting.SetupTestStorage(t)
	ctrl := service.NewControllerService(logging.NewNoopLogger())
	cfgSvc := service.NewConfigurationServiceV2(logging.NewNoopLogger(), sm, ctrl)
	for _, id := range []string{"tenant-x", "tenant-y"} {
		require.NoError(t, sm.GetTenantStore().CreateTenant(ctxkeys.WithSystem(context.Background()),
			&business.TenantData{ID: id, Name: id, Status: business.TenantStatusActive}))
	}

	mc, err := cache.New(filepath.Join(t.TempDir(), "module-cache"))
	require.NoError(t, err)
	store := &failableApprovalStore{ModuleApprovalStore: pkgtesting.SetupTestModuleApprovalStore()}
	mc.SetApprovalStore(store)

	queue := NewTenantQueue()
	return &moduleFixture{
		t:        t,
		ca:       newTestCA(t),
		cfgSvc:   cfgSvc,
		ctrl:     ctrl,
		cache:    mc,
		workflow: approval.New(mc),
		store:    store,
		queue:    queue,
		h:        NewModuleBundleHandler(mc, cfgSvc, ctrl, queue, logging.NewNoopLogger()),
	}
}

// ingest puts a signed bundle through the real ApprovalWorkflow (so it lands
// pending) and optionally approves it.
func (f *moduleFixture) ingest(opts testutil.BundleOptions, approve bool) *testutil.SignedBundle {
	f.t.Helper()
	if opts.Publisher == "" {
		opts.Publisher = "acme-corp"
	}
	if opts.Name == "" {
		opts.Name = "widget"
	}
	if opts.Platforms == nil {
		opts.Platforms = []string{"linux-amd64", "windows-amd64"}
	}
	sb := testutil.NewSignedBundle(f.t, opts)
	decision, err := f.workflow.EvaluateAndStore(sb.Bundle, trust.NewInMemoryTrustStore())
	require.NoError(f.t, err)
	require.Equal(f.t, approval.QueueForReview, decision)
	if approve {
		require.NoError(f.t, f.workflow.Approve(sb.ContentAddress()))
	}
	return sb
}

// steward registers a steward under tenant and stores its device configuration
// requiring the given modules.
func (f *moduleFixture) steward(id, tenant string, required ...stewardtypes.RequiredModule) {
	f.t.Helper()
	require.NoError(f.t, f.ctrl.RegisterSteward(id, tenant, "localhost:4433", "connected"))
	cfg := minimalStewardConfig(id)
	cfg.RequiredModules = required
	require.NoError(f.t, f.cfgSvc.SetConfiguration(ctxkeys.WithSystem(context.Background()), tenant, id, cfg))
}

func req(version, platform string) *transportpb.FetchModuleBundleRequest {
	return &transportpb.FetchModuleBundleRequest{Publisher: "acme-corp", Name: "widget", Version: version, Platform: platform}
}

func (f *moduleFixture) fetch(stewardID string, r *transportpb.FetchModuleBundleRequest) (*moduleStream, error) {
	f.t.Helper()
	ctx := peerContextWithCA(f.t, f.ca, stewardID)
	st := &moduleStream{ctx: ctx}
	return st, f.h.HandleGRPC(ctx, r, st)
}

var requireWidget = stewardtypes.RequiredModule{Name: "acme-corp/widget", Version: "1.0.0"}

// reassemble rebuilds the single-platform installation root from the received
// stream and reads it back through bundle.ReadInstalledPayload.
func reassemble(t *testing.T, st *moduleStream, platform string) (*bundle.Bundle, *transportpb.ModuleBundleHeader) {
	t.Helper()
	require.GreaterOrEqual(t, len(st.chunks), 2, "header chunk plus at least one data chunk")
	header := st.chunks[0].GetHeader()
	require.NotNil(t, header)
	assert.Empty(t, st.chunks[0].GetData(), "header chunk carries no data")

	var data []byte
	for i, c := range st.chunks[1:] {
		assert.Nil(t, c.GetHeader())
		assert.EqualValues(t, i+1, c.GetChunkIndex())
		assert.Equal(t, i == len(st.chunks)-2, c.GetFinal(), "final only on the last chunk")
		data = append(data, c.GetData()...)
	}
	assert.EqualValues(t, len(data), header.GetFileSize())

	manifest, err := modules.ParseModuleMetadata(bytes.NewReader(header.GetManifest()))
	require.NoError(t, err)
	b := &bundle.Bundle{
		Manifest:      manifest,
		ManifestBytes: header.GetManifest(),
		Binaries:      map[string]string{platform: header.GetFileName()},
		BinaryDigests: header.GetBinaryDigests(),
		ContentHash:   header.GetContentHash(),
		BinaryContent: map[string][]byte{platform: data},
	}
	for _, s := range header.GetSignatures() {
		b.Signatures = append(b.Signatures, bundle.BundleSignature{Publisher: s.GetPublisher(), Algorithm: s.GetAlgorithm(), Signature: s.GetSignature()})
	}
	root := filepath.Join(t.TempDir(), "installed")
	require.NoError(t, bundle.WriteInstalled(b, root, bundle.WriteOptions{Platform: platform}))
	got, err := bundle.ReadInstalledPayload(root, bundle.ReadOptions{Platform: platform})
	require.NoError(t, err)
	return got, header
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// [REQUIRED TEST] An approved, config-required bundle streams manifest,
// signatures, the full digest list and the selected platform's binary; it
// reassembles under own-platform ReadInstalledPayload and the recomputed hash
// equals the signed hash. Fixture provenance: bundle from the #4980 test builder
// (two platforms), ingested through the real ApprovalWorkflow and ModuleCache;
// received signatures are byte-equal to the publisher's.
func TestModuleBundle_ServesApprovedRequiredBundle(t *testing.T) {
	f := newModuleFixture(t)
	sb := f.ingest(testutil.BundleOptions{Version: "1.0.0"}, true)
	f.steward("steward-a", "tenant-x", requireWidget)

	for _, platform := range []string{"linux-amd64", "windows-amd64"} {
		st, err := f.fetch("steward-a", req("1.0.0", platform))
		require.NoError(t, err)

		got, header := reassemble(t, st, platform)
		assert.Equal(t, sb.ContentHash, got.ContentHash, "recomputed hash equals the signed hash")
		assert.Equal(t, sb.ContentHash, header.GetContentHash())
		assert.Equal(t, sb.ManifestBytes, got.ManifestBytes)
		assert.Equal(t, sb.BinaryContent[platform], got.BinaryContent[platform], "exactly the selected platform's binary")
		assert.Len(t, got.BinaryContent, 1, "one platform binary per stream")
		assert.Equal(t, testutil.BinaryFileName("widget", platform), header.GetFileName())

		// The FULL digest list travels, not just the selected platform's.
		assert.Equal(t, sb.BinaryDigests, header.GetBinaryDigests())
		assert.Len(t, header.GetBinaryDigests(), 2)

		// Signatures are verbatim, byte for byte.
		require.Len(t, got.Signatures, len(sb.Signatures))
		for i, s := range sb.Signatures {
			assert.Equal(t, s.Signature, got.Signatures[i].Signature)
			assert.Equal(t, s.Publisher, got.Signatures[i].Publisher)
			assert.Equal(t, s.Algorithm, got.Signatures[i].Algorithm)
			assert.True(t, ed25519.Verify(sb.PublicKey, []byte(got.ContentHash), got.Signatures[i].Signature))
		}
	}
}

// A binary larger than one chunk is split and reassembles exactly.
func TestModuleBundle_ChunksLargeBinary(t *testing.T) {
	f := newModuleFixture(t)
	big := bytes.Repeat([]byte("0123456789abcdef"), 40_000) // 640 KB
	sb := f.ingest(testutil.BundleOptions{BinaryContent: map[string][]byte{"linux-amd64": big}}, true)
	f.steward("steward-a", "tenant-x", requireWidget)

	st, err := f.fetch("steward-a", req("1.0.0", "linux-amd64"))
	require.NoError(t, err)
	assert.Greater(t, len(st.chunks), 3)
	got, _ := reassemble(t, st, "linux-amd64")
	assert.Equal(t, big, got.BinaryContent["linux-amd64"])
	assert.Equal(t, sb.ContentHash, got.ContentHash)
}

// [REQUIRED TEST] approve -> served; reject (same process, same cache) -> next
// request refused; approval-store error -> refused.
func TestModuleBundle_ApprovalIsCheckedOnEveryRequest(t *testing.T) {
	f := newModuleFixture(t)
	sb := f.ingest(testutil.BundleOptions{}, false)
	f.steward("steward-a", "tenant-x", requireWidget)

	// Pending: refused.
	st, err := f.fetch("steward-a", req("1.0.0", "linux-amd64"))
	require.Error(t, err)
	assert.Empty(t, st.chunks)

	// Approved: served.
	require.NoError(t, f.workflow.Approve(sb.ContentAddress()))
	_, err = f.fetch("steward-a", req("1.0.0", "linux-amd64"))
	require.NoError(t, err)

	// Rejected afterwards, same cache: the next request is refused.
	require.NoError(t, f.cache.SetApprovalStatus(sb.ContentAddress(), cache.ApprovalStatusRejected))
	st, err = f.fetch("steward-a", req("1.0.0", "linux-amd64"))
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
	assert.Empty(t, st.chunks)

	// Approved again, then the approval store errors: refused.
	require.NoError(t, f.cache.SetApprovalStatus(sb.ContentAddress(), cache.ApprovalStatusApproved))
	_, err = f.fetch("steward-a", req("1.0.0", "linux-amd64"))
	require.NoError(t, err)
	f.store.failReads.Store(true)
	st, err = f.fetch("steward-a", req("1.0.0", "linux-amd64"))
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
	assert.Empty(t, st.chunks)
}

// [REQUIRED TEST] Four distinct refusals return identical code and text, and the
// text names no path, reason or request value.
func TestModuleBundle_RefusalsAreIndistinguishable(t *testing.T) {
	f := newModuleFixture(t)

	// absent: required by the caller but never ingested.
	f.ingest(testutil.BundleOptions{Name: "present", Platforms: []string{"linux-amd64"}}, true)
	// pending: required only by steward-b's configuration, not the caller's.
	f.ingest(testutil.BundleOptions{Name: "pending"}, false)
	// rejected: required by the caller.
	rej := f.ingest(testutil.BundleOptions{Name: "rejected"}, false)
	require.NoError(t, f.workflow.RejectPending(rej.ContentAddress()))

	f.steward("steward-a", "tenant-x",
		stewardtypes.RequiredModule{Name: "acme-corp/absent", Version: "1.0.0"},
		stewardtypes.RequiredModule{Name: "acme-corp/rejected", Version: "1.0.0"},
		stewardtypes.RequiredModule{Name: "acme-corp/present", Version: "1.0.0"},
	)
	f.steward("steward-b", "tenant-x", stewardtypes.RequiredModule{Name: "acme-corp/pending", Version: "1.0.0"})

	cases := map[string]*transportpb.FetchModuleBundleRequest{
		"absent module":                        {Publisher: "acme-corp", Name: "absent", Version: "1.0.0", Platform: "linux-amd64"},
		"pending, required by another steward": {Publisher: "acme-corp", Name: "pending", Version: "1.0.0", Platform: "linux-amd64"},
		"rejected module":                      {Publisher: "acme-corp", Name: "rejected", Version: "1.0.0", Platform: "linux-amd64"},
		"platform not in the bundle":           {Publisher: "acme-corp", Name: "present", Version: "1.0.0", Platform: "windows-amd64"},
		"platform outside the allowlist":       {Publisher: "acme-corp", Name: "present", Version: "1.0.0", Platform: "plan9-riscv"},
		"path-like name":                       {Publisher: "acme-corp", Name: "../present", Version: "1.0.0", Platform: "linux-amd64"},
	}
	for label, r := range cases {
		st, err := f.fetch("steward-a", r)
		require.Error(t, err, label)
		assert.Equal(t, codes.NotFound, status.Code(err), label)
		assert.Equal(t, moduleBundleRefusal, status.Convert(err).Message(), label)
		assert.Empty(t, st.chunks, label)
	}
	// And the control: the present bundle with its platform is served.
	_, err := f.fetch("steward-a", &transportpb.FetchModuleBundleRequest{Publisher: "acme-corp", Name: "present", Version: "1.0.0", Platform: "linux-amd64"})
	require.NoError(t, err)
}

// [REQUIRED TEST] A steward in tenant X cannot fetch an approved module that only
// tenant Y's configuration requires; no or invalid client certificate is
// refused; an identity-like field in the request is ignored.
func TestModuleBundle_AuthorizationBoundaries(t *testing.T) {
	f := newModuleFixture(t)
	f.ingest(testutil.BundleOptions{}, true)
	f.steward("steward-a", "tenant-x")
	f.steward("steward-y", "tenant-y", requireWidget)

	// Tenant Y's steward can fetch; tenant X's cannot.
	_, err := f.fetch("steward-y", req("1.0.0", "linux-amd64"))
	require.NoError(t, err)
	st, err := f.fetch("steward-a", req("1.0.0", "linux-amd64"))
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
	assert.Empty(t, st.chunks)

	// No peer at all.
	noPeer := &moduleStream{ctx: context.Background()}
	err = f.h.HandleGRPC(noPeer.ctx, req("1.0.0", "linux-amd64"), noPeer)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
	assert.Empty(t, noPeer.chunks)

	// A certificate whose chain was not verified.
	ctx := peerContextWithCA(t, f.ca, "steward-y")
	p, _ := peer.FromContext(ctx)
	info := p.AuthInfo.(credentials.TLSInfo)
	info.State = tls.ConnectionState{PeerCertificates: info.State.PeerCertificates, HandshakeComplete: true}
	unverified := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: info})
	bad := &moduleStream{ctx: unverified}
	err = f.h.HandleGRPC(unverified, req("1.0.0", "linux-amd64"), bad)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
	assert.Empty(t, bad.chunks)

	// A verified certificate for a steward the registry does not know.
	st, err = f.fetch("steward-unknown", req("1.0.0", "linux-amd64"))
	assert.Equal(t, codes.NotFound, status.Code(err))
	assert.Empty(t, st.chunks)

	// Identity-like fields smuggled into the request (unknown fields on the wire)
	// are ignored: steward-a presenting steward-y's id is still steward-a.
	r := req("1.0.0", "linux-amd64")
	var unknown []byte
	for _, num := range []protowire.Number{5, 6, 7} {
		unknown = protowire.AppendTag(unknown, num, protowire.BytesType)
		unknown = protowire.AppendString(unknown, "steward-y")
	}
	r.ProtoReflect().SetUnknown(unknown)
	wire, err := proto.Marshal(r)
	require.NoError(t, err)
	var decoded transportpb.FetchModuleBundleRequest
	require.NoError(t, proto.Unmarshal(wire, &decoded))
	st, err = f.fetch("steward-a", &decoded)
	assert.Equal(t, codes.NotFound, status.Code(err))
	assert.Empty(t, st.chunks)
}

// [REQUIRED TEST] A steward whose config names acme-corp/widget@1.0.0 cannot
// fetch 1.0.1 or another name, even when those are approved in the cache.
func TestModuleBundle_ExactVersionAndName(t *testing.T) {
	f := newModuleFixture(t)
	f.ingest(testutil.BundleOptions{Version: "1.0.0"}, true)
	f.ingest(testutil.BundleOptions{Version: "1.0.1"}, true)
	f.ingest(testutil.BundleOptions{Name: "gadget", Version: "1.0.0"}, true)
	f.steward("steward-a", "tenant-x", requireWidget)

	_, err := f.fetch("steward-a", req("1.0.0", "linux-amd64"))
	require.NoError(t, err)

	for label, r := range map[string]*transportpb.FetchModuleBundleRequest{
		"other version":   req("1.0.1", "linux-amd64"),
		"v-prefixed":      req("v1.0.0", "linux-amd64"),
		"constraint":      req("^1.0.0", "linux-amd64"),
		"other name":      {Publisher: "acme-corp", Name: "gadget", Version: "1.0.0", Platform: "linux-amd64"},
		"other publisher": {Publisher: "evil-corp", Name: "widget", Version: "1.0.0", Platform: "linux-amd64"},
	} {
		st, err := f.fetch("steward-a", r)
		require.Error(t, err, label)
		assert.Equal(t, codes.NotFound, status.Code(err), label)
		assert.Empty(t, st.chunks, label)
	}
}

// A requirement declared at a parent tenant level reaches the steward through the
// effective (cascade-merged) configuration.
func TestModuleBundle_RequirementInheritedFromTenantCascade(t *testing.T) {
	f := newModuleFixture(t)
	f.ingest(testutil.BundleOptions{}, true)
	f.steward("steward-a", "tenant-x") // no device-level requirement

	_, err := f.fetch("steward-a", req("1.0.0", "linux-amd64"))
	require.Error(t, err)

	cfg := minimalStewardConfig("tenant-x-policy")
	cfg.RequiredModules = []stewardtypes.RequiredModule{requireWidget}
	cfg.Resources = nil
	data, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, f.cfgSvc.GetConfigStore().StoreConfig(context.Background(), &cfgconfig.ConfigEntry{
		Key:  &cfgconfig.ConfigKey{TenantID: "tenant-x", Namespace: "msp-policies", Name: "global"},
		Data: data,
	}))

	_, err = f.fetch("steward-a", req("1.0.0", "linux-amd64"))
	require.NoError(t, err)
}

// [REQUIRED TEST] Immutability through the handler: after a second valid bundle
// for the same triple (different hash) is refused at ingest, the handler still
// serves the original bytes.
func TestModuleBundle_ImmutableAfterConflictingIngest(t *testing.T) {
	f := newModuleFixture(t)
	orig := f.ingest(testutil.BundleOptions{}, true)
	f.steward("steward-a", "tenant-x", requireWidget)

	second := testutil.NewSignedBundle(t, testutil.BundleOptions{
		Publisher: "acme-corp", Name: "widget", Platforms: []string{"linux-amd64", "windows-amd64"},
		BinaryContent: map[string][]byte{"linux-amd64": []byte("replacement"), "windows-amd64": []byte("replacement-win")},
	})
	require.NotEqual(t, orig.ContentHash, second.ContentHash)
	_, err := f.workflow.EvaluateAndStore(second.Bundle, trust.NewInMemoryTrustStore())
	require.ErrorIs(t, err, cache.ErrContentAddressConflict)

	st, err := f.fetch("steward-a", req("1.0.0", "linux-amd64"))
	require.NoError(t, err)
	got, header := reassemble(t, st, "linux-amd64")
	assert.Equal(t, orig.ContentHash, header.GetContentHash())
	assert.Equal(t, orig.BinaryContent["linux-amd64"], got.BinaryContent["linux-amd64"])
}

// [REQUIRED TEST] An altered stored binary is refused before any chunk is sent.
func TestModuleBundle_AlteredStoredBinaryRefusedBeforeAnyChunk(t *testing.T) {
	f := newModuleFixture(t)
	sb := f.ingest(testutil.BundleOptions{}, true)
	f.steward("steward-a", "tenant-x", requireWidget)

	meta, err := f.cache.Get(sb.ContentAddress())
	require.NoError(t, err)
	path := meta.Binaries["linux-amd64"]
	require.NoError(t, os.WriteFile(path, []byte("tampered bytes"), 0o600))

	st, err := f.fetch("steward-a", req("1.0.0", "linux-amd64"))
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
	assert.Equal(t, moduleBundleRefusal, status.Convert(err).Message())
	assert.NotContains(t, err.Error(), path, "no filesystem path reaches the caller")
	assert.Empty(t, st.chunks, "no chunk, not even the header, before verification")
}

// [REQUIRED TEST] A stream request beyond maxConcurrentModuleStreams is refused,
// and the slot is returned when a stream finishes.
func TestModuleBundle_ConcurrentStreamLimit(t *testing.T) {
	f := newModuleFixture(t)
	f.ingest(testutil.BundleOptions{}, true)
	f.steward("steward-a", "tenant-x", requireWidget)

	release := make(chan struct{})
	var inFlight sync.WaitGroup
	var started sync.WaitGroup
	started.Add(maxConcurrentModuleStreams)
	var once [maxConcurrentModuleStreams]sync.Once
	for i := 0; i < maxConcurrentModuleStreams; i++ {
		inFlight.Add(1)
		go func(i int) {
			defer inFlight.Done()
			ctx := peerContextWithCA(t, f.ca, "steward-a")
			st := &moduleStream{ctx: ctx, onSend: func() {
				once[i].Do(started.Done)
				<-release
			}}
			assert.NoError(t, f.h.HandleGRPC(ctx, req("1.0.0", "linux-amd64"), st))
		}(i)
	}
	started.Wait()

	st, err := f.fetch("steward-a", req("1.0.0", "linux-amd64"))
	require.Error(t, err)
	assert.Equal(t, codes.ResourceExhausted, status.Code(err))
	assert.Empty(t, st.chunks)

	close(release)
	inFlight.Wait()
	_, err = f.fetch("steward-a", req("1.0.0", "linux-amd64"))
	require.NoError(t, err, "slots are released when streams finish")
}

// TenantQueue back-pressure applies per tenant.
func TestModuleBundle_TenantQueueBackPressure(t *testing.T) {
	f := newModuleFixture(t)
	f.ingest(testutil.BundleOptions{}, true)
	f.steward("steward-a", "tenant-x", requireWidget)

	for i := 0; i < MaxConcurrentPerTenant; i++ {
		require.NoError(t, f.queue.Acquire("tenant-x"))
	}
	st, err := f.fetch("steward-a", req("1.0.0", "linux-amd64"))
	require.Error(t, err)
	assert.Equal(t, codes.ResourceExhausted, status.Code(err))
	assert.Empty(t, st.chunks)

	f.queue.Release("tenant-x")
	_, err = f.fetch("steward-a", req("1.0.0", "linux-amd64"))
	require.NoError(t, err)
}

// A steward with no stored configuration, or whose configuration cannot be
// resolved, is refused with the same error.
func TestModuleBundle_NoConfigurationIsRefused(t *testing.T) {
	f := newModuleFixture(t)
	f.ingest(testutil.BundleOptions{}, true)
	require.NoError(t, f.ctrl.RegisterSteward("steward-nocfg", "tenant-x", "localhost:4433", "connected"))

	st, err := f.fetch("steward-nocfg", req("1.0.0", "linux-amd64"))
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
	assert.Equal(t, moduleBundleRefusal, status.Convert(err).Message())
	assert.Empty(t, st.chunks)
}

// A cancelled stream stops sending.
func TestModuleBundle_StopsWhenStreamCancelled(t *testing.T) {
	f := newModuleFixture(t)
	big := bytes.Repeat([]byte("x"), 1<<20)
	f.ingest(testutil.BundleOptions{BinaryContent: map[string][]byte{"linux-amd64": big}}, true)
	f.steward("steward-a", "tenant-x", requireWidget)

	base := peerContextWithCA(t, f.ca, "steward-a")
	ctx, cancel := context.WithCancel(base)
	st := &moduleStream{ctx: ctx, onSend: func() { cancel() }}
	err := f.h.HandleGRPC(ctx, req("1.0.0", "linux-amd64"), st)
	require.Error(t, err)
	assert.Equal(t, codes.Canceled, status.Code(err))
	assert.Less(t, len(st.chunks), 20, "sending stopped well before the end")
}
