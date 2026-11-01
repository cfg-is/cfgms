// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package transport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/controller/directory"
	"github.com/cfgis/cfgms/features/controller/heartbeat"
	stewardclient "github.com/cfgis/cfgms/features/steward/client"
	sdna "github.com/cfgis/cfgms/features/steward/dna"
	cfgcert "github.com/cfgis/cfgms/pkg/cert"
	cpinterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	dpinterfaces "github.com/cfgis/cfgms/pkg/dataplane/interfaces"
	dptypes "github.com/cfgis/cfgms/pkg/dataplane/types"
	egi "github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	egprovider "github.com/cfgis/cfgms/pkg/entitygraph/providers/sqlite"
	egtypes "github.com/cfgis/cfgms/pkg/entitygraph/types"
	"github.com/cfgis/cfgms/pkg/entitygraph/writers/dnasync"
	"github.com/cfgis/cfgms/pkg/logging"
)

// ---------------------------------------------------------------------------
// Harness: a real handler, a real BulkManifestStore, and the real steward-side
// bulk handler (stewardclient.BulkSyncResponder), joined by an in-process data
// plane that carries each DNATransfer to DNAHandler.HandleGRPC as DNAChunks.
// ---------------------------------------------------------------------------

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)} }
func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// recPublisher records the commands a handler publishes. Commands are queued, not
// run inline, because the handler publishes while it holds a round lock.
type recPublisher struct {
	mu    sync.Mutex
	queue []recCmd
	total int
	err   error
}

type recCmd struct {
	steward string
	params  map[string]interface{}
}

func (p *recPublisher) PublishCommand(_ context.Context, stewardID string, _ cpTypes.CommandType, params map[string]interface{}) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return "", p.err
	}
	p.total++
	p.queue = append(p.queue, recCmd{steward: stewardID, params: params})
	return fmt.Sprintf("cmd-%d", p.total), nil
}

func (p *recPublisher) pop() (recCmd, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.queue) == 0 {
		return recCmd{}, false
	}
	c := p.queue[0]
	p.queue = p.queue[1:]
	return c, true
}

func (p *recPublisher) published() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.total
}

type staticTenants map[string]string

func (m staticTenants) TenantForDevice(id string) (string, bool) {
	t, ok := m[id]
	return t, ok
}

type staticKinds struct {
	kinds []string
	err   error
}

func (k staticKinds) ListPerObjectKinds(string) ([]string, error) { return k.kinds, k.err }

type domainAuth map[string]string // peer -> the one domain it is authority for

func (d domainAuth) IsDirectoryAuthority(peer, domain string) bool { return d[peer] == domain }

// recSink is a MembershipSink that records every ApplyBatch call, and what the
// bulk store held at that moment.
type recSink struct {
	mu    sync.Mutex
	calls []sinkCall
	fail  error
	store *BulkManifestStore
}

type sinkCall struct {
	peer, authority string
	upserts         []directory.Fragment
	removed         []directory.RemovedFragment
	storedAtCall    map[string]bool
}

func (s *recSink) ApplyBatch(_ context.Context, peer, authority string, upserts []directory.Fragment, removed []directory.RemovedFragment) (directory.ApplyResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stored := map[string]bool{}
	if s.store != nil {
		m, _ := s.store.CurrentManifest(peer)
		for _, e := range m {
			stored[e.GetFragmentId()] = true
		}
	}
	s.calls = append(s.calls, sinkCall{peer: peer, authority: authority, upserts: upserts, removed: removed, storedAtCall: stored})
	if s.fail != nil {
		err := s.fail
		s.fail = nil
		return directory.ApplyResult{}, err
	}
	return directory.ApplyResult{}, nil
}

func (s *recSink) ApplyGroup(context.Context, string, string, string, []directory.GroupMember, time.Time) (directory.ApplyResult, error) {
	return directory.ApplyResult{}, nil
}

func (s *recSink) snapshot() []sinkCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]sinkCall(nil), s.calls...)
}

type bulkSteward struct {
	id   string
	resp *stewardclient.BulkSyncResponder
	sess *pairSession
}

// pairSession is the steward's data plane session: SendDNA delivers the transfer
// to the node's DNAHandler.HandleGRPC exactly as the wire would, as DNAChunks.
type pairSession struct {
	env     *bulkEnv
	steward string
	tamper  func(*dptypes.DNATransfer) *dptypes.DNATransfer

	mu     sync.Mutex
	sent   []wireRecord
	errors []error
}

type wireRecord struct {
	mode  string // buckets | manifest | fragments
	bytes int
	frags int
}

func (s *pairSession) SendDNA(ctx context.Context, t *dptypes.DNATransfer) error {
	if s.tamper != nil {
		t = s.tamper(t)
		if t == nil {
			return nil
		}
	}
	payload, err := json.Marshal(t)
	if err != nil {
		return err
	}
	rec := wireRecord{bytes: len(payload), frags: len(t.Fragments)}
	switch {
	case t.Delta:
		rec.mode = "fragments"
	case len(t.BucketRoots) > 0:
		rec.mode = "buckets"
	default:
		rec.mode = "manifest"
	}
	parts := len(payload)/(64<<10) + 1
	chunks := dnaChunksForTransfer(s.env.t, t, parts)
	for _, c := range chunks {
		c.IsDelta = t.Delta
	}
	stream := newTestDNAStream(s.env.peerCtx(s.steward), chunks...)
	hErr := s.env.handler.HandleGRPC(stream)
	s.mu.Lock()
	s.sent = append(s.sent, rec)
	if hErr != nil {
		s.errors = append(s.errors, hErr)
	}
	s.mu.Unlock()
	return nil
}

func (s *pairSession) records() []wireRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]wireRecord(nil), s.sent...)
}

func (s *pairSession) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent, s.errors = nil, nil
}

func (s *pairSession) ID() string                                                { return "pair" }
func (s *pairSession) PeerID() string                                            { return "controller" }
func (s *pairSession) IsClosed() bool                                            { return false }
func (s *pairSession) LocalAddr() string                                         { return "127.0.0.1:0" }
func (s *pairSession) RemoteAddr() string                                        { return "127.0.0.1:1" }
func (s *pairSession) Close(context.Context) error                               { return nil }
func (s *pairSession) SendConfig(context.Context, *dptypes.ConfigTransfer) error { return nil }
func (s *pairSession) ReceiveConfig(context.Context) (*dptypes.ConfigTransfer, error) {
	return nil, nil
}
func (s *pairSession) ReceiveDNA(context.Context) (*dptypes.DNATransfer, error)   { return nil, nil }
func (s *pairSession) SendBulk(context.Context, *dptypes.BulkTransfer) error      { return nil }
func (s *pairSession) ReceiveBulk(context.Context) (*dptypes.BulkTransfer, error) { return nil, nil }

var _ dpinterfaces.DataPlaneSession = (*pairSession)(nil)

type bulkEnv struct {
	t       *testing.T
	ca      *cfgcert.CA
	clock   *fakeClock
	cs      *countingConfigStore
	store   *BulkManifestStore
	pub     *recPublisher
	handler *DNAHandler
	sink    *recSink
	graph   *egprovider.SQLiteEntityGraphProvider

	ctxs      map[string]context.Context
	stewards  map[string]*bulkSteward
	kinds     []string
	tenants   staticTenants
	dirAuth   domainAuth
	withGraph bool
	fastStore bool
}

type envOpt func(*bulkEnv)

// withFastStore roots the flatfile config store on tmpfs when one is available.
// The 50,000-fragment tests rewrite every bucket shard per batch; fsync on a real
// disk, not the protocol, would otherwise dominate their run time.
func withFastStore() envOpt { return func(e *bulkEnv) { e.fastStore = true } }

func withGraph() envOpt            { return func(e *bulkEnv) { e.withGraph = true } }
func withKinds(k ...string) envOpt { return func(e *bulkEnv) { e.kinds = k } }

func newBulkEnv(t *testing.T, opts ...envOpt) *bulkEnv {
	t.Helper()
	ca, err := cfgcert.NewCA(&cfgcert.CAConfig{Organization: "CFGMS Bulk Round Test", Country: "US", ValidityDays: 1, KeySize: 2048})
	require.NoError(t, err)
	require.NoError(t, ca.Initialize(nil))

	e := &bulkEnv{
		t: t, ca: ca, clock: newFakeClock(),
		ctxs: map[string]context.Context{}, stewards: map[string]*bulkSteward{},
		kinds: []string{"user"}, tenants: staticTenants{}, dirAuth: domainAuth{},
	}
	for _, o := range opts {
		o(e)
	}
	root := t.TempDir()
	if e.fastStore {
		if dir, mkErr := os.MkdirTemp("/dev/shm", "cfgms-bulk-"); mkErr == nil {
			root = dir
			t.Cleanup(func() { _ = os.RemoveAll(dir) })
		}
	}
	e.cs = &countingConfigStore{ConfigStore: newFlatfileConfigStore(t, root)}
	store, err := NewBulkManifestStore(e.cs)
	require.NoError(t, err)
	e.store = store
	e.pub = &recPublisher{}
	e.sink = &recSink{store: store}
	e.handler = e.newHandler(store, e.pub)
	if e.withGraph {
		g, err := egprovider.NewSQLiteEntityGraphProvider(filepath.Join(t.TempDir(), "eg.db"))
		require.NoError(t, err)
		t.Cleanup(func() { _ = g.Close() })
		e.graph = g
		w, err := dnasync.New(g, dnasync.WithDirectoryAuthority(e.dirAuth))
		require.NoError(t, err)
		e.handler.WithEntityGraph(w, egtypes.DefaultTaxonomy())
	}
	return e
}

func (e *bulkEnv) newHandler(store FragmentDeltaStore, pub CommandPublisher) *DNAHandler {
	h := NewDNAHandler(logging.NewNoopLogger(), NewTenantQueue(), nil).
		WithPartialSync(store, pub).
		WithTenantResolver(e.tenants).
		WithBulkLane(staticKinds{kinds: e.kinds}, e.sink, e.dirAuth)
	h.now = e.clock.Now
	return h
}

func (e *bulkEnv) peerCtx(id string) context.Context {
	if c, ok := e.ctxs[id]; ok {
		return c
	}
	c := peerContextWithCA(e.t, e.ca, id)
	e.ctxs[id] = c
	return c
}

func (e *bulkEnv) addSteward(id string, frags []*commonpb.Fragment, bulkKinds ...string) *bulkSteward {
	e.t.Helper()
	if len(bulkKinds) == 0 {
		bulkKinds = e.kinds
	}
	e.tenants[id] = "tenant-1"
	sess := &pairSession{env: e, steward: id}
	resp := stewardclient.NewBulkSyncResponder(logging.NewNoopLogger(), id, "tenant-1", bulkKinds, sess, frags)
	s := &bulkSteward{id: id, resp: resp, sess: sess}
	e.stewards[id] = s
	return s
}

// heartbeat delivers the steward's current bulk root to the handler and runs
// every command the handler issues to completion.
func (e *bulkEnv) heartbeat(s *bulkSteward) {
	e.t.Helper()
	e.handler.HandleHeartbeatBulkRoot(context.Background(), s.id, s.resp.BulkRoot())
	e.pump(e.pub)
}

func (e *bulkEnv) pump(pub *recPublisher) {
	e.t.Helper()
	for i := 0; i < 5000; i++ {
		c, ok := pub.pop()
		if !ok {
			return
		}
		st := e.stewards[c.steward]
		require.NotNil(e.t, st, "command for unknown steward")
		cmd := &cpTypes.Command{ID: "c", Type: cpTypes.CommandSyncDNA, StewardID: c.steward, Params: c.params}
		_ = st.resp.Handle(context.Background(), st.sess, cmd)
	}
	e.t.Fatal("command pump did not settle")
}

func (e *bulkEnv) storedRoot(id string) string {
	e.t.Helper()
	m, err := e.store.CurrentManifest(id)
	require.NoError(e.t, err)
	return sdna.BulkRoot(m)
}

func (e *bulkEnv) storedIDs(id string) map[string]bool {
	e.t.Helper()
	m, err := e.store.CurrentManifest(id)
	require.NoError(e.t, err)
	out := map[string]bool{}
	for _, x := range m {
		out[x.GetFragmentId()] = true
	}
	return out
}

func objFrag(t testing.TB, id string, content map[string]interface{}) *commonpb.Fragment {
	t.Helper()
	f, err := sdna.NewFragment(id, "directory", sdna.MapState(content))
	require.NoError(t, err)
	return f
}

func userFrags(t testing.TB, n int) []*commonpb.Fragment {
	t.Helper()
	out := make([]*commonpb.Fragment, n)
	for i := range out {
		out[i] = objFrag(t, fmt.Sprintf("user:u%06d", i), map[string]interface{}{"name": fmt.Sprintf("user %d", i)})
	}
	return out
}

func replaceFrag(frags []*commonpb.Fragment, f *commonpb.Fragment) []*commonpb.Fragment {
	out := append([]*commonpb.Fragment(nil), frags...)
	for i := range out {
		if out[i].GetFragmentId() == f.GetFragmentId() {
			out[i] = f
			return out
		}
	}
	return append(out, f)
}

func dropFrag(frags []*commonpb.Fragment, id string) []*commonpb.Fragment {
	var out []*commonpb.Fragment
	for _, f := range frags {
		if f.GetFragmentId() != id {
			out = append(out, f)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Required tests
// ---------------------------------------------------------------------------

func TestBulkSync_InitialSyncOf50000Fragments_Completes(t *testing.T) {
	e := newBulkEnv(t, withFastStore())
	frags := userFrags(t, 50000)
	s := e.addSteward("steward-1", frags)

	e.heartbeat(s)

	assert.Equal(t, s.resp.BulkRoot(), e.storedRoot("steward-1"), "stored bulk root must equal the heartbeat root")
	assert.Len(t, e.storedIDs("steward-1"), 50000)
	var batches int
	for _, r := range s.sess.records() {
		if r.mode == "fragments" {
			batches++
			assert.LessOrEqual(t, r.frags, maxBulkBatchFragments)
		}
	}
	assert.GreaterOrEqual(t, batches, 25, "50,000 fragments need at least 25 batches of 2,000")
}

func TestBulkSync_OneChangedUserAmong50000_MovesUnder1MB(t *testing.T) {
	e := newBulkEnv(t, withFastStore())
	frags := userFrags(t, 50000)
	s := e.addSteward("steward-1", frags)
	// The first sync is covered by the initial-sync test; seed it directly so this
	// test measures only the second one.
	require.NoError(t, e.store.ApplyDelta("steward-1", frags))
	require.Equal(t, s.resp.BulkRoot(), e.storedRoot("steward-1"))

	changed := objFrag(t, "user:u012345", map[string]interface{}{"name": "renamed"})
	s.resp.SetFragments(replaceFrag(frags, changed))
	s.sess.reset()
	e.clock.Advance(2 * time.Minute)
	e.heartbeat(s)

	require.Equal(t, s.resp.BulkRoot(), e.storedRoot("steward-1"))
	total, fragTransfers, fragCount := 0, 0, 0
	seen := map[string]int{}
	for _, r := range s.sess.records() {
		total += r.bytes
		seen[r.mode]++
		if r.mode == "fragments" {
			fragTransfers++
			fragCount += r.frags
		}
	}
	assert.Equal(t, 1, seen["buckets"])
	assert.Equal(t, 1, seen["manifest"], "one differing bucket needs one manifest request")
	assert.Equal(t, 1, fragCount, "only the changed fragment moves")
	assert.Less(t, total, 1<<20, "wire bytes of the second sync must stay under 1 MB (got %d)", total)
}

func TestBulkSync_NewObjectIsAccepted(t *testing.T) {
	e := newBulkEnv(t)
	frags := userFrags(t, 40)
	s := e.addSteward("steward-1", frags)
	e.heartbeat(s)

	added := objFrag(t, "user:brand-new", map[string]interface{}{"name": "new"})
	s.resp.SetFragments(append(append([]*commonpb.Fragment(nil), frags...), added))
	e.clock.Advance(2 * time.Minute)
	e.heartbeat(s)

	assert.True(t, e.storedIDs("steward-1")["user:brand-new"], "an id the diff asked for is accepted")
	assert.Equal(t, s.resp.BulkRoot(), e.storedRoot("steward-1"))
}

func TestBulkSync_RemovedObjectIsRetractedInStoreAndGraph(t *testing.T) {
	e := newBulkEnv(t, withGraph())
	frags := userFrags(t, 20)
	s := e.addSteward("steward-1", frags)
	e.heartbeat(s)

	gone := mustEID(t, "host:steward-1/user:u000003")
	kept := mustEID(t, "host:steward-1/user:u000004")
	require.True(t, e.entityVisible(gone), "the object must reach the graph first")

	s.resp.SetFragments(dropFrag(frags, "user:u000003"))
	e.clock.Advance(2 * time.Minute)
	e.heartbeat(s)

	assert.False(t, e.storedIDs("steward-1")["user:u000003"], "removed id leaves the store")
	assert.False(t, e.entityVisible(gone), "removed id is retracted from the graph")
	assert.True(t, e.entityVisible(kept), "other objects stay")
	assert.Equal(t, s.resp.BulkRoot(), e.storedRoot("steward-1"))
}

func (e *bulkEnv) entityVisible(eid egtypes.EID) bool {
	view, err := e.graph.GetEntity(context.Background(), eid, egi.GetEntityOpts{})
	return err == nil && view != nil
}

func mustEID(t *testing.T, s string) egtypes.EID {
	t.Helper()
	eid, err := egtypes.ParseEID(s)
	require.NoError(t, err)
	return eid
}

func TestBulkSync_RetractionKeepsOtherReportersObservation(t *testing.T) {
	// The PDC moved: the old reporter stops reporting the shared object, the new
	// one reports it. The old reporter's retraction must not remove the entity.
	e := newBulkEnv(t, withGraph(), withKinds("cluster"))
	shared := objFrag(t, "cluster:shared", map[string]interface{}{"resource_owner": "tenant-a"})
	oldPDC := e.addSteward("steward-old", []*commonpb.Fragment{shared})
	newPDC := e.addSteward("steward-new", []*commonpb.Fragment{shared})
	e.heartbeat(oldPDC)
	e.heartbeat(newPDC)
	eid := mustEID(t, "cluster:shared")
	require.True(t, e.entityVisible(eid))

	oldPDC.resp.SetFragments(nil)
	e.clock.Advance(2 * time.Minute)
	e.handler.HandleHeartbeatBulkRoot(context.Background(), "steward-old", "")
	// An empty claim is not a heartbeat root; the old reporter stops claiming the
	// object by reporting a different bulk set instead.
	other := objFrag(t, "cluster:other", map[string]interface{}{"resource_owner": "tenant-a"})
	oldPDC.resp.SetFragments([]*commonpb.Fragment{other})
	e.heartbeat(oldPDC)

	assert.False(t, e.storedIDs("steward-old")["cluster:shared"])
	assert.True(t, e.entityVisible(eid), "the new reporter's observation keeps the entity visible")
}

func TestBulkSync_WithheldOrMutatedFragmentFailsRootCheck(t *testing.T) {
	t.Run("mutated bytes under the asserted hash", func(t *testing.T) {
		e := newBulkEnv(t)
		s := e.addSteward("steward-1", userFrags(t, 10))
		s.sess.tamper = func(tr *dptypes.DNATransfer) *dptypes.DNATransfer {
			if tr.Delta && len(tr.Fragments) > 0 {
				f := proto.Clone(tr.Fragments[0]).(*commonpb.Fragment)
				f.CanonicalBytes = append(append([]byte(nil), f.CanonicalBytes...), 'x')
				tr.Fragments[0] = f
			}
			return tr
		}
		e.heartbeat(s)
		assert.Empty(t, e.storedIDs("steward-1"), "nothing from the rejected batch is committed")
		assert.NotEqual(t, s.resp.BulkRoot(), e.storedRoot("steward-1"))
	})

	t.Run("mutated bytes with a recomputed hash", func(t *testing.T) {
		e := newBulkEnv(t)
		s := e.addSteward("steward-1", userFrags(t, 10))
		s.sess.tamper = func(tr *dptypes.DNATransfer) *dptypes.DNATransfer {
			if tr.Delta && len(tr.Fragments) > 0 {
				f := proto.Clone(tr.Fragments[0]).(*commonpb.Fragment)
				f.CanonicalBytes = append(append([]byte(nil), f.CanonicalBytes...), 'x')
				f.FragmentHash = sdna.FragmentHash(f.CanonicalBytes)
				tr.Fragments[0] = f
			}
			return tr
		}
		e.heartbeat(s)
		assert.Empty(t, e.storedIDs("steward-1"))
	})

	t.Run("manifest entry withheld", func(t *testing.T) {
		e := newBulkEnv(t)
		s := e.addSteward("steward-1", userFrags(t, 10))
		s.sess.tamper = func(tr *dptypes.DNATransfer) *dptypes.DNATransfer {
			if !tr.Delta && len(tr.Manifest) > 0 {
				tr.Manifest = tr.Manifest[1:]
			}
			return tr
		}
		e.heartbeat(s)
		assert.Empty(t, e.storedIDs("steward-1"))
	})

	t.Run("fragment withheld", func(t *testing.T) {
		e := newBulkEnv(t)
		s := e.addSteward("steward-1", userFrags(t, 10))
		s.sess.tamper = func(tr *dptypes.DNATransfer) *dptypes.DNATransfer {
			if tr.Delta && len(tr.Fragments) > 1 {
				tr.Fragments = tr.Fragments[1:]
			}
			return tr
		}
		e.heartbeat(s)
		assert.NotEqual(t, s.resp.BulkRoot(), e.storedRoot("steward-1"), "an incomplete round never verifies the root")
		_, done := e.handler.verifiedBulkRoots.Load("steward-1")
		assert.False(t, done)
	})
}

func TestBulkSync_RejectsUnownedKindOverBoundAndInventedIDs(t *testing.T) {
	t.Run("unowned kind", func(t *testing.T) {
		e := newBulkEnv(t) // only "user" is owned
		frags := append(userFrags(t, 5), objFrag(t, "host:os", map[string]interface{}{"name": "linux"}))
		s := e.addSteward("steward-1", frags, "user", "host")
		e.heartbeat(s)
		assert.Empty(t, e.storedIDs("steward-1"), "a host kind never reaches the store")
	})

	t.Run("invented id", func(t *testing.T) {
		e := newBulkEnv(t)
		s := e.addSteward("steward-1", userFrags(t, 5))
		s.sess.tamper = func(tr *dptypes.DNATransfer) *dptypes.DNATransfer {
			if tr.Delta {
				tr.Fragments = append(tr.Fragments, objFrag(t, "user:invented", map[string]interface{}{"name": "x"}))
			}
			return tr
		}
		e.heartbeat(s)
		assert.Empty(t, e.storedIDs("steward-1"))
	})

	t.Run("over the delta bound", func(t *testing.T) {
		r := &bulkRound{kinds: map[string]struct{}{"user": {}}, pending: map[string]struct{}{}}
		var recv []*commonpb.Fragment
		for i := 0; i < maxBulkBatchFragments+1; i++ {
			f := objFrag(t, fmt.Sprintf("user:b%05d", i), map[string]interface{}{"n": "x"})
			r.pending[f.GetFragmentId()] = struct{}{}
			recv = append(recv, f)
		}
		require.Error(t, r.validateBulkFragments(recv))
		require.NoError(t, r.validateBulkFragments(recv[:maxBulkBatchFragments]))
	})

	t.Run("over the byte bound", func(t *testing.T) {
		r := &bulkRound{kinds: map[string]struct{}{"user": {}}, pending: map[string]struct{}{}}
		var recv []*commonpb.Fragment
		for i := 0; i < 9; i++ { // 9 x 960 KiB > 8 MiB
			f := &commonpb.Fragment{FragmentId: fmt.Sprintf("user:big%d", i), CanonicalBytes: make([]byte, 960<<10)}
			r.pending[f.GetFragmentId()] = struct{}{}
			recv = append(recv, f)
		}
		require.Error(t, r.validateBulkFragments(recv))
	})

	t.Run("bad id charset", func(t *testing.T) {
		r := &bulkRound{kinds: map[string]struct{}{"user": {}}, pending: map[string]struct{}{"user:a\nb": {}}}
		require.Error(t, r.validateBulkFragments([]*commonpb.Fragment{{FragmentId: "user:a\nb", CanonicalBytes: []byte("x")}}))
	})

	t.Run("stored count cap", func(t *testing.T) {
		e := newBulkEnv(t)
		s := e.addSteward("steward-1", userFrags(t, 3))
		ids := map[string]string{}
		for _, f := range userFrags(t, 3) {
			ids[f.GetFragmentId()] = f.GetFragmentHash()
		}
		var entries []*commonpb.ManifestEntry
		for id, h := range ids {
			entries = append(entries, &commonpb.ManifestEntry{FragmentId: id, FragmentHash: h})
		}
		roots := sdna.BucketRoots(entries)
		diff := map[int]bool{}
		for id := range ids {
			diff[sdna.BucketOf(id)] = true
		}
		var buckets []int
		for b := range diff {
			buckets = append(buckets, b)
		}
		e.handler.bulkRounds.Store("steward-1", &bulkRound{
			steward: "steward-1", claimedRoot: s.resp.BulkRoot(), kinds: map[string]struct{}{"user": {}},
			progressAt: e.clock.Now(), phase: bulkPhaseManifest, storedTotal: MaxBulkFragmentsPerSteward,
			bucketRoots: roots, diffBuckets: buckets[:1], storedByID: map[string]string{}, remoteHash: map[string]string{},
		})
		var inBucket []*commonpb.ManifestEntry
		for _, en := range entries {
			if sdna.BucketOf(en.GetFragmentId()) == buckets[0] {
				inBucket = append(inBucket, en)
			}
		}
		err := e.handler.handleBulkManifest(context.Background(), "steward-1", inBucket)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "fragment limit")
	})

	t.Run("lookup fails closed", func(t *testing.T) {
		for name, lister := range map[string]PerObjectKindLister{
			"nil lookup":   nil,
			"failing":      staticKinds{err: errors.New("cache down")},
			"empty answer": staticKinds{},
		} {
			e := newBulkEnv(t)
			s := e.addSteward("steward-1", userFrags(t, 3))
			e.handler.WithBulkLane(lister, e.sink, e.dirAuth)
			e.heartbeat(s)
			assert.Zero(t, e.pub.published(), name+": no round starts")
		}
		e := newBulkEnv(t)
		s := e.addSteward("steward-1", userFrags(t, 3))
		delete(e.tenants, "steward-1")
		e.heartbeat(s)
		assert.Zero(t, e.pub.published(), "unknown tenant: no round starts")
	})

	t.Run("reply with no round", func(t *testing.T) {
		e := newBulkEnv(t)
		s := e.addSteward("steward-1", userFrags(t, 3))
		cmd := &cpTypes.Command{ID: "c", Params: map[string]interface{}{cpTypes.SyncDNAParamBulk: cpTypes.SyncDNABulkBuckets}}
		require.NoError(t, s.resp.Handle(context.Background(), s.sess, cmd))
		assert.Len(t, s.sess.errors, 1, "an unsolicited bulk reply is rejected")
	})
}

func TestBulkSync_HostRootMismatchWithStoreWired_StartsNoHostRound(t *testing.T) {
	e := newBulkEnv(t)
	s := e.addSteward("steward-1", userFrags(t, 5))
	e.heartbeat(s)
	before := e.pub.published()
	require.NotZero(t, before)

	e.handler.HandleHeartbeatRoot(context.Background(), "steward-1", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")

	assert.Equal(t, before, e.pub.published(), "no host partial-sync command is published")
	_, pending := e.handler.pendingDeltas.Load("steward-1")
	assert.False(t, pending, "no host delta request is recorded")
	assert.False(t, e.handler.hostPartialSync)
}

func TestBulkSync_OnlyConnectedNodeIsCommanded(t *testing.T) {
	e := newBulkEnv(t)
	pubB := &recPublisher{}
	storeB, err := NewBulkManifestStore(e.cs) // shares the ConfigStore with node A
	require.NoError(t, err)
	handlerB := e.newHandler(storeB, pubB)

	frags := userFrags(t, 30)
	s := e.addSteward("steward-1", frags)

	// The steward is connected to node A: only A is commanded.
	e.handler.HandleHeartbeatBulkRoot(context.Background(), "steward-1", s.resp.BulkRoot())
	assert.Equal(t, 1, e.pub.published())
	assert.Zero(t, pubB.published(), "node B is never commanded for a steward connected to A")

	// Mid-round it reconnects to node B. B starts its own round; A's is abandoned
	// and its late reply is rejected.
	sessB := &pairSession{env: e, steward: "steward-1"}
	respB := stewardclient.NewBulkSyncResponder(logging.NewNoopLogger(), "steward-1", "tenant-1", e.kinds, sessB, frags)
	e.clock.Advance(2 * time.Minute)
	prevHandler := e.handler
	e.handler = handlerB
	handlerB.HandleHeartbeatBulkRoot(context.Background(), "steward-1", respB.BulkRoot())
	e.stewards["steward-1"] = &bulkSteward{id: "steward-1", resp: respB, sess: sessB}
	e.pump(pubB)
	assert.Equal(t, respB.BulkRoot(), e.storedRoot("steward-1"), "B completes the round")
	assert.Equal(t, 1, e.pub.published(), "A issued nothing further")

	// Back on A with changed state: A's stale round is replaced cleanly.
	e.handler = prevHandler
	changed := objFrag(t, "user:u000001", map[string]interface{}{"name": "moved"})
	sessA := &pairSession{env: e, steward: "steward-1"}
	respA := stewardclient.NewBulkSyncResponder(logging.NewNoopLogger(), "steward-1", "tenant-1", e.kinds, sessA, replaceFrag(frags, changed))
	e.stewards["steward-1"] = &bulkSteward{id: "steward-1", resp: respA, sess: sessA}
	e.clock.Advance(2 * time.Minute)
	e.handler.HandleHeartbeatBulkRoot(context.Background(), "steward-1", respA.BulkRoot())
	e.pump(e.pub)
	assert.Equal(t, respA.BulkRoot(), e.storedRoot("steward-1"), "the restarted round on A completes")
}

type heartbeatCP struct {
	cpinterfaces.ControlPlaneProvider
	handler cpinterfaces.HeartbeatHandler
}

func (p *heartbeatCP) SubscribeHeartbeats(_ context.Context, h cpinterfaces.HeartbeatHandler) error {
	p.handler = h
	return nil
}

func TestBulkSync_HeartbeatBulkRootReachesHandlerViaRealHeartbeatService(t *testing.T) {
	e := newBulkEnv(t)
	s := e.addSteward("steward-1", userFrags(t, 12))

	cp := &heartbeatCP{}
	svc, err := heartbeat.New(&heartbeat.Config{ControlPlane: cp, Logger: logging.NewNoopLogger()})
	require.NoError(t, err)
	svc.SetOnBulkRoot(e.handler.HandleHeartbeatBulkRoot)
	require.NoError(t, svc.Start(context.Background()))
	t.Cleanup(func() { _ = svc.Stop(context.Background()) })
	require.NotNil(t, cp.handler)

	// The root rides the Metrics side-channel exactly as the steward sends it.
	require.NoError(t, cp.handler(context.Background(), &cpTypes.Heartbeat{
		StewardID: "steward-1", Status: cpTypes.StatusHealthy, Timestamp: time.Now(),
		DNABulkRoot: s.resp.BulkRoot(),
	}))
	require.Equal(t, 1, e.pub.published(), "the heartbeat must start a bulk round")
	e.pump(e.pub)
	assert.Equal(t, s.resp.BulkRoot(), e.storedRoot("steward-1"))
}

func TestBulkSync_RootFlappingIsRateLimited(t *testing.T) {
	flap := func(i int) string { return fmt.Sprintf("%064x", i+1) }

	t.Run("one round a minute", func(t *testing.T) {
		e := newBulkEnv(t)
		e.addSteward("steward-1", userFrags(t, 3))
		for i := 0; i <= 300; i++ { // a changed root every second for five minutes
			e.handler.HandleHeartbeatBulkRoot(context.Background(), "steward-1", flap(i))
			e.clock.Advance(time.Second)
		}
		assert.Equal(t, 6, e.pub.published(), "rounds start at 0, 60, ..., 300 seconds and no more often")
	})

	t.Run("twenty an hour", func(t *testing.T) {
		e := newBulkEnv(t)
		e.addSteward("steward-1", userFrags(t, 3))
		for i := 0; i < 59; i++ {
			e.handler.HandleHeartbeatBulkRoot(context.Background(), "steward-1", flap(i))
			e.clock.Advance(61 * time.Second)
		}
		assert.Equal(t, bulkRoundsPerHour, e.pub.published())
	})

	t.Run("other stewards are not limited by it", func(t *testing.T) {
		e := newBulkEnv(t)
		e.addSteward("steward-1", userFrags(t, 3))
		e.addSteward("steward-2", userFrags(t, 3))
		e.handler.HandleHeartbeatBulkRoot(context.Background(), "steward-1", flap(1))
		e.handler.HandleHeartbeatBulkRoot(context.Background(), "steward-2", flap(1))
		assert.Equal(t, 2, e.pub.published())
	})
}

// ---------------------------------------------------------------------------
// Membership sink
// ---------------------------------------------------------------------------

func dirFrag(t testing.TB, kind, id, domain string, memberOf ...string) *commonpb.Fragment {
	t.Helper()
	m := make([]interface{}, len(memberOf))
	for i, g := range memberOf {
		m[i] = g
	}
	return objFrag(t, kind+":"+id, map[string]interface{}{
		"directory_domain": domain, "display_name": id, "member_of": m,
	})
}

func newDirEnv(t *testing.T) *bulkEnv {
	e := newBulkEnv(t, withKinds("directory_user", "directory_group"))
	e.dirAuth["steward-1"] = "a.example"
	return e
}

func TestBulkSync_UpsertedUserFragmentReachesMembershipSink(t *testing.T) {
	e := newDirEnv(t)
	s := e.addSteward("steward-1", []*commonpb.Fragment{
		dirFrag(t, "directory_user", "alice", "a.example", "g1"),
		dirFrag(t, "directory_group", "g1", "a.example"),
	})
	e.heartbeat(s)

	calls := e.sink.snapshot()
	require.NotEmpty(t, calls)
	var users []directory.Fragment
	for _, c := range calls {
		assert.Equal(t, "steward-1", c.peer)
		assert.Equal(t, "directory:a.example", c.authority, "authority is the verifier's answer")
		for _, u := range c.upserts {
			if u.Kind == "directory_user" {
				users = append(users, u)
			}
			assert.False(t, c.storedAtCall[u.Kind+":"+u.ObjectID], "the sink runs before the batch is committed")
		}
	}
	require.Len(t, users, 1)
	assert.Equal(t, "alice", users[0].ObjectID)
	assert.Contains(t, users[0].Attributes, "member_of")
	assert.True(t, e.storedIDs("steward-1")["directory_user:alice"], "and the batch is committed afterwards")
}

func TestBulkSync_RemovedUserFragmentReachesMembershipSinkAsRemoval(t *testing.T) {
	e := newDirEnv(t)
	frags := []*commonpb.Fragment{
		dirFrag(t, "directory_user", "alice", "a.example"),
		dirFrag(t, "directory_user", "bob", "a.example"),
		dirFrag(t, "directory_group", "g1", "a.example"),
	}
	s := e.addSteward("steward-1", frags)
	e.heartbeat(s)

	s.resp.SetFragments(dropFrag(dropFrag(frags, "directory_user:alice"), "directory_group:g1"))
	e.clock.Advance(2 * time.Minute)
	e.heartbeat(s)

	var removed []directory.RemovedFragment
	for _, c := range e.sink.snapshot() {
		removed = append(removed, c.removed...)
	}
	assert.ElementsMatch(t, []directory.RemovedFragment{
		{Kind: "directory_user", ObjectID: "alice"},
		{Kind: "directory_group", ObjectID: "g1"},
	}, removed)
	assert.False(t, e.storedIDs("steward-1")["directory_user:alice"])
}

func TestBulkSync_UnverifiedClaimNeverReachesSink(t *testing.T) {
	e := newDirEnv(t)
	s := e.addSteward("steward-1", []*commonpb.Fragment{
		dirFrag(t, "directory_user", "mallory", "victim.example"), // steward is not authority for it
		dirFrag(t, "directory_user", "alice", "a.example"),
		dirFrag(t, "directory_user", "nodomain", ""),
	})
	e.heartbeat(s)

	for _, c := range e.sink.snapshot() {
		for _, u := range c.upserts {
			assert.NotEqual(t, "mallory", u.ObjectID)
			assert.NotEqual(t, "nodomain", u.ObjectID)
		}
		assert.NotEqual(t, "directory:victim.example", c.authority)
	}
	var alice bool
	for _, c := range e.sink.snapshot() {
		for _, u := range c.upserts {
			alice = alice || u.ObjectID == "alice"
		}
	}
	assert.True(t, alice, "the verified claim still reaches the sink")
}

func TestBulkSync_SinkFailureLeavesBatchUncommittedAndNextRoundRefetches(t *testing.T) {
	e := newDirEnv(t)
	s := e.addSteward("steward-1", []*commonpb.Fragment{
		dirFrag(t, "directory_user", "alice", "a.example", "g1"),
	})
	e.sink.fail = errors.New("sink unavailable")
	e.heartbeat(s)

	assert.Empty(t, e.storedIDs("steward-1"), "the batch is not committed when the sink fails")
	assert.NotEqual(t, s.resp.BulkRoot(), e.storedRoot("steward-1"))

	e.clock.Advance(2 * time.Minute)
	e.heartbeat(s)

	assert.True(t, e.storedIDs("steward-1")["directory_user:alice"], "the next round re-diffs and re-fetches the batch")
	assert.Equal(t, s.resp.BulkRoot(), e.storedRoot("steward-1"))
	var delivered int
	for _, c := range e.sink.snapshot() {
		delivered += len(c.upserts)
	}
	assert.Equal(t, 2, delivered, "the sink saw the batch on both rounds (idempotent)")
}

// ---------------------------------------------------------------------------
// Ingest bounds
// ---------------------------------------------------------------------------

func TestBulkIngest_MaxMemberOfObjectAccepted_OverBoundRejected(t *testing.T) {
	memberIDs := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("S-1-5-21-1111111111-2222222222-3333333333-%08d", i)
		}
		return out
	}

	t.Run("10,000 member_of ids pass", func(t *testing.T) {
		e := newDirEnv(t)
		big := dirFrag(t, "directory_user", "big", "a.example", memberIDs(10000)...)
		require.Less(t, proto.Size(big), maxDNAFragmentBytes, "the 10,000 id object is within the fragment bound")
		s := e.addSteward("steward-1", []*commonpb.Fragment{big})
		e.heartbeat(s)
		assert.True(t, e.storedIDs("steward-1")["directory_user:big"])
		assert.Equal(t, s.resp.BulkRoot(), e.storedRoot("steward-1"))
	})

	t.Run("a fragment over maxDNAFragmentBytes is rejected", func(t *testing.T) {
		e := newDirEnv(t)
		huge := dirFrag(t, "directory_user", "huge", "a.example", memberIDs(40000)...)
		require.Greater(t, proto.Size(huge), maxDNAFragmentBytes)
		s := e.addSteward("steward-1", []*commonpb.Fragment{huge})
		e.heartbeat(s)
		assert.Empty(t, e.storedIDs("steward-1"))
	})
}
