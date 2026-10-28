// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package client

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/features/steward/commands"
	"github.com/cfgis/cfgms/features/steward/dna"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	dpTypes "github.com/cfgis/cfgms/pkg/dataplane/types"
)

// kindObjectModule is a real per-kind module: Get(kind) returns the objects
// registered for that kind under the reserved per-object key.
type kindObjectModule struct {
	objects map[string][]interface{}
}

var _ modules.Module = (*kindObjectModule)(nil)

func (m *kindObjectModule) Get(_ context.Context, kind string) (modules.ConfigState, error) {
	return &inMemoryConfigState{data: map[string]interface{}{
		modules.PerObjectKey: m.objects[kind],
	}}, nil
}
func (m *kindObjectModule) Set(_ context.Context, _ string, _ modules.ConfigState) error { return nil }

func objectList(n int) []interface{} {
	out := make([]interface{}, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, map[string]interface{}{
			"id":    fmt.Sprintf("obj-%05d", i),
			"attrs": map[string]interface{}{"name": fmt.Sprintf("object %d", i)},
		})
	}
	return out
}

func bulkFragments(kind string, n int) []*commonpb.Fragment {
	out := make([]*commonpb.Fragment, 0, n)
	for i := 0; i < n; i++ {
		canonical := []byte(fmt.Sprintf(`{"i":%d}`, i))
		out = append(out, &commonpb.Fragment{
			FragmentId:     fmt.Sprintf("%s:obj-%05d", kind, i),
			Authority:      "directory",
			CanonicalBytes: canonical,
			FragmentHash:   dna.FragmentHash(canonical),
		})
	}
	return out
}

func hostFragments(kinds ...string) []*commonpb.Fragment {
	out := make([]*commonpb.Fragment, 0, len(kinds))
	for _, k := range kinds {
		out = append(out, makeHostFact(k))
	}
	return out
}

func perObjectSpecs(kinds ...string) []cpTypes.ObserveModuleSpec {
	specs := make([]cpTypes.ObserveModuleSpec, 0, len(kinds))
	for _, k := range kinds {
		specs = append(specs, cpTypes.ObserveModuleSpec{Name: "directory", Kind: k, PerObject: true})
	}
	return specs
}

func newBulkSession() *testDataPlaneSession {
	return &testDataPlaneSession{dnaSent: make(chan *dpTypes.DNATransfer, 64)}
}

func drainTransfers(s *testDataPlaneSession) []*dpTypes.DNATransfer {
	var out []*dpTypes.DNATransfer
	for {
		select {
		case tr := <-s.dnaSent:
			out = append(out, tr)
		default:
			return out
		}
	}
}

// runSync dispatches cmd and waits for its asynchronous execution to finish.
func runSync(t *testing.T, h *commands.Handler, cmd *cpTypes.SignedCommand) {
	t.Helper()
	require.NoError(t, h.HandleCommand(context.Background(), cmd))
	h.Wait()
}

func syncDNACmd(id string, params map[string]interface{}) *cpTypes.SignedCommand {
	return &cpTypes.SignedCommand{Command: cpTypes.Command{
		ID: id, Type: cpTypes.CommandSyncDNA, StewardID: "steward-1", TenantID: "tenant-1",
		Timestamp: time.Now(), Params: params,
	}}
}

// newBulkSyncClient returns a client holding the given bulk fragments, wired
// to an in-process data plane session and a real command handler.
func newBulkSyncClient(t *testing.T, bulk []*commonpb.Fragment) (*TransportClient, *testDataPlaneSession, *commands.Handler) {
	t.Helper()
	c := newMinimalClient(t)
	c.stewardID, c.tenantID = "steward-1", "tenant-1"
	c.bulkKinds = map[string]bool{"user": true}
	c.setCurrentDNAFragments(append(hostFragments("host:os"), bulk...))
	sess := newBulkSession()
	c.mu.Lock()
	c.dataPlaneSession = sess
	c.mu.Unlock()
	h, err := c.setupCommandHandler(context.Background(), "steward-1")
	require.NoError(t, err)
	return c, sess, h
}

func TestHandleObserveModules_TwoKindModuleKeepsBothKinds(t *testing.T) {
	c, _ := newObserveTestClient(t)
	mod := &kindObjectModule{objects: map[string][]interface{}{"user": objectList(3), "group": objectList(2)}}
	c.observeModuleLoader = newInMemoryLoader(map[string]modules.Module{"directory": mod})

	require.NoError(t, c.handleObserveModules(context.Background(), observeCmd(t, perObjectSpecs("user", "group"))))

	c.dnaMu.RLock()
	defer c.dnaMu.RUnlock()
	kinds := map[string]int{}
	for _, f := range c.currentBulkFragments {
		k, _, _ := strings.Cut(f.GetFragmentId(), ":")
		kinds[k]++
	}
	assert.Equal(t, map[string]int{"user": 3, "group": 2}, kinds)
	assert.NotEmpty(t, c.currentBulkRoot)
}

func TestParseObserveModuleSpecs_ReadsPerObjectInAllShapes(t *testing.T) {
	want := cpTypes.ObserveModuleSpec{Name: "directory", Kind: "user", PerObject: true}

	raw, err := json.Marshal([]cpTypes.ObserveModuleSpec{want})
	require.NoError(t, err)
	fromString, err := parseObserveModuleSpecs(string(raw))
	require.NoError(t, err)
	assert.Equal(t, []cpTypes.ObserveModuleSpec{want}, fromString)

	fromIface, err := parseObserveModuleSpecs([]interface{}{
		map[string]interface{}{"name": "directory", "kind": "user", "per_object": true}})
	require.NoError(t, err)
	assert.Equal(t, []cpTypes.ObserveModuleSpec{want}, fromIface)

	fromNative, err := parseObserveModuleSpecs([]cpTypes.ObserveModuleSpec{want})
	require.NoError(t, err)
	assert.Equal(t, []cpTypes.ObserveModuleSpec{want}, fromNative)
}

func TestSetCurrentDNAFragments_SplitsBulkAndKeepsHostRootStable(t *testing.T) {
	host := hostFragments("host:os", "host:cpu")

	plain := newMinimalClient(t)
	plain.setCurrentDNAFragments(host)
	plain.dnaMu.RLock()
	plainRoot := plain.currentDNAAggregateRoot
	plain.dnaMu.RUnlock()
	assert.Empty(t, plain.currentBulkRoot, "no bulk fragments means no bulk root")

	c := newMinimalClient(t)
	c.bulkKinds = map[string]bool{"user": true}
	bulk := bulkFragments("user", 10)
	c.setCurrentDNAFragments(append(append([]*commonpb.Fragment{}, host...), bulk...))

	c.dnaMu.RLock()
	defer c.dnaMu.RUnlock()
	assert.Equal(t, plainRoot, c.currentDNAAggregateRoot, "host root must not depend on bulk fragments")
	assert.Len(t, c.currentDNAFragments, 2)
	assert.Len(t, c.currentBulkFragments, 10)
	assert.Equal(t, dna.BulkRoot(manifestOf(bulk)), c.currentBulkRoot)

	// Collector refreshes must not wipe the bulk lane.
	c.dnaMu.RUnlock()
	c.setCurrentHostDNAFragments(host)
	c.dnaMu.RLock()
	assert.Len(t, c.currentBulkFragments, 10)
}

func TestHeartbeatCarriesBulkRoot(t *testing.T) {
	c := newMinimalClient(t)
	c.bulkKinds = map[string]bool{"user": true}
	c.setCurrentDNAFragments(append(hostFragments("host:os"), bulkFragments("user", 3)...))
	c.dnaMu.RLock()
	defer c.dnaMu.RUnlock()
	assert.Len(t, c.currentBulkRoot, dna.AggregateRootHexLen)
}

func TestPublishDNAUpdate_ExcludesBulkFragments(t *testing.T) {
	c, q := newClientWithOfflineQueue(t)
	c.bulkKinds = map[string]bool{"user": true}
	c.setCurrentDNAFragments(append(hostFragments("host:os"), bulkFragments("user", 5000)...))

	require.NoError(t, c.PublishDNAUpdate(context.Background(), map[string]string{"k": "v"}, "", ""))
	var ev *cpTypes.Event
	q.Drain(func(e *cpTypes.Event) error { ev = e; return nil })
	require.NotNil(t, ev)

	payload, err := json.Marshal(ev.Details)
	require.NoError(t, err)
	assert.Less(t, len(payload), 64*1024, "event payload must not grow with bulk fragments")
	assert.NotContains(t, string(payload), "user:obj-")

	// A bulk-only change must not trigger a publish.
	c.setCurrentDNAFragments(append(hostFragments("host:os"), bulkFragments("user", 4000)...))
	require.NoError(t, c.PublishDNAUpdate(context.Background(), map[string]string{"k": "v"}, "", ""))
	assert.Equal(t, 0, q.Len(), "bulk-only change must not pass the skip-when-unchanged gate")
}

// bulkInCollector returns bulk-kind fragments from CollectFragments to prove
// the full-sync snapshot filters them out.
type bulkInCollector struct{ frags []*commonpb.Fragment }

func (b *bulkInCollector) CollectAttributes(context.Context) (map[string]string, error) {
	return map[string]string{"os": "linux"}, nil
}
func (b *bulkInCollector) CollectFragments(context.Context) []*commonpb.Fragment { return b.frags }

func TestSyncDNA_FullSnapshotExcludesBulk(t *testing.T) {
	c, sess, h := newBulkSyncClient(t, bulkFragments("user", 20))
	c.dnaCollector = &bulkInCollector{frags: append(hostFragments("host:os"), bulkFragments("user", 20)...)}
	c.setCurrentDNAFromAttrs(map[string]string{"os": "linux"})

	runSync(t, h, syncDNACmd("full-1", map[string]interface{}{}))
	trs := drainTransfers(sess)
	require.Len(t, trs, 1)
	assert.False(t, trs[0].Delta)
	assert.False(t, trs[0].Bulk)
	require.Len(t, trs[0].FragmentBytes, 1, "only the host fragment travels in the snapshot")
	for _, b := range trs[0].FragmentBytes {
		assert.NotContains(t, string(b), "user:obj-")
	}
}

func TestSyncDNA_BulkBuckets_Manifest_Fragments_Replies(t *testing.T) {
	bulk := bulkFragments("user", 300)
	_, sess, h := newBulkSyncClient(t, bulk)

	// bulk=buckets
	runSync(t, h, syncDNACmd("b1", map[string]interface{}{"bulk": "buckets"}))
	trs := drainTransfers(sess)
	require.Len(t, trs, 1)
	assert.True(t, trs[0].Bulk)
	require.Len(t, trs[0].BucketRoots, dna.BucketCount)
	assert.Equal(t, dna.BucketRoots(manifestOf(bulk)), trs[0].BucketRoots)

	// bulk=manifest for two buckets: entries only from those buckets.
	b0 := dna.BucketOf(bulk[0].GetFragmentId())
	b1 := dna.BucketOf(bulk[1].GetFragmentId())
	want := map[int]bool{b0: true, b1: true}
	list := make([]interface{}, 0, 2)
	for b := range want {
		list = append(list, float64(b)) // wire shape: JSON-decoded numbers
	}
	runSync(t, h, syncDNACmd("m1", map[string]interface{}{"bulk": "manifest", "buckets": list}))
	trs = drainTransfers(sess)
	require.Len(t, trs, 1)
	assert.True(t, trs[0].Bulk)
	require.NotEmpty(t, trs[0].Manifest)
	for _, e := range trs[0].Manifest {
		assert.True(t, want[dna.BucketOf(e.GetFragmentId())], "manifest entry outside requested buckets")
	}
	expected := 0
	for _, f := range bulk {
		if want[dna.BucketOf(f.GetFragmentId())] {
			expected++
		}
	}
	assert.Len(t, trs[0].Manifest, expected)

	// bulk=fragments: exactly the requested ids; unknown id skipped, no full-sync fallback.
	ids, err := json.Marshal([]string{bulk[3].GetFragmentId(), "user:does-not-exist", bulk[7].GetFragmentId()})
	require.NoError(t, err)
	runSync(t, h, syncDNACmd("f1", map[string]interface{}{"bulk": "fragments", "fragment_ids": string(ids)}))
	trs = drainTransfers(sess)
	require.Len(t, trs, 1)
	assert.True(t, trs[0].Delta)
	assert.True(t, trs[0].Bulk)
	require.Len(t, trs[0].Fragments, 2)
	assert.Equal(t, bulk[3].GetFragmentId(), trs[0].Fragments[0].GetFragmentId())
	assert.Equal(t, bulk[7].GetFragmentId(), trs[0].Fragments[1].GetFragmentId())
}

func TestSyncDNA_BulkFragmentsSplitOnObjectBoundaries(t *testing.T) {
	big := make([]*commonpb.Fragment, 0, 5)
	for i := 0; i < 5; i++ {
		canonical := []byte(strings.Repeat("x", 3<<20)) // 3 MiB each
		big = append(big, &commonpb.Fragment{
			FragmentId: fmt.Sprintf("user:big-%d", i), CanonicalBytes: canonical, FragmentHash: dna.FragmentHash(canonical),
		})
	}
	_, sess, h := newBulkSyncClient(t, big)
	ids := make([]string, 0, len(big))
	for _, f := range big {
		ids = append(ids, f.GetFragmentId())
	}
	raw, _ := json.Marshal(ids)
	runSync(t, h, syncDNACmd("split", map[string]interface{}{"bulk": "fragments", "fragment_ids": string(raw)}))
	trs := drainTransfers(sess)
	require.Len(t, trs, 3, "5 x 3 MiB splits as 2+2+1 under the 8 MiB budget")
	total := 0
	for _, tr := range trs {
		assert.True(t, tr.Delta)
		assert.True(t, tr.Bulk)
		size := 0
		for _, f := range tr.Fragments {
			size += len(f.GetCanonicalBytes())
		}
		assert.LessOrEqual(t, size, maxBulkReplyBytes)
		total += len(tr.Fragments)
	}
	assert.Equal(t, 5, total)
}

func TestSyncDNA_BulkRequestOverBoundIsRejected(t *testing.T) {
	_, sess, h := newBulkSyncClient(t, bulkFragments("user", 5))

	tooManyBuckets := make([]interface{}, 257)
	for i := range tooManyBuckets {
		tooManyBuckets[i] = float64(i % 256)
	}
	runSync(t, h, syncDNACmd("o1",
		map[string]interface{}{"bulk": "manifest", "buckets": tooManyBuckets}))

	runSync(t, h, syncDNACmd("o2",
		map[string]interface{}{"bulk": "manifest", "buckets": []interface{}{float64(256)}}))

	ids := make([]string, maxRequestedFragmentIDs+1)
	for i := range ids {
		ids[i] = fmt.Sprintf("user:obj-%d", i)
	}
	raw, _ := json.Marshal(ids)
	// The command-level params bound may refuse this before the handler runs;
	// either way no reply is produced.
	_ = h.HandleCommand(context.Background(), syncDNACmd("o3",
		map[string]interface{}{"bulk": "fragments", "fragment_ids": string(raw)}))
	h.Wait()

	runSync(t, h, syncDNACmd("o4", map[string]interface{}{"bulk": "bogus"}))

	assert.Empty(t, drainTransfers(sess), "rejected requests must not produce a reply")

	// The bounds themselves, checked at the parser.
	_, err := parseBucketNumbers(tooManyBuckets)
	assert.Error(t, err)
	_, err = parseBucketNumbers([]interface{}{float64(-1)})
	assert.Error(t, err)
	_, err = parseFragmentIDs(string(raw))
	assert.Error(t, err)
}

func TestObserveSweep_OmittedPerObjectKindIsRetired(t *testing.T) {
	c, _ := newObserveTestClient(t)
	mod := &kindObjectModule{objects: map[string][]interface{}{"user": objectList(3), "group": objectList(2)}}
	c.observeModuleLoader = newInMemoryLoader(map[string]modules.Module{"directory": mod})
	ctx := context.Background()

	require.NoError(t, c.handleObserveModules(ctx, observeCmd(t, perObjectSpecs("user", "group"))))
	c.dnaMu.RLock()
	require.Len(t, c.currentBulkFragments, 5)
	c.dnaMu.RUnlock()

	// "group" omitted: its fragments retire, "user" stays.
	require.NoError(t, c.handleObserveModules(ctx, observeCmdWithID(t, "c2", perObjectSpecs("user"))))
	c.dnaMu.RLock()
	require.Len(t, c.currentBulkFragments, 3)
	for _, f := range c.currentBulkFragments {
		assert.True(t, strings.HasPrefix(f.GetFragmentId(), "user:"))
	}
	c.dnaMu.RUnlock()

	// An empty sweep omits every held kind.
	require.NoError(t, c.handleObserveModules(ctx, observeCmdWithID(t, "c3", nil)))
	c.dnaMu.RLock()
	defer c.dnaMu.RUnlock()
	assert.Empty(t, c.currentBulkFragments)
	assert.Empty(t, c.currentBulkRoot)
}
