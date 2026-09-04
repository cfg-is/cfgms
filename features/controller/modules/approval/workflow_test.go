// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package approval_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/features/controller/modules/approval"
	"github.com/cfgis/cfgms/features/controller/modules/cache"
	modules "github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/pkg/modules/bundle"
	"github.com/cfgis/cfgms/pkg/modules/trust"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// testKeys holds an Ed25519 key pair for a named publisher.
type testKeys struct {
	publisher string
	pubKey    ed25519.PublicKey
	privKey   ed25519.PrivateKey
}

func generateKeys(t *testing.T, publisher string) testKeys {
	t.Helper()
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return testKeys{publisher: publisher, pubKey: pubKey, privKey: privKey}
}

// makeSignedBundle creates a Bundle with a valid Ed25519 signature for the given publisher.
func makeSignedBundle(t *testing.T, keys testKeys, name, version string) *bundle.Bundle {
	t.Helper()
	meta := &modules.ModuleMetadata{
		Name:      name,
		Version:   version,
		Publisher: keys.publisher,
		Executors: []string{"steward"},
	}
	binaries := map[string][]byte{"linux-amd64": []byte("fake-binary-content")}
	manifestBytes, err := yaml.Marshal(meta)
	require.NoError(t, err)

	contentHash, err := bundle.ComputeContentHash(binaries, manifestBytes)
	require.NoError(t, err)

	sig := ed25519.Sign(keys.privKey, []byte(contentHash))
	return &bundle.Bundle{
		Manifest: meta,
		Binaries: map[string]string{"linux-amd64": "binaries/linux-amd64"},
		Signatures: []bundle.BundleSignature{
			{Publisher: keys.publisher, Algorithm: "ed25519", Signature: sig},
		},
		ContentHash: contentHash,
	}
}

func makeWorkflow(t *testing.T) (*approval.ApprovalWorkflow, *cache.ModuleCache) {
	t.Helper()
	c, err := cache.New(t.TempDir() + "/module-cache")
	require.NoError(t, err)
	return approval.New(c), c
}

func makeTrustStore(keys ...testKeys) trust.TrustStore {
	store := trust.NewInMemoryTrustStore()
	for _, k := range keys {
		_ = store.AddPublisher(trust.PublisherIdentity{
			Name:      k.publisher,
			PublicKey: []byte(k.pubKey),
			Algorithm: "ed25519",
		})
	}
	return store
}

// [REQUIRED TEST] Trusted publisher + valid signature → AutoApprove.
func TestApprovalWorkflow_Evaluate_TrustedPublisher_ValidSignature(t *testing.T) {
	wf, _ := makeWorkflow(t)
	keys := generateKeys(t, "cfgms")
	b := makeSignedBundle(t, keys, "hyperv", "0.2.1")
	store := makeTrustStore(keys)

	decision, err := wf.Evaluate(b, store)
	require.NoError(t, err)
	assert.Equal(t, approval.AutoApprove, decision)
}

// [REQUIRED TEST] Unknown publisher → QueueForReview.
func TestApprovalWorkflow_Evaluate_UnknownPublisher(t *testing.T) {
	wf, _ := makeWorkflow(t)
	keys := generateKeys(t, "unknown-vendor")
	b := makeSignedBundle(t, keys, "hyperv", "0.2.1")
	// Trust store only knows "cfgms", not "unknown-vendor".
	cfgmsKeys := generateKeys(t, "cfgms")
	store := makeTrustStore(cfgmsKeys)

	decision, err := wf.Evaluate(b, store)
	require.NoError(t, err)
	assert.Equal(t, approval.QueueForReview, decision)
}

// [REQUIRED TEST] Tampered bundle (hash mismatch) → Reject.
func TestApprovalWorkflow_Evaluate_TamperedBundle(t *testing.T) {
	wf, _ := makeWorkflow(t)
	keys := generateKeys(t, "cfgms")
	b := makeSignedBundle(t, keys, "hyperv", "0.2.1")
	store := makeTrustStore(keys)

	// Tamper: change the content hash so the signature is no longer valid.
	b.ContentHash = "tampered-hash-that-was-not-signed"

	decision, err := wf.Evaluate(b, store)
	require.NoError(t, err)
	assert.Equal(t, approval.Reject, decision)
}

// [REQUIRED TEST] Admin Approve() call transitions QueueForReview entry to approved.
func TestApprovalWorkflow_Approve_TransitionsToApproved(t *testing.T) {
	wf, c := makeWorkflow(t)
	keys := generateKeys(t, "unknown-vendor")
	b := makeSignedBundle(t, keys, "tool", "1.0.0")

	// Store the bundle manually in pending state (simulating QueueForReview from Evaluate).
	require.NoError(t, c.Put(b))
	addr := b.ContentAddress()

	// Verify it starts as pending.
	status, err := c.GetApprovalStatus(addr)
	require.NoError(t, err)
	assert.Equal(t, cache.ApprovalStatusPending, status)

	// Admin approves.
	require.NoError(t, wf.Approve(addr))

	// Verify it is now approved.
	status, err = c.GetApprovalStatus(addr)
	require.NoError(t, err)
	assert.Equal(t, cache.ApprovalStatusApproved, status)
}

// TestApprovalWorkflow_Approve_AlreadyApproved returns ErrNotQueued.
func TestApprovalWorkflow_Approve_AlreadyApproved(t *testing.T) {
	wf, c := makeWorkflow(t)
	keys := generateKeys(t, "cfgms")
	b := makeSignedBundle(t, keys, "mod", "1.0.0")
	require.NoError(t, c.Put(b))
	require.NoError(t, c.SetApprovalStatus(b.ContentAddress(), cache.ApprovalStatusApproved))

	err := wf.Approve(b.ContentAddress())
	assert.ErrorIs(t, err, approval.ErrNotQueued)
}

// TestApprovalWorkflow_Approve_NotFound returns ErrBundleNotFound for missing entries.
func TestApprovalWorkflow_Approve_NotFound(t *testing.T) {
	wf, _ := makeWorkflow(t)
	addr := bundle.ContentAddress{Publisher: "cfgms", Name: "missing", Version: "1.0.0", ContentHash: "nohash"}
	err := wf.Approve(addr)
	assert.ErrorIs(t, err, cache.ErrBundleNotFound)
}

// TestApprovalWorkflow_EvaluateAndStore_AutoApprove persists AutoApprove correctly.
func TestApprovalWorkflow_EvaluateAndStore_AutoApprove(t *testing.T) {
	wf, c := makeWorkflow(t)
	keys := generateKeys(t, "cfgms")
	b := makeSignedBundle(t, keys, "hyperv", "0.2.1")
	store := makeTrustStore(keys)

	decision, err := wf.EvaluateAndStore(b, store)
	require.NoError(t, err)
	assert.Equal(t, approval.AutoApprove, decision)

	status, err := c.GetApprovalStatus(b.ContentAddress())
	require.NoError(t, err)
	assert.Equal(t, cache.ApprovalStatusApproved, status)
}

// TestApprovalWorkflow_EvaluateAndStore_QueueForReview persists pending status correctly.
func TestApprovalWorkflow_EvaluateAndStore_QueueForReview(t *testing.T) {
	wf, c := makeWorkflow(t)
	keys := generateKeys(t, "unknown-vendor")
	b := makeSignedBundle(t, keys, "tool", "1.0.0")
	store := makeTrustStore(generateKeys(t, "cfgms"))

	decision, err := wf.EvaluateAndStore(b, store)
	require.NoError(t, err)
	assert.Equal(t, approval.QueueForReview, decision)

	status, err := c.GetApprovalStatus(b.ContentAddress())
	require.NoError(t, err)
	assert.Equal(t, cache.ApprovalStatusPending, status)
}

// TestApprovalWorkflow_EvaluateAndStore_Reject persists rejected status correctly.
func TestApprovalWorkflow_EvaluateAndStore_Reject(t *testing.T) {
	wf, c := makeWorkflow(t)
	keys := generateKeys(t, "cfgms")
	b := makeSignedBundle(t, keys, "hyperv", "0.2.1")
	store := makeTrustStore(keys)

	// Tamper the bundle.
	b.ContentHash = "tampered"

	decision, err := wf.EvaluateAndStore(b, store)
	require.NoError(t, err)
	assert.Equal(t, approval.Reject, decision)

	status, err := c.GetApprovalStatus(b.ContentAddress())
	require.NoError(t, err)
	assert.Equal(t, cache.ApprovalStatusRejected, status)
}

// TestApprovalWorkflow_Evaluate_NilBundle returns Reject and an error.
func TestApprovalWorkflow_Evaluate_NilBundle(t *testing.T) {
	wf, _ := makeWorkflow(t)
	store := trust.NewInMemoryTrustStore()

	decision, err := wf.Evaluate(nil, store)
	assert.Equal(t, approval.Reject, decision)
	assert.Error(t, err)
}

// TestApprovalWorkflow_RejectPending_TransitionsToRejected verifies that
// an admin can reject a bundle in pending state.
func TestApprovalWorkflow_RejectPending_TransitionsToRejected(t *testing.T) {
	wf, c := makeWorkflow(t)
	keys := generateKeys(t, "unknown-vendor")
	b := makeSignedBundle(t, keys, "tool", "1.0.0")

	require.NoError(t, c.Put(b))
	addr := b.ContentAddress()

	status, err := c.GetApprovalStatus(addr)
	require.NoError(t, err)
	assert.Equal(t, cache.ApprovalStatusPending, status)

	require.NoError(t, wf.RejectPending(addr))

	status, err = c.GetApprovalStatus(addr)
	require.NoError(t, err)
	assert.Equal(t, cache.ApprovalStatusRejected, status)
}

// TestApprovalWorkflow_RejectPending_AlreadyApproved returns ErrNotQueued.
func TestApprovalWorkflow_RejectPending_AlreadyApproved(t *testing.T) {
	wf, c := makeWorkflow(t)
	keys := generateKeys(t, "cfgms")
	b := makeSignedBundle(t, keys, "mod", "1.0.0")
	require.NoError(t, c.Put(b))
	require.NoError(t, c.SetApprovalStatus(b.ContentAddress(), cache.ApprovalStatusApproved))

	err := wf.RejectPending(b.ContentAddress())
	assert.ErrorIs(t, err, approval.ErrNotQueued)
}

// TestApprovalWorkflow_RejectPending_AlreadyRejected returns ErrNotQueued.
func TestApprovalWorkflow_RejectPending_AlreadyRejected(t *testing.T) {
	wf, c := makeWorkflow(t)
	keys := generateKeys(t, "cfgms")
	b := makeSignedBundle(t, keys, "mod", "2.0.0")
	require.NoError(t, c.Put(b))
	require.NoError(t, c.SetApprovalStatus(b.ContentAddress(), cache.ApprovalStatusRejected))

	err := wf.RejectPending(b.ContentAddress())
	assert.ErrorIs(t, err, approval.ErrNotQueued)
}

// TestApprovalWorkflow_RejectPending_NotFound returns ErrBundleNotFound.
func TestApprovalWorkflow_RejectPending_NotFound(t *testing.T) {
	wf, _ := makeWorkflow(t)
	addr := bundle.ContentAddress{Publisher: "cfgms", Name: "missing", Version: "1.0.0", ContentHash: "nohash"}
	err := wf.RejectPending(addr)
	assert.ErrorIs(t, err, cache.ErrBundleNotFound)
}

// TestApprovalWorkflow_ConcurrentApproveRejectConverges is the workflow-level
// [REQUIRED TEST] closing the TOCTOU race Issue #3886 exists to fix:
// Approve/RejectPending previously did a separate Get then Set, so a decision
// racing in between could be silently overwritten. Two ApprovalWorkflow
// instances (simulating two controller nodes) share one ModuleApprovalStore
// and race an Approve against a RejectPending for the same bundle. Exactly one
// must win, and the loser must observe ErrNotQueued rather than clobbering the
// winner. Run with -race.
func TestApprovalWorkflow_ConcurrentApproveRejectConverges(t *testing.T) {
	sharedStore := pkgtesting.SetupTestModuleApprovalStore()

	cacheA, err := cache.New(t.TempDir() + "/module-cache-a")
	require.NoError(t, err)
	cacheA.SetApprovalStore(sharedStore)
	wfA := approval.New(cacheA)

	cacheB, err := cache.New(t.TempDir() + "/module-cache-b")
	require.NoError(t, err)
	cacheB.SetApprovalStore(sharedStore)
	wfB := approval.New(cacheB)

	keys := generateKeys(t, "unknown-vendor")
	b := makeSignedBundle(t, keys, "tool", "1.0.0")
	// Both simulated nodes need the bundle content locally; Put is
	// deterministic so both calls produce identical content and only the
	// first actually seeds the shared store's pending record.
	require.NoError(t, cacheA.Put(b))
	require.NoError(t, cacheB.Put(b))
	addr := b.ContentAddress()

	var wg sync.WaitGroup
	results := make(chan error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		results <- wfA.Approve(addr)
	}()
	go func() {
		defer wg.Done()
		results <- wfB.RejectPending(addr)
	}()
	wg.Wait()
	close(results)

	successes, conflicts := 0, 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case assert.ErrorIs(t, err, approval.ErrNotQueued):
			conflicts++
		}
	}
	assert.Equal(t, 1, successes, "exactly one of the concurrent approve/reject decisions must win")
	assert.Equal(t, 1, conflicts, "the losing decision must observe ErrNotQueued, not silently overwrite the winner")

	statusA, err := cacheA.GetApprovalStatus(addr)
	require.NoError(t, err)
	statusB, err := cacheB.GetApprovalStatus(addr)
	require.NoError(t, err)
	assert.Equal(t, statusA, statusB, "both simulated nodes must observe the same winning status through the shared store")
	assert.NotEqual(t, cache.ApprovalStatusPending, statusA, "the bundle must have been decided, not left pending")
}

// TestApprovalWorkflow_EvaluateAndStore_PreservesRejectionAcrossNodes is the
// regression test for the ingestion path erasing a decision. EvaluateAndStore is
// the push-time path (cfg upload → module resolution), so it runs on whichever
// controller node serves the upload and runs again for every later push naming
// the same module. With a shared approval store, an ingestion that unconditionally
// wrote "pending" would erase an operator's rejection made on a peer node and then
// auto-approve the bundle afresh, cluster-wide, because that store is authoritative
// for every node.
func TestApprovalWorkflow_EvaluateAndStore_PreservesRejectionAcrossNodes(t *testing.T) {
	sharedStore := pkgtesting.SetupTestModuleApprovalStore()

	cacheA, err := cache.New(t.TempDir() + "/module-cache-a")
	require.NoError(t, err)
	cacheA.SetApprovalStore(sharedStore)
	wfA := approval.New(cacheA)

	cacheB, err := cache.New(t.TempDir() + "/module-cache-b")
	require.NoError(t, err)
	cacheB.SetApprovalStore(sharedStore)
	wfB := approval.New(cacheB)

	// A trusted publisher with a valid signature: re-evaluation on node B would
	// auto-approve if the standing decision were not consulted.
	keys := generateKeys(t, "cfgms")
	b := makeSignedBundle(t, keys, "hyperv", "0.2.1")
	trustStore := makeTrustStore(keys)
	addr := b.ContentAddress()

	// Node A ingests it as pending (publisher not yet trusted there) and the
	// operator rejects it.
	decision, err := wfA.EvaluateAndStore(b, makeTrustStore())
	require.NoError(t, err)
	require.Equal(t, approval.QueueForReview, decision)
	require.NoError(t, wfA.RejectPending(addr))

	// Node B ingests the same bundle from a later cfg push.
	decision, err = wfB.EvaluateAndStore(b, trustStore)
	require.NoError(t, err)
	assert.Equal(t, approval.Reject, decision,
		"re-ingestion must report the standing rejection so resolution keeps blocking the deployment")

	statusB, err := cacheB.GetApprovalStatus(addr)
	require.NoError(t, err)
	assert.Equal(t, cache.ApprovalStatusRejected, statusB,
		"re-ingestion on a peer node must not reset an operator's rejection to pending")

	statusA, err := cacheA.GetApprovalStatus(addr)
	require.NoError(t, err)
	assert.Equal(t, cache.ApprovalStatusRejected, statusA,
		"the node that recorded the rejection must still enforce it")
}

// TestApprovalWorkflow_EvaluateAndStore_PreservesRejectionOnReingestion is the
// single-node form of the same guarantee: a bundle an operator rejected stays
// rejected when the next cfg push re-ingests it, rather than being re-evaluated
// into an auto-approval.
func TestApprovalWorkflow_EvaluateAndStore_PreservesRejectionOnReingestion(t *testing.T) {
	wf, c := makeWorkflow(t)
	keys := generateKeys(t, "cfgms")
	b := makeSignedBundle(t, keys, "hyperv", "0.2.1")
	trustStore := makeTrustStore(keys)
	addr := b.ContentAddress()

	decision, err := wf.EvaluateAndStore(b, makeTrustStore())
	require.NoError(t, err)
	require.Equal(t, approval.QueueForReview, decision)
	require.NoError(t, wf.RejectPending(addr))

	decision, err = wf.EvaluateAndStore(b, trustStore)
	require.NoError(t, err)
	assert.Equal(t, approval.Reject, decision)

	status, err := c.GetApprovalStatus(addr)
	require.NoError(t, err)
	assert.Equal(t, cache.ApprovalStatusRejected, status)
}

// TestApprovalWorkflow_EvaluateAndStore_ReportsExistingApproval covers the
// converse: an operator's approval of a bundle from a publisher this node does
// not trust is a decision too, so re-ingestion reports AutoApprove instead of
// queueing the bundle for a second review.
func TestApprovalWorkflow_EvaluateAndStore_ReportsExistingApproval(t *testing.T) {
	wf, c := makeWorkflow(t)
	keys := generateKeys(t, "unknown-vendor")
	b := makeSignedBundle(t, keys, "tool", "1.0.0")
	addr := b.ContentAddress()

	decision, err := wf.EvaluateAndStore(b, makeTrustStore())
	require.NoError(t, err)
	require.Equal(t, approval.QueueForReview, decision)
	require.NoError(t, wf.Approve(addr))

	decision, err = wf.EvaluateAndStore(b, makeTrustStore())
	require.NoError(t, err)
	assert.Equal(t, approval.AutoApprove, decision)

	status, err := c.GetApprovalStatus(addr)
	require.NoError(t, err)
	assert.Equal(t, cache.ApprovalStatusApproved, status)
}
