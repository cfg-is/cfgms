// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package approval_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/features/controller/modules/approval"
	"github.com/cfgis/cfgms/features/controller/modules/cache"
	modules "github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/pkg/modules/bundle"
	"github.com/cfgis/cfgms/pkg/modules/trust"
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
