// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

// Tests for wireClusterModuleApprovalStore (Issue #3886), the call site that
// decides whether ModuleCache reaches module bundle approval status through the
// cluster-visible ModuleApprovalStore or through its node-local approval.yaml
// files. A wrong answer here produces a working ModuleCache either way, and only
// shows up as an approval decision that never propagates to other nodes — so
// these tests assert on the resulting ModuleCache's observable behaviour (which
// store a decision lands in, whether a second node observes it) rather than only
// on whether SetApprovalStore was called.
package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
	modulecache "github.com/cfgis/cfgms/features/controller/modules/cache"
	modules "github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/modules/bundle"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

func moduleApprovalWiringTestConfig(mode string) *config.Config {
	return &config.Config{HA: &config.HAConfig{Mode: mode}}
}

// TestWireClusterModuleApprovalStore_ClusterModeSharesAcrossInstances is the
// functional test for the cluster branch: two independent ModuleCache instances
// both wired against the same clustered StorageManager must observe each other's
// approval decisions with no restart, proving they share the store rather than
// each falling back to its own node-local file.
func TestWireClusterModuleApprovalStore_ClusterModeSharesAcrossInstances(t *testing.T) {
	sm, err := interfaces.CreateOSSStorageManager(t.TempDir(), t.TempDir()+"/module-approval-wiring.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = sm.Close() })
	sm.SetModuleApprovalStore(pkgtesting.SetupTestModuleApprovalStore())

	cfg := moduleApprovalWiringTestConfig("cluster")
	logger := logging.NewNoopLogger()

	cacheA, err := modulecache.New(t.TempDir() + "/module-cache-a")
	require.NoError(t, err)
	wireClusterModuleApprovalStore(cacheA, cfg, sm, logger)

	cacheB, err := modulecache.New(t.TempDir() + "/module-cache-b")
	require.NoError(t, err)
	wireClusterModuleApprovalStore(cacheB, cfg, sm, logger)

	assert.True(t, cacheA.HasSharedApprovalStore(),
		"a wired cache must report cluster-visible approval status — that is what lets any node serve approve/reject")

	b := makeWiringTestBundle(t, "cfgms", "hyperv", "0.2.1", "wiring-hash")
	require.NoError(t, cacheA.Put(b))
	require.NoError(t, cacheB.Put(b))
	addr := b.ContentAddress()

	require.NoError(t, cacheA.SetApprovalStatus(addr, modulecache.ApprovalStatusApproved))

	status, err := cacheB.GetApprovalStatus(addr)
	require.NoError(t, err)
	assert.Equal(t, modulecache.ApprovalStatusApproved, status,
		"a decision made through cacheA must be observed through cacheB — proof both share the wired cluster store")
}

// TestWireClusterModuleApprovalStore_SingleNodeKeepsNodeLocalFile is the AC guard:
// a single-node deployment must see no behavioural change, so the shared store is
// not selected even when the StorageManager happens to carry one. Dropping the
// IsClusterMode() check would pass the cluster test above and fail this one.
func TestWireClusterModuleApprovalStore_SingleNodeKeepsNodeLocalFile(t *testing.T) {
	sm, err := interfaces.CreateOSSStorageManager(t.TempDir(), t.TempDir()+"/module-approval-wiring-single.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = sm.Close() })
	sm.SetModuleApprovalStore(pkgtesting.SetupTestModuleApprovalStore())

	cfg := moduleApprovalWiringTestConfig("single")
	logger := logging.NewNoopLogger()

	cacheA, err := modulecache.New(t.TempDir() + "/module-cache-a")
	require.NoError(t, err)
	wireClusterModuleApprovalStore(cacheA, cfg, sm, logger)

	cacheB, err := modulecache.New(t.TempDir() + "/module-cache-b")
	require.NoError(t, err)
	wireClusterModuleApprovalStore(cacheB, cfg, sm, logger)

	b := makeWiringTestBundle(t, "cfgms", "hyperv", "0.2.1", "wiring-hash-single")
	require.NoError(t, cacheA.Put(b))
	require.NoError(t, cacheB.Put(b))
	addr := b.ContentAddress()

	require.NoError(t, cacheA.SetApprovalStatus(addr, modulecache.ApprovalStatusApproved))

	status, err := cacheB.GetApprovalStatus(addr)
	require.NoError(t, err)
	assert.Equal(t, modulecache.ApprovalStatusPending, status,
		"single-node mode must leave each ModuleCache on its own node-local file, never sharing a store (AC: no behavioural change)")
}

// TestWireClusterModuleApprovalStore_NoStoreAvailableIsNoop covers the fallback
// branches: cluster mode with no StorageManager, and cluster mode with a
// StorageManager whose provider implements no ModuleApprovalStoreCreator (nil
// getter). Both must leave the ModuleCache on its file-backed default — and must
// say so through HasSharedApprovalStore(), because that is what keeps the
// REST approve/reject handlers on their leadership gate instead of letting every
// node decide against its own node-local approval.yaml (Issue #3886). A silent
// fallback that still reported cluster-visible status would be the fail-open.
func TestWireClusterModuleApprovalStore_NoStoreAvailableIsNoop(t *testing.T) {
	unwired, err := interfaces.CreateOSSStorageManager(t.TempDir(), t.TempDir()+"/module-approval-unwired.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = unwired.Close() })
	require.Nil(t, unwired.GetModuleApprovalStore(), "sanity: the OSS tier wires no module approval store")

	tests := []struct {
		name           string
		storageManager *interfaces.StorageManager
	}{
		{"nil storage manager", nil},
		{"storage manager without module approval store", unwired},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cacheA, err := modulecache.New(t.TempDir() + "/module-cache-a")
			require.NoError(t, err)
			cacheB, err := modulecache.New(t.TempDir() + "/module-cache-b")
			require.NoError(t, err)

			wireClusterModuleApprovalStore(cacheA, moduleApprovalWiringTestConfig("cluster"), tc.storageManager, logging.NewNoopLogger())
			wireClusterModuleApprovalStore(cacheB, moduleApprovalWiringTestConfig("cluster"), tc.storageManager, logging.NewNoopLogger())

			assert.False(t, cacheA.HasSharedApprovalStore(),
				"an unwired cache must report node-local approval status so the approve/reject handlers keep their leadership gate")

			b := makeWiringTestBundle(t, "cfgms", "hyperv", "0.2.1", "wiring-hash-unwired-"+tc.name)
			require.NoError(t, cacheA.Put(b))
			require.NoError(t, cacheB.Put(b))
			addr := b.ContentAddress()

			require.NoError(t, cacheA.SetApprovalStatus(addr, modulecache.ApprovalStatusApproved))

			status, err := cacheB.GetApprovalStatus(addr)
			require.NoError(t, err)
			assert.Equal(t, modulecache.ApprovalStatusPending, status,
				"without an available store, each ModuleCache must stay on its own node-local file")
		})
	}
}

func makeWiringTestBundle(t *testing.T, publisher, name, version, hash string) *bundle.Bundle {
	t.Helper()
	return &bundle.Bundle{
		Manifest: &modules.ModuleMetadata{
			Name:      name,
			Version:   version,
			Publisher: publisher,
			Executors: []string{"steward"},
		},
		Binaries:    map[string]string{"linux-amd64": "binaries/linux-amd64"},
		Signatures:  []bundle.BundleSignature{{Publisher: publisher, Algorithm: "ed25519", Signature: make([]byte, 64)}},
		ContentHash: hash,
	}
}
