// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Tests for wireClusterCertStores (Issue #3852 AC3), the single point that decides
// whether a controller's cert.Manager reaches revocation and signing-cursor state
// through the cluster-visible stores or through pkg/cert's node-local files.
//
// The decision is invisible at the call site — a wrong answer produces a working
// cert.Manager either way, and only shows up as a revocation that never propagates
// to the other nodes. These tests therefore assert on the resulting Manager's
// observable behaviour (which store its revocations land in, which store its cursor
// is read from) rather than only on the config fields.
package initialization

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/pkg/cert"
	certinterfaces "github.com/cfgis/cfgms/pkg/cert/interfaces"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// certStoreFixture is a StorageManager carrying a pair of shared cert stores, plus
// direct handles on those stores so a test can read and write them as another
// controller node would.
type certStoreFixture struct {
	storageManager *interfaces.StorageManager
	revocation     certinterfaces.RevocationStore
	cursor         certinterfaces.SigningCursorStore
	sharedDir      string
}

// newCertStoreFixture builds a real StorageManager (OSS tier) and wires a pair of
// real cert stores onto it through the same Set* accessors
// CreateClusterStorageManager uses.
//
// The stores are pkg/cert's own file-backed implementations rooted in a directory
// shared by every reader — not the Postgres-backed ones — because what is under test
// here is the *selection*: does the Manager end up reading and writing the store the
// StorageManager supplied, or its own node-local files under certPath? Keeping that
// distinction visible as two different directories makes the assertion exact and
// keeps this test free of a database dependency. The Postgres-backed stores' own
// cluster visibility is covered by pkg/cert/cluster_store_test.go, and the
// StorageManager-side wiring by pkg/storage/interfaces/cert_store_wiring_test.go.
func newCertStoreFixture(t *testing.T) *certStoreFixture {
	t.Helper()

	sm, err := interfaces.CreateOSSStorageManager(t.TempDir(), filepath.Join(t.TempDir(), "cert-store-wiring.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sm.Close() })

	sharedDir := t.TempDir()
	revStore, err := cert.NewFileRevocationStore(sharedDir)
	require.NoError(t, err)
	cursorStore, err := cert.NewFileSigningCursorStore(sharedDir)
	require.NoError(t, err)

	sm.SetCertRevocationStore(revStore)
	sm.SetSigningCursorStore(cursorStore)

	return &certStoreFixture{
		storageManager: sm,
		revocation:     revStore,
		cursor:         cursorStore,
		sharedDir:      sharedDir,
	}
}

// certStoreTestConfig returns the minimum controller config newClusterManagerConfig
// reads, at the given ha.mode.
func certStoreTestConfig(mode string) *config.Config {
	return &config.Config{
		Certificate: &config.CertificateConfig{
			EnableCertManagement: true,
			RenewalThresholdDays: 7,
			Server: &config.ServerCertificateConfig{
				Organization: "Test Org",
			},
		},
		HA: &config.HAConfig{Mode: mode},
	}
}

// TestWireClusterCertStores_ClusterModeManagerUsesSharedStores is the functional test
// for the cluster branch: a clustered controller's cert.Manager must revoke into, and
// read its signing cursor from, the store the StorageManager supplied — never the
// node-local files under certPath. A regression here (the guard inverted, the getters
// ignored, the fields overwritten later) leaves every node revoking into its own file
// again, which is exactly the silent divergence this story exists to remove.
func TestWireClusterCertStores_ClusterModeManagerUsesSharedStores(t *testing.T) {
	fx := newCertStoreFixture(t)
	certPath := t.TempDir()
	ctx := context.Background()

	managerCfg, err := newClusterManagerConfig(certStoreTestConfig("cluster"), certPath, fx.storageManager)
	require.NoError(t, err)
	require.Same(t, fx.revocation, managerCfg.RevocationStore,
		"cluster mode must hand cert.NewManager the StorageManager's revocation store")
	require.Same(t, fx.cursor, managerCfg.SigningCursorStore,
		"cluster mode must hand cert.NewManager the StorageManager's signing cursor store")

	mgr, err := cert.NewManager(managerCfg)
	require.NoError(t, err)

	// A revocation issued through this Manager lands in the shared store...
	const localSerial = "3852000000000001"
	require.NoError(t, mgr.Revoke(localSerial))
	entries, err := fx.revocation.ListRevoked(ctx)
	require.NoError(t, err)
	require.True(t, revocationEntriesContain(entries, localSerial),
		"a revocation issued by the clustered Manager must be written to the shared store")

	// ...and nowhere else: no node-local revocation file is created under certPath.
	_, statErr := os.Stat(filepath.Join(certPath, "revocation.json"))
	assert.True(t, os.IsNotExist(statErr),
		"a clustered Manager must not fall back to the node-local revocation file")

	// The reverse direction — a revocation another node wrote to the shared store is
	// observed by this Manager with no restart.
	const remoteSerial = "3852000000000002"
	require.NoError(t, fx.revocation.Revoke(ctx, certinterfaces.RevocationEntry{
		Serial:    remoteSerial,
		RevokedAt: time.Now().UTC(),
		Reason:    "revoked by another node",
	}))
	revoked, err := mgr.IsRevoked(remoteSerial)
	require.NoError(t, err)
	assert.True(t, revoked,
		"the clustered Manager must observe a revocation written by another node through the shared store")

	// The signing cursor resolves through the shared store too: a rotation recorded by
	// another node is what this Manager reports.
	_, err = fx.cursor.TransitionCursor(ctx, "3852000000000003", 7, false)
	require.NoError(t, err)
	state, err := mgr.GetSigningCursorState()
	require.NoError(t, err)
	require.NotNil(t, state)
	assert.Equal(t, "3852000000000003", state.CurrentSerial,
		"the clustered Manager must read the signing cursor from the shared store")
	_, statErr = os.Stat(filepath.Join(certPath, "signing-cursor.json"))
	assert.True(t, os.IsNotExist(statErr),
		"a clustered Manager must not fall back to the node-local signing-cursor file")
}

// TestWireClusterCertStores_SingleNodeManagerKeepsNodeLocalStores is the AC2 guard: a
// single-node deployment must see no behavioural change, so the shared stores are not
// selected even when the StorageManager happens to carry them. Dropping the
// IsClusterMode() check would pass the cluster test above and fail this one.
func TestWireClusterCertStores_SingleNodeManagerKeepsNodeLocalStores(t *testing.T) {
	fx := newCertStoreFixture(t)
	certPath := t.TempDir()
	ctx := context.Background()

	managerCfg, err := newClusterManagerConfig(certStoreTestConfig("single"), certPath, fx.storageManager)
	require.NoError(t, err)
	require.Nil(t, managerCfg.RevocationStore,
		"single-node mode must leave the revocation store unset so cert.NewManager applies its file-backed default")
	require.Nil(t, managerCfg.SigningCursorStore,
		"single-node mode must leave the signing cursor store unset so cert.NewManager applies its file-backed default")

	mgr, err := cert.NewManager(managerCfg)
	require.NoError(t, err)

	const serial = "3852000000000004"
	require.NoError(t, mgr.Revoke(serial))

	_, statErr := os.Stat(filepath.Join(certPath, "revocation.json"))
	assert.NoError(t, statErr,
		"a single-node Manager must keep writing the node-local revocation file (AC2: no behavioural change)")

	entries, err := fx.revocation.ListRevoked(ctx)
	require.NoError(t, err)
	assert.False(t, revocationEntriesContain(entries, serial),
		"a single-node Manager must not write into the shared store")
}

// TestWireClusterCertStores_LeavesConfigUntouchedWithoutStores covers the fallback
// branches: cluster mode with no StorageManager, and cluster mode with a StorageManager
// whose provider implements neither creator extension (both getters nil). Both must
// leave the config fields unset so cert.NewManager applies its file-backed default —
// the alternative, writing a nil interface value into the config, would hand
// cert.NewManager a store it cannot use.
func TestWireClusterCertStores_LeavesConfigUntouchedWithoutStores(t *testing.T) {
	unwired, err := interfaces.CreateOSSStorageManager(t.TempDir(), filepath.Join(t.TempDir(), "unwired.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = unwired.Close() })
	require.Nil(t, unwired.GetCertRevocationStore(), "sanity: the OSS tier wires no cert revocation store")
	require.Nil(t, unwired.GetSigningCursorStore(), "sanity: the OSS tier wires no signing cursor store")

	tests := []struct {
		name           string
		storageManager *interfaces.StorageManager
	}{
		{"nil storage manager", nil},
		{"storage manager without cert stores", unwired},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			managerCfg := &cert.ManagerConfig{StoragePath: t.TempDir()}
			wireClusterCertStores(managerCfg, certStoreTestConfig("cluster"), tc.storageManager)
			assert.Nil(t, managerCfg.RevocationStore,
				"no cluster-visible revocation store is available, so the field must stay unset for the file-backed fallback")
			assert.Nil(t, managerCfg.SigningCursorStore,
				"no cluster-visible signing cursor store is available, so the field must stay unset for the file-backed fallback")
		})
	}
}

// TestWireClusterCertStores_PartiallyWiredStorageManager covers a provider that
// supplies one store but not the other: the available store must be selected and the
// missing one left to the file-backed fallback, rather than an all-or-nothing choice.
func TestWireClusterCertStores_PartiallyWiredStorageManager(t *testing.T) {
	sm, err := interfaces.CreateOSSStorageManager(t.TempDir(), filepath.Join(t.TempDir(), "partial.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sm.Close() })

	revStore, err := cert.NewFileRevocationStore(t.TempDir())
	require.NoError(t, err)
	sm.SetCertRevocationStore(revStore)

	managerCfg := &cert.ManagerConfig{StoragePath: t.TempDir()}
	wireClusterCertStores(managerCfg, certStoreTestConfig("cluster"), sm)

	assert.Same(t, revStore, managerCfg.RevocationStore,
		"the store the provider does supply must be selected")
	assert.Nil(t, managerCfg.SigningCursorStore,
		"the store the provider does not supply must be left to the file-backed fallback")
}

// revocationEntriesContain reports whether serial appears in entries.
func revocationEntriesContain(entries []certinterfaces.RevocationEntry, serial string) bool {
	for _, e := range entries {
		if e.Serial == serial {
			return true
		}
	}
	return false
}
