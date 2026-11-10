// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Tests for wireUpgradeStore (Issue #5977): the controller-startup call site that
// hands the steward upgrade store the storage provider created to the HTTP API
// server, with no in-memory fallback.
package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/blob"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/testutil"
)

const upgradeWiringTenant = "fleet-root/fleet-child-a"

// upgradeNoCreatorSQLite is the real SQLite provider with its optional
// UpgradeStoreCreator hidden: embedding only the StorageProvider interface drops
// the creator methods, and OpenBusinessStores is forwarded so the manager still
// builds from the SQLite bundle. It models a provider that has no upgrade store.
type upgradeNoCreatorSQLite struct {
	interfaces.StorageProvider
	opener interfaces.BusinessStoreOpener
}

func (p upgradeNoCreatorSQLite) OpenBusinessStores(path string) (*interfaces.BusinessStoreBundle, error) {
	return p.opener.OpenBusinessStores(path)
}

// installSQLiteWithoutUpgradeCreator swaps the registered sqlite provider for the
// creator-less wrapper and restores the original on cleanup.
func installSQLiteWithoutUpgradeCreator(t *testing.T) {
	t.Helper()
	original, err := interfaces.GetStorageProvider("sqlite")
	require.NoError(t, err, "the sqlite provider must be registered for this test")
	opener, ok := original.(interfaces.BusinessStoreOpener)
	require.True(t, ok, "the sqlite provider opens its business stores as a bundle")
	_, hasCreator := original.(interfaces.UpgradeStoreCreator)
	require.True(t, hasCreator, "the sqlite provider implements UpgradeStoreCreator")
	wrapper := upgradeNoCreatorSQLite{StorageProvider: original, opener: opener}
	_, hasCreator = interface{}(wrapper).(interfaces.UpgradeStoreCreator)
	require.False(t, hasCreator, "the wrapper must not implement UpgradeStoreCreator")
	interfaces.RegisterStorageProvider(wrapper)
	t.Cleanup(func() { interfaces.RegisterStorageProvider(original) })
}

// upgradeWiringServer builds a real controller Server (flatfile + SQLite OSS
// composite) plus a seeded API key allowed to dispatch, read and roll back
// steward upgrades under upgradeWiringTenant.
func upgradeWiringServer(t *testing.T, cfg *config.Config) *Server {
	t.Helper()
	srv := servernewCharNewServer(t, cfg, logging.NewNoopLogger())
	require.NotNil(t, srv.httpServer)
	// The permission check resolves the key's tenant for its assurance policy.
	mustCreateTenantForWiring(t, srv.storageManager.GetTenantStore(), "fleet-root", "fleet-root", "")
	mustCreateTenantForWiring(t, srv.storageManager.GetTenantStore(), upgradeWiringTenant, "fleet-child-a", "fleet-root")
	return srv
}

// seedUpgradeAPIKey exports a fresh API key the next Server built will accept and
// returns it.
func seedUpgradeAPIKey(t *testing.T) string {
	t.Helper()
	keyBytes := make([]byte, 16)
	_, err := rand.Read(keyBytes)
	require.NoError(t, err)
	key := "upgrade-wiring-" + hex.EncodeToString(keyBytes)
	t.Setenv("CFGMS_SEED_TEST_API_KEYS", "1")
	t.Setenv("CFGMS_API_KEY_UPGRADE_TEST", key)
	return key
}

// callUpgradeAPI sends a request through the server's real router and returns the
// status code and body.
func callUpgradeAPI(t *testing.T, srv *Server, key, method, path, body string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("X-API-Key", key)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.httpServer.GetRouter().ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

const upgradeDispatchBody = `{"selector":"id:steward-1","version":"v1.2.3","platform":"linux","arch":"amd64"}`

// TestWireUpgradeStore_ProviderWithoutCreatorLeavesEndpointAt503 is the [REQUIRED
// TEST] for the no-fallback rule: a server wired from a storage manager whose
// provider has no upgrade-store creator answers 503 UPGRADE_STORE_UNAVAILABLE from
// the dispatch endpoint, and no store — memory or otherwise — is constructed.
func TestWireUpgradeStore_ProviderWithoutCreatorLeavesEndpointAt503(t *testing.T) {
	installSQLiteWithoutUpgradeCreator(t)
	key := seedUpgradeAPIKey(t)
	srv := upgradeWiringServer(t, servernewCharConfig(t))

	require.Nil(t, srv.storageManager.GetUpgradeStore(),
		"a provider without UpgradeStoreCreator leaves the manager's store nil; nothing falls back to memory")

	code, body := callUpgradeAPI(t, srv, key, http.MethodPost, "/api/v1/stewards/upgrade", upgradeDispatchBody)
	assert.Equal(t, http.StatusServiceUnavailable, code, body)
	assert.Contains(t, body, "UPGRADE_STORE_UNAVAILABLE")

	// Wiring again from the same manager must not conjure a store either.
	wireUpgradeStore(srv.httpServer, srv.storageManager, srv.cfg, logging.NewNoopLogger())
	code, body = callUpgradeAPI(t, srv, key, http.MethodGet, "/api/v1/stewards/upgrade/no-such-upgrade", "")
	assert.Equal(t, http.StatusServiceUnavailable, code, body)
	assert.Contains(t, body, "UPGRADE_STORE_UNAVAILABLE")
}

// TestWireUpgradeStore_SQLiteProviderStoreIsWiredAndDurable proves the
// single-node shape: the SQLite provider's creator supplies the store, New wires
// it, and records written through the endpoint's store survive a restart of the
// store on the same file.
func TestWireUpgradeStore_SQLiteProviderStoreIsWiredAndDurable(t *testing.T) {
	key := seedUpgradeAPIKey(t)
	cfg := servernewCharConfig(t)
	srv := upgradeWiringServer(t, cfg)

	store := srv.storageManager.GetUpgradeStore()
	require.NotNil(t, store, "the SQLite provider implements UpgradeStoreCreator")

	code, body := callUpgradeAPI(t, srv, key, http.MethodGet, "/api/v1/stewards/upgrade/no-such-upgrade", "")
	assert.Equal(t, http.StatusNotFound, code, body)
	assert.Contains(t, body, "UPGRADE_NOT_FOUND", "a wired store answers not-found, not 503")

	rec := upgradeWiringRecord("upg-sqlite-durable")
	require.NoError(t, store.CreateUpgrade(context.Background(), rec))
	code, body = callUpgradeAPI(t, srv, key, http.MethodGet, "/api/v1/stewards/upgrade/upg-sqlite-durable", "")
	assert.Equal(t, http.StatusOK, code, body)

	// A second manager on the same SQLite file (a restart) reads the record back.
	restarted, err := interfaces.CreateOSSStorageManager(t.TempDir(), cfg.Storage.SQLitePath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = restarted.Close() })
	got, err := restarted.GetUpgradeStore().GetUpgrade(context.Background(), "upg-sqlite-durable")
	require.NoError(t, err)
	assert.Equal(t, rec.BundleSignature, got.BundleSignature)
}

func TestWireUpgradeStore_NilArgumentsAreNoops(t *testing.T) {
	sm, err := interfaces.CreateOSSStorageManager(t.TempDir(), filepath.Join(t.TempDir(), "upgrade-wiring-nil.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sm.Close() })

	assert.NotPanics(t, func() { wireUpgradeStore(nil, sm, &config.Config{}, logging.NewNoopLogger()) })
	assert.NotPanics(t, func() { wireUpgradeStore(newBareAPIServer(t), nil, &config.Config{}, logging.NewNoopLogger()) })
}

func upgradeWiringRecord(id string) *business.UpgradeRecord {
	now := time.Now().UTC().Truncate(time.Millisecond)
	return &business.UpgradeRecord{
		ID:        id,
		StewardID: "steward-1",
		TenantID:  upgradeWiringTenant,
		Version:   "v1.2.3",
		Platform:  "linux",
		Arch:      "amd64",
		SHA256:    "deadbeefdeadbeefdeadbeefdeadbeef",
		Status:    business.UpgradeStatusCommitted,
		InitiatedBy: business.InitiatedByIdentity{
			Subject:    "operator@example.com",
			TenantID:   upgradeWiringTenant,
			AuthMethod: "api_key",
		},
		Publisher:       "cfgms",
		SignatureDigest: "sha256:cafebabe",
		BundleSignature: []byte{0xca, 0xfe, 0xba, 0xbe, 0x01, 0x02, 0x03, 0x04},
		CreatedAt:       now,
		OperationNonce:  []byte{0xde, 0xad, 0xbe, 0xef},
		DispatchedAt:    now,
	}
}

// putRollbackTarget stores an approved steward binary where the controller reads
// rollback targets: its installer blob store, in the caller's tenant namespace.
func putRollbackTarget(t *testing.T, cfg *config.Config, version string) {
	t.Helper()
	root := filepath.Join(filepath.Dir(cfg.Storage.FlatfileRoot), "installers")
	store, err := blob.CreateBlobStoreFromConfig("filesystem", map[string]interface{}{"root": root})
	require.NoError(t, err)

	content := []byte("cfgms-steward-binary-" + version)
	sum := sha256.Sum256(content)
	sig := make([]byte, 64)
	for i := range sig {
		sig[i] = byte(i)
	}
	sigDigest := sha256.Sum256(sig)
	key := blob.BlobKey{TenantID: upgradeWiringTenant, Namespace: "steward-binaries", Name: version + "-linux-amd64"}
	require.NoError(t, store.PutBlob(context.Background(), key, bytes.NewReader(content), blob.BlobMeta{
		ContentType: "application/octet-stream",
		Labels: map[string]string{
			"version":          version,
			"platform":         "linux",
			"arch":             "amd64",
			"publisher":        "cfgms",
			"published_by":     "publisher@example.com",
			"publisher_tenant": upgradeWiringTenant,
			"signature":        base64.RawURLEncoding.EncodeToString(sig),
			"signature_digest": hex.EncodeToString(sigDigest[:]),
			"sha256":           hex.EncodeToString(sum[:]),
			"approved_by":      "approver@example.com",
		},
	}))
}

// requireCrossNodeRollback is the shared body of the two-node tests. nodeA and
// nodeB are separate controller Servers whose upgrade stores are separate handles
// on one shared database. An upgrade record created through node A must be
// returned by GET on node B, and rolling it back by ID through node B must
// succeed and be visible from node A.
func requireCrossNodeRollback(t *testing.T, key string, nodeA, nodeB *Server, storeA, storeB business.UpgradeStore) {
	t.Helper()
	ctx := context.Background()
	rec := upgradeWiringRecord("upg-cross-node-" + fmt.Sprintf("%d", time.Now().UnixNano()))
	require.NoError(t, storeA.CreateUpgrade(ctx, rec))

	// The node that holds the record serves it...
	code, body := callUpgradeAPI(t, nodeA, key, http.MethodGet, "/api/v1/stewards/upgrade/"+rec.ID, "")
	require.Equal(t, http.StatusOK, code, body)

	// ...and so does the other node.
	code, body = callUpgradeAPI(t, nodeB, key, http.MethodGet, "/api/v1/stewards/upgrade/"+rec.ID, "")
	require.Equal(t, http.StatusOK, code, "node B must return a record created through node A: %s", body)
	assert.Contains(t, body, rec.ID)
	assert.Contains(t, body, rec.StewardID)

	// Rollback by --upgrade-id through the other node.
	code, body = callUpgradeAPI(t, nodeB, key, http.MethodPost,
		"/api/v1/stewards/upgrade/"+rec.ID+"/rollback", `{"version":"v1.0.0"}`)
	require.Equal(t, http.StatusAccepted, code, "rollback through node B must succeed: %s", body)

	var resp struct {
		Data struct {
			UpgradeID string `json:"upgrade_id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &resp))
	require.NotEmpty(t, resp.Data.UpgradeID)

	// The rollback record node B wrote is the same record node A reads.
	rollback, err := storeA.GetUpgrade(ctx, resp.Data.UpgradeID)
	require.NoError(t, err, "node A must read the rollback record node B created")
	assert.Equal(t, rec.StewardID, rollback.StewardID)
	assert.Equal(t, "v1.0.0", rollback.Version)
	assert.Equal(t, rec.TenantID, rollback.TenantID)
}

// upgradeNode builds one controller Server of a two-node test, with its upgrade
// store replaced by the one in sm, and the rollback target staged in its blob
// store (installer artifacts are per-node here; in a cluster they are shared).
func upgradeNode(t *testing.T, sm *interfaces.StorageManager) (*Server, business.UpgradeStore) {
	t.Helper()
	cfg := servernewCharConfig(t)
	srv := upgradeWiringServer(t, cfg)
	putRollbackTarget(t, cfg, "v1.0.0")
	wireUpgradeStore(srv.httpServer, sm, srv.cfg, logging.NewNoopLogger())
	store := sm.GetUpgradeStore()
	require.NotNil(t, store)
	return srv, store
}

// TestWireUpgradeStore_TwoNodesShareUpgradeRecords_SQLite runs the cross-node
// scenario over two SQLite store handles on one file, which needs no external
// infrastructure.
func TestWireUpgradeStore_TwoNodesShareUpgradeRecords_SQLite(t *testing.T) {
	key := seedUpgradeAPIKey(t)
	sharedDB := filepath.Join(t.TempDir(), "shared-upgrades.db")
	smA, err := interfaces.CreateOSSStorageManager(t.TempDir(), sharedDB)
	require.NoError(t, err)
	t.Cleanup(func() { _ = smA.Close() })
	smB, err := interfaces.CreateOSSStorageManager(t.TempDir(), sharedDB)
	require.NoError(t, err)
	t.Cleanup(func() { _ = smB.Close() })

	nodeA, storeA := upgradeNode(t, smA)
	nodeB, storeB := upgradeNode(t, smB)
	requireCrossNodeRollback(t, key, nodeA, nodeB, storeA, storeB)
}

// clusterStorageManagerOrSkip builds a cluster storage manager on the shared test
// PostgreSQL, skipping when it is unreachable (Docker integration tier).
func clusterStorageManagerOrSkip(t *testing.T) *interfaces.StorageManager {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping PostgreSQL-backed test in short mode")
	}
	port := os.Getenv("CFGMS_TEST_DB_PORT")
	if port == "" {
		port = "5432"
	}
	dsn := fmt.Sprintf("host=localhost port=%s dbname=cfgms_test user=cfgms_test password=%s sslmode=disable",
		port, testutil.GetTestDBPassword())
	db, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		t.Skip("PostgreSQL test database not reachable:", err)
	}
	_ = db.Close()

	hmacKey := make([]byte, 32)
	_, err = rand.Read(hmacKey)
	require.NoError(t, err)
	sm, err := interfaces.CreateClusterStorageManager(dsn, hex.EncodeToString(hmacKey), nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sm.Close() })
	return sm
}

// TestWireUpgradeStore_TwoNodesShareUpgradeRecords is the [REQUIRED TEST] for the
// cluster property: two api.Server instances, each built on its own
// DatabaseUpgradeStore handle (its own cluster storage manager and connection
// pool) to one database. A record created through the first is returned by
// GET /api/v1/stewards/upgrade/{upgrade_id} on the second, and
// POST /api/v1/stewards/upgrade/{upgrade_id}/rollback through the second succeeds.
// It skips when PostgreSQL is unreachable (Docker integration tier).
func TestWireUpgradeStore_TwoNodesShareUpgradeRecords(t *testing.T) {
	smA := clusterStorageManagerOrSkip(t)
	smB := clusterStorageManagerOrSkip(t)
	require.NotSame(t, smA.GetUpgradeStore(), smB.GetUpgradeStore(), "each node holds its own store handle")
	require.Equal(t, "database", smA.GetProviderName())

	key := seedUpgradeAPIKey(t)
	nodeA, storeA := upgradeNode(t, smA)
	nodeB, storeB := upgradeNode(t, smB)
	requireCrossNodeRollback(t, key, nodeA, nodeB, storeA, storeB)
}

// legacyUpgradeLogCount counts the legacy-records info lines a logger captured.
func legacyUpgradeLogCount(l *recordingLogger) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, e := range l.entries {
		if strings.Contains(e.msg, "legacy per-node upgrade records") {
			n++
		}
	}
	return n
}

// TestLogLegacyUpgradeRecords is the [REQUIRED TEST] for the legacy-file notice:
// it is logged once, at info level, when the database provider is active and the
// configured SQLite file exists, and not otherwise.
func TestLogLegacyUpgradeRecords(t *testing.T) {
	existing := filepath.Join(t.TempDir(), "legacy.db")
	require.NoError(t, os.WriteFile(existing, []byte("legacy"), 0o600))
	missing := filepath.Join(t.TempDir(), "absent.db")

	cases := []struct {
		name     string
		provider string
		cfg      *config.Config
		want     int
	}{
		{"database provider, file exists", "database", &config.Config{Storage: &config.StorageConfig{SQLitePath: existing}}, 1},
		{"database provider, file missing", "database", &config.Config{Storage: &config.StorageConfig{SQLitePath: missing}}, 0},
		{"database provider, no path configured", "database", &config.Config{Storage: &config.StorageConfig{}}, 0},
		{"database provider, no storage section", "database", &config.Config{}, 0},
		{"database provider, nil config", "database", nil, 0},
		{"composite provider, file exists", "composite", &config.Config{Storage: &config.StorageConfig{SQLitePath: existing}}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logger := &recordingLogger{}
			logLegacyUpgradeRecords(logger, tc.provider, tc.cfg)
			assert.Equal(t, tc.want, legacyUpgradeLogCount(logger))
			if tc.want == 1 {
				logger.mu.Lock()
				defer logger.mu.Unlock()
				require.Len(t, logger.entries, 1, "exactly one line")
				assert.Contains(t, logger.entries[0].kvs, existing, "the notice names the configured file")
			}
		})
	}
}

// TestWireUpgradeStore_LegacyNoticeOnlyWithStore proves wiring emits the legacy
// notice through the manager's provider name: the SQLite-backed (composite)
// manager never does, and a manager without a store logs nothing.
func TestWireUpgradeStore_LegacyNoticeOnlyWithStore(t *testing.T) {
	existing := filepath.Join(t.TempDir(), "legacy.db")
	require.NoError(t, os.WriteFile(existing, []byte("legacy"), 0o600))
	cfg := &config.Config{Storage: &config.StorageConfig{SQLitePath: existing}}

	sm, err := interfaces.CreateOSSStorageManager(t.TempDir(), filepath.Join(t.TempDir(), "notice.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sm.Close() })
	require.NotNil(t, sm.GetUpgradeStore())

	logger := &recordingLogger{}
	wireUpgradeStore(newBareAPIServer(t), sm, cfg, logger)
	assert.Zero(t, legacyUpgradeLogCount(logger), "the SQLite provider is not the database provider")

	sm.SetUpgradeStore(nil)
	wireUpgradeStore(newBareAPIServer(t), sm, cfg, logger)
	assert.Zero(t, legacyUpgradeLogCount(logger))
}
