// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package auditsink

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/blob"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/blobstore/filesystem" // register filesystem blob provider for tests
	_ "github.com/cfgis/cfgms/pkg/storage/providers/flatfile"             // register flatfile provider for OSS composite manager
	_ "github.com/cfgis/cfgms/pkg/storage/providers/sqlite"               // register sqlite provider for OSS composite manager
)

// newTestBlobStore returns a real, fully functional filesystem-backed
// blob.BlobStore rooted at a fresh t.TempDir(). It deliberately does not
// implement blob.ObjectLockProber, mirroring production (the filesystem
// provider offers no WORM guarantee) and exercising the ObjectLockUnknown
// fallback path without a real S3/MinIO endpoint.
func newTestBlobStore(t *testing.T) blob.BlobStore {
	t.Helper()
	return newTestBlobStoreAt(t, t.TempDir())
}

// newTestBlobStoreAt is newTestBlobStore rooted at a caller-supplied directory,
// for tests that inspect the on-disk tree directly (to prove a failed ship wrote
// nothing anywhere under the root, not merely nothing at the intended key).
func newTestBlobStoreAt(t *testing.T, root string) blob.BlobStore {
	t.Helper()
	store, err := blob.CreateBlobStoreFromConfig("filesystem", map[string]interface{}{"root": root})
	require.NoError(t, err)
	return store
}

// newTestMarkerStore returns a real filesystem-backed marker blob.BlobStore
// rooted at a fresh t.TempDir(), distinct from any WORM target root used in
// the same test — markers must stay writable independent of the WORM target.
func newTestMarkerStore(t *testing.T) blob.BlobStore {
	t.Helper()
	return newTestBlobStoreAt(t, t.TempDir())
}

// newTestLocalStore returns a real SQLite-backed business.AuditStore (via the
// OSS composite storage manager) — the sequence authority a WORMAuditStore
// wraps. The backing storage manager is closed on test cleanup.
func newTestLocalStore(t *testing.T) business.AuditStore {
	t.Helper()
	tmpDir := t.TempDir()
	sm, err := interfaces.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = sm.Close() })
	return sm.GetAuditStore()
}

// newTestWORMStore constructs a WORMAuditStore with the given local/WORM
// stores and a fresh real marker store, failing the test immediately if
// construction returns an error. Returns the store and its marker store so
// tests can inspect marker state directly.
func newTestWORMStore(t *testing.T, ctx context.Context, local business.AuditStore, blobStore blob.BlobStore, logger logging.Logger) (*WORMAuditStore, blob.BlobStore) {
	t.Helper()
	markerStore := newTestMarkerStore(t)
	store, err := NewWORMAuditStore(ctx, local, blobStore, markerStore, logger)
	require.NoError(t, err)
	return store, markerStore
}

// testChecksum returns a computeChecksum function that HMAC-signs an entry's
// identity and chain-linkage fields with key — standing in for
// audit.Manager.generateChecksum without depending on the audit package (which
// this story does not modify, per scope).
func testChecksum(key []byte) func(entry *business.AuditEntry) string {
	return func(entry *business.AuditEntry) string {
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(entry.ID + entry.TenantID + entry.Action + entry.PreviousChecksum))
		return hex.EncodeToString(mac.Sum(nil))
	}
}

func newTestEntry(tenantID, id, action string) *business.AuditEntry {
	return &business.AuditEntry{
		ID:           id,
		TenantID:     tenantID,
		Timestamp:    time.Now().UTC(),
		EventType:    business.AuditEventConfiguration,
		Action:       action,
		UserID:       "user1",
		UserType:     business.AuditUserTypeHuman,
		ResourceType: "resource",
		ResourceID:   id,
		Result:       business.AuditResultSuccess,
		Severity:     business.AuditSeverityMedium,
		Source:       "worm_store_test",
	}
}

func wormBlobKey(tenantID string, seq uint64) blob.BlobKey {
	return blob.BlobKey{TenantID: tenantID, Namespace: wormNamespace, Name: fmt.Sprintf("%020d", seq)}
}

func readBlob(t *testing.T, store blob.BlobStore, key blob.BlobKey) []byte {
	t.Helper()
	rc, _, err := store.GetBlob(context.Background(), key)
	require.NoError(t, err)
	defer func() { _ = rc.Close() }()
	data, err := io.ReadAll(rc)
	require.NoError(t, err)
	return data
}

// markerExists reports whether a pending marker is present for tenantID/entryID.
func markerExists(t *testing.T, markerStore blob.BlobStore, tenantID, entryID string) bool {
	t.Helper()
	ok, err := markerStore.BlobExists(context.Background(), blob.BlobKey{TenantID: tenantID, Namespace: pendingMarkerNamespace, Name: entryID})
	require.NoError(t, err)
	return ok
}

// failingBlobStore wraps a real filesystem-backed blob.BlobStore and forces
// PutBlobIfAbsent to fail while failing() is true — simulating a WORM outage
// through fault injection over a real implementation, never a mock, mirroring
// inMemoryS3's "not a mock" precedent (pkg/storage/providers/blobstore/s3).
// Every other operation, and PutBlobIfAbsent itself once cleared, is the real
// filesystem provider.
type failingBlobStore struct {
	blob.BlobStore
	mu      sync.Mutex
	failNow bool
}

func newFailingBlobStore(t *testing.T) *failingBlobStore {
	t.Helper()
	return &failingBlobStore{BlobStore: newTestBlobStore(t)}
}

func (f *failingBlobStore) setFailing(v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failNow = v
}

func (f *failingBlobStore) PutBlobIfAbsent(ctx context.Context, key blob.BlobKey, r io.Reader, meta blob.BlobMeta) error {
	f.mu.Lock()
	failing := f.failNow
	f.mu.Unlock()
	if failing {
		return errors.New("simulated WORM outage: PutBlobIfAbsent refused")
	}
	return f.BlobStore.PutBlobIfAbsent(ctx, key, r, meta)
}

// testChecksumKey is a fixed HMAC key shared across tests in this file that
// don't care about the key's value.
var testChecksumKey = []byte("shared-key")

// TestWORMAuditStore_ShipsOneImmutableBlobPerSequence is a REQUIRED contract
// test (Issue #4037 AC): shipping a sequence of entries produces exactly one
// blob per sequence number, and the stored JSON round-trips to the original
// AuditEntry including Checksum/SequenceNumber/PreviousChecksum.
func TestWORMAuditStore_ShipsOneImmutableBlobPerSequence(t *testing.T) {
	ctx := context.Background()
	blobStore := newTestBlobStore(t)
	store, _ := newTestWORMStore(t, ctx, newTestLocalStore(t), blobStore, logging.NewNoopLogger())
	checksum := testChecksum(testChecksumKey)

	const tenantID = "tenant-a"
	var entries []*business.AuditEntry
	for i := 0; i < 3; i++ {
		e := newTestEntry(tenantID, fmt.Sprintf("id-%d", i), fmt.Sprintf("action-%d", i))
		require.NoError(t, store.AppendChainedEntry(ctx, tenantID, e, checksum))
		entries = append(entries, e)
	}

	// Sequence numbers only increase — assigned by the local store, never by
	// the shipper.
	for i, e := range entries {
		assert.Equal(t, uint64(i+1), e.SequenceNumber)
		if i > 0 {
			assert.Equal(t, entries[i-1].Checksum, e.PreviousChecksum)
		}
	}

	blobs, err := blobStore.ListBlobs(ctx, blob.BlobKey{TenantID: tenantID, Namespace: wormNamespace})
	require.NoError(t, err)
	require.Len(t, blobs, 3, "exactly one blob per shipped sequence number — no duplicate ships for an already-shipped sequence")

	for _, e := range entries {
		data := readBlob(t, blobStore, wormBlobKey(tenantID, e.SequenceNumber))

		var roundTripped business.AuditEntry
		require.NoError(t, json.Unmarshal(data, &roundTripped))
		assert.Equal(t, e.ID, roundTripped.ID)
		assert.Equal(t, e.Action, roundTripped.Action)
		assert.Equal(t, e.SequenceNumber, roundTripped.SequenceNumber)
		assert.Equal(t, e.PreviousChecksum, roundTripped.PreviousChecksum)
		assert.NotEmpty(t, roundTripped.Checksum)
		assert.Equal(t, e.Checksum, roundTripped.Checksum)
	}
}

// TestWORMAuditStore_DirectOverwriteAttemptRefused is a REQUIRED contract test
// (Issue #4037 AC): attempting to overwrite an already-shipped key via a
// direct PutBlobIfAbsent call returns blob.ErrBlobAlreadyExists, and the
// original content is left untouched.
func TestWORMAuditStore_DirectOverwriteAttemptRefused(t *testing.T) {
	ctx := context.Background()
	blobStore := newTestBlobStore(t)
	store, _ := newTestWORMStore(t, ctx, newTestLocalStore(t), blobStore, logging.NewNoopLogger())
	checksum := testChecksum(testChecksumKey)

	const tenantID = "tenant-b"
	e := newTestEntry(tenantID, "id-1", "original-action")
	require.NoError(t, store.AppendChainedEntry(ctx, tenantID, e, checksum))

	key := wormBlobKey(tenantID, e.SequenceNumber)
	original := readBlob(t, blobStore, key)

	err := blobStore.PutBlobIfAbsent(ctx, key, strings.NewReader(`{"action":"overwrite-attempt"}`), blob.BlobMeta{ContentType: "application/json"})
	require.ErrorIs(t, err, blob.ErrBlobAlreadyExists)

	assert.Equal(t, original, readBlob(t, blobStore, key), "an already-shipped blob must remain byte-identical after a refused overwrite attempt")
}

// TestWORMAuditStore_KeyHolderCannotOverwriteFlushedHistory is a REQUIRED test
// (Issue #4037 AC), equivalent in spirit to
// TestVerifyChain_KeyHolderCanForgeConsistentChain
// (pkg/audit/manager_test.go): an actor who holds the chain's HMAC key — here,
// a second, fully independent local AuditStore standing in for a
// host-compromised controller's rewritten chain — can locally produce a
// self-consistent forged chain landing on the exact same sequence numbers as
// the original. It proves that despite holding the key, the forger cannot
// overwrite the WORM target's already-flushed history: the shared blob store's
// atomicity refuses every re-ship attempt at an already-shipped key, and the
// originally shipped bytes are left byte-identical.
func TestWORMAuditStore_KeyHolderCannotOverwriteFlushedHistory(t *testing.T) {
	ctx := context.Background()
	sharedBlobStore := newTestBlobStore(t)
	checksum := testChecksum([]byte("shared-hmac-key")) // same key both "controllers" hold
	const tenantID = "forge-tenant"

	// The legitimate controller: local store A, wrapped, ships the real chain.
	wormA, _ := newTestWORMStore(t, ctx, newTestLocalStore(t), sharedBlobStore, logging.NewNoopLogger())

	var original []*business.AuditEntry
	for i := 0; i < 3; i++ {
		e := newTestEntry(tenantID, fmt.Sprintf("orig-%d", i), fmt.Sprintf("original_action_%d", i))
		require.NoError(t, wormA.AppendChainedEntry(ctx, tenantID, e, checksum))
		original = append(original, e)
	}

	originalBytes := make(map[uint64][]byte, len(original))
	for _, e := range original {
		originalBytes[e.SequenceNumber] = readBlob(t, sharedBlobStore, wormBlobKey(tenantID, e.SequenceNumber))
	}

	// The attacker: an independent, second local store — modeling a
	// host-compromised controller's replacement chain — holding the same HMAC
	// key. Its sequence assignment starts fresh at 1, naturally landing on the
	// identical sequence numbers the original chain shipped at, and it targets
	// the SAME shared WORM blob store the legitimate controller shipped to.
	wormB, _ := newTestWORMStore(t, ctx, newTestLocalStore(t), sharedBlobStore, logging.NewNoopLogger())

	var forged []*business.AuditEntry
	for i := 0; i < 3; i++ {
		f := newTestEntry(tenantID, fmt.Sprintf("forged-%d", i), fmt.Sprintf("forged_action_%d", i))
		require.NoError(t, wormB.AppendChainedEntry(ctx, tenantID, f, checksum),
			"the forger's own local write must succeed — only shipping to the shared WORM target is expected to be refused")
		forged = append(forged, f)
	}

	for i, f := range forged {
		require.Equal(t, original[i].SequenceNumber, f.SequenceNumber,
			"the forged chain must land on the same sequence numbers as the original to model the ADR-004 key-holder scenario")
		assert.NotEqual(t, original[i].Action, f.Action)
	}

	// Every attempt to re-ship at an already-shipped sequence number is refused
	// by the blob store's atomicity, and the originally shipped bytes are
	// untouched.
	for _, f := range forged {
		key := wormBlobKey(tenantID, f.SequenceNumber)

		forgedData, err := json.Marshal(f)
		require.NoError(t, err)
		putErr := sharedBlobStore.PutBlobIfAbsent(ctx, key, bytes.NewReader(forgedData), blob.BlobMeta{ContentType: "application/json"})
		assert.ErrorIs(t, putErr, blob.ErrBlobAlreadyExists,
			"a direct re-ship attempt at sequence %d must be refused by the blob store's atomicity", f.SequenceNumber)

		assert.Equal(t, originalBytes[f.SequenceNumber], readBlob(t, sharedBlobStore, key),
			"the blob at sequence %d must remain byte-identical to what was first shipped, proving the forger cannot overwrite flushed history even though they hold the HMAC key", f.SequenceNumber)
	}
}

// filesUnder returns every regular file beneath root, relative to root. Used to
// prove a failed ship left nothing on the WORM target — including outside the
// key's intended prefix.
func filesUnder(t *testing.T, root string) []string {
	t.Helper()
	var found []string
	require.NoError(t, filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		found = append(found, rel)
		return nil
	}))
	return found
}

// findWarnWithPrefix returns the fields of the first captured Warn whose message
// starts with prefix. The ship-failure messages carry the wormShipRetryNote
// suffix, so they are matched by prefix rather than by equality.
func findWarnWithPrefix(logger *logging.CapturingLogger, prefix string) (logging.LogEntry, string, bool) {
	for i, msg := range logger.WarnMessages {
		if strings.HasPrefix(msg, prefix) {
			return logger.WarnEntries[i], msg, true
		}
	}
	return nil, "", false
}

// TestWORMAuditStore_ShipFailureIsLoggedNotReturned is a REQUIRED contract test
// (Issue #4037 AC) pinning the documented behavior: when the WORM target
// refuses a ship for any reason other than blob.ErrBlobAlreadyExists, the
// local write has already committed, so AppendChainedEntry returns nil to the
// caller and the failure surfaces only as a Warn. The entry stays durable in
// the local sequence authority, and its pending marker (Issue #4039) survives
// so the reconciliation loop retries the ship once the outage clears.
func TestWORMAuditStore_ShipFailureIsLoggedNotReturned(t *testing.T) {
	ctx := context.Background()
	blobRoot := t.TempDir()
	blobStore := newTestBlobStoreAt(t, blobRoot)
	local := newTestLocalStore(t)
	logger := logging.NewCapturingLogger()
	store, _ := newTestWORMStore(t, ctx, local, blobStore, logger)

	// A hierarchical tenant path containing ".." — accepted by the local
	// sequence authority, rejected by the real filesystem blob provider's
	// path-traversal guard. A genuine non-ErrBlobAlreadyExists ship failure
	// produced by the real provider, with no fault injection.
	const tenantID = "tenant-ship-fail/../escape"

	// Confirm this drives the intended branch: the provider's refusal is a
	// plain error, not the already-shipped sentinel the WORM contract expects.
	directErr := blobStore.PutBlobIfAbsent(ctx, wormBlobKey(tenantID, 1), strings.NewReader(`{}`), blob.BlobMeta{ContentType: "application/json"})
	require.Error(t, directErr)
	require.NotErrorIs(t, directErr, blob.ErrBlobAlreadyExists,
		"this test must exercise the ship-failed-for-another-reason branch, not the refuse-to-overwrite branch")

	e := newTestEntry(tenantID, "id-1", "action-1")
	require.NoError(t, store.AppendChainedEntry(ctx, tenantID, e, testChecksum([]byte("k"))),
		"a ship failure must never be returned to the caller — the local write already committed and its durability is not lost")

	// The local sequence authority committed the entry and assigned its chain
	// fields, exactly as it would have on a successful ship.
	assert.Equal(t, uint64(1), e.SequenceNumber)
	assert.NotEmpty(t, e.Checksum)
	got, err := local.GetAuditEntry(ctx, e.ID)
	require.NoError(t, err, "the entry must remain durable in the local store despite the ship failure")
	assert.Equal(t, e.Checksum, got.Checksum)
	assert.Equal(t, e.SequenceNumber, got.SequenceNumber)

	// Nothing reached the WORM target: this entry is not yet WORM-protected.
	assert.Empty(t, filesUnder(t, blobRoot),
		"a failed ship must leave no blob anywhere under the WORM root")

	// This test's tenant ID is deliberately hostile to the filesystem blob
	// provider's key validation (see directErr above), so the marker write
	// against the same tenant ID fails identically — logged, not fatal — and
	// no marker exists to assert on here. Marker persistence-through-failure
	// is covered by TestWORMAuditStore_OutageThenRecoveryReconciliationShipsPendingEntry
	// with a well-formed tenant ID and fault-injected failure instead.

	fields, msg, found := findWarnWithPrefix(logger, "audit sink: worm: failed to ship audit entry")
	require.True(t, found, "a failed ship must be logged at Warn")
	assert.Contains(t, msg, "retried automatically by the reconciliation loop",
		"the ship-failure line must state the failure is retried by reconciliation (Issue #4039), not that it is a permanent unretried gap")
	assert.Equal(t, logging.SanitizeLogValue(tenantID), fields["tenant_id"])
	assert.Equal(t, uint64(1), fields["sequence_number"],
		"the Warn must name the sequence number that is missing from the WORM target, so the gap is reconcilable")
	errText, ok := fields["error"].(string)
	require.True(t, ok, "the underlying ship error must be logged")
	assert.NotEmpty(t, errText)
}

// TestWORMAuditStore_ShipMarshalFailureIsLoggedNotReturned is a REQUIRED
// contract test (Issue #4037 AC) for ship()'s other swallowed branch: an entry
// that cannot be serialized is logged at Warn and never shipped, and ship()
// returns normally so AppendChainedEntry's caller still sees no error.
//
// ship() is exercised directly here because the full AppendChainedEntry path
// cannot reach this branch: the local sequence authority marshals Details itself
// and rejects the entry first. The test asserts that rather than assuming it, so
// the reason for the direct call stays honest if the local store ever changes.
func TestWORMAuditStore_ShipMarshalFailureIsLoggedNotReturned(t *testing.T) {
	ctx := context.Background()
	blobRoot := t.TempDir()
	local := newTestLocalStore(t)
	logger := logging.NewCapturingLogger()
	store, _ := newTestWORMStore(t, ctx, local, newTestBlobStoreAt(t, blobRoot), logger)

	const tenantID = "tenant-marshal-fail"
	e := newTestEntry(tenantID, "id-1", "action-1")
	e.Details = map[string]interface{}{"unserializable": make(chan int)} // json.Marshal rejects channels

	require.Error(t, store.AppendChainedEntry(ctx, tenantID, e, testChecksum([]byte("k"))),
		"the local store rejects an unserializable entry before it is ever shipped — so ship() is called directly below")
	require.Empty(t, logger.WarnMessages[1:],
		"nothing beyond the startup line is logged when the local write fails: ship() was never reached")

	e.SequenceNumber = 7
	store.ship(ctx, tenantID, e)

	assert.Empty(t, filesUnder(t, blobRoot), "an entry that cannot be serialized must not be shipped")

	fields, msg, found := findWarnWithPrefix(logger, "audit sink: worm: failed to marshal audit entry")
	require.True(t, found, "a marshal failure must be logged at Warn")
	assert.Contains(t, msg, "retried automatically by the reconciliation loop")
	assert.Equal(t, logging.SanitizeLogValue(tenantID), fields["tenant_id"])
	assert.Equal(t, uint64(7), fields["sequence_number"])
	errText, ok := fields["error"].(string)
	require.True(t, ok, "the underlying marshal error must be logged")
	assert.NotEmpty(t, errText)
}

// TestWORMAuditStore_DelegatesReadMethods verifies non-AppendChainedEntry
// methods pass straight through to the wrapped local store.
func TestWORMAuditStore_DelegatesReadMethods(t *testing.T) {
	ctx := context.Background()
	store, _ := newTestWORMStore(t, ctx, newTestLocalStore(t), newTestBlobStore(t), logging.NewNoopLogger())
	checksum := testChecksum([]byte("k"))

	const tenantID = "delegate-tenant"
	e := newTestEntry(tenantID, "id-1", "action-1")
	require.NoError(t, store.AppendChainedEntry(ctx, tenantID, e, checksum))

	got, err := store.GetAuditEntry(ctx, e.ID)
	require.NoError(t, err)
	assert.Equal(t, e.Action, got.Action)

	last, err := store.GetLastAuditEntry(ctx, tenantID)
	require.NoError(t, err)
	assert.Equal(t, e.ID, last.ID)

	list, err := store.ListAuditEntries(ctx, &business.AuditFilter{TenantID: tenantID})
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, e.ID, list[0].ID)

	stats, err := store.GetAuditStats(ctx)
	require.NoError(t, err)
	assert.NotNil(t, stats)

	archived, err := store.ArchiveAuditEntries(ctx, time.Now().Add(-24*time.Hour))
	require.NoError(t, err, "delegation must reach the local store's real ArchiveAuditEntries behavior, not a stub")
	assert.Equal(t, int64(0), archived, "no entry is older than the cutoff, so the real store must report zero archived")
}

// TestWORMAuditStore_CloseDelegatesToLocal verifies Close() releases the
// wrapped local store's handle rather than being a no-op, and that Close is
// safe to call even when Start was never called.
func TestWORMAuditStore_CloseDelegatesToLocal(t *testing.T) {
	tmpDir := t.TempDir()
	sm, err := interfaces.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = sm.Close() })

	store, _ := newTestWORMStore(t, context.Background(), sm.GetAuditStore(), newTestBlobStore(t), logging.NewNoopLogger())
	require.NoError(t, store.Close())
}

// objectLockStubStore wraps a real, fully functional BlobStore and reports a
// fixed ObjectLockProber outcome, letting the startup-log tests below drive
// all three probe branches without a real S3/MinIO endpoint. Every operation
// other than ProbeObjectLock delegates to the real filesystem-backed store.
type objectLockStubStore struct {
	blob.BlobStore
	status blob.ObjectLockStatus
}

func (o *objectLockStubStore) ProbeObjectLock(context.Context) (blob.ObjectLockStatus, error) {
	return o.status, nil
}

// TestNewWORMAuditStore_StartupLogSeverityMatchesProbeOutcome is a REQUIRED
// test (Issue #4037 AC): ObjectLockEnabled logs at Info; ObjectLockDisabled and
// ObjectLockUnknown both log at Warn and must name the reduced bound plainly —
// never wording either as the strong bound the Enabled case carries. All three
// outcomes must leave the returned store usable (construction never fails).
func TestNewWORMAuditStore_StartupLogSeverityMatchesProbeOutcome(t *testing.T) {
	cases := []struct {
		name   string
		status blob.ObjectLockStatus
	}{
		{"enabled", blob.ObjectLockEnabled},
		{"disabled", blob.ObjectLockDisabled},
		{"unknown", blob.ObjectLockUnknown},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub := &objectLockStubStore{BlobStore: newTestBlobStore(t), status: tc.status}
			logger := logging.NewCapturingLogger()

			store, err := NewWORMAuditStore(context.Background(), newTestLocalStore(t), stub, newTestMarkerStore(t), logger)
			require.NoError(t, err)
			require.NotNil(t, store, "the probe outcome must never prevent construction — no fail-closed on sink misconfiguration")

			if tc.status == blob.ObjectLockEnabled {
				fields, found := logger.FindInfo("Audit sink selected")
				require.True(t, found, "ObjectLockEnabled must log at Info")
				assert.Equal(t, "worm", fields["sink"])
				assert.Equal(t, "enabled", fields["object_lock"])
				bound, ok := fields["bound"].(string)
				require.True(t, ok)
				assert.NotContains(t, strings.ToUpper(bound), "REDUCED BOUND",
					"the strong-bound (enabled) log line must not word itself as a reduced bound")

				_, warnFound := logger.FindWarn("Audit sink selected")
				assert.False(t, warnFound, "ObjectLockEnabled must not also log at Warn")
			} else {
				fields, found := logger.FindWarn("Audit sink selected")
				require.True(t, found, "%s must log at Warn", tc.status)
				assert.Equal(t, "worm", fields["sink"])
				assert.Equal(t, tc.status.String(), fields["object_lock"])
				bound, ok := fields["bound"].(string)
				require.True(t, ok)
				assert.Contains(t, bound, "REDUCED BOUND",
					"a Disabled/Unknown log line must name the reduced bound plainly, never claim complete WORM protection")

				_, infoFound := logger.FindInfo("Audit sink selected")
				assert.False(t, infoFound, "%s must not also log at Info", tc.status)
			}

			shipRetry, ok := findAuditSinkLog(logger, tc.status)["ship_retry"].(string)
			require.True(t, ok)
			assert.Contains(t, shipRetry, "retried automatically by the reconciliation loop",
				"the startup line must state ship failures are retried by reconciliation (Issue #4039), not that they are an unretried gap")
		})
	}
}

// findAuditSinkLog returns whichever of FindInfo/FindWarn recorded the "Audit
// sink selected" line for the given probe outcome.
func findAuditSinkLog(logger *logging.CapturingLogger, status blob.ObjectLockStatus) logging.LogEntry {
	if status == blob.ObjectLockEnabled {
		f, _ := logger.FindInfo("Audit sink selected")
		return f
	}
	f, _ := logger.FindWarn("Audit sink selected")
	return f
}

// TestNewWORMAuditStore_NonProbingBlobStoreLogsUnknown verifies the fallback
// path: a blob store that does not implement blob.ObjectLockProber at all
// (the filesystem provider, exactly as production would see in a
// misconfiguration or a provider without the capability) is treated as
// ObjectLockUnknown, never as ObjectLockEnabled.
func TestNewWORMAuditStore_NonProbingBlobStoreLogsUnknown(t *testing.T) {
	logger := logging.NewCapturingLogger()
	store, err := NewWORMAuditStore(context.Background(), newTestLocalStore(t), newTestBlobStore(t), newTestMarkerStore(t), logger)
	require.NoError(t, err)
	require.NotNil(t, store)

	fields, found := logger.FindWarn("Audit sink selected")
	require.True(t, found)
	assert.Equal(t, "unknown", fields["object_lock"])
}

// TestNewWORMAuditStore_MarkerStoreUnwritableFailsStartup is a REQUIRED test
// (Issue #4039 AC): construction must fail closed with a named error when the
// marker store cannot actually be written to, and must never fall back to
// running the worm sink without crash-safety. The marker store's root
// directory exists and is readable (so a MkdirAll no-op would otherwise mask
// the problem) but a plain file sits where the probe's write needs a
// directory, forcing a real, non-permission-bit write failure that is
// reliable regardless of which OS user runs the test (root bypasses Unix
// permission bits, so a chmod-based test would be flaky in a root container).
func TestNewWORMAuditStore_MarkerStoreUnwritableFailsStartup(t *testing.T) {
	root := t.TempDir()
	// probeMarkerStoreWritable writes under BlobKey{TenantID:
	// tenantRegistryTenantID, Namespace: markerProbeNamespace, ...}; the
	// filesystem provider's PutBlob needs <root>/<TenantID>/<Namespace>/ to be
	// a creatable directory. Pre-creating a regular file at
	// <root>/<TenantID> blocks that unconditionally.
	blockingPath := filepath.Join(root, tenantRegistryTenantID)
	require.NoError(t, os.WriteFile(blockingPath, []byte("not a directory"), 0o600))

	markerStore, err := blob.CreateBlobStoreFromConfig("filesystem", map[string]interface{}{"root": root})
	require.NoError(t, err, "the root directory itself is writable — only the probe's specific subpath is blocked")

	store, constructErr := NewWORMAuditStore(context.Background(), newTestLocalStore(t), newTestBlobStore(t), markerStore, logging.NewNoopLogger())
	require.Error(t, constructErr, "construction must fail closed when the marker store is not writable")
	assert.Nil(t, store, "a failed construction must never return a usable store")
	assert.Contains(t, constructErr.Error(), "not writable",
		"the startup error must name the problem plainly")
}

// TestWORMAuditStore_MarkerWrittenBeforeAppendAndClearedAfterSuccess is a
// REQUIRED test (Issue #4039 AC): the marker exists before the local append
// commits and is cleared once the ship succeeds.
func TestWORMAuditStore_MarkerWrittenBeforeAppendAndClearedAfterSuccess(t *testing.T) {
	ctx := context.Background()
	local := newTestLocalStore(t)
	store, markerStore := newTestWORMStore(t, ctx, local, newTestBlobStore(t), logging.NewNoopLogger())

	const tenantID = "tenant-marker-lifecycle"
	e := newTestEntry(tenantID, "id-1", "action-1")

	var markerSeenBeforeCommit bool
	store.testBeforeLocalAppend = func() {
		markerSeenBeforeCommit = markerExists(t, markerStore, tenantID, e.ID)
		_, getErr := local.GetAuditEntry(ctx, e.ID)
		assert.True(t, errors.Is(getErr, business.ErrAuditNotFound),
			"the local append must not have committed yet when the marker is already visible")
	}

	require.NoError(t, store.AppendChainedEntry(ctx, tenantID, e, testChecksum(testChecksumKey)))

	assert.True(t, markerSeenBeforeCommit, "the marker must be written before the local append is attempted")
	assert.False(t, markerExists(t, markerStore, tenantID, e.ID), "the marker must be cleared once the ship succeeds")
}

// TestWORMAuditStore_OutageThenRecoveryReconciliationShipsPendingEntry is a
// REQUIRED test (Issue #4039 AC): an entry written during a simulated WORM
// outage keeps its marker and returns no error to the caller; once the outage
// clears, a reconciliation pass ships it and clears the marker.
func TestWORMAuditStore_OutageThenRecoveryReconciliationShipsPendingEntry(t *testing.T) {
	ctx := context.Background()
	local := newTestLocalStore(t)
	blobStore := newFailingBlobStore(t)
	store, markerStore := newTestWORMStore(t, ctx, local, blobStore, logging.NewNoopLogger())

	const tenantID = "tenant-outage-recovery"
	e := newTestEntry(tenantID, "id-1", "action-1")

	blobStore.setFailing(true)
	require.NoError(t, store.AppendChainedEntry(ctx, tenantID, e, testChecksum(testChecksumKey)),
		"a WORM outage must never be returned to the caller")

	assert.True(t, markerExists(t, markerStore, tenantID, e.ID), "the marker must persist while the outage continues")
	_, _, err := blobStore.GetBlob(ctx, wormBlobKey(tenantID, e.SequenceNumber))
	require.ErrorIs(t, err, blob.ErrBlobNotFound, "nothing must have reached the WORM target during the outage")

	blobStore.setFailing(false)
	store.reconcileOnce(ctx)

	assert.False(t, markerExists(t, markerStore, tenantID, e.ID), "reconciliation must clear the marker once the entry ships")
	data := readBlob(t, blobStore, wormBlobKey(tenantID, e.SequenceNumber))
	var shipped business.AuditEntry
	require.NoError(t, json.Unmarshal(data, &shipped))
	assert.Equal(t, e.ID, shipped.ID)
	assert.Equal(t, e.Checksum, shipped.Checksum)
}

// TestWORMAuditStore_ReconciliationDiscardsMarkerForNeverCommittedEntry is a
// REQUIRED test (Issue #4039 AC): a marker written for an entry ID that was
// never actually committed locally (simulating a crash between the marker
// write and the local append) is detected via
// errors.Is(err, business.ErrAuditNotFound), discarded without shipping
// anything, and no PutBlobIfAbsent call is made for it.
func TestWORMAuditStore_ReconciliationDiscardsMarkerForNeverCommittedEntry(t *testing.T) {
	ctx := context.Background()
	local := newTestLocalStore(t)
	blobRoot := t.TempDir()
	blobStore := newTestBlobStoreAt(t, blobRoot)
	store, markerStore := newTestWORMStore(t, ctx, local, blobStore, logging.NewNoopLogger())

	const tenantID = "tenant-never-committed"
	const entryID = "ghost-entry"

	// Simulate the crash window directly: register the tenant and write the
	// marker, as AppendChainedEntry would, but never call local.AppendChainedEntry.
	store.registerTenant(ctx, tenantID)
	store.putMarker(ctx, tenantID, entryID)
	require.True(t, markerExists(t, markerStore, tenantID, entryID))

	_, getErr := local.GetAuditEntry(ctx, entryID)
	require.True(t, errors.Is(getErr, business.ErrAuditNotFound),
		"verify against the real local store that this entry genuinely does not exist")

	store.reconcileOnce(ctx)

	assert.False(t, markerExists(t, markerStore, tenantID, entryID), "the marker for a never-committed entry must be discarded")
	assert.Empty(t, filesUnder(t, blobRoot), "no PutBlobIfAbsent call must be made for an entry that was never locally committed")
}

// TestWORMAuditStore_InFlightRaceReconciliationSkipsUncommittedEntry is a
// REQUIRED test (Issue #4039 AC, PO finding epic #4033): the reconciliation
// loop must not discard a marker for an entry whose local append has not
// committed yet. The interleaving is driven deterministically via
// testBeforeLocalAppend, never a time.Sleep: the synchronous path is held
// between the marker write and local.AppendChainedEntry while exactly one
// reconciliation tick runs (which must skip the marker because its ID is
// in-flight), then released to commit, then the ship attempt is forced to
// fail. The marker must still exist afterward, and the entry must ship on a
// later reconciliation tick. This test fails if the in-flight-set skip is
// ever removed.
func TestWORMAuditStore_InFlightRaceReconciliationSkipsUncommittedEntry(t *testing.T) {
	ctx := context.Background()
	local := newTestLocalStore(t)
	blobStore := newFailingBlobStore(t)
	store, markerStore := newTestWORMStore(t, ctx, local, blobStore, logging.NewNoopLogger())

	const tenantID = "tenant-in-flight-race"
	e := newTestEntry(tenantID, "id-1", "action-1")

	holdAppend := make(chan struct{})
	releaseAppend := make(chan struct{})
	store.testBeforeLocalAppend = func() {
		close(holdAppend)
		<-releaseAppend
	}

	appendDone := make(chan error, 1)
	go func() {
		appendDone <- store.AppendChainedEntry(ctx, tenantID, e, testChecksum(testChecksumKey))
	}()

	<-holdAppend // marker is written; local append has not been called yet

	require.True(t, markerExists(t, markerStore, tenantID, e.ID), "the marker must exist before the local append is attempted")
	_, getErr := local.GetAuditEntry(ctx, e.ID)
	require.True(t, errors.Is(getErr, business.ErrAuditNotFound),
		"the local append genuinely has not committed yet at this point")

	// Exactly one reconciliation tick while the entry is in flight: it must
	// skip this marker rather than treating the not-found local read as
	// "never happened".
	store.reconcileOnce(ctx)
	assert.True(t, markerExists(t, markerStore, tenantID, e.ID),
		"reconciliation must not discard the marker for an entry that is still in flight — this is the entire point of the in-flight set")

	// Force the eventual ship attempt to fail once the append commits.
	blobStore.setFailing(true)
	close(releaseAppend)
	require.NoError(t, <-appendDone)

	assert.True(t, markerExists(t, markerStore, tenantID, e.ID), "the marker must persist after the forced ship failure")

	// A later tick, once the entry is no longer in flight and the outage
	// clears, ships it.
	blobStore.setFailing(false)
	store.reconcileOnce(ctx)

	assert.False(t, markerExists(t, markerStore, tenantID, e.ID), "the entry must ship and clear its marker on the later tick")
	_ = readBlob(t, blobStore, wormBlobKey(tenantID, e.SequenceNumber))
}

// TestWORMAuditStore_SameTimestampDifferentSequenceBothShipped is a REQUIRED
// regression guard (Issue #4039 AC): two entries sharing the same Timestamp
// but different SequenceNumbers are both shipped. True by construction —
// nothing in this design inspects Timestamp — asserted explicitly to catch a
// future reintroduction of timestamp-based logic.
func TestWORMAuditStore_SameTimestampDifferentSequenceBothShipped(t *testing.T) {
	ctx := context.Background()
	blobStore := newTestBlobStore(t)
	store, _ := newTestWORMStore(t, ctx, newTestLocalStore(t), blobStore, logging.NewNoopLogger())
	checksum := testChecksum(testChecksumKey)

	const tenantID = "tenant-same-timestamp"
	sharedTimestamp := time.Now().UTC()

	e1 := newTestEntry(tenantID, "id-1", "action-1")
	e1.Timestamp = sharedTimestamp
	e2 := newTestEntry(tenantID, "id-2", "action-2")
	e2.Timestamp = sharedTimestamp

	require.NoError(t, store.AppendChainedEntry(ctx, tenantID, e1, checksum))
	require.NoError(t, store.AppendChainedEntry(ctx, tenantID, e2, checksum))

	require.NotEqual(t, e1.SequenceNumber, e2.SequenceNumber)
	require.Equal(t, e1.Timestamp, e2.Timestamp)

	blobs, err := blobStore.ListBlobs(ctx, blob.BlobKey{TenantID: tenantID, Namespace: wormNamespace})
	require.NoError(t, err)
	require.Len(t, blobs, 2, "both entries must be shipped despite sharing a Timestamp")
}

// TestWORMAuditStore_ReconciliationDiscoversTenantAcrossRestart proves the
// durable tenant registry (Issue #4039): a fresh WORMAuditStore instance,
// sharing the same local/WORM/marker stores but with no in-memory state from
// before, still discovers and ships a pending marker for a tenant it has
// never itself seen an AppendChainedEntry call for — modeling a controller
// restart after a crash mid-outage.
func TestWORMAuditStore_ReconciliationDiscoversTenantAcrossRestart(t *testing.T) {
	ctx := context.Background()
	local := newTestLocalStore(t)
	blobStore := newFailingBlobStore(t)
	markerStore := newTestMarkerStore(t)

	storeBeforeRestart, err := NewWORMAuditStore(ctx, local, blobStore, markerStore, logging.NewNoopLogger())
	require.NoError(t, err)

	const tenantID = "tenant-restart"
	e := newTestEntry(tenantID, "id-1", "action-1")

	blobStore.setFailing(true)
	require.NoError(t, storeBeforeRestart.AppendChainedEntry(ctx, tenantID, e, testChecksum(testChecksumKey)))
	require.True(t, markerExists(t, markerStore, tenantID, e.ID))

	// "Restart": a brand-new WORMAuditStore over the same durable stores, with
	// an empty in-memory knownTenants cache. It must never have seen an
	// AppendChainedEntry call for tenantID.
	storeAfterRestart, err := NewWORMAuditStore(ctx, local, blobStore, markerStore, logging.NewNoopLogger())
	require.NoError(t, err)

	blobStore.setFailing(false)
	storeAfterRestart.reconcileOnce(ctx)

	assert.False(t, markerExists(t, markerStore, tenantID, e.ID),
		"the post-restart store must discover and ship the pending marker via the durable tenant registry")
	data := readBlob(t, blobStore, wormBlobKey(tenantID, e.SequenceNumber))
	var shipped business.AuditEntry
	require.NoError(t, json.Unmarshal(data, &shipped))
	assert.Equal(t, e.ID, shipped.ID)
}

// TestWORMAuditStore_StartAndCloseReconciliationLoop is a REQUIRED test
// (Issue #4039 AC): the reconciliation loop starts and stops cleanly with no
// goroutine leak, and while running actually ships a pending entry on its own
// tick — not just when reconcileOnce is called directly.
func TestWORMAuditStore_StartAndCloseReconciliationLoop(t *testing.T) {
	ctx := context.Background()
	local := newTestLocalStore(t)
	blobStore := newFailingBlobStore(t)
	store, markerStore := newTestWORMStore(t, ctx, local, blobStore, logging.NewNoopLogger())
	store.reconcileInterval = 10 * time.Millisecond

	const tenantID = "tenant-lifecycle"
	e := newTestEntry(tenantID, "id-1", "action-1")

	blobStore.setFailing(true)
	require.NoError(t, store.AppendChainedEntry(ctx, tenantID, e, testChecksum(testChecksumKey)))
	require.True(t, markerExists(t, markerStore, tenantID, e.ID))

	store.Start(ctx)
	blobStore.setFailing(false)

	require.Eventually(t, func() bool {
		return !markerExists(t, markerStore, tenantID, e.ID)
	}, time.Second, 5*time.Millisecond, "the running reconciliation loop must ship the pending entry on its own tick")

	closeDone := make(chan error, 1)
	go func() { closeDone <- store.Close() }()

	select {
	case err := <-closeDone:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not return — the reconciliation loop goroutine leaked")
	}
}
