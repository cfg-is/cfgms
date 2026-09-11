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
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"strings"
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

// TestWORMAuditStore_ShipsOneImmutableBlobPerSequence is a REQUIRED contract
// test (Issue #4037 AC): shipping a sequence of entries produces exactly one
// blob per sequence number, and the stored JSON round-trips to the original
// AuditEntry including Checksum/SequenceNumber/PreviousChecksum.
func TestWORMAuditStore_ShipsOneImmutableBlobPerSequence(t *testing.T) {
	ctx := context.Background()
	blobStore := newTestBlobStore(t)
	store := NewWORMAuditStore(ctx, newTestLocalStore(t), blobStore, logging.NewNoopLogger())
	checksum := testChecksum([]byte("shared-key"))

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
	store := NewWORMAuditStore(ctx, newTestLocalStore(t), blobStore, logging.NewNoopLogger())
	checksum := testChecksum([]byte("shared-key"))

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
	wormA := NewWORMAuditStore(ctx, newTestLocalStore(t), sharedBlobStore, logging.NewNoopLogger())

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
	wormB := NewWORMAuditStore(ctx, newTestLocalStore(t), sharedBlobStore, logging.NewNoopLogger())

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
// starts with prefix. The ship-failure messages carry the wormShipNotRetriedNote
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
// (Issue #4037 AC) pinning the transitional gap documented in
// docs/architecture/controller-operating-model.md: when the WORM target refuses
// a ship for any reason other than blob.ErrBlobAlreadyExists, the local write
// has already committed, so AppendChainedEntry returns nil to the caller and the
// failure surfaces only as a Warn. The entry stays durable in the local sequence
// authority but is NOT WORM-protected — no retry until Story 5 of Epic #4033.
func TestWORMAuditStore_ShipFailureIsLoggedNotReturned(t *testing.T) {
	ctx := context.Background()
	blobRoot := t.TempDir()
	blobStore := newTestBlobStoreAt(t, blobRoot)
	local := newTestLocalStore(t)
	logger := logging.NewCapturingLogger()
	store := NewWORMAuditStore(ctx, local, blobStore, logger)

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

	// Nothing reached the WORM target: this entry is not WORM-protected. That
	// is the documented transitional gap, not an accident.
	assert.Empty(t, filesUnder(t, blobRoot),
		"a failed ship must leave no blob anywhere under the WORM root")

	fields, msg, found := findWarnWithPrefix(logger, "audit sink: worm: failed to ship audit entry")
	require.True(t, found, "a failed ship must be logged at Warn")
	assert.Contains(t, msg, "not retried",
		"the ship-failure line must state the failure is not retried, matching the documented transitional gap")
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
	store := NewWORMAuditStore(ctx, local, newTestBlobStoreAt(t, blobRoot), logger)

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
	assert.Contains(t, msg, "not retried")
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
	store := NewWORMAuditStore(ctx, newTestLocalStore(t), newTestBlobStore(t), logging.NewNoopLogger())
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
// wrapped local store's handle rather than being a no-op.
func TestWORMAuditStore_CloseDelegatesToLocal(t *testing.T) {
	tmpDir := t.TempDir()
	sm, err := interfaces.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = sm.Close() })

	store := NewWORMAuditStore(context.Background(), sm.GetAuditStore(), newTestBlobStore(t), logging.NewNoopLogger())
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

			store := NewWORMAuditStore(context.Background(), newTestLocalStore(t), stub, logger)
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
			assert.Contains(t, shipRetry, "not retried",
				"the startup line must state ship failures are not yet retried, in addition to the object-lock outcome (Story 5 pending)")
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
	store := NewWORMAuditStore(context.Background(), newTestLocalStore(t), newTestBlobStore(t), logger)
	require.NotNil(t, store)

	fields, found := logger.FindWarn("Audit sink selected")
	require.True(t, found)
	assert.Equal(t, "unknown", fields["object_lock"])
}
