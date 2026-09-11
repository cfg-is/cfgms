// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package auditsink implements the WORM (write-once-read-many) audit shipper
// (Issue #4037/#4039, ADR-033, Epic #4033). WORMAuditStore wraps a local
// business.AuditStore — which remains the sole sequence authority — and a
// blob.BlobStore WORM target. It is a forward-only shipper of already-sequenced
// entries, never a replacement AuditStore: every method except
// AppendChainedEntry delegates straight to the wrapped local store.
//
// Buffer-then-flush design (Issue #4039, Tech Lead design, epic #4033): a WORM
// outage never blocks or fails AppendChainedEntry. Before the local append, a
// marker (the entry ID only — never audit content) is written to a genuinely
// local, always-writable marker store. If shipping fails, the marker survives
// and a background reconciliation loop (Start/Close) retries it once the WORM
// target recovers. The marker design is provably correct, not probabilistic: an
// entry's fate is resolved by asking the one authority that always knows the
// truth — local.GetAuditEntry — rather than inferring from a timestamp window
// or a persisted high-water mark that can drift from reality. There is
// therefore no comparison arithmetic and no "clean vs. crashed restart"
// branching to get subtly wrong. This replaces the earlier high-water-mark and
// timestamp-window designs entirely; neither is layered on top of this one.
//
// Per-tenant entries are NOT guaranteed to be appended in non-decreasing
// Timestamp order: Timestamp is assigned by the calling goroutine before
// enqueue into pkg/audit.Manager's queue, while SequenceNumber is assigned
// later by whichever drainLoop iteration dequeues the entry, so the two can
// diverge under ordinary concurrent RecordEvent calls. Nothing in this design
// inspects Timestamp at all — only entry ID (for markers) and SequenceNumber
// (for the WORM blob key), both assigned by the local sequence authority.
package auditsink

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/blob"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// wormNamespace is the blob namespace shipped audit entries are stored under.
// A dedicated namespace keeps the shipper's key space unambiguous from any
// other blob consumer sharing the same bucket.
const wormNamespace = "audit-chain"

// pendingMarkerNamespace is the marker store namespace holding one blob per
// locally-committed-but-not-yet-confirmed-shipped entry, keyed by tenant then
// entry ID. The blob's mere existence is the signal — body is empty.
const pendingMarkerNamespace = "audit-chain-pending"

// tenantRegistryTenantID/tenantRegistryNamespace hold a durable, per-tenant
// idempotent marker (blob name = tenant ID) recording every tenant the marker
// store has ever seen a pending entry for. Reconciliation cannot enumerate
// "every tenant" through blob.BlobStore — ListBlobs requires a TenantID prefix
// — so without this registry a fresh process would have no way to discover a
// tenant's pending markers left over from before a restart until that tenant's
// next AppendChainedEntry call. The registry is written with the same
// idempotent PutBlobIfAbsent mechanism as the entry markers themselves and
// holds nothing but tenant ID strings — bookkeeping, not audit content, same
// as the entry markers.
const (
	tenantRegistryTenantID  = "_audit_worm_tenant_registry"
	tenantRegistryNamespace = "audit-chain-pending-tenants"
)

// markerProbeNamespace is used only by the startup writability probe, under
// the same sentinel tenant ID as the tenant registry. The probe blob is
// deleted immediately after the check, so it never appears in ListBlobs
// results for tenantRegistryNamespace.
const markerProbeNamespace = "audit-chain-pending-probe"

// defaultReconcileInterval is the fixed tick period for the background
// reconciliation loop. Conservative default chosen to keep the loop cheap at
// idle (ListBlobs per known tenant) while bounding how long a WORM outage's
// backlog goes unretried once the target recovers. Not configurable in this
// story (Issue #4039) — a follow-up can expose it if operators need tuning.
const defaultReconcileInterval = 30 * time.Second

// wormShipRetryNote documents that a ship failure is not a permanent gap: the
// pending marker written before the local append survives the failure, and
// the background reconciliation loop (Issue #4039) retries it automatically
// once the WORM target recovers. This replaces Story 4's transitional
// "currently logged, not retried" wording now that reconciliation exists.
const wormShipRetryNote = "ship failures are buffered locally via a pending marker and retried automatically by the reconciliation loop until the WORM target recovers (Issue #4039, Epic #4033)"

// WORMAuditStore implements business.AuditStore.
type WORMAuditStore struct {
	local       business.AuditStore
	blobStore   blob.BlobStore
	markerStore blob.BlobStore
	logger      logging.Logger

	reconcileInterval time.Duration

	// mu guards inFlight and knownTenants — both are genuinely shared mutable
	// state touched by the synchronous ship path and the reconciliation loop
	// goroutine. This is unrelated to the marker *blobs* themselves, which need
	// no lock (see putMarker/deleteMarker doc comments): there is no shared
	// in-process structure the two paths read-mutate-write for a marker blob,
	// so the blob store's own atomicity (PutBlobIfAbsent) and idempotency
	// (DeleteBlob) are the entire safety mechanism there. mu protects only the
	// two in-memory maps below.
	mu sync.Mutex

	// inFlight holds the entry IDs currently between "marker written" and
	// "ship attempt resolved" in AppendChainedEntry. It closes a race the
	// marker-before-append ordering otherwise opens (PO review, epic #4033):
	// the marker is written before the local append commits, so there is a
	// real window where the marker exists but local.GetAuditEntry still
	// returns ErrAuditNotFound — not because the append never happened, but
	// because it hasn't happened yet. Without this set, a reconciliation tick
	// landing in that window would conclude "the append never happened" and
	// delete the marker, and the append would then commit with nothing left to
	// retry from — the exact permanent silent gap this design exists to close.
	//
	// In-memory is correct here, not a weakness: if the process dies, the
	// synchronous path dies with it, and the durable marker (already written
	// before local append is even attempted) is what survives to be
	// reconciled by the next process. Do not "upgrade" this to durable state.
	inFlight map[string]struct{}

	// knownTenants caches which tenants have already been durably registered
	// in the tenant registry, so a hot AppendChainedEntry path only pays for
	// the registry's idempotent PutBlobIfAbsent once per tenant per process
	// lifetime rather than on every call.
	knownTenants map[string]struct{}

	// testBeforeLocalAppend, when non-nil, runs synchronously after the marker
	// write and before local.AppendChainedEntry. Test-only hook (same-package
	// tests only) for deterministically driving the in-flight race window
	// without a time.Sleep. Always nil in production.
	testBeforeLocalAppend func()

	stopOnce sync.Once
	stop     chan struct{}
	done     chan struct{}
}

var _ business.AuditStore = (*WORMAuditStore)(nil)

// NewWORMAuditStore wraps local with a WORM shipper backed by blobStore, using
// markerStore as the genuinely local pending-entry marker store (Issue #4039).
// markerStore must be a separate instance from blobStore — never the same,
// possibly unreachable, WORM target — because markers must stay writable
// precisely during the outage this design exists to survive.
//
// Construction fails closed if markerStore is not writable: the marker
// mechanism is what makes "an entry is never silently dropped" true, so
// starting the worm sink without a working marker store would silently
// degrade shipping back to best-effort with no crash-safety (PO review, epic
// #4033). It probes blobStore for object-lock enforcement
// (blob.ObjectLockProber) exactly once and logs the startup line documenting
// the resulting bound; the probe outcome never fails or blocks construction —
// fail-closed on sink misconfiguration was explicitly rejected by the founder
// (Epic #4033) — only markerStore's writability does.
//
// The returned store's background reconciliation loop is not started; call
// Start to begin it and Close to stop it and release the wrapped local store.
func NewWORMAuditStore(ctx context.Context, local business.AuditStore, blobStore blob.BlobStore, markerStore blob.BlobStore, logger logging.Logger) (*WORMAuditStore, error) {
	if logger == nil {
		logger = logging.NewNoopLogger()
	}
	if err := probeMarkerStoreWritable(ctx, markerStore); err != nil {
		return nil, fmt.Errorf("audit worm sink: marker store is not writable: %w", err)
	}

	logStartup(ctx, blobStore, logger)

	return &WORMAuditStore{
		local:             local,
		blobStore:         blobStore,
		markerStore:       markerStore,
		logger:            logger,
		reconcileInterval: defaultReconcileInterval,
		inFlight:          make(map[string]struct{}),
		knownTenants:      make(map[string]struct{}),
	}, nil
}

// probeMarkerStoreWritable writes and then deletes a throwaway blob to confirm
// markerStore is genuinely writable before this store is allowed to start.
// This must go through an actual write, not merely a directory-existence
// check: a directory can exist and still refuse writes (read-only mount, full
// disk, permission on the parent that MkdirAll's no-op skip would not surface).
func probeMarkerStoreWritable(ctx context.Context, markerStore blob.BlobStore) error {
	key := blob.BlobKey{TenantID: tenantRegistryTenantID, Namespace: markerProbeNamespace, Name: "startup-probe"}
	if err := markerStore.PutBlob(ctx, key, bytes.NewReader(nil), blob.BlobMeta{ContentType: "application/octet-stream"}); err != nil {
		return err
	}
	return markerStore.DeleteBlob(ctx, key)
}

// logStartup runs the Object Lock probe once and logs the resulting bound.
// blob.ObjectLockEnabled is the only outcome that may be worded as the strong
// bound; ObjectLockDisabled and ObjectLockUnknown both log at Warn and must
// name the reduced bound plainly (PO product review, epic #4033).
func logStartup(ctx context.Context, blobStore blob.BlobStore, logger logging.Logger) {
	status := blob.ObjectLockUnknown
	if prober, ok := blobStore.(blob.ObjectLockProber); ok {
		if probed, err := prober.ProbeObjectLock(ctx); err == nil {
			status = probed
		}
	}

	switch status {
	case blob.ObjectLockEnabled:
		logger.Info("Audit sink selected",
			"sink", "worm",
			"object_lock", status.String(),
			"bound", "ADR-004/ADR-033: bucket-level Object Lock confirmed — flushed history cannot be overwritten or deleted, even by a compromised controller",
			"ship_retry", wormShipRetryNote,
		)
	default:
		logger.Warn("Audit sink selected",
			"sink", "worm",
			"object_lock", status.String(),
			"bound", reducedBoundMessage(status),
			"ship_retry", wormShipRetryNote,
		)
	}
}

// reducedBoundMessage names the reduced bound for the ObjectLockDisabled and
// ObjectLockUnknown outcomes. Neither may be worded as the strong bound the
// Enabled case carries.
func reducedBoundMessage(status blob.ObjectLockStatus) string {
	if status == blob.ObjectLockDisabled {
		return "ADR-004/ADR-033 REDUCED BOUND: bucket-level Object Lock is confirmed OFF — entries are write-once against the controller's own code path only; a credential-holding attacker with bucket access can still delete or overwrite flushed history"
	}
	return "ADR-004/ADR-033 REDUCED BOUND: bucket-level Object Lock could not be verified — treat flushed history as NOT protected against a credential-holding attacker until this is confirmed"
}

// Start begins the background reconciliation loop, which retries shipping any
// entry whose marker is still pending once the WORM target is reachable
// again. Safe to call at most once; the loop runs until Close is called or ctx
// is cancelled.
func (w *WORMAuditStore) Start(ctx context.Context) {
	w.stop = make(chan struct{})
	w.done = make(chan struct{})
	go w.reconcileLoop(ctx)
}

// reconcileLoop ticks at reconcileInterval, running one reconciliation pass
// per tick, until stopped or ctx is cancelled.
func (w *WORMAuditStore) reconcileLoop(ctx context.Context) {
	defer close(w.done)

	ticker := time.NewTicker(w.reconcileInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			w.reconcileOnce(ctx)
		case <-w.stop:
			return
		case <-ctx.Done():
			return
		}
	}
}

// reconcileOnce runs a single reconciliation pass across every durably
// registered tenant. Called on each loop tick and directly by tests that need
// to drive reconciliation deterministically rather than waiting on a ticker.
func (w *WORMAuditStore) reconcileOnce(ctx context.Context) {
	tenants, err := w.listKnownTenants(ctx)
	if err != nil {
		w.logger.Warn("audit sink: worm: reconciliation failed to list known tenants — marker backlog left in place for the next tick",
			"error", logging.SanitizeLogValue(err.Error()))
		return
	}
	for _, tenantID := range tenants {
		w.reconcileTenant(ctx, tenantID)
	}
}

// reconcileTenant lists tenantID's pending markers and resolves each one.
//
// The invariant that authorizes discarding a marker is exactly "not in flight
// AND not found" — never "not found" alone. The in-flight check below is what
// makes a not-found result safe to interpret as "the append genuinely never
// happened": a later change must not delete this check as a redundant-looking
// optimization, since it is the only thing distinguishing a real never-happened
// append from an in-progress one still short of committing.
func (w *WORMAuditStore) reconcileTenant(ctx context.Context, tenantID string) {
	markers, err := w.markerStore.ListBlobs(ctx, blob.BlobKey{TenantID: tenantID, Namespace: pendingMarkerNamespace})
	if err != nil {
		w.logger.Warn("audit sink: worm: reconciliation failed to list pending markers — left in place for the next tick",
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"error", logging.SanitizeLogValue(err.Error()),
		)
		return
	}

	for _, marker := range markers {
		entryID := marker.Key.Name

		// The synchronous ship path already owns this entry's lifecycle; revisit
		// it on a later tick once it is no longer in flight. Skipping here — not
		// calling GetAuditEntry at all — is what keeps a not-found result below
		// trustworthy.
		if w.isInFlight(entryID) {
			continue
		}

		entry, getErr := w.local.GetAuditEntry(ctx, entryID)
		switch {
		case getErr == nil:
			// The local append committed — this covers both an ordinary failed
			// ship (outage, transient error) and a crash between the local
			// commit and the marker delete, via the exact same code path.
			w.ship(ctx, tenantID, entry)

		case errors.Is(getErr, business.ErrAuditNotFound):
			// Not in flight AND not found: no SequenceNumber was ever consumed
			// for this ID, so nothing is missing from the chain. This is the
			// same pre-existing loss window pkg/audit.Manager's in-memory queue
			// already has today (a crash before drainLoop writes a queued entry
			// loses it, with or without this story) — not a new gap introduced
			// here, just this design correctly declining to ship an entry that
			// was never actually recorded.
			w.deleteMarker(ctx, tenantID, entryID)

		default:
			// A transient local-store read failure, e.g. Only a definitive
			// ErrAuditNotFound on a not-in-flight ID authorizes discarding a
			// marker — anything else leaves it in place for the next tick.
			w.logger.Warn("audit sink: worm: reconciliation failed to read local entry — marker left in place for the next tick",
				"tenant_id", logging.SanitizeLogValue(tenantID),
				"entry_id", logging.SanitizeLogValue(entryID),
				"error", logging.SanitizeLogValue(getErr.Error()),
			)
		}
	}
}

// Stop stops the background reconciliation loop, if running. Idempotent and
// safe to call even if Start was never called. Unlike Close, Stop does not
// release the wrapped local store — a shutdown sequence calls Stop explicitly
// (mirroring pkg/audit.Manager's Stop(ctx), stopped alongside it) and relies
// on the storage manager's own Close pass to release the local store
// separately via the AuditStore interface's Close method below.
func (w *WORMAuditStore) Stop() {
	w.stopOnce.Do(func() {
		if w.stop != nil {
			close(w.stop)
		}
	})
	if w.done != nil {
		<-w.done
	}
}

// Close stops the reconciliation loop (see Stop) and releases the wrapped
// local store. Required by business.AuditStore — the storage manager's
// generic Close pass reaches this through that interface, so Stop must be
// idempotent with an explicit prior Stop() call from the shutdown sequence.
func (w *WORMAuditStore) Close() error {
	w.Stop()
	return w.local.Close()
}

// markInFlight and clearInFlight manage the in-flight set described on the
// WORMAuditStore.inFlight field doc comment above.
func (w *WORMAuditStore) markInFlight(entryID string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.inFlight[entryID] = struct{}{}
}

func (w *WORMAuditStore) clearInFlight(entryID string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.inFlight, entryID)
}

func (w *WORMAuditStore) isInFlight(entryID string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	_, ok := w.inFlight[entryID]
	return ok
}

// registerTenant durably records tenantID in the tenant registry (idempotent,
// via PutBlobIfAbsent) the first time this process observes it, so the
// reconciliation loop can discover this tenant's pending markers even after a
// restart with no further activity from it. knownTenants caches the result so
// a hot AppendChainedEntry path pays the registry write at most once per
// tenant per process lifetime.
func (w *WORMAuditStore) registerTenant(ctx context.Context, tenantID string) {
	w.mu.Lock()
	_, known := w.knownTenants[tenantID]
	if !known {
		w.knownTenants[tenantID] = struct{}{}
	}
	w.mu.Unlock()
	if known {
		return
	}

	key := blob.BlobKey{TenantID: tenantRegistryTenantID, Namespace: tenantRegistryNamespace, Name: tenantID}
	if err := w.markerStore.PutBlobIfAbsent(ctx, key, bytes.NewReader(nil), blob.BlobMeta{ContentType: "application/octet-stream"}); err != nil && !errors.Is(err, blob.ErrBlobAlreadyExists) {
		w.logger.Warn("audit sink: worm: failed to durably register tenant in marker registry — reconciliation may miss this tenant's markers until process restart",
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"error", logging.SanitizeLogValue(err.Error()),
		)
	}
}

// listKnownTenants returns every tenant ID durably recorded in the tenant
// registry.
func (w *WORMAuditStore) listKnownTenants(ctx context.Context) ([]string, error) {
	infos, err := w.markerStore.ListBlobs(ctx, blob.BlobKey{TenantID: tenantRegistryTenantID, Namespace: tenantRegistryNamespace})
	if err != nil {
		return nil, err
	}
	tenants := make([]string, 0, len(infos))
	for _, info := range infos {
		tenants = append(tenants, info.Key.Name)
	}
	return tenants, nil
}

// markerKey builds the pending-marker blob key for tenantID/entryID.
func (w *WORMAuditStore) markerKey(tenantID, entryID string) blob.BlobKey {
	return blob.BlobKey{TenantID: tenantID, Namespace: pendingMarkerNamespace, Name: entryID}
}

// putMarker writes (or idempotently re-writes) the pending marker for
// tenantID/entryID. No lock is needed here: each marker is its own
// independent blob keyed by entry ID, so there is no shared in-process
// structure for two callers to race on — the blob store's own write
// semantics are the entire safety mechanism for the marker blobs themselves
// (this is distinct from, and does not replace, the inFlight map's mutex
// above, which protects real shared in-memory state).
func (w *WORMAuditStore) putMarker(ctx context.Context, tenantID, entryID string) {
	if err := w.markerStore.PutBlob(ctx, w.markerKey(tenantID, entryID), bytes.NewReader(nil), blob.BlobMeta{ContentType: "application/octet-stream"}); err != nil {
		w.logger.Warn("audit sink: worm: failed to write pending marker",
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"entry_id", logging.SanitizeLogValue(entryID),
			"error", logging.SanitizeLogValue(err.Error()),
		)
	}
}

// deleteMarker clears the pending marker for tenantID/entryID once a ship is
// confirmed. DeleteBlob returns nil if the blob does not exist
// (blob_store.go:73), so a delete race with another caller is harmless — no
// lock needed here either, for the same reason as putMarker.
func (w *WORMAuditStore) deleteMarker(ctx context.Context, tenantID, entryID string) {
	if err := w.markerStore.DeleteBlob(ctx, w.markerKey(tenantID, entryID)); err != nil {
		w.logger.Warn("audit sink: worm: failed to delete cleared pending marker",
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"entry_id", logging.SanitizeLogValue(entryID),
			"error", logging.SanitizeLogValue(err.Error()),
		)
	}
}

// AppendChainedEntry appends to the local sequence authority first — this is
// where SequenceNumber/PreviousChecksum/Checksum are assigned and durably
// committed. A pending marker is written before the local append, not after
// (see the package doc comment and the inFlight field doc comment for why),
// and only cleared once a ship is confirmed. A WORM outage never blocks or
// fails this call: the local write and the marker write are unaffected by the
// WORM target's availability, and a failed ship is retried later by the
// reconciliation loop rather than returned to the caller.
func (w *WORMAuditStore) AppendChainedEntry(ctx context.Context, tenantID string, entry *business.AuditEntry, computeChecksum func(entry *business.AuditEntry) string) error {
	w.markInFlight(entry.ID)
	defer w.clearInFlight(entry.ID)

	w.registerTenant(ctx, tenantID)
	w.putMarker(ctx, tenantID, entry.ID)

	if w.testBeforeLocalAppend != nil {
		w.testBeforeLocalAppend()
	}

	if err := w.local.AppendChainedEntry(ctx, tenantID, entry, computeChecksum); err != nil {
		// The local append never committed. The marker written above now
		// refers to an entry ID that will never exist locally; the
		// reconciliation loop's ErrAuditNotFound branch discards it once this
		// entry drops out of the in-flight set (via the deferred clear above).
		return err
	}

	w.ship(ctx, tenantID, entry)
	return nil
}

// ship serializes entry as JSON and ships it to the blob store under a key
// zero-padded for lexicographic ordering under ListBlobs. PutBlobIfAbsent's
// atomicity (S3 IfNoneMatch: "*", Issue #3895) is the entire refuse-to-overwrite
// mechanism — no second locking layer is added here. On success or
// ErrBlobAlreadyExists the pending marker is cleared; on any other failure the
// marker is re-asserted (an idempotent PutBlob) so the next reconciliation
// attempt never has to assume the marker written earlier is still there.
func (w *WORMAuditStore) ship(ctx context.Context, tenantID string, entry *business.AuditEntry) {
	data, err := json.Marshal(entry)
	if err != nil {
		w.logger.Warn("audit sink: worm: failed to marshal audit entry for shipping — "+wormShipRetryNote,
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"sequence_number", entry.SequenceNumber,
			"error", logging.SanitizeLogValue(err.Error()),
		)
		w.putMarker(ctx, tenantID, entry.ID)
		return
	}

	key := blob.BlobKey{
		TenantID:  tenantID,
		Namespace: wormNamespace,
		Name:      fmt.Sprintf("%020d", entry.SequenceNumber),
	}
	if err := w.blobStore.PutBlobIfAbsent(ctx, key, bytes.NewReader(data), blob.BlobMeta{ContentType: "application/json"}); err != nil {
		if errors.Is(err, blob.ErrBlobAlreadyExists) {
			w.deleteMarker(ctx, tenantID, entry.ID)
			return
		}
		w.logger.Warn("audit sink: worm: failed to ship audit entry to WORM target — "+wormShipRetryNote,
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"sequence_number", entry.SequenceNumber,
			"error", logging.SanitizeLogValue(err.Error()),
		)
		w.putMarker(ctx, tenantID, entry.ID)
		return
	}

	w.deleteMarker(ctx, tenantID, entry.ID)
}

// The remaining methods delegate straight to the wrapped local store — the
// WORM shipper never becomes a second sequence authority or read path.

func (w *WORMAuditStore) StoreAuditEntry(ctx context.Context, entry *business.AuditEntry) error {
	return w.local.StoreAuditEntry(ctx, entry)
}

func (w *WORMAuditStore) GetAuditEntry(ctx context.Context, id string) (*business.AuditEntry, error) {
	return w.local.GetAuditEntry(ctx, id)
}

func (w *WORMAuditStore) ListAuditEntries(ctx context.Context, filter *business.AuditFilter) ([]*business.AuditEntry, error) {
	return w.local.ListAuditEntries(ctx, filter)
}

func (w *WORMAuditStore) StoreAuditBatch(ctx context.Context, entries []*business.AuditEntry) error {
	return w.local.StoreAuditBatch(ctx, entries)
}

func (w *WORMAuditStore) GetAuditsByUser(ctx context.Context, userID string, timeRange *business.TimeRange) ([]*business.AuditEntry, error) {
	return w.local.GetAuditsByUser(ctx, userID, timeRange)
}

func (w *WORMAuditStore) GetAuditsByResource(ctx context.Context, resourceType, resourceID string, timeRange *business.TimeRange) ([]*business.AuditEntry, error) {
	return w.local.GetAuditsByResource(ctx, resourceType, resourceID, timeRange)
}

func (w *WORMAuditStore) GetAuditsByAction(ctx context.Context, action string, timeRange *business.TimeRange) ([]*business.AuditEntry, error) {
	return w.local.GetAuditsByAction(ctx, action, timeRange)
}

func (w *WORMAuditStore) GetFailedActions(ctx context.Context, timeRange *business.TimeRange, limit int) ([]*business.AuditEntry, error) {
	return w.local.GetFailedActions(ctx, timeRange, limit)
}

func (w *WORMAuditStore) GetSuspiciousActivity(ctx context.Context, tenantID string, timeRange *business.TimeRange) ([]*business.AuditEntry, error) {
	return w.local.GetSuspiciousActivity(ctx, tenantID, timeRange)
}

func (w *WORMAuditStore) GetAuditStats(ctx context.Context) (*business.AuditStats, error) {
	return w.local.GetAuditStats(ctx)
}

func (w *WORMAuditStore) GetLastAuditEntry(ctx context.Context, tenantID string) (*business.AuditEntry, error) {
	return w.local.GetLastAuditEntry(ctx, tenantID)
}

func (w *WORMAuditStore) ArchiveAuditEntries(ctx context.Context, beforeDate time.Time) (int64, error) {
	return w.local.ArchiveAuditEntries(ctx, beforeDate)
}

func (w *WORMAuditStore) PurgeAuditEntries(ctx context.Context, beforeDate time.Time) (int64, error) {
	return w.local.PurgeAuditEntries(ctx, beforeDate)
}
