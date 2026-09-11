// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package auditsink implements the WORM (write-once-read-many) audit shipper
// (Issue #4037, ADR-033, Epic #4033). WORMAuditStore wraps a local
// business.AuditStore — which remains the sole sequence authority — and a
// blob.BlobStore WORM target. It is a forward-only shipper of already-sequenced
// entries, never a replacement AuditStore: every method except
// AppendChainedEntry delegates straight to the wrapped local store.
package auditsink

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/blob"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// wormNamespace is the blob namespace shipped audit entries are stored under.
// A dedicated namespace keeps the shipper's key space unambiguous from any
// other blob consumer sharing the same bucket.
const wormNamespace = "audit-chain"

// wormShipNotRetriedNote is the transitional truth-in-labeling caveat (PO
// product review, epic #4033): Story 5 of Epic #4033, not this story, adds
// ship-failure retry/reconciliation. Until it lands, a failed ship is a real,
// unretried gap. Story 5 MUST update this line to drop the caveat once
// reconciliation ships.
const wormShipNotRetriedNote = "ship failures are currently logged, not retried — gaps are possible until outage recovery ships (tracking: Epic #4033)"

// WORMAuditStore implements business.AuditStore.
type WORMAuditStore struct {
	local     business.AuditStore
	blobStore blob.BlobStore
	logger    logging.Logger
}

var _ business.AuditStore = (*WORMAuditStore)(nil)

// NewWORMAuditStore wraps local with a WORM shipper backed by blobStore. It
// probes blobStore for object-lock enforcement (blob.ObjectLockProber) exactly
// once and logs the startup line documenting the resulting bound. The probe
// outcome never fails or blocks construction — fail-closed on sink
// misconfiguration was explicitly rejected by the founder (Epic #4033); it only
// changes what is logged.
func NewWORMAuditStore(ctx context.Context, local business.AuditStore, blobStore blob.BlobStore, logger logging.Logger) *WORMAuditStore {
	if logger == nil {
		logger = logging.NewNoopLogger()
	}
	logStartup(ctx, blobStore, logger)
	return &WORMAuditStore{local: local, blobStore: blobStore, logger: logger}
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
			"ship_retry", wormShipNotRetriedNote,
		)
	default:
		logger.Warn("Audit sink selected",
			"sink", "worm",
			"object_lock", status.String(),
			"bound", reducedBoundMessage(status),
			"ship_retry", wormShipNotRetriedNote,
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

// AppendChainedEntry appends to the local sequence authority first — this is
// where SequenceNumber/PreviousChecksum/Checksum are assigned and durably
// committed. Only on success is the now-fully-sequenced entry shipped to the
// WORM blob target, keyed by tenant/zero-padded-sequence so a second write to
// the same key is refused. A ship failure is logged, never returned to the
// caller: the local write already succeeded and durability is not lost (Story
// 5, Epic #4033, makes this retryable).
func (w *WORMAuditStore) AppendChainedEntry(ctx context.Context, tenantID string, entry *business.AuditEntry, computeChecksum func(entry *business.AuditEntry) string) error {
	if err := w.local.AppendChainedEntry(ctx, tenantID, entry, computeChecksum); err != nil {
		return err
	}
	w.ship(ctx, tenantID, entry)
	return nil
}

// ship serializes entry as JSON and ships it to the blob store under a key
// zero-padded for lexicographic ordering under ListBlobs. PutBlobIfAbsent's
// atomicity (S3 IfNoneMatch: "*", Issue #3895) is the entire refuse-to-overwrite
// mechanism — no second locking layer is added here.
func (w *WORMAuditStore) ship(ctx context.Context, tenantID string, entry *business.AuditEntry) {
	data, err := json.Marshal(entry)
	if err != nil {
		w.logger.Warn("audit sink: worm: failed to marshal audit entry for shipping — "+wormShipNotRetriedNote,
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"sequence_number", entry.SequenceNumber,
			"error", logging.SanitizeLogValue(err.Error()),
		)
		return
	}

	key := blob.BlobKey{
		TenantID:  tenantID,
		Namespace: wormNamespace,
		Name:      fmt.Sprintf("%020d", entry.SequenceNumber),
	}
	if err := w.blobStore.PutBlobIfAbsent(ctx, key, bytes.NewReader(data), blob.BlobMeta{ContentType: "application/json"}); err != nil {
		w.logger.Warn("audit sink: worm: failed to ship audit entry to WORM target — "+wormShipNotRetriedNote,
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"sequence_number", entry.SequenceNumber,
			"error", logging.SanitizeLogValue(err.Error()),
		)
	}
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

func (w *WORMAuditStore) Close() error {
	return w.local.Close()
}
