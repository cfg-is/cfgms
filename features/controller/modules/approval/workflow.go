// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

// Package approval implements the module bundle approval workflow.
// The workflow evaluates an incoming bundle against the trust store and assigns
// an approval decision. Admin operators may explicitly approve queued bundles
// via Approve().
package approval

import (
	"errors"
	"fmt"

	"github.com/cfgis/cfgms/features/controller/modules/cache"
	"github.com/cfgis/cfgms/pkg/modules/bundle"
	"github.com/cfgis/cfgms/pkg/modules/trust"
)

// ApprovalDecision is the outcome of evaluating a bundle against the trust store.
type ApprovalDecision int

const (
	// AutoApprove means the bundle is from a trusted publisher with a valid signature.
	AutoApprove ApprovalDecision = iota
	// QueueForReview means the publisher is unknown; an admin must act before the bundle is staged.
	QueueForReview
	// Reject means the signature verification failed (tampered or malformed bundle).
	Reject
)

// ErrNotQueued is returned by Approve when the entry is not in QueueForReview (pending) state.
var ErrNotQueued = errors.New("module is not queued for review")

// ApprovalWorkflow evaluates incoming bundles and manages their approval state.
// State is persisted via the ModuleCache (filesystem-backed durable storage).
type ApprovalWorkflow struct {
	cache *cache.ModuleCache
}

// New returns an ApprovalWorkflow backed by the given cache.
func New(c *cache.ModuleCache) *ApprovalWorkflow {
	return &ApprovalWorkflow{cache: c}
}

// Evaluate determines the approval decision for b against store.
//
// Decision rules:
//   - Publisher in trust store AND at least one signature from that publisher passes
//     VerifyBundleSignature → AutoApprove.
//   - Publisher NOT in trust store → QueueForReview.
//   - Publisher in trust store but no valid signature found → Reject.
//
// Evaluate is a pure read: it does not modify the cache. The caller must call
// cache.Put followed by cache.SetApprovalStatus to persist the decision.
func (w *ApprovalWorkflow) Evaluate(b *bundle.Bundle, store trust.TrustStore) (ApprovalDecision, error) {
	if b == nil || b.Manifest == nil {
		return Reject, errors.New("bundle or manifest is nil")
	}

	publisher := b.Manifest.Publisher
	_, known := store.GetPublisher(publisher)
	if !known {
		return QueueForReview, nil
	}

	// Publisher is trusted — verify their signature.
	for _, sig := range b.Signatures {
		if sig.Publisher != publisher {
			continue
		}
		if err := trust.VerifyBundleSignature(b, sig, store); err == nil {
			return AutoApprove, nil
		}
	}

	// Publisher trusted but no valid signature found.
	return Reject, nil
}

// Approve transitions a queued (pending) cache entry to approved.
// Returns ErrNotQueued if the entry is not in pending state.
// Returns cache.ErrBundleNotFound if no entry exists for addr.
func (w *ApprovalWorkflow) Approve(addr bundle.ContentAddress) error {
	status, err := w.cache.GetApprovalStatus(addr)
	if err != nil {
		return fmt.Errorf("get approval status: %w", err)
	}
	if status != cache.ApprovalStatusPending {
		return fmt.Errorf("%w: current status is %q", ErrNotQueued, status)
	}
	return w.cache.SetApprovalStatus(addr, cache.ApprovalStatusApproved)
}

// EvaluateAndStore evaluates b, stores it in the cache, and persists the decision as
// the initial approval status. It is a convenience method that combines Evaluate +
// cache.Put + cache.SetApprovalStatus into a single atomic-ish operation.
//
// Rejected bundles are still stored in the cache (with rejected status) so operators
// can audit what was blocked.
func (w *ApprovalWorkflow) EvaluateAndStore(b *bundle.Bundle, store trust.TrustStore) (ApprovalDecision, error) {
	decision, err := w.Evaluate(b, store)
	if err != nil {
		return decision, err
	}

	if putErr := w.cache.Put(b); putErr != nil {
		return decision, fmt.Errorf("cache Put: %w", putErr)
	}

	var targetStatus cache.ApprovalStatus
	switch decision {
	case AutoApprove:
		targetStatus = cache.ApprovalStatusApproved
	case QueueForReview:
		targetStatus = cache.ApprovalStatusPending
	case Reject:
		targetStatus = cache.ApprovalStatusRejected
	}

	if setErr := w.cache.SetApprovalStatus(b.ContentAddress(), targetStatus); setErr != nil {
		return decision, fmt.Errorf("set approval status: %w", setErr)
	}

	return decision, nil
}
