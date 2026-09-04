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
// Evaluate is a pure read: it does not modify the cache. Use EvaluateAndStore to
// persist the verdict without discarding a decision already in force.
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
	return w.transition(addr, cache.ApprovalStatusApproved)
}

// RejectPending transitions a queued (pending) cache entry to rejected by admin decision.
// Returns ErrNotQueued if the entry is not in pending state.
// Returns cache.ErrBundleNotFound if no entry exists for addr.
func (w *ApprovalWorkflow) RejectPending(addr bundle.ContentAddress) error {
	return w.transition(addr, cache.ApprovalStatusRejected)
}

// transition atomically moves addr from pending to newStatus via
// cache.CompareAndSetApprovalStatus, rather than a separate Get-then-Set pair.
// A plain read-then-write would let a concurrent decision from another
// controller node (once approval status is backed by a cluster-visible store,
// Issue #3886) land between the read and the write, silently overwriting it —
// the split-brain approve/reject race this CAS closes.
func (w *ApprovalWorkflow) transition(addr bundle.ContentAddress, newStatus cache.ApprovalStatus) error {
	ok, err := w.cache.CompareAndSetApprovalStatus(addr, cache.ApprovalStatusPending, newStatus)
	if err != nil {
		return fmt.Errorf("compare-and-set approval status: %w", err)
	}
	if ok {
		return nil
	}

	current, getErr := w.cache.GetApprovalStatus(addr)
	if getErr != nil {
		return fmt.Errorf("get approval status: %w", getErr)
	}
	return fmt.Errorf("%w: current status is %q", ErrNotQueued, current)
}

// EvaluateAndStore evaluates b, stores it in the cache, and records the decision
// as the bundle's initial approval status. It is the push-time ingestion path
// (cfg upload → module resolution), reached on every controller node that
// resolves the bundle and callable repeatedly for the same content.
//
// A decision already standing for this bundle is never discarded. Ingestion only
// seeds a status for a bundle that has none (cache.Put), and an automatic verdict
// is applied with a pending → verdict compare-and-set, so a rejection recorded by
// an operator — on this node, or on a peer sharing the cluster-visible approval
// store — survives re-ingestion and is what this method reports back. Without
// that, a rejected bundle would be reset to pending and auto-approved again by
// the next cfg push that referenced it (Issue #3886).
//
// The returned decision is therefore the status in force for the bundle, not
// merely this node's fresh verdict: callers (resolution.ResolveCfgRequiredModules)
// gate deployment on it. The one exception is a bundle whose signature does not
// verify (Evaluate → Reject): that is a property of the content itself, so it is
// reported as Reject no matter what status is stored.
//
// Rejected bundles are still stored in the cache (with rejected status) so operators
// can audit what was blocked.
func (w *ApprovalWorkflow) EvaluateAndStore(b *bundle.Bundle, store trust.TrustStore) (ApprovalDecision, error) {
	decision, err := w.Evaluate(b, store)
	if err != nil {
		return decision, err
	}

	// Put seeds pending only if the bundle has no status yet.
	if putErr := w.cache.Put(b); putErr != nil {
		return decision, fmt.Errorf("cache Put: %w", putErr)
	}
	addr := b.ContentAddress()

	if targetStatus, automatic := statusForDecision(decision); automatic {
		ok, casErr := w.cache.CompareAndSetApprovalStatus(addr, cache.ApprovalStatusPending, targetStatus)
		if casErr != nil {
			return decision, fmt.Errorf("record initial approval status: %w", casErr)
		}
		if ok {
			return decision, nil
		}
	}

	// Either the bundle stays queued for review, or it already carries a
	// decision that this ingestion must not overwrite. Report what is in force.
	current, getErr := w.cache.GetApprovalStatus(addr)
	if getErr != nil {
		return decision, fmt.Errorf("get approval status: %w", getErr)
	}
	if decision == Reject {
		return Reject, nil
	}
	return decisionForStatus(current), nil
}

// statusForDecision maps an evaluation verdict to the approval status it records.
// automatic is false for QueueForReview, which records no verdict of its own —
// the bundle simply stays in the pending state ingestion seeded.
func statusForDecision(decision ApprovalDecision) (status cache.ApprovalStatus, automatic bool) {
	switch decision {
	case AutoApprove:
		return cache.ApprovalStatusApproved, true
	case Reject:
		return cache.ApprovalStatusRejected, true
	default:
		return cache.ApprovalStatusPending, false
	}
}

// decisionForStatus maps a stored approval status back to the decision callers
// gate deployment on, so a status recorded by an operator (or by a peer node)
// carries the same weight as a freshly computed verdict.
func decisionForStatus(status cache.ApprovalStatus) ApprovalDecision {
	switch status {
	case cache.ApprovalStatusApproved:
		return AutoApprove
	case cache.ApprovalStatusRejected:
		return Reject
	default:
		return QueueForReview
	}
}

// ApprovalStatusIsClusterVisible reports whether the approval status this
// workflow decides is backed by the cluster-visible, CAS-protected store rather
// than node-local files. The REST approve/reject handlers consult it to decide
// whether any node may serve a decision or whether the leadership gate must
// still apply (Issue #3886).
func (w *ApprovalWorkflow) ApprovalStatusIsClusterVisible() bool {
	return w.cache.HasSharedApprovalStore()
}
