// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
// Package business defines the ModuleApprovalStore interface for cluster-visible
// module bundle approval status (ADR-031 Decision 1, Issue #3886). Approval status
// previously lived only in ModuleCache, a per-process local-filesystem directory
// (features/controller/modules/cache) — an any-node approve/reject service against
// that store would let a concurrent approve on one controller node overwrite an
// operator's rejection on another, and would leave a bundle rejected on one node
// still approvable, stageable and distributable from a peer, since every staging
// path gated on the *local* status. This is the trust decision authorizing
// publisher-signed binaries to run on managed endpoints (Issue #3761 residual
// review), so the gate on the approve/reject handlers stayed in place until this
// store existed.
package business

import "context"

// ModuleApprovalStatus is the approval state of a cached module bundle. Defined
// independently of features/controller/modules/cache.ApprovalStatus (rather than
// imported from it) because business is a storage-interfaces leaf package and
// features/controller/modules/cache is a higher-level feature package that itself
// depends on this store — cache.go converts between the two at its call sites.
type ModuleApprovalStatus string

const (
	ModuleApprovalPending  ModuleApprovalStatus = "pending"
	ModuleApprovalApproved ModuleApprovalStatus = "approved"
	ModuleApprovalRejected ModuleApprovalStatus = "rejected"
)

// ModuleApprovalStore defines durable, cluster-visible storage for module bundle
// approval status. A cluster-visible implementation makes an approve/reject
// decision made on one controller node immediately observable — and enforceable —
// by every node sharing the same store, closing the split-brain window where a
// bundle rejected on one node remained approvable, stageable, and distributable
// from a peer.
type ModuleApprovalStore interface {
	// GetApprovalStatus returns the status currently stored for addr. found is
	// false if no record has ever been written for addr.
	GetApprovalStatus(ctx context.Context, addr string) (status ModuleApprovalStatus, found bool, err error)

	// PutApprovalStatusIfAbsent records status for addr only when no record
	// exists yet, and returns the status in force afterwards: the newly written
	// status when this call created the record, otherwise the status that was
	// already stored. It never overwrites an existing decision.
	//
	// Insert-if-absent is the only ingestion primitive this interface offers, on
	// purpose. A bundle is ingested on every node that resolves it, so an
	// unconditional "seed as pending" write would reset a rejection an operator
	// had already recorded on a peer node — and, because the store is
	// authoritative for every node, would unblock the bundle cluster-wide.
	// Deciding a bundle is CompareAndSetApprovalStatus's job.
	PutApprovalStatusIfAbsent(ctx context.Context, addr string, status ModuleApprovalStatus) (effective ModuleApprovalStatus, err error)

	// CompareAndSetApprovalStatus atomically transitions addr's status from
	// expectedCurrent to newStatus. The compare-and-write is atomic with respect
	// to every other caller of this store — including callers on different
	// controller nodes sharing it — so a concurrent approve and reject against
	// the same bundle always converge on exactly one winner. Returns ok=false
	// with a nil error when the stored status is not expectedCurrent (including
	// when no record exists at all), so callers can distinguish "lost the race"
	// from an infrastructure failure.
	CompareAndSetApprovalStatus(ctx context.Context, addr string, expectedCurrent, newStatus ModuleApprovalStatus) (ok bool, err error)
}
