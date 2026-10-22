// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package server

import (
	controllerTransport "github.com/cfgis/cfgms/features/controller/transport"
)

// ingestAdmissionQueues holds the per-tenant admission gates for the steward
// ingest paths (Issue #3759, ADR-031 Decision 6).
//
// There are deliberately FOUR TenantQueue instances. Two are split by how much
// the controller trusts the bucket key each path uses, the third by workload:
//
//   - connectHeartbeat gates Register (connect) and the ControlChannel heartbeat
//     message. Its bucket key is produced by
//     pkg/controlplane/providers/grpc.Provider.admissionBucket and is always
//     server-verified: the tenant the registration token is bound to, else the
//     tenant this controller's own fleet record reports for the mTLS-verified
//     certificate CN, else the CN itself in the reserved "steward-cn:"
//     namespace — and never a tenant field the steward put on the wire. Every
//     key is additionally length- and charset-bounded, which is what preserves
//     TenantQueue's "bounded by number of active tenants" invariant (entries are
//     created lazily and never evicted).
//
//   - events gates steward events on the ControlChannel. Its key is the same
//     server-verified bucket as connectHeartbeat, but events run arbitrary
//     handlers that can be slow, so they get their own queue: a flood of slow
//     event handlers from one tenant must never use up that tenant's connect or
//     heartbeat slots (Issue #5120).
//
//   - responses gates steward responses on the ControlChannel with the same
//     server-verified key. Response subscribers read stores, so they get their
//     own queue: slow response handlers must never use up event or heartbeat
//     slots.
//
//   - dnaBulk gates SyncDNA and BulkTransfer. The DNA handler keys its bucket on
//     the first chunk's tenant_id — unverified wire data (BulkHandler keys on
//     the mTLS peer CN). Those call sites are unchanged by #3759.
//
// Sharing one instance across both groups would re-expose the caller-controlled
// DNA key to the connect and heartbeat paths: a steward with a valid certificate
// (CLAUDE.md threat model: stewards run on hosts that may be compromised) could
// open MaxConcurrentPerTenant concurrent SyncDNA streams naming a victim
// tenant's ID, hold the slots for the life of each RPC, and thereby starve that
// victim tenant's connects and drop its heartbeats fleet-wide — and could mint
// unbounded never-evicted map entries in the same queue. Keeping the instances
// separate bounds a flood on the wire-keyed paths to those paths, exactly as it
// was before connect/heartbeat were gated.
//
// The split is by key trust level, not by path count: a third path may share
// connectHeartbeat only once its bucket key is derived server-side the same way.
type ingestAdmissionQueues struct {
	connectHeartbeat *controllerTransport.TenantQueue
	events           *controllerTransport.TenantQueue
	responses        *controllerTransport.TenantQueue
	dnaBulk          *controllerTransport.TenantQueue
}

// newIngestAdmissionQueues builds the ingest admission gates. Both queues are
// the same TenantQueue type with the same MaxConcurrentPerTenant limit; only the
// key space differs.
func newIngestAdmissionQueues() *ingestAdmissionQueues {
	return &ingestAdmissionQueues{
		connectHeartbeat: controllerTransport.NewTenantQueue(),
		events:           controllerTransport.NewTenantQueue(),
		responses:        controllerTransport.NewTenantQueue(),
		dnaBulk:          controllerTransport.NewTenantQueue(),
	}
}

// connectHeartbeatQueue returns the gate for the server-verified-key paths,
// tolerating a Server assembled without New (queues absent).
func (q *ingestAdmissionQueues) connectHeartbeatQueue() *controllerTransport.TenantQueue {
	if q == nil {
		return controllerTransport.NewTenantQueue()
	}
	return q.connectHeartbeat
}

// dnaBulkQueue returns the gate for the wire-keyed paths, tolerating a Server
// assembled without New (queues absent).
func (q *ingestAdmissionQueues) dnaBulkQueue() *controllerTransport.TenantQueue {
	if q == nil {
		return controllerTransport.NewTenantQueue()
	}
	return q.dnaBulk
}

// eventsQueue returns the gate for steward events, tolerating a Server
// assembled without New (queues absent).
func (q *ingestAdmissionQueues) eventsQueue() *controllerTransport.TenantQueue {
	if q == nil {
		return controllerTransport.NewTenantQueue()
	}
	return q.events
}

// responsesQueue returns the gate for steward responses, tolerating a Server
// assembled without New (queues absent).
func (q *ingestAdmissionQueues) responsesQueue() *controllerTransport.TenantQueue {
	if q == nil {
		return controllerTransport.NewTenantQueue()
	}
	return q.responses
}
