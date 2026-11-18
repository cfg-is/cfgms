// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package service

import (
	"context"
	"errors"
	"sync"

	"github.com/cfgis/cfgms/features/controller/commands"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// PendingDeliveryDrainHook drains a reconnecting steward's durable outbox
// backlog (Issue #3757) immediately on connect, rather than waiting for some
// unrelated future dispatch to notice the pending row.
//
// Identity scoping (ADR-031 Decision 3, Issue #3764, Security review round 2):
// OnConnect's stewardID argument is the mTLS-authenticated CN of the
// connecting steward, supplied by the transport layer on every successful
// ControlChannel registration — never a value a client can otherwise choose.
// This hook resolves that steward's CURRENT tenant from stewardStore itself
// and passes both to CommandStore.ListPendingDeliveries, which further scopes
// by the steward's tenant chain. A steward reconnecting can therefore never
// trigger delivery of, or receive, another steward's pending rows: the ID it
// is scoped by is the one the mTLS handshake proved it is, not one it
// supplies in a request.
type PendingDeliveryDrainHook struct {
	commandStore business.CommandStore
	stewardStore business.StewardStore
	logger       logging.Logger

	floorSent *FloorSentTracker

	mu        sync.RWMutex
	publisher *commands.Publisher
	resolver  SigningResolutionSource
}

// SigningResolutionSource reports how a steward's connection resolves for
// signing. *commands.CapabilityResolver satisfies it.
type SigningResolutionSource interface {
	Resolve(ctx context.Context, stewardID string) commands.Resolution
}

// NewPendingDeliveryDrainHook constructs the hook. publisher may be nil at
// construction time — commands.Publisher is constructed later in the same
// init-cycle break service.NewSigningRotationService's SetPublisher
// documents — and must be supplied via SetPublisher before this hook does
// anything; until then OnConnect is a no-op.
func NewPendingDeliveryDrainHook(commandStore business.CommandStore, stewardStore business.StewardStore, publisher *commands.Publisher, logger logging.Logger) *PendingDeliveryDrainHook {
	return &PendingDeliveryDrainHook{
		commandStore: commandStore,
		stewardStore: stewardStore,
		publisher:    publisher,
		logger:       logger,
		floorSent:    NewFloorSentTracker(),
	}
}

// SetSigningResolver injects the resolver the hook asks, before it publishes a
// row, whether the row will be signed at the floor profile of a connection that
// can still declare late. Without one no row is tracked.
func (h *PendingDeliveryDrainHook) SetSigningResolver(r SigningResolutionSource) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.resolver = r
}

func (h *PendingDeliveryDrainHook) currentResolver() SigningResolutionSource {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.resolver
}

// FloorSent returns the tracker of the rows this hook published in the floor
// form. The late-declaration replay and the rejection recorder share it.
func (h *PendingDeliveryDrainHook) FloorSent() *FloorSentTracker {
	if h == nil {
		return nil
	}
	return h.floorSent
}

// SetPublisher injects the command publisher once it has been constructed.
func (h *PendingDeliveryDrainHook) SetPublisher(p *commands.Publisher) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.publisher = p
}

func (h *PendingDeliveryDrainHook) currentPublisher() *commands.Publisher {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.publisher
}

// OnConnect implements the StewardOnConnectHook contract
// (OnConnect(ctx, stewardID) error).
func (h *PendingDeliveryDrainHook) OnConnect(ctx context.Context, stewardID string) error {
	if h == nil || h.commandStore == nil || h.stewardStore == nil {
		return nil
	}
	publisher := h.currentPublisher()
	if publisher == nil {
		return nil
	}

	record, err := h.stewardStore.GetSteward(ctx, stewardID)
	if err != nil || record == nil || record.TenantID == "" {
		// No resolvable tenant for this steward: ListPendingDeliveries requires
		// one and fails closed without it (business.ErrCommandTenantIDRequired).
		// Nothing can be drained safely, so this is not treated as an error.
		return nil
	}

	pending, err := h.commandStore.ListPendingDeliveries(ctx, stewardID, record.TenantID)
	if err != nil {
		if h.logger != nil {
			h.logger.Warn("pending-delivery drain: failed to list pending deliveries",
				"steward_id", logging.SanitizeLogValue(stewardID),
				"error", logging.SanitizeLogValue(err.Error()))
		}
		return err
	}

	resolver := h.currentResolver()
	for _, rec := range pending {
		if rec != nil {
			h.redeliver(ctx, publisher, resolver, stewardID, rec)
		}
	}
	return nil
}

// redeliver publishes one pending row and records it delivered. A failed publish
// leaves the row pending for the next drain.
func (h *PendingDeliveryDrainHook) redeliver(ctx context.Context, publisher *commands.Publisher, resolver SigningResolutionSource, stewardID string, rec *business.CommandRecord) {
	tracked := h.trackIfFloor(ctx, resolver, stewardID, rec.ID)
	if pubErr := publisher.PublishCommandWithID(ctx, rec.ID, stewardID, controlplaneTypes.CommandType(rec.Type), rec.Payload); pubErr != nil {
		if tracked {
			// Never sent, so there is no floor-form command to recover from.
			h.floorSent.Untrack(stewardID, rec.ID)
		}
		if errors.Is(pubErr, commands.ErrCommandTypeUnsupportedByPeer) {
			// The connection will never handle this type, so leaving the row
			// pending would only retry it on every reconnect. End it terminally.
			h.rejectUnsupported(ctx, stewardID, rec)
			return
		}
		if h.logger != nil {
			h.logger.Warn("pending-delivery drain: redelivery attempt failed, leaving pending",
				"steward_id", logging.SanitizeLogValue(stewardID),
				"command_id", logging.SanitizeLogValue(rec.ID),
				"error", logging.SanitizeLogValue(pubErr.Error()))
		}
		return
	}
	// A late declaration may already have marked this row refused for its
	// signing form; that outcome stands, so delivered is not written over it.
	h.floorSent.WriteUnlessRefused(stewardID, rec.ID, func() {
		if updErr := h.commandStore.UpdateDeliveryStatus(ctx, rec.ID, business.DeliveryStatusDelivered, ""); updErr != nil && h.logger != nil {
			h.logger.Warn("pending-delivery drain: failed to record delivered status",
				"steward_id", logging.SanitizeLogValue(stewardID),
				"command_id", logging.SanitizeLogValue(rec.ID),
				"error", logging.SanitizeLogValue(updErr.Error()))
		}
	})
}

// rejectUnsupported ends a pending row whose command type the steward's
// connection does not handle: it is rejected with the controller-assigned detail,
// which is terminal, and the command was never sent.
func (h *PendingDeliveryDrainHook) rejectUnsupported(ctx context.Context, stewardID string, rec *business.CommandRecord) {
	if h.logger != nil {
		h.logger.Info("pending-delivery drain: command not sent, steward does not support its type",
			"event", EventCommandNotSentPeerUnsupported,
			"steward_id", logging.SanitizeLogValue(stewardID),
			"command_id", logging.SanitizeLogValue(rec.ID),
			"command_type", logging.SanitizeLogValue(rec.Type))
	}
	err := h.commandStore.UpdateDeliveryStatus(ctx, rec.ID, business.DeliveryStatusRejected, business.DeliveryDetailCommandTypeUnsupportedByPeer)
	if err != nil && h.logger != nil {
		h.logger.Warn("pending-delivery drain: failed to record unsupported command type",
			"steward_id", logging.SanitizeLogValue(stewardID),
			"command_id", logging.SanitizeLogValue(rec.ID),
			"error", logging.SanitizeLogValue(err.Error()))
	}
}

// trackIfFloor records row id in the floor-sent tracker when the publisher is
// about to sign it in v1 for a connection that has declared nothing yet. It is
// recorded before the publish, so a late declaration that lands while the row is
// in flight still finds it.
func (h *PendingDeliveryDrainHook) trackIfFloor(ctx context.Context, resolver SigningResolutionSource, stewardID, id string) bool {
	if resolver == nil {
		return false
	}
	res := resolver.Resolve(ctx, stewardID)
	if !res.Undeclared || res.Version != controlplaneTypes.SigningPayloadV1 || res.ConnectionID == "" {
		return false
	}
	h.floorSent.Track(stewardID, res.ConnectionID, id)
	return true
}

const (
	// maxFloorSentPerConnection bounds the row IDs tracked for one connection;
	// the oldest is dropped first.
	maxFloorSentPerConnection = 1024
	// maxFloorSentConnections bounds the stewards tracked; the one tracked
	// longest ago is dropped first.
	maxFloorSentConnections = 4096
)

// FloorSentTracker remembers, in memory and per connection, the outbox rows the
// drain hook published while the connection was settled at the floor profile
// (signed v1). Only the drain hook has a delivery row for a command it sends
// during the grace; every other command sent in v1 has none and needs no entry.
//
// The memory is safe to lose: it only exists to relabel rows of a connection that
// declares late, and a connection that ended is not going to.
type FloorSentTracker struct {
	mu    sync.Mutex
	sets  map[string]*floorSentSet
	order []string
}

type floorSentSet struct {
	connectionID string
	refused      map[string]bool // row ID -> the late declaration already marked it
	fifo         []string
}

// NewFloorSentTracker returns an empty tracker.
func NewFloorSentTracker() *FloorSentTracker {
	return &FloorSentTracker{sets: make(map[string]*floorSentSet)}
}

// Track records that row id is being sent to the steward's connection in the
// floor form. A connection other than the one already tracked replaces its set.
func (t *FloorSentTracker) Track(stewardID, connectionID, id string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	set, ok := t.sets[stewardID]
	if !ok || set.connectionID != connectionID {
		if !ok {
			t.order = append(t.order, stewardID)
			for len(t.order) > maxFloorSentConnections {
				delete(t.sets, t.order[0])
				t.order = t.order[1:]
			}
		}
		set = &floorSentSet{connectionID: connectionID, refused: make(map[string]bool)}
		t.sets[stewardID] = set
	}
	if _, dup := set.refused[id]; dup {
		return
	}
	set.refused[id] = false
	set.fifo = append(set.fifo, id)
	for len(set.fifo) > maxFloorSentPerConnection {
		delete(set.refused, set.fifo[0])
		set.fifo = set.fifo[1:]
	}
}

// Untrack drops a row that was never sent.
func (t *FloorSentTracker) Untrack(stewardID, id string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if set, ok := t.sets[stewardID]; ok {
		delete(set.refused, id)
	}
}

// ConnectionOf returns the connection row id was sent to in the floor form, and
// false when the row is not tracked.
func (t *FloorSentTracker) ConnectionOf(stewardID, id string) (connectionID string, ok bool) {
	if t == nil {
		return "", false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	set, found := t.sets[stewardID]
	if !found {
		return "", false
	}
	if _, tracked := set.refused[id]; !tracked {
		return "", false
	}
	return set.connectionID, true
}

// WriteUnlessRefused runs write unless the late declaration already marked row
// id, holding the tracker's lock so the two writers cannot interleave.
func (t *FloorSentTracker) WriteUnlessRefused(stewardID, id string, write func()) {
	if t == nil {
		write()
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if set, ok := t.sets[stewardID]; ok && set.refused[id] {
		return
	}
	write()
}

// RefuseAll calls mark once for every row not yet marked that was sent in the
// floor form on connectionID, and remembers it as marked. A set that belongs to
// another connection is left alone. The lock is held across mark, so a rejection
// recorder asking ConnectionOf waits for the marking to finish and then sees the
// outcome on the row.
func (t *FloorSentTracker) RefuseAll(stewardID, connectionID string, mark func(id string)) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	set, ok := t.sets[stewardID]
	if !ok || (connectionID != "" && set.connectionID != connectionID) {
		return
	}
	for _, id := range set.fifo {
		if refused, tracked := set.refused[id]; !tracked || refused {
			continue
		}
		mark(id)
		set.refused[id] = true
	}
}
