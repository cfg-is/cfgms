// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package commands

import (
	"context"
	"time"

	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/transport/registry"
)

const (
	// DefaultCapabilityResolveWait is how long after a connection starts the
	// resolver waits for that connection to declare its capabilities before it
	// signs for it at the floor profile. It is shorter than the control channel's
	// own grace period, so a silent steward's first command is not held for the
	// whole grace.
	DefaultCapabilityResolveWait = 3 * time.Second

	// defaultCapabilityPollInterval is how often a node that does not hold the
	// connection re-reads the durable record while the connection is pending.
	defaultCapabilityPollInterval = 100 * time.Millisecond
)

// ConnectionLookup finds the connection this node holds for a steward.
type ConnectionLookup interface {
	Get(stewardID string) (*registry.StewardConnection, bool)
}

// StewardRecordReader reads a steward's durable record, which carries the
// capability record of its latest connection.
type StewardRecordReader interface {
	GetSteward(ctx context.Context, stewardID string) (*business.StewardRecord, error)
}

// CapabilityResolver chooses the signing payload version for a steward's current
// connection. It implements controlplaneTypes.SigningVersionSource.
//
// The floor profile signs v1, so a steward build that predates v2 verifies the
// command; every other steward signs v2. The choice reads controller-held state
// only: the per-connection state on the node that holds the connection, the
// durable record on any other node. It never reads the command or its params.
//
// The wait for an undeclared connection happens here, at the point of signing,
// and nowhere else: a connect hook that waited would delay every hook behind it.
type CapabilityResolver struct {
	conns  ConnectionLookup
	store  StewardRecordReader
	logger logging.Logger

	wait time.Duration
	poll time.Duration
	now  func() time.Time
}

// CapabilityResolverOption configures a CapabilityResolver.
type CapabilityResolverOption func(*CapabilityResolver)

// WithCapabilityResolveWait sets how long after a connection starts the resolver
// waits for its declaration. A value that is not positive keeps the default.
func WithCapabilityResolveWait(d time.Duration) CapabilityResolverOption {
	return func(r *CapabilityResolver) {
		if d > 0 {
			r.wait = d
		}
	}
}

// WithCapabilityPollInterval sets how often the durable record is re-read while a
// connection this node does not hold is pending. A value that is not positive
// keeps the default.
func WithCapabilityPollInterval(d time.Duration) CapabilityResolverOption {
	return func(r *CapabilityResolver) {
		if d > 0 {
			r.poll = d
		}
	}
}

// WithCapabilityResolverClock replaces the clock the wait is measured against.
func WithCapabilityResolverClock(now func() time.Time) CapabilityResolverOption {
	return func(r *CapabilityResolver) {
		if now != nil {
			r.now = now
		}
	}
}

// NewCapabilityResolver builds a resolver over the node's connection registry and
// the steward store. A nil conns or store drops that source, and a steward with
// no state from either is signed for as current.
func NewCapabilityResolver(conns ConnectionLookup, store StewardRecordReader, logger logging.Logger, opts ...CapabilityResolverOption) *CapabilityResolver {
	r := &CapabilityResolver{
		conns:  conns,
		store:  store,
		logger: logger,
		wait:   DefaultCapabilityResolveWait,
		poll:   defaultCapabilityPollInterval,
		now:    time.Now,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Resolution is what the resolver decided for one steward's connection.
type Resolution struct {
	// Version is the signing payload version the steward is signed for.
	Version uint32
	// ConnectionID identifies the connection the decision was read from. Empty
	// when it came from the durable record of a connection another node holds,
	// or from no state at all.
	ConnectionID string
	// Undeclared is true while the connection has declared nothing: it is still
	// pending, or its grace period ended and settled it at the floor profile. A
	// version of v1 on such a connection is a guess a later declaration can
	// overturn. It is false for a connection that declared, whatever the set,
	// and for a decision read from the durable record.
	Undeclared bool
	// CommandTypes are the command type numbers the steward's connection handles:
	// its declared set, or the floor set for a connection that declared nothing.
	// Nil when the controller holds no state for the steward, which gates nothing.
	CommandTypes []int32
}

// SigningVersionFor returns SigningPayloadV1 when the steward's connection
// resolves to the floor profile and SigningPayloadV2 otherwise. A connection that
// has not declared is waited on until its start plus the resolve wait, then
// resolved to the floor for this call only: a later declaration is picked up by
// the next call. A nil resolver returns v2.
func (r *CapabilityResolver) SigningVersionFor(ctx context.Context, stewardID string) uint32 {
	return r.Resolve(ctx, stewardID).Version
}

// Resolve is SigningVersionFor with the connection the decision was read from.
func (r *CapabilityResolver) Resolve(ctx context.Context, stewardID string) Resolution {
	if r == nil {
		return Resolution{Version: controlplaneTypes.SigningPayloadV2}
	}
	if r.conns != nil {
		if conn, ok := r.conns.Get(stewardID); ok && conn != nil {
			return r.fromConnection(ctx, conn)
		}
	}
	return r.fromRecord(ctx, stewardID)
}

// SupportsCommandType reports whether the steward's current connection handles
// cmdType, resolved exactly as the signing version is (so a connection that has
// not declared is waited on, bounded, then taken at the floor profile for this
// call). It is false only for a known profile that lacks the type: a type the
// controller does not know, a steward with no state and a nil resolver are all
// supported, so nothing is gated on a guess.
func (r *CapabilityResolver) SupportsCommandType(ctx context.Context, stewardID string, cmdType controlplaneTypes.CommandType) bool {
	if r == nil {
		return true
	}
	n, known := controlplaneTypes.CommandTypeNumber(cmdType)
	if !known {
		return true
	}
	res := r.Resolve(ctx, stewardID)
	if len(res.CommandTypes) == 0 {
		return true
	}
	return controlplaneTypes.CapabilityProfile{CommandTypes: res.CommandTypes}.SupportsCommandType(n)
}

// ConnectionID returns the ID of the connection this node holds for the steward,
// or "" when it holds none. It reads no capability state and never waits.
func (r *CapabilityResolver) ConnectionID(stewardID string) string {
	id, _ := r.Connection(stewardID)
	return id
}

// Connection returns the ID of the connection this node holds for the steward
// and whether that connection has declared its capabilities. It never waits. The
// ID is "" when this node holds no connection.
func (r *CapabilityResolver) Connection(stewardID string) (connectionID string, declared bool) {
	if r == nil || r.conns == nil {
		return "", false
	}
	conn, ok := r.conns.Get(stewardID)
	if !ok || conn == nil {
		return "", false
	}
	return conn.ConnectionID, conn.CapabilitySnapshot().State == registry.CapabilityDeclared
}

// fromConnection resolves from the live connection this node holds. Its state is
// the authority; the durable record is never read, so a record left by an earlier
// connection cannot be taken for this one.
func (r *CapabilityResolver) fromConnection(ctx context.Context, conn *registry.StewardConnection) Resolution {
	snap := conn.CapabilitySnapshot()
	if snap.State == registry.CapabilityPending {
		if remaining := r.remaining(conn.ConnectedAt); remaining > 0 {
			timer := time.NewTimer(remaining)
			select {
			case <-conn.CapabilitiesSettled():
			case <-timer.C:
			case <-ctx.Done():
			}
			timer.Stop()
			snap = conn.CapabilitySnapshot()
		}
	}
	res := Resolution{ConnectionID: conn.ConnectionID, Undeclared: snap.State != registry.CapabilityDeclared}
	if snap.State == registry.CapabilityDeclared {
		res.Version = versionFor(snap.SigningPayloadVersions)
		res.CommandTypes = snap.CommandTypes
		return res
	}
	res.Version = controlplaneTypes.SigningPayloadV1 // floor, or still pending past the bound
	res.CommandTypes = controlplaneTypes.FloorProfile().CommandTypes
	return res
}

// fromRecord resolves from the durable record, for a steward whose connection
// another node holds (or that is not connected). No record is current, and
// carries no command types, so nothing is gated for it.
func (r *CapabilityResolver) fromRecord(ctx context.Context, stewardID string) Resolution {
	if r.store == nil {
		return Resolution{Version: controlplaneTypes.SigningPayloadV2}
	}
	floor := Resolution{
		Version:      controlplaneTypes.SigningPayloadV1,
		CommandTypes: controlplaneTypes.FloorProfile().CommandTypes,
	}
	firstRead := r.now()
	for {
		caps := r.readCapabilities(ctx, stewardID)
		if caps == nil {
			return Resolution{Version: controlplaneTypes.SigningPayloadV2}
		}
		switch caps.State {
		case business.StewardCapabilityDeclared:
			return Resolution{Version: versionFor(caps.SigningPayloadVersions), CommandTypes: caps.CommandTypes}
		case business.StewardCapabilityPending:
			// Pending: the record is the new connection's own, since a reset
			// replaces the previous one, so no earlier sets are carried over. Poll
			// it until the connection starts plus the resolve wait.
			started := caps.ConnectedAt
			if started.IsZero() {
				started = firstRead
			}
			if !r.pause(ctx, r.remaining(started)) {
				return floor
			}
		default: // floor
			return floor
		}
	}
}

// readCapabilities returns the steward's stored capability record, or nil when
// there is none or it cannot be read.
func (r *CapabilityResolver) readCapabilities(ctx context.Context, stewardID string) *business.StewardCapabilityRecord {
	rec, err := r.store.GetSteward(ctx, stewardID)
	if err != nil {
		if r.logger != nil {
			r.logger.Warn("capability record unreadable; signing for the steward as current",
				"steward_id", logging.SanitizeLogValue(stewardID),
				"error", logging.SanitizeLogValue(err.Error()))
		}
		return nil
	}
	if rec == nil {
		return nil
	}
	return rec.Capabilities
}

// pause sleeps one poll interval, never past remaining. It returns false when
// there is no time left or ctx ended, so the caller stops polling.
func (r *CapabilityResolver) pause(ctx context.Context, remaining time.Duration) bool {
	if remaining <= 0 || ctx.Err() != nil {
		return false
	}
	sleep := r.poll
	if sleep > remaining {
		sleep = remaining
	}
	timer := time.NewTimer(sleep)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// remaining is how much of the resolve wait is left for a connection that started
// at connectedAt. An unknown start counts as now.
func (r *CapabilityResolver) remaining(connectedAt time.Time) time.Duration {
	now := r.now()
	if connectedAt.IsZero() {
		connectedAt = now
	}
	return r.wait - now.Sub(connectedAt)
}

// versionFor picks the version for a declared set: v2 when it lists v2, else v1
// when it lists v1. A set that lists neither is current; the steward cannot be
// signed for either way.
func versionFor(declared []uint32) uint32 {
	profile := controlplaneTypes.CapabilityProfile{SigningPayloadVersions: declared}
	if profile.SupportsSigningPayloadVersion(controlplaneTypes.SigningPayloadV2) {
		return controlplaneTypes.SigningPayloadV2
	}
	if profile.SupportsSigningPayloadVersion(controlplaneTypes.SigningPayloadV1) {
		return controlplaneTypes.SigningPayloadV1
	}
	return controlplaneTypes.SigningPayloadV2
}
