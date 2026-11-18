// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package service

import (
	"context"
	"sort"

	"github.com/cfgis/cfgms/pkg/logging"
)

// StewardRegistryConnectHook upserts a steward into the admin registry on every
// authenticated (re)connect (Issue #2008). It implements the gRPC
// StewardOnConnectHook contract (OnConnect(ctx, stewardID) error).
//
// This is the PRIMARY fix for the cert-reuse reconnect gap: a steward's normal
// reconnect reuses its existing certificate and returns WITHOUT calling HTTP
// /register, so the registry's only live-path writer (RegisterSteward) never
// runs. The connect hook fires on every successful ControlChannel registration
// with the mTLS-authenticated CN, so list/status/exec see the steward again
// without waiting for a controller restart.
//
// Tenant is resolved authoritatively inside EnsureSteward from durable storage
// by stewardID; the hook only carries the mTLS CN and never supplies a tenant,
// so cross-tenant exec scoping cannot be influenced by a steward-supplied value.
type StewardRegistryConnectHook struct {
	controllerService *ControllerService
	logger            logging.Logger
}

// NewStewardRegistryConnectHook constructs the registry connect hook.
func NewStewardRegistryConnectHook(controllerService *ControllerService, logger logging.Logger) *StewardRegistryConnectHook {
	return &StewardRegistryConnectHook{
		controllerService: controllerService,
		logger:            logger,
	}
}

// OnConnect implements the StewardOnConnectHook interface. stewardID is the
// mTLS-authenticated CN of the connecting steward. EnsureSteward upserts the
// registry entry and resolves the tenant from durable storage; the empty tenant
// passed here is only a fallback EnsureSteward ignores when a durable record
// exists. Fail-open: EnsureSteward never errors, so the stream is never refused.
func (h *StewardRegistryConnectHook) OnConnect(_ context.Context, stewardID string) error {
	if h == nil || h.controllerService == nil {
		return nil
	}
	h.controllerService.EnsureSteward(stewardID, "", "active")
	return nil
}

// CompositeOnConnectHook chains multiple StewardOnConnectHook implementations so
// the single hook slot on the gRPC provider can drive several independent
// on-connect concerns (e.g. signing-cert refresh AND admin-registry upsert).
// Hooks run in order; one hook's error does not prevent later hooks from
// running, and all errors are joined into the returned error (logged fail-open
// by the provider).
type CompositeOnConnectHook struct {
	hooks  []onConnectHook
	logger logging.Logger
}

// onConnectHook is the minimal contract the composite chains. It matches the
// gRPC StewardOnConnectHook interface without importing the provider package
// (avoids an import cycle: the provider already depends on this package's hooks
// only structurally, via the interface).
type onConnectHook interface {
	OnConnect(ctx context.Context, stewardID string) error
}

// ConnectHookSlot names a place in the on-connect chain.
type ConnectHookSlot string

// The on-connect hooks, by what they do. The first five never sign or send a
// command; the last four do, and a command they send waits (bounded) for the
// connection's capability declaration before it is signed.
const (
	SlotRegistry            ConnectHookSlot = "registry"
	SlotCompletionReconcile ConnectHookSlot = "completion_reconciler"
	SlotRouting             ConnectHookSlot = "routing"
	SlotLockdown            ConnectHookSlot = "lockdown"
	SlotRepair              ConnectHookSlot = "repair"
	SlotSigningRotation     ConnectHookSlot = "signing_rotation"
	SlotMigration           ConnectHookSlot = "migration"
	SlotDrain               ConnectHookSlot = "drain"
	SlotTransportAddress    ConnectHookSlot = "transport_address"
)

// connectHookOrder is the order the chain runs its hooks in. The chain is
// sequential, so a hook that waits delays every hook behind it: the hooks that do
// not sign run first, and the hooks that sign (and so may wait on the connection's
// capability declaration at the point of signing) run last. Lockdown runs before
// the signing push, never after it.
func connectHookOrder() []ConnectHookSlot {
	return []ConnectHookSlot{
		SlotRegistry, SlotCompletionReconcile, SlotRouting, SlotLockdown, SlotRepair,
		SlotSigningRotation, SlotMigration, SlotDrain, SlotTransportAddress,
	}
}

// signs reports whether the hook in the slot signs and sends a command.
func (s ConnectHookSlot) signs() bool {
	switch s {
	case SlotSigningRotation, SlotMigration, SlotDrain, SlotTransportAddress:
		return true
	}
	return false
}

// SlottedConnectHook is a hook with the slot it occupies in the chain.
type SlottedConnectHook struct {
	Slot ConnectHookSlot
	Hook interface {
		OnConnect(ctx context.Context, stewardID string) error
	}
}

// NewOrderedCompositeOnConnectHook builds a composite that runs the given hooks in
// connectHookOrder, whatever order they are passed in. A nil Hook is skipped. A
// hook whose slot is not in the order runs last, after the signing hooks, in the
// order it was given.
func NewOrderedCompositeOnConnectHook(logger logging.Logger, hooks ...SlottedConnectHook) *CompositeOnConnectHook {
	rank := make(map[ConnectHookSlot]int)
	for i, slot := range connectHookOrder() {
		rank[slot] = i
	}
	ordered := make([]SlottedConnectHook, 0, len(hooks))
	for _, h := range hooks {
		if h.Hook != nil {
			ordered = append(ordered, h)
		}
	}
	position := func(h SlottedConnectHook) int {
		if r, ok := rank[h.Slot]; ok {
			return r
		}
		return len(rank)
	}
	sort.SliceStable(ordered, func(i, j int) bool { return position(ordered[i]) < position(ordered[j]) })
	chain := make([]onConnectHook, 0, len(ordered))
	for _, h := range ordered {
		chain = append(chain, h.Hook)
	}
	return NewCompositeOnConnectHook(logger, chain...)
}

// NewCompositeOnConnectHook builds a composite from the given hooks, skipping
// nil entries so callers can pass optionally-constructed hooks directly.
func NewCompositeOnConnectHook(logger logging.Logger, hooks ...onConnectHook) *CompositeOnConnectHook {
	filtered := make([]onConnectHook, 0, len(hooks))
	for _, h := range hooks {
		if h == nil {
			continue
		}
		filtered = append(filtered, h)
	}
	return &CompositeOnConnectHook{hooks: filtered, logger: logger}
}

// OnConnect runs every chained hook. A hook error is logged and the chain
// continues, so an admin-registry upsert is not skipped because a signing-cert
// push failed (or vice versa). The first non-nil error is returned for the
// provider's fail-open logging.
func (c *CompositeOnConnectHook) OnConnect(ctx context.Context, stewardID string) error {
	var firstErr error
	for _, h := range c.hooks {
		if err := h.OnConnect(ctx, stewardID); err != nil {
			if c.logger != nil {
				c.logger.Warn("on-connect hook in chain errored, continuing",
					"steward_id", logging.SanitizeLogValue(stewardID), "error", err)
			}
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}
