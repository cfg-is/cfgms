// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package fleet

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// TamperStateSender delivers the data-free TamperState signal to a connected
// steward. The control plane provider satisfies it.
type TamperStateSender interface {
	SendTamperState(ctx context.Context, stewardID string, locked bool) error
}

// Lockdown is the single place that decides whether a steward is locked down,
// and the single place that tells a steward its current tamper state.
//
// The decision is read from the steward store on every call. Nothing is cached,
// so there is no stale window and another controller node sees a transition on
// its next call. Consumers (the command gate, the data-plane gate, the reporting
// gate) take it through a one-method interface declared on their side.
type Lockdown struct {
	store  business.StewardStore
	logger logging.Logger
	sender atomic.Pointer[TamperStateSender]
}

// NewLockdown builds the predicate over the durable steward store.
func NewLockdown(store business.StewardStore, logger logging.Logger) *Lockdown {
	return &Lockdown{store: store, logger: logger}
}

// SetSender binds the control plane that carries TamperState. The sender is
// built after the connect hooks, so it is bound late. Until it is set, sends fail.
func (l *Lockdown) SetSender(s TamperStateSender) {
	if s == nil {
		l.sender.Store(nil)
		return
	}
	l.sender.Store(&s)
}

// IsLockedDown reports whether the steward is locked down. It fails closed: any
// failure to establish the status (no store, unknown steward, store error)
// returns true together with the error.
func (l *Lockdown) IsLockedDown(ctx context.Context, stewardID string) (bool, error) {
	if l == nil || l.store == nil {
		return true, errors.New("steward store unavailable")
	}
	record, err := l.store.GetSteward(ctx, stewardID)
	if err != nil {
		return true, fmt.Errorf("read steward status: %w", err)
	}
	if record == nil {
		return true, errors.New("steward record missing")
	}
	return record.Status == business.StewardStatusTampered, nil
}

// OnConnect sends the steward its current tamper state as its control stream
// registers. A lookup error is sent as locked. It satisfies the provider's
// on-connect hook; an error is logged by the caller and does not close the stream.
func (l *Lockdown) OnConnect(ctx context.Context, stewardID string) error {
	return l.send(ctx, stewardID)
}

// NotifyTransition re-sends the tamper state to a steward that is connected now.
// The tamper transition calls it so a live steward need not reconnect to learn.
func (l *Lockdown) NotifyTransition(ctx context.Context, stewardID string) error {
	return l.send(ctx, stewardID)
}

func (l *Lockdown) send(ctx context.Context, stewardID string) error {
	sp := l.sender.Load()
	if sp == nil {
		return errors.New("tamper state sender not bound")
	}
	locked, err := l.IsLockedDown(ctx, stewardID)
	if err != nil && l.logger != nil {
		l.logger.Warn("tamper state lookup failed, reporting locked",
			"steward_id", logging.SanitizeLogValue(stewardID),
			"error", logging.SanitizeLogValue(err.Error()))
	}
	if sendErr := (*sp).SendTamperState(ctx, stewardID, locked); sendErr != nil {
		return fmt.Errorf("send tamper state: %w", sendErr)
	}
	return nil
}
