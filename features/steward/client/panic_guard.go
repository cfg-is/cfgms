// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package client

import (
	"errors"
	"fmt"

	"github.com/cfgis/cfgms/pkg/logging"
)

// healthReasonCodePanic is the reason code recorded when a component recovered
// from a panic.
const healthReasonCodePanic = "panic"

// Component names under which a recovered panic is recorded as a health reason.
const (
	componentHeartbeat     = "heartbeat"
	componentConvergence   = "convergence"
	componentDNARefresh    = "dna_refresh"
	componentConfigRefetch = "config_refetch"
	componentOnConnectSync = "on_connect_sync"
	componentCommandHandle = "command_handler"
	componentEventEmitter  = "event_emitter"
	componentTelemetry     = "telemetry_stream"
)

// errPanicRecovered is returned by recoverToError when fn panicked. It is a
// fixed string: the panic value is never part of it.
var errPanicRecovered = errors.New("recovered from a panic")

// panicReasonMessage is the controller-visible reason text for a recovered
// panic. It is built from the component name only; the recovered value never
// reaches it.
func panicReasonMessage(component string) string {
	return component + " recovered from a panic"
}

// recordPanic logs a recovered panic (value and stack sanitized) and records the
// health reason through set.
func recordPanic(logger logging.Logger, component string, recovered interface{}, set func(component, code, message string)) {
	if logger != nil {
		logger.Error("Recovered from panic",
			"component", component,
			"panic", logging.SanitizeLogValue(fmt.Sprint(recovered)))
	}
	if set != nil {
		set(component, healthReasonCodePanic, panicReasonMessage(component))
	}
}

// guard runs one iteration of a long-running loop under recover. A panic is
// logged, recorded as a health reason for component and swallowed so the caller
// loop keeps running; a clean return clears a previously recorded panic reason
// for component. It reports whether fn returned normally.
//
// guard wraps an iteration of work, never a verification call: a panic inside
// verification must reject, not continue (see commands.Handler.HandleCommand).
// runtime.Goexit is not intercepted: recover returns nil for it.
func (c *TransportClient) guard(component string, fn func()) (completed bool) {
	defer func() {
		if r := recover(); r != nil {
			recordPanic(c.logger, component, r, c.SetHealthReason)
			completed = false
		}
	}()
	fn()
	c.healthReasonRegistry().ClearIfCode(component, healthReasonCodePanic)
	return true
}

// recoverToError runs fn and converts a panic into errPanicRecovered after
// logging it and calling onPanic, so a retry loop around fn backs off and tries
// again instead of ending the process.
func recoverToError(logger logging.Logger, component string, onPanic func(component string), fn func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			recordPanic(logger, component, r, nil)
			if onPanic != nil {
				onPanic(component)
			}
			err = errPanicRecovered
		}
	}()
	return fn()
}

// recordComponentPanic records the fixed-string panic reason for component. It
// is the OnPanic hook handed to components that own their own recover.
func (c *TransportClient) recordComponentPanic(component string) {
	c.SetHealthReason(component, healthReasonCodePanic, panicReasonMessage(component))
}
