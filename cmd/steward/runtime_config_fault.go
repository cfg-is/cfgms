// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package main

import (
	"strings"
	"sync/atomic"

	"github.com/cfgis/cfgms/features/steward/client"
	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/pkg/logging"
)

const (
	// runtimeConfigFaultComponent and runtimeConfigFaultCode identify the
	// heartbeat reason reported while the local steward config is rejected.
	runtimeConfigFaultComponent = "config"
	runtimeConfigFaultCode      = "config.invalid"

	// maxRuntimeConfigFaultMessage bounds the reason message carried on the heartbeat.
	maxRuntimeConfigFaultMessage = 200
)

// runtimeConfigFault is a rejected local configuration: the steward connects
// with the strictest settings and reports the rejection until the file is fixed.
type runtimeConfigFault struct {
	message string
}

// invalidConfigRuntimeConfig returns the strictest effective settings, used in
// place of a local configuration that was rejected. It is deliberately not the
// no-file default: a config that fails validation may have been corrupted on
// purpose, and the weaker default module trust mode would loosen a check that
// refuses today. Modules from extra publishers then fail and are reported.
// Remote terminal is turned off: its local `enabled: false` switch is read only
// from this file, so a rejected file must not silently turn it back on.
func invalidConfigRuntimeConfig() stewardconfig.StewardConfig {
	var cfg stewardconfig.StewardConfig
	remoteTerminalEnabled := false
	cfg.Steward.RemoteTerminal = stewardconfig.RemoteTerminalConfig{Enabled: &remoteTerminalEnabled}
	cfg.Steward.ModuleTrust = stewardconfig.ModuleTrustConfig{Mode: stewardconfig.ModuleTrustModeStrict}
	cfg.Steward.ScriptSigning = stewardconfig.ScriptSigningConfig{
		Policy:             stewardconfig.ScriptSigningPolicyOptional,
		RequireSignedAdhoc: true,
	}
	return cfg
}

// resolveConnectedRuntimeConfig loads the local config for one connect attempt.
// A rejected config (parse/validation failure, or a value the security profile
// forbids) is never used: it is logged, converted to the strict settings, and
// returned as a fault to report. It runs on every attempt, so fixing the file
// clears the fault on the next reconnect.
func resolveConnectedRuntimeConfig(publicBeta bool, logger logging.Logger) (stewardconfig.StewardConfig, *runtimeConfigFault) {
	cfg, err := loadConnectedRuntimeConfig(publicBeta)
	if err == nil {
		return cfg, nil
	}
	msg := logging.SanitizeLogValue(err.Error())
	if len(msg) > maxRuntimeConfigFaultMessage {
		msg = strings.ToValidUTF8(msg[:maxRuntimeConfigFaultMessage], "")
	}
	logger.Error("Local steward configuration rejected; connecting with strict settings",
		"operation", "runtime_config_invalid",
		"error", msg)
	return invalidConfigRuntimeConfig(), &runtimeConfigFault{message: msg}
}

// pendingRuntimeConfigFault holds the fault of the connect attempt in progress,
// because the client does not exist when the config is loaded. It is replaced
// on every attempt, so a fixed file leaves it nil.
var pendingRuntimeConfigFault atomic.Pointer[runtimeConfigFault]

// applyPendingRuntimeConfigFault reports the pending fault on tc (or clears a
// stale config reason) and returns the status the initial heartbeat carries.
// It runs before that heartbeat so the first heartbeat already has the reason.
func applyPendingRuntimeConfigFault(tc *client.TransportClient) string {
	f := pendingRuntimeConfigFault.Load()
	if f == nil {
		tc.ClearHealthReason(runtimeConfigFaultComponent)
		return "healthy"
	}
	tc.SetHealthReason(runtimeConfigFaultComponent, runtimeConfigFaultCode, f.message)
	return "degraded"
}
