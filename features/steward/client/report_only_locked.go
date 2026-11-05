// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package client

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/features/config/stewardtypes"
	"github.com/cfgis/cfgms/features/steward/commands"
	"github.com/cfgis/cfgms/features/steward/operatorroster"
	controlplaneInterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
)

// Locked tools on the report-only link.
//
// A locked steward still runs three operator-signed action kinds: an inline
// script, a structured steward action and a remote terminal. They are verified
// by a commands.LockedTrust that rests only on a root whose fingerprint is baked
// into the binary (see features/steward/commands/locked_trust.go). Nothing here
// reads trust material from the data folder: the revocation manifest is fetched
// over the link but verified against the baked root alone, and the terminal
// stays on the control-plane connection whose server certificate the locked
// handler checks per command. A change that moves the terminal elsewhere must
// repeat that check.

// lockedToolsMessages are the fixed health-reason messages of the locked-tools codes.
var lockedToolsMessages = map[string]string{
	cpTypes.ReasonCodeLockedNoBakedRoot:        "no controller root is baked into this binary; operator actions are refused while locked",
	cpTypes.ReasonCodeLockedBakedRootMalformed: "the baked controller root list is malformed; operator actions are refused while locked",
	cpTypes.ReasonCodeLockedRootMismatch:       "a command chain does not end in a baked controller root; the command was refused",
	cpTypes.ReasonCodeLockedLinkNotAnchored:    "the controller link is not anchored to the command's baked root; the command was refused",
	cpTypes.ReasonCodeLockedRevocationStale:    "no fresh revocation manifest verified against the baked root; operator actions are refused",
}

// LockedToolsConfig enables operator actions on a report-only link.
type LockedToolsConfig struct {
	// MatchesBakedRoot reports whether a certificate is a self-signed CA whose
	// fingerprint is in the baked list. Required.
	MatchesBakedRoot func(*x509.Certificate) bool

	// BakedRootReason returns "" when the baked list is usable, else the reason
	// code. Nil means usable.
	BakedRootReason func() string

	// DisableRemoteTerminal refuses open_terminal. Config can only restrict.
	DisableRemoteTerminal bool

	// RevocationRefreshInterval overrides the manifest refresh cadence (tests).
	RevocationRefreshInterval time.Duration
}

// lazyEmitter forwards to the client's event emitter, which the report-only
// connect starts after the locked handler is built.
type lazyEmitter struct{ c *TransportClient }

func (l lazyEmitter) Enqueue(entry *transportpb.LogEntry) {
	l.c.mu.RLock()
	e := l.c.eventEmitter
	l.c.mu.RUnlock()
	if e != nil {
		e.Enqueue(entry)
	}
}

// EnableLockedTools builds the locked-trust command handler and routes the
// report-only link's Command kind to it. Call it before Connect so a command
// sent on connect is seen. Without it a report-only link drops every command.
func (c *TransportClient) EnableLockedTools(cfg LockedToolsConfig) error {
	if !c.reportOnly.Load() {
		return fmt.Errorf("locked tools need a report-only link")
	}
	interval := cfg.RevocationRefreshInterval
	if interval <= 0 {
		interval = revocationManifestRefreshInterval
	}
	var trust *commands.LockedTrust
	trust, err := commands.NewLockedTrust(commands.LockedTrustConfig{
		MatchesBakedRoot:          cfg.MatchesBakedRoot,
		BakedRootReason:           cfg.BakedRootReason,
		RevocationRefreshInterval: interval,
		OnReason:                  c.setLockedToolsReason,
		RefreshRevocation: func(ctx context.Context) error {
			return c.refreshLockedRevocation(ctx, trust)
		},
	})
	if err != nil {
		return err
	}

	c.mu.RLock()
	stewardID := c.stewardID
	c.mu.RUnlock()
	handler, err := commands.New(&commands.Config{
		StewardID: stewardID,
		OnStatus: func(ctx context.Context, event *cpTypes.Event) {
			if err := c.publishEventWithQueue(ctx, event); err != nil {
				c.logger.Error("Failed to publish status event", "error", logging.SanitizeLogValue(err.Error()))
			}
		},
		Logger:         c.logger,
		OnPanic:        c.recordComponentPanic,
		ReplayWindow:   c.commandReplayWindow,
		MaxParamsBytes: c.commandMaxParamsBytes,
		TenantID:       c.GetTenantID(),
		EventEmitter:   lazyEmitter{c: c},
		Locked:         trust,
	})
	if err != nil {
		return fmt.Errorf("failed to create locked command handler: %w", err)
	}
	// Only the three accepted kinds have handlers. The terminal dials over the
	// control-plane connection the per-command link check covers.
	handler.RegisterExecuteScriptHandler()
	handler.RegisterOpenTerminalHandler(&terminalDialer{c: c})
	handler.RegisterStewardActionHandler()
	if cfg.DisableRemoteTerminal || c.remoteTerminalDisabled {
		handler.DisableRemoteTerminal()
	}

	c.reportOnlyMu.Lock()
	c.lockedTrust = trust
	c.reportOnlyMu.Unlock()
	c.SetLockedCommandHandler(func(ctx context.Context, sc *cpTypes.SignedCommand, peer controlplaneInterfaces.PeerChain) error {
		return c.receiveCommand(ctx, sc, func(ctx context.Context, sc *cpTypes.SignedCommand) error {
			return handler.HandleLockedCommand(ctx, sc, peer)
		})
	})
	trust.ReportBakedState()
	return nil
}

// setLockedToolsReason records (or, for "", clears) the locked-tools health reason.
func (c *TransportClient) setLockedToolsReason(code string) {
	if code == "" {
		c.ClearHealthReason(cpTypes.HealthComponentLockedTools)
		return
	}
	c.SetHealthReason(cpTypes.HealthComponentLockedTools, code, lockedToolsMessages[code])
}

// refreshLockedRevocation fetches the revocation manifest and verifies it
// against the baked root only. The transport carries it; the signature decides.
func (c *TransportClient) refreshLockedRevocation(ctx context.Context, trust *commands.LockedTrust) error {
	if trust == nil {
		return errors.New("locked trust not ready")
	}
	url, err := operatorroster.BuildManifestURL(c.controllerHTTPSBaseURL)
	if err != nil {
		return err
	}
	httpClient, err := c.buildHTTPClientForUpgrade()
	if err != nil {
		return err
	}
	return trust.Revocation().FetchAndVerify(ctx, httpClient, url, stewardtypes.ModuleTrustModeStrict)
}

// startLockedRevocationRefresh runs the periodic manifest refresh for the life
// of ctx. The first fetch before any command has no root to verify with and
// fails; the on-demand refresh in the command path covers that gap.
func (c *TransportClient) startLockedRevocationRefresh(ctx context.Context) {
	c.reportOnlyMu.Lock()
	trust := c.lockedTrust
	c.reportOnlyMu.Unlock()
	if trust == nil {
		return
	}
	url, err := operatorroster.BuildManifestURL(c.controllerHTTPSBaseURL)
	if err != nil {
		c.logger.Warn("Revocation manifest fetch disabled: cannot build manifest URL",
			"error", logging.SanitizeLogValue(err.Error()))
		return
	}
	httpClient, err := c.buildHTTPClientForUpgrade()
	if err != nil {
		c.logger.Warn("Revocation manifest fetch disabled: cannot build mTLS HTTP client",
			"error", logging.SanitizeLogValue(err.Error()))
		return
	}
	go trust.Revocation().RunPeriodicRefresh(ctx, httpClient, url, stewardtypes.ModuleTrustModeStrict,
		trust.RevocationRefreshInterval(), func(err error) {
			c.logger.Debug("Locked revocation manifest fetch failed",
				"error", logging.SanitizeLogValue(err.Error()))
		})
}
