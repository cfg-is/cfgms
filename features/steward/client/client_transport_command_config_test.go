// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package client exercises command-authentication config wiring in TransportClient.
package client

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/steward/commands"
	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
)

// TestNewTransportClient_StoresCommandAuthFields verifies that
// SignedCommandReplayWindow and SignedCommandMaxParamsBytes from TransportConfig
// are stored on the TransportClient so that setupCommandHandler can pass them
// to commands.New (Story #919 fix for PR #927).
func TestNewTransportClient_StoresCommandAuthFields(t *testing.T) {
	replayWindow := 10 * time.Minute
	maxParams := 128 * 1024

	c, err := NewTransportClient(&TransportConfig{
		ControllerURL:               "localhost:4433",
		SignedCommandReplayWindow:   replayWindow,
		SignedCommandMaxParamsBytes: maxParams,
		Logger:                      newTestLogger(t),
	})
	require.NoError(t, err)
	assert.Equal(t, replayWindow, c.commandReplayWindow,
		"commandReplayWindow must be stored from TransportConfig.SignedCommandReplayWindow")
	assert.Equal(t, maxParams, c.commandMaxParamsBytes,
		"commandMaxParamsBytes must be stored from TransportConfig.SignedCommandMaxParamsBytes")
}

// TestNewTransportClient_ZeroCommandAuthFieldsArePreserved verifies that when
// SignedCommandReplayWindow and SignedCommandMaxParamsBytes are zero (unset),
// those zero values are stored unchanged so that commands.New can apply its own
// defaults (5 min / 64 KiB) rather than having the caller silently override them.
func TestNewTransportClient_ZeroCommandAuthFieldsArePreserved(t *testing.T) {
	c, err := NewTransportClient(&TransportConfig{
		ControllerURL: "localhost:4433",
		Logger:        newTestLogger(t),
	})
	require.NoError(t, err)
	assert.Equal(t, time.Duration(0), c.commandReplayWindow,
		"zero SignedCommandReplayWindow must be stored as-is so commands.Handler applies its default")
	assert.Equal(t, 0, c.commandMaxParamsBytes,
		"zero SignedCommandMaxParamsBytes must be stored as-is so commands.Handler applies its default")
}

// TestNewTransportClient_StoresScriptSigningConfig verifies that the
// ScriptSigning policy from TransportConfig is stored on the TransportClient so
// setupCommandHandler can wire it into commands.New (Issue #1671 — controller-
// connected production wiring gap from PR #1713 review).
func TestNewTransportClient_StoresScriptSigningConfig(t *testing.T) {
	signing := stewardconfig.ScriptSigningConfig{
		Policy:             stewardconfig.ScriptSigningPolicyRequired,
		TrustMode:          stewardconfig.TrustModeTrustedKeys,
		RequireSignedAdhoc: true,
		TrustedKeys: []stewardconfig.TrustedKeyRef{
			{Name: "ci-key", Thumbprint: "abc123"},
		},
	}

	c, err := NewTransportClient(&TransportConfig{
		ControllerURL: "localhost:4433",
		ScriptSigning: signing,
		Logger:        newTestLogger(t),
	})
	require.NoError(t, err)
	assert.Equal(t, signing, c.scriptSigning,
		"scriptSigning must be stored from TransportConfig.ScriptSigning")
}

// TestSetupCommandHandler_EnforcesRequireSignedAdhoc verifies that the command
// handler built by setupCommandHandler actually enforces the wired script
// signing policy. Before the PR #1713 review fix, setupCommandHandler created
// commands.New without SigningConfig/RequireSignedAdhoc, so an unsigned ad-hoc
// CommandExecuteScript was accepted in controller-connected deployments even
// when the steward config set require_signed_adhoc: true.
func TestSetupCommandHandler_EnforcesRequireSignedAdhoc(t *testing.T) {
	const stewardID = "steward-sig-test"

	unsignedExecuteScript := func(id string) *cpTypes.SignedCommand {
		return &cpTypes.SignedCommand{
			Command: cpTypes.Command{
				ID:        id,
				Type:      cpTypes.CommandExecuteScript,
				StewardID: stewardID,
				Timestamp: time.Now(),
				Params: map[string]interface{}{
					"script_content": base64.StdEncoding.EncodeToString([]byte("echo wired")),
					"shell":          "bash",
					"execution_id":   id,
					// No signature_* params — an unsigned ad-hoc command.
				},
			},
		}
	}

	t.Run("require_signed_adhoc true rejects unsigned ad-hoc command", func(t *testing.T) {
		c, err := NewTransportClient(&TransportConfig{
			ControllerURL: "localhost:4433",
			ScriptSigning: stewardconfig.ScriptSigningConfig{
				Policy:             stewardconfig.ScriptSigningPolicyRequired,
				RequireSignedAdhoc: true,
			},
			Logger: newTestLogger(t),
		})
		require.NoError(t, err)

		handler, err := c.setupCommandHandler(context.Background(), stewardID)
		require.NoError(t, err)
		t.Cleanup(handler.Wait)

		err = handler.HandleCommand(context.Background(), unsignedExecuteScript("sig-wired-reject"))
		require.ErrorIs(t, err, commands.ErrUnauthenticatedCommand,
			"unsigned ad-hoc command must be rejected when require_signed_adhoc is wired true")
	})

	t.Run("require_signed_adhoc false accepts unsigned ad-hoc command", func(t *testing.T) {
		c, err := NewTransportClient(&TransportConfig{
			ControllerURL: "localhost:4433",
			ScriptSigning: stewardconfig.ScriptSigningConfig{
				Policy:             stewardconfig.ScriptSigningPolicyOptional,
				RequireSignedAdhoc: false,
			},
			Logger: newTestLogger(t),
		})
		require.NoError(t, err)

		handler, err := c.setupCommandHandler(context.Background(), stewardID)
		require.NoError(t, err)
		t.Cleanup(handler.Wait)

		err = handler.HandleCommand(context.Background(), unsignedExecuteScript("sig-wired-accept"))
		assert.NotErrorIs(t, err, commands.ErrUnauthenticatedCommand,
			"unsigned ad-hoc command must pass signature preflight when require_signed_adhoc is false")
	})

	t.Run("invalid controller CA PEM degrades gracefully and still enforces", func(t *testing.T) {
		// An unparseable CACertPEM leaves controllerCARoots nil — setupCommandHandler
		// must not fail, and require_signed_adhoc enforcement must still be active.
		c, err := NewTransportClient(&TransportConfig{
			ControllerURL: "localhost:4433",
			CACertPEM:     "-----BEGIN CERTIFICATE-----\nnot-valid-base64\n-----END CERTIFICATE-----",
			ScriptSigning: stewardconfig.ScriptSigningConfig{
				Policy:             stewardconfig.ScriptSigningPolicyRequired,
				RequireSignedAdhoc: true,
			},
			Logger: newTestLogger(t),
		})
		require.NoError(t, err)

		handler, err := c.setupCommandHandler(context.Background(), stewardID)
		require.NoError(t, err, "setupCommandHandler must tolerate an unparseable controller CA PEM")
		t.Cleanup(handler.Wait)

		err = handler.HandleCommand(context.Background(), unsignedExecuteScript("sig-wired-badca"))
		require.ErrorIs(t, err, commands.ErrUnauthenticatedCommand,
			"require_signed_adhoc enforcement must remain active even when CA roots cannot be built")
	})
}
