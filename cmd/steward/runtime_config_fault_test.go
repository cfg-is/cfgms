// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package main

import (
	"context"
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	stewardtypes "github.com/cfgis/cfgms/features/config/stewardtypes"
	"github.com/cfgis/cfgms/features/steward/client"
	"github.com/cfgis/cfgms/pkg/cert"
	grpcCP "github.com/cfgis/cfgms/pkg/controlplane/providers/grpc"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	quictransport "github.com/cfgis/cfgms/pkg/transport/quic"
	"github.com/cfgis/cfgms/pkg/transport/registry"
)

func assertStrictRuntimeConfig(t *testing.T, mode stewardtypes.ModuleTrustMode, requireSigned bool, publishers []string) {
	t.Helper()
	assert.Equal(t, stewardtypes.ModuleTrustModeStrict, mode)
	assert.True(t, requireSigned)
	assert.Empty(t, publishers)
}

func TestInvalidConfigRuntimeConfig_IsStrictest(t *testing.T) {
	cfg := invalidConfigRuntimeConfig()
	assertStrictRuntimeConfig(t, cfg.Steward.ModuleTrust.Mode, cfg.Steward.ScriptSigning.RequireSignedAdhoc, cfg.Steward.ModuleTrust.AdditionalPublishers)
}

func TestInvalidConfigRuntimeConfig_DisablesRemoteTerminal(t *testing.T) {
	cfg := invalidConfigRuntimeConfig()
	require.NotNil(t, cfg.Steward.RemoteTerminal.Enabled, "an absent value means enabled")
	assert.False(t, *cfg.Steward.RemoteTerminal.Enabled)
	assert.False(t, cfg.Steward.RemoteTerminal.IsEnabled())
}

func TestResolveConnectedRuntimeConfig_RejectedConfigDisablesRemoteTerminal(t *testing.T) {
	writeLocalConfig(t, "steward:\n  id: s1\n  remote_terminal:\n    enabled: false\n  logging:\n    level: bogus\nresources: []\n")
	cfg, fault := resolveConnectedRuntimeConfig(false, logging.NewLogger("error"))
	require.NotNil(t, fault)
	assert.False(t, cfg.Steward.RemoteTerminal.IsEnabled(), "a rejected config must not turn remote terminal back on")
}

func TestResolveConnectedRuntimeConfig_RejectedConfigYieldsStrictNotDeclared(t *testing.T) {
	bodies := map[string]string{
		"bypass attempt":       "steward:\n  id: s1\n  module_trust:\n    mode: bypass\n    additional_publishers: [evil]\nresources: []\n",
		"strict but invalid":   "steward:\n  id: s1\n  module_trust:\n    mode: strict\n  logging:\n    level: bogus\nresources: []\n",
		"unparsable":           "steward: [unterminated\n\t:::",
		"controller but wrong": "steward:\n  id: s1\n  module_trust:\n    mode: controller\n  logging:\n    level: bogus\nresources: []\n",
	}
	if stewardtypes.ModuleTrustBypassAllowed() {
		delete(bodies, "bypass attempt")
	}
	for name, body := range bodies {
		for _, publicBeta := range []bool{false, true} {
			t.Run(name, func(t *testing.T) {
				writeLocalConfig(t, body)
				cfg, fault := resolveConnectedRuntimeConfig(publicBeta, logging.NewLogger("error"))
				require.NotNil(t, fault)
				assert.NotEmpty(t, fault.message)
				assertStrictRuntimeConfig(t, cfg.Steward.ModuleTrust.Mode, cfg.Steward.ScriptSigning.RequireSignedAdhoc, cfg.Steward.ModuleTrust.AdditionalPublishers)
				assert.Empty(t, cfg.Steward.ID, "no field of a rejected config may reach the runtime config")
			})
		}
	}
}

func TestResolveConnectedRuntimeConfig_PublicBetaUnsetAdhocIsStrictWithReason(t *testing.T) {
	writeLocalConfig(t, "steward:\n  id: s1\nresources: []\n")
	cfg, fault := resolveConnectedRuntimeConfig(true, logging.NewLogger("error"))
	require.NotNil(t, fault)
	assert.True(t, cfg.Steward.ScriptSigning.RequireSignedAdhoc)
	assert.Equal(t, stewardtypes.ModuleTrustModeStrict, cfg.Steward.ModuleTrust.Mode)
	assert.Empty(t, cfg.Steward.ID)
}

func TestResolveConnectedRuntimeConfig_FixedFileClearsFault(t *testing.T) {
	writeLocalConfig(t, "steward: [unterminated\n\t:::")
	host, err := os.Hostname()
	require.NoError(t, err)
	_, fault := resolveConnectedRuntimeConfig(false, logging.NewLogger("error"))
	require.NotNil(t, fault)

	require.NoError(t, os.WriteFile(filepath.Join(".", host+".cfg"), []byte("steward:\n  id: s1\nresources: []\n"), 0o600))
	cfg, fault := resolveConnectedRuntimeConfig(false, logging.NewLogger("error"))
	assert.Nil(t, fault, "fixing the file clears the fault on the next attempt")
	assert.Equal(t, "s1", cfg.Steward.ID)
}

// TestRegisterAndConnect_CorruptConfigStillConnectsDegraded connects to a real
// control plane with a corrupt local config and checks the heartbeat reports
// config.invalid, then that a fixed file connects with no such reason.
func TestRegisterAndConnect_CorruptConfigStillConnectsDegraded(t *testing.T) {
	f := newStoredIdentityFixture(t, "placeholder")

	serverCert := f.serverCert(t)
	serverTLS, err := cert.CreateServerTLSConfig(serverCert.CertificatePEM, serverCert.PrivateKeyPEM, []byte(f.caPEM), tls.VersionTLS13)
	require.NoError(t, err)
	serverTLS.NextProtos = []string{quictransport.ALPNProtocol}
	server := grpcCP.New(grpcCP.ModeServer)
	require.NoError(t, server.Initialize(context.Background(), map[string]interface{}{
		"mode": "server", "addr": "127.0.0.1:0", "tls_config": serverTLS, "registry": registry.NewRegistry(),
	}))
	require.NoError(t, server.Start(context.Background()))
	t.Cleanup(server.ForceStop)
	got := make(chan *cpTypes.Heartbeat, 4)
	require.NoError(t, server.SubscribeHeartbeats(context.Background(), func(_ context.Context, hb *cpTypes.Heartbeat) error {
		got <- hb
		return nil
	}))
	id, err := loadIdentity(f.certStoreDir)
	require.NoError(t, err)
	id.TransportAddress = server.ListenAddr()
	require.NoError(t, saveIdentity(f.certStoreDir, *id))

	srv, httpsCAPEM, _ := registrationCounter(t)
	writeLocalConfig(t, "steward: [unterminated\n\t:::")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	tc, cerr := registerAndConnect(ctx, "one-time-token", srv.URL, trustSourceInstallPinned, httpsCAPEM, nil, false, logging.NewLogger("error"))
	require.NoError(t, cerr, "a bad local config must not block connecting")
	require.NotNil(t, tc)
	t.Cleanup(func() { _ = tc.Disconnect(context.Background()) })

	// The initial heartbeat is sent inside the connect sequence.
	select {
	case hb := <-got:
		assert.Equal(t, cpTypes.StatusDegraded, hb.Status)
		require.Len(t, hb.Reasons, 1)
		assert.Equal(t, "config", hb.Reasons[0].Component)
		assert.Equal(t, "config.invalid", hb.Reasons[0].Code)
		assert.NotEmpty(t, hb.Reasons[0].Message)
	case <-time.After(5 * time.Second):
		t.Fatal("heartbeat not received")
	}
}

func TestApplyPendingRuntimeConfigFault_SetsThenClears(t *testing.T) {
	t.Cleanup(func() { pendingRuntimeConfigFault.Store(nil) })
	tc := &client.TransportClient{}

	pendingRuntimeConfigFault.Store(&runtimeConfigFault{message: "bad"})
	assert.Equal(t, "degraded", applyPendingRuntimeConfigFault(tc))
	require.Len(t, tc.HealthReasons(), 1)
	assert.Equal(t, "config.invalid", tc.HealthReasons()[0].Code)

	pendingRuntimeConfigFault.Store(nil)
	assert.Equal(t, "healthy", applyPendingRuntimeConfigFault(tc))
	assert.Empty(t, tc.HealthReasons(), "a fixed config clears the reason")
}
