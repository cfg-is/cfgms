// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package client

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/commands"
	"github.com/cfgis/cfgms/features/controller/service"
	stewardcommands "github.com/cfgis/cfgms/features/steward/commands"
	"github.com/cfgis/cfgms/pkg/cert"
	cpinterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/testutil"
	"github.com/cfgis/cfgms/pkg/transport/registry"
)

// stewardLoopbackCP is the controller's control plane for one steward: a command
// goes through the real steward command handler (signature check against the
// steward's trust set, then the real push_signing_cert handler), and the events the
// handler emits go back to the controller's publisher.
type stewardLoopbackCP struct {
	cpinterfaces.ControlPlaneProvider
	handler *stewardcommands.Handler
}

func (l *stewardLoopbackCP) SendCommand(ctx context.Context, sc *cpTypes.SignedCommand) error {
	// A command the steward rejects is dropped silently, as on a real stream.
	_ = l.handler.HandleCommand(ctx, sc)
	return nil
}

type loopbackSender struct{}

func (loopbackSender) SendMsg(interface{}) error { return nil }

// TestSigningMigration_RealStewardHandler_LegacyOnlyStewardEndsWithSharedOnly runs
// the controller's migration service against a steward driven by its real command
// handler and push_signing_cert handler. The steward starts trusting only a legacy
// node key; it must end trusting the shared certificate alone.
func TestSigningMigration_RealStewardHandler_LegacyOnlyStewardEndsWithSharedOnly(t *testing.T) {
	ctx := context.Background()
	const tenant = "cluster-ca-tenant"
	secrets := testutil.NewMemSecretStore()
	cursor, err := cert.NewFileSigningCursorStore(t.TempDir())
	require.NoError(t, err)
	acks, err := cert.NewFileSigningTrustAckStore(t.TempDir())
	require.NoError(t, err)

	build := func(dir string, withKeys bool) *cert.Manager {
		cfg := &cert.ManagerConfig{
			StoragePath:        dir,
			CAConfig:           &cert.CAConfig{Organization: "Test", Country: "US", ValidityDays: 365, KeySize: 2048},
			SigningCursorStore: cursor,
		}
		if withKeys {
			ks, kerr := cert.NewSecretStoreSigningKeyStore(secrets, tenant, "")
			require.NoError(t, kerr)
			cfg.SigningKeyStore = ks
		}
		m, merr := cert.NewManagerFromSecretStore(ctx, secrets, tenant, "cluster-ca", cfg)
		require.NoError(t, merr)
		return m
	}
	var nodes []*cert.Manager
	var legacyPEMs [][]byte
	var serials []string
	for i := 0; i < 2; i++ {
		dir := t.TempDir()
		legacy := build(dir, false)
		require.NoError(t, legacy.EnsureSigningCertificate(&cert.SigningCertConfig{CommonName: "cfgms-config-signer", ValidityDays: 365, KeySize: 2048}))
		local, lerr := legacy.GetCurrentCertForPurpose(cert.PurposeSigning)
		require.NoError(t, lerr)
		node := build(dir, true)
		res, ierr := node.ImportLocalSigningCertificates(ctx)
		require.NoError(t, ierr)
		require.True(t, res[0].Imported, res[0].Reason)
		nodes = append(nodes, node)
		legacyPEMs = append(legacyPEMs, local.CertificatePEM)
		serials = append(serials, local.SerialNumber)
	}
	_, created, err := nodes[0].ElectSharedSigningSerial(ctx, serials[0])
	require.NoError(t, err)
	require.True(t, created)

	// The steward trusts only node 1's legacy key and pins the cluster CA.
	const stewardID = "steward-real"
	c := minimalClientForPushTest(t)
	c.stewardID = stewardID
	caPEM, err := nodes[0].GetCACertificate()
	require.NoError(t, err)
	c.mu.Lock()
	c.caCertPEM = string(caPEM)
	c.signingCertPEMs = []string{string(legacyPEMs[1])}
	c.mu.Unlock()

	loop := &stewardLoopbackCP{}
	pub, err := commands.New(&commands.Config{ControlPlane: loop, Logger: logging.NewNoopLogger()})
	require.NoError(t, err)
	handler, err := stewardcommands.New(&stewardcommands.Config{
		StewardID: stewardID,
		Logger:    logging.NewNoopLogger(),
		Verifier:  c.buildVerifierOnDemand(),
		OnStatus: func(ctx context.Context, ev *cpTypes.Event) {
			_ = pub.HandleEventUpdate(ctx, ev)
		},
	})
	require.NoError(t, err)
	handler.RegisterHandler(cpTypes.CommandPushSigningCert, func(ctx context.Context, cmd *cpTypes.Command) error {
		return c.handlePushSigningCert(ctx, cmd)
	})
	loop.handler = handler
	// handlePushSigningCert refreshes this handler's verifier after each applied push.
	c.mu.Lock()
	c.commandHandler = handler
	c.mu.Unlock()

	reg := registry.NewRegistry()
	require.NoError(t, reg.Register(&registry.StewardConnection{StewardID: stewardID, Sender: loopbackSender{}}))

	svc := service.NewStewardSigningMigrationService(nodes[0], acks, logging.NewNoopLogger())
	svc.SetPublisher(pub)
	svc.SetConnectedStewards(reg)
	svc.SetTimings(500*time.Millisecond, time.Hour, time.Hour)
	svc.Start(ctx)
	t.Cleanup(svc.Stop)
	require.NoError(t, svc.OnConnect(ctx, stewardID))

	require.Eventually(t, func() bool {
		ack, aerr := acks.GetAck(ctx, stewardID, serials[0])
		if aerr != nil || ack == nil {
			return false
		}
		c.mu.RLock()
		defer c.mu.RUnlock()
		return len(c.signingCertPEMs) == 1 && c.signingTrustGen == 3
	}, 30*time.Second, 20*time.Millisecond, "steward confirmed and legacy certificate retired")

	c.mu.RLock()
	defer c.mu.RUnlock()
	require.Len(t, c.signingCertPEMs, 1)
	parsed, err := cert.ParseCertificateFromPEM([]byte(c.signingCertPEMs[0]))
	require.NoError(t, err)
	assert.Equal(t, serials[0], parsed.SerialNumber.String(), "the steward trusts the shared certificate only")
}
