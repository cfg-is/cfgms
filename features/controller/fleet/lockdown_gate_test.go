// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package fleet_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/features/controller/commands"
	"github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	grpcCP "github.com/cfgis/cfgms/pkg/controlplane/providers/grpc"
	"github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/transport/registry"
)

type gateAudit struct {
	mu      sync.Mutex
	refused []string
	allowed []string
}

func (a *gateAudit) CommandRefused(_ context.Context, id string, t types.CommandType, _ string) {
	a.mu.Lock()
	a.refused = append(a.refused, id+"|"+string(t))
	a.mu.Unlock()
}

func (a *gateAudit) OperatorCommandAllowed(_ context.Context, op, id string, t types.CommandType) {
	a.mu.Lock()
	a.allowed = append(a.allowed, op+"|"+id+"|"+string(t))
	a.mu.Unlock()
}

// newGatedServer starts a server whose command gate reads the real steward
// store through the real lockdown predicate, as the controller wires it.
func newGatedServer(t *testing.T, pki *testPKI, pred interfaces.LockdownChecker, obs interfaces.LockdownObserver) (*grpcCP.Provider, registry.Registry) {
	t.Helper()
	reg := registry.NewRegistry()
	server := grpcCP.New(grpcCP.ModeServer, grpcCP.WithLockdown(pred, obs))
	require.NoError(t, server.Initialize(context.Background(), map[string]interface{}{
		"mode": "server", "addr": "127.0.0.1:0", "tls_config": pki.serverTLS, "registry": reg,
	}))
	require.NoError(t, server.Start(context.Background()))
	t.Cleanup(server.ForceStop)
	return server, reg
}

func connectWithCommands(t *testing.T, pki *testPKI, server *grpcCP.Provider, reg registry.Registry, id string) chan *types.SignedCommand {
	t.Helper()
	client := connect(t, pki, server, reg, id, &tamperRecorder{})
	ch := make(chan *types.SignedCommand, 8)
	require.NoError(t, client.SubscribeCommands(context.Background(), id, func(_ context.Context, sc *types.SignedCommand) error {
		ch <- sc
		return nil
	}))
	return ch
}

func newGateSigner(t *testing.T) signature.Signer {
	t.Helper()
	ca, err := cert.NewCA(&cert.CAConfig{Organization: "Gate Test", Country: "US", ValidityDays: 1, KeySize: 2048})
	require.NoError(t, err)
	require.NoError(t, ca.Initialize(nil))
	sc, err := ca.GenerateSigningCertificate(&cert.SigningCertConfig{CommonName: "gate-test", ValidityDays: 1, KeySize: 2048})
	require.NoError(t, err)
	signer, err := signature.NewSigner(&signature.SignerConfig{CertificatePEM: sc.CertificatePEM, PrivateKeyPEM: sc.PrivateKeyPEM})
	require.NoError(t, err)
	return signer
}

// A push_signing_cert signed through PublishCommandWithSigner is denied for a
// tampered steward and delivered to a normal one.
func TestGate_PushSigningCertViaPublishCommandWithSigner_DeniedForTampered(t *testing.T) {
	pki := newTestPKI(t)
	store := newStewardStore(t)
	registerSteward(t, store, "s-tampered", business.StewardStatusTampered)
	registerSteward(t, store, "s-active", business.StewardStatusActive)
	audit := &gateAudit{}
	server, reg := newGatedServer(t, pki, fleet.NewLockdown(store, logging.NewNoopLogger()), audit)
	tamperedCh := connectWithCommands(t, pki, server, reg, "s-tampered")
	activeCh := connectWithCommands(t, pki, server, reg, "s-active")

	pub, err := commands.New(&commands.Config{ControlPlane: server, Logger: logging.NewNoopLogger()})
	require.NoError(t, err)
	signer := newGateSigner(t)

	_, err = pub.PublishCommandWithSigner(context.Background(), "s-tampered", types.CommandPushSigningCert,
		map[string]interface{}{"cert_pem": "x"}, signer)
	require.ErrorIs(t, err, interfaces.ErrStewardLockedDown)

	// Even an operator-origin context cannot push a signing certificate.
	opCtx := commands.NewOperatorOrigin(context.Background(), "alice")
	_, err = pub.PublishCommandWithSigner(opCtx, "s-tampered", types.CommandPushSigningCert,
		map[string]interface{}{"cert_pem": "x"}, signer)
	require.ErrorIs(t, err, interfaces.ErrStewardLockedDown)

	_, err = pub.PublishCommandWithSigner(context.Background(), "s-active", types.CommandPushSigningCert,
		map[string]interface{}{"cert_pem": "x"}, signer)
	require.NoError(t, err)

	select {
	case got := <-activeCh:
		assert.Equal(t, types.CommandPushSigningCert, got.Command.Type)
	case <-time.After(5 * time.Second):
		t.Fatal("normal steward did not receive push_signing_cert")
	}
	select {
	case got := <-tamperedCh:
		t.Fatalf("tampered steward received %s", got.Command.Type)
	case <-time.After(150 * time.Millisecond):
	}
	audit.mu.Lock()
	defer audit.mu.Unlock()
	assert.Len(t, audit.refused, 2)
}

// A lookup error on the real predicate refuses the command.
func TestGate_StoreLookupError_DeniesCommand(t *testing.T) {
	pki := newTestPKI(t)
	store := newStewardStore(t)
	registerSteward(t, store, "s1", business.StewardStatusActive)
	// Connect with a healthy predicate first, then let the gate read a failing store.
	flaky := &swapChecker{inner: fleet.NewLockdown(store, logging.NewNoopLogger())}
	server, reg := newGatedServer(t, pki, flaky, nil)
	ch := connectWithCommands(t, pki, server, reg, "s1")

	cmd := &types.SignedCommand{Command: types.Command{ID: "c1", Type: types.CommandSyncDNA, StewardID: "s1", Timestamp: time.Now()}}
	require.NoError(t, server.SendCommand(context.Background(), cmd))
	<-ch

	flaky.set(fleet.NewLockdown(failingReadStore{store}, logging.NewNoopLogger()))
	cmd.Command.ID = "c2"
	require.ErrorIs(t, server.SendCommand(context.Background(), cmd), interfaces.ErrStewardLockedDown)
}

type swapChecker struct {
	mu    sync.Mutex
	inner interfaces.LockdownChecker
}

func (s *swapChecker) set(c interfaces.LockdownChecker) {
	s.mu.Lock()
	s.inner = c
	s.mu.Unlock()
}

func (s *swapChecker) IsLockedDown(ctx context.Context, id string) (bool, error) {
	s.mu.Lock()
	c := s.inner
	s.mu.Unlock()
	return c.IsLockedDown(ctx, id)
}

// A command queued while the steward was active is refused once the steward becomes tampered.
func TestGate_CommandQueuedBeforeTamper_RefusedAtSend(t *testing.T) {
	pki := newTestPKI(t)
	store := newStewardStore(t)
	registerSteward(t, store, "s1", business.StewardStatusActive)
	server, reg := newGatedServer(t, pki, fleet.NewLockdown(store, logging.NewNoopLogger()), nil)
	ch := connectWithCommands(t, pki, server, reg, "s1")

	pub, err := commands.New(&commands.Config{ControlPlane: server, Logger: logging.NewNoopLogger()})
	require.NoError(t, err)

	// The delivery record is created while the steward is active; the send happens later.
	setStatus(t, store, "s1", business.StewardStatusTampered, business.StewardStatusActive)
	err = pub.PublishCommandWithID(context.Background(), "queued-1", "s1", types.CommandSyncConfig, nil)
	require.ErrorIs(t, err, interfaces.ErrStewardLockedDown)

	select {
	case got := <-ch:
		t.Fatalf("tampered steward received queued command %s", got.Command.ID)
	case <-time.After(150 * time.Millisecond):
	}
}
