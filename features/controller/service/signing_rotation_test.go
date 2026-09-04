// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package service_test

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/features/controller/commands"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/pkg/cert"
	grpcCP "github.com/cfgis/cfgms/pkg/controlplane/providers/grpc"
	"github.com/cfgis/cfgms/pkg/controlplane/providers/memory"
	"github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	quictransport "github.com/cfgis/cfgms/pkg/transport/quic"
	"github.com/cfgis/cfgms/pkg/transport/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingLogger captures all log calls for assertion in tests.
type recordingLogger struct {
	mu      sync.Mutex
	entries []recordedLogEntry
}

type recordedLogEntry struct {
	level  string
	msg    string
	fields []interface{}
}

func (r *recordingLogger) allText() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var b strings.Builder
	for _, e := range r.entries {
		b.WriteString(e.level)
		b.WriteString(" ")
		b.WriteString(e.msg)
		for i := 0; i+1 < len(e.fields); i += 2 {
			fmt.Fprintf(&b, " %v=%v", e.fields[i], e.fields[i+1])
		}
		b.WriteString("\n")
	}
	return b.String()
}

func (r *recordingLogger) record(level, msg string, kv []interface{}) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = append(r.entries, recordedLogEntry{level: level, msg: msg, fields: kv})
}

func (r *recordingLogger) Debug(msg string, kv ...interface{}) { r.record("DEBUG", msg, kv) }
func (r *recordingLogger) Info(msg string, kv ...interface{})  { r.record("INFO", msg, kv) }
func (r *recordingLogger) Warn(msg string, kv ...interface{})  { r.record("WARN", msg, kv) }
func (r *recordingLogger) Error(msg string, kv ...interface{}) { r.record("ERROR", msg, kv) }
func (r *recordingLogger) Fatal(msg string, kv ...interface{}) { r.record("FATAL", msg, kv) }
func (r *recordingLogger) DebugCtx(_ context.Context, msg string, kv ...interface{}) {
	r.record("DEBUG", msg, kv)
}
func (r *recordingLogger) InfoCtx(_ context.Context, msg string, kv ...interface{}) {
	r.record("INFO", msg, kv)
}
func (r *recordingLogger) WarnCtx(_ context.Context, msg string, kv ...interface{}) {
	r.record("WARN", msg, kv)
}
func (r *recordingLogger) ErrorCtx(_ context.Context, msg string, kv ...interface{}) {
	r.record("ERROR", msg, kv)
}
func (r *recordingLogger) FatalCtx(_ context.Context, msg string, kv ...interface{}) {
	r.record("FATAL", msg, kv)
}

// newTestCertManager creates a cert.Manager with a CA and a signing cert in dir.
func newTestCertManager(t *testing.T, dir string) *cert.Manager {
	t.Helper()
	mgr, err := cert.NewManager(&cert.ManagerConfig{
		CAConfig: &cert.CAConfig{
			Organization: "CFGMS Test",
			Country:      "US",
			ValidityDays: 1,
			KeySize:      2048,
		},
		StoragePath: dir,
	})
	require.NoError(t, err)
	require.NoError(t, mgr.EnsureSigningCertificate(nil))
	return mgr
}

// tlsForTest generates a matched server/client TLS pair using a fresh CA.
func tlsForTest(t *testing.T, stewardID string) (serverTLS, clientTLS *tls.Config) {
	t.Helper()

	ca, err := cert.NewCA(&cert.CAConfig{
		Organization: "CFGMS Test",
		Country:      "US",
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)
	require.NoError(t, ca.Initialize(nil))
	caPEM, err := ca.GetCACertificate()
	require.NoError(t, err)

	serverCert, err := ca.GenerateServerCertificate(&cert.ServerCertConfig{
		CommonName:   "localhost",
		DNSNames:     []string{"localhost"},
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)

	clientCert, err := ca.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:   stewardID,
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)

	serverTLS, err = cert.CreateServerTLSConfig(serverCert.CertificatePEM, serverCert.PrivateKeyPEM, caPEM, tls.VersionTLS13)
	require.NoError(t, err)

	clientTLS, err = cert.CreateClientTLSConfig(clientCert.CertificatePEM, clientCert.PrivateKeyPEM, caPEM, "localhost", tls.VersionTLS13)
	require.NoError(t, err)
	serverTLS.NextProtos = []string{quictransport.ALPNProtocol}
	clientTLS.NextProtos = []string{quictransport.ALPNProtocol}
	return serverTLS, clientTLS
}

// TestSigningRotationService_OnConnect_CallsEnsureStewardCurrent verifies that
// OnConnect delegates to EnsureStewardCurrent.
func TestSigningRotationService_OnConnect_CallsEnsureStewardCurrent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	certMgr := newTestCertManager(t, dir)
	logger := logging.NewNoopLogger()

	svc := service.NewSigningRotationService(certMgr, logger)

	// Without a publisher, EnsureStewardCurrent returns an error.
	err := svc.OnConnect(context.Background(), "steward-test")
	assert.Error(t, err, "OnConnect without publisher should error")
	assert.Contains(t, err.Error(), "publisher not initialized")
}

// TestStewardRefreshOnConnectAfterOfflineRotation verifies the full connect-hook
// flow: on every ControlChannel registration the controller pushes a
// push_signing_cert command to the steward (Issue #1817).
//
// The publisher is set BEFORE the client connects (mirroring server.go where
// Start() is called only after all services are wired).
func TestStewardRefreshOnConnectAfterOfflineRotation(t *testing.T) {
	t.Parallel()
	const stewardID = "steward-refresh-on-connect"

	dir := t.TempDir()
	certMgr := newTestCertManager(t, dir)
	logger := logging.NewNoopLogger()

	svc := service.NewSigningRotationService(certMgr, logger)

	serverTLS, clientTLS := tlsForTest(t, stewardID)
	reg := registry.NewRegistry()

	// Build server with hook injected.
	serverProvider := grpcCP.New(grpcCP.ModeServer, grpcCP.WithOnConnectHook(svc))
	require.NoError(t, serverProvider.Initialize(context.Background(), map[string]interface{}{
		"mode":       "server",
		"addr":       "127.0.0.1:0",
		"tls_config": serverTLS,
		"registry":   reg,
	}))
	require.NoError(t, serverProvider.Start(context.Background()))
	t.Cleanup(serverProvider.ForceStop)

	// Wire the publisher BEFORE the client connects — mirrors server.go order.
	publisher, err := commands.New(&commands.Config{
		ControlPlane: serverProvider,
		Logger:       logger,
	})
	require.NoError(t, err)
	svc.SetPublisher(publisher)

	// Build client and subscribe to commands before connecting.
	clientProvider := grpcCP.New(grpcCP.ModeClient)
	require.NoError(t, clientProvider.Initialize(context.Background(), map[string]interface{}{
		"mode":       "client",
		"addr":       serverProvider.ListenAddr(),
		"tls_config": clientTLS,
		"steward_id": stewardID,
	}))

	var (
		mu           sync.Mutex
		receivedCmds []*types.SignedCommand
	)
	require.NoError(t, clientProvider.SubscribeCommands(context.Background(), stewardID, func(_ context.Context, sc *types.SignedCommand) error {
		mu.Lock()
		receivedCmds = append(receivedCmds, sc)
		mu.Unlock()
		return nil
	}))

	// Connect: triggers ControlChannel → hook → push_signing_cert.
	require.NoError(t, clientProvider.Start(context.Background()))
	t.Cleanup(func() { _ = clientProvider.Stop(context.Background()) })

	require.Eventually(t, func() bool {
		_, ok := reg.Get(stewardID)
		return ok
	}, 5*time.Second, 10*time.Millisecond, "steward should be registered")

	// On connect the hook must deliver push_signing_cert.
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		for _, cmd := range receivedCmds {
			if cmd.Command.Type == types.CommandPushSigningCert {
				return true
			}
		}
		return false
	}, 5*time.Second, 10*time.Millisecond, "push_signing_cert command should be received on connect")

	// Verify cert_pem param is present, non-empty, and valid base64.
	mu.Lock()
	var pushCmd *types.SignedCommand
	for _, cmd := range receivedCmds {
		if cmd.Command.Type == types.CommandPushSigningCert {
			pushCmd = cmd
			break
		}
	}
	mu.Unlock()

	require.NotNil(t, pushCmd, "push_signing_cert command must be present")
	certPEMB64, ok := pushCmd.Command.Params["cert_pem"].(string)
	require.True(t, ok, "cert_pem param must be a string")
	certPEM, decErr := base64.StdEncoding.DecodeString(certPEMB64)
	require.NoError(t, decErr, "cert_pem must be valid base64")
	assert.NotEmpty(t, certPEM, "cert_pem must not be empty")
}

// TestRefreshOnConnectFailureNoPartialState verifies that when EnsureStewardCurrent
// fails (publisher not yet wired), the ControlChannel stream continues and the
// steward's existing state is unchanged — fail-open per Issue #1817.
func TestRefreshOnConnectFailureNoPartialState(t *testing.T) {
	t.Parallel()
	const stewardID = "steward-hook-fail-nostate"

	dir := t.TempDir()
	certMgr := newTestCertManager(t, dir)
	logger := logging.NewNoopLogger()

	// Service without a publisher: every OnConnect call will error.
	svc := service.NewSigningRotationService(certMgr, logger)

	serverTLS, clientTLS := tlsForTest(t, stewardID)
	reg := registry.NewRegistry()

	serverProvider := grpcCP.New(grpcCP.ModeServer, grpcCP.WithOnConnectHook(svc))
	require.NoError(t, serverProvider.Initialize(context.Background(), map[string]interface{}{
		"mode":       "server",
		"addr":       "127.0.0.1:0",
		"tls_config": serverTLS,
		"registry":   reg,
	}))
	require.NoError(t, serverProvider.Start(context.Background()))
	t.Cleanup(serverProvider.ForceStop)

	clientProvider := grpcCP.New(grpcCP.ModeClient)
	require.NoError(t, clientProvider.Initialize(context.Background(), map[string]interface{}{
		"mode":       "client",
		"addr":       serverProvider.ListenAddr(),
		"tls_config": clientTLS,
		"steward_id": stewardID,
	}))
	require.NoError(t, clientProvider.Start(context.Background()))
	t.Cleanup(func() { _ = clientProvider.Stop(context.Background()) })

	// Hook error must not tear down the stream: steward should still be registered.
	require.Eventually(t, func() bool {
		_, ok := reg.Get(stewardID)
		return ok
	}, 5*time.Second, 10*time.Millisecond, "steward must remain registered after hook error (fail-open)")

	// Controller can still send commands on the live stream.
	sc := &types.SignedCommand{
		Command: types.Command{
			ID:        "cmd-after-hook-fail",
			Type:      types.CommandSyncConfig,
			StewardID: stewardID,
		},
	}
	assert.NoError(t, serverProvider.SendCommand(context.Background(), sc),
		"controller should still be able to send commands after hook error")
}

// TestEnsureStewardCurrentDelivery verifies that EnsureStewardCurrent delivers a
// push_signing_cert command with a valid cert_pem and overlap_expires_at param.
func TestEnsureStewardCurrentDelivery(t *testing.T) {
	t.Parallel()
	const stewardID = "steward-ensure-current-delivery"

	dir := t.TempDir()
	certMgr := newTestCertManager(t, dir)
	// newTestCertManager creates an initial signing cert (cert v1) via EnsureSigningCertificate.

	// Generate a second signing cert (2048-bit for speed) to act as the "rotated" cert.
	rotatedCert, genErr := certMgr.GenerateSigningCertificate(&cert.SigningCertConfig{
		CommonName:   "cfgms-config-signer-v2",
		ValidityDays: 30,
		KeySize:      2048,
	})
	require.NoError(t, genErr)

	// Find the initial cert serial (the one that is NOT rotatedCert).
	allSigning, listErr := certMgr.GetAllValidCertificatesForPurpose(cert.PurposeSigning)
	require.NoError(t, listErr)
	require.GreaterOrEqual(t, len(allSigning), 2, "must have at least 2 signing certs")
	var initialSerial string
	for _, c := range allSigning {
		if c.SerialNumber != rotatedCert.SerialNumber {
			initialSerial = c.SerialNumber
			break
		}
	}
	require.NotEmpty(t, initialSerial, "initial signing cert serial must be found")

	// Write a cursor that mirrors what RotateSigningCertificate would produce for a
	// second rotation: CurrentSerial = rotatedCert, RotatingSerial = initialCert (active
	// 7-day overlap window). This makes EnsureStewardCurrent produce a non-empty
	// overlap_expires_at for assertion.
	cursorToWrite := &cert.SigningCertCursor{
		CurrentSerial:     rotatedCert.SerialNumber,
		RotatingSerial:    initialSerial,
		OverlapWindowDays: 7,
		RotatedAt:         time.Now().UTC(),
	}
	cursorJSON, marshalErr := json.Marshal(cursorToWrite)
	require.NoError(t, marshalErr)
	require.NoError(t, os.WriteFile(
		filepath.Join(certMgr.GetStoragePath(), "signing-cursor.json"),
		cursorJSON, 0600,
	))

	logger := logging.NewNoopLogger()

	svc := service.NewSigningRotationService(certMgr, logger)

	serverTLS, clientTLS := tlsForTest(t, stewardID)
	reg := registry.NewRegistry()

	serverProvider := grpcCP.New(grpcCP.ModeServer)
	require.NoError(t, serverProvider.Initialize(context.Background(), map[string]interface{}{
		"mode":       "server",
		"addr":       "127.0.0.1:0",
		"tls_config": serverTLS,
		"registry":   reg,
	}))
	require.NoError(t, serverProvider.Start(context.Background()))
	t.Cleanup(serverProvider.ForceStop)

	publisher, err := commands.New(&commands.Config{
		ControlPlane: serverProvider,
		Logger:       logger,
	})
	require.NoError(t, err)
	svc.SetPublisher(publisher)

	clientProvider := grpcCP.New(grpcCP.ModeClient)
	require.NoError(t, clientProvider.Initialize(context.Background(), map[string]interface{}{
		"mode":       "client",
		"addr":       serverProvider.ListenAddr(),
		"tls_config": clientTLS,
		"steward_id": stewardID,
	}))

	var (
		mu           sync.Mutex
		receivedCmds []*types.SignedCommand
	)
	require.NoError(t, clientProvider.SubscribeCommands(context.Background(), stewardID, func(_ context.Context, sc *types.SignedCommand) error {
		mu.Lock()
		receivedCmds = append(receivedCmds, sc)
		mu.Unlock()
		return nil
	}))

	require.NoError(t, clientProvider.Start(context.Background()))
	t.Cleanup(func() { _ = clientProvider.Stop(context.Background()) })

	require.Eventually(t, func() bool {
		_, ok := reg.Get(stewardID)
		return ok
	}, 5*time.Second, 10*time.Millisecond, "steward should be registered")

	require.NoError(t, svc.EnsureStewardCurrent(context.Background(), stewardID))

	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		for _, cmd := range receivedCmds {
			if cmd.Command.Type == types.CommandPushSigningCert {
				return true
			}
		}
		return false
	}, 5*time.Second, 10*time.Millisecond, "push_signing_cert must be received")

	mu.Lock()
	var pushCmd *types.SignedCommand
	for _, cmd := range receivedCmds {
		if cmd.Command.Type == types.CommandPushSigningCert {
			pushCmd = cmd
			break
		}
	}
	mu.Unlock()

	require.NotNil(t, pushCmd)

	// cert_pem must be present and decode to non-empty PEM bytes.
	certPEMB64, ok := pushCmd.Command.Params["cert_pem"].(string)
	require.True(t, ok, "cert_pem param must be a string")
	certPEMBytes, decErr := base64.StdEncoding.DecodeString(certPEMB64)
	require.NoError(t, decErr, "cert_pem must be valid base64")
	assert.NotEmpty(t, certPEMBytes, "decoded cert_pem must not be empty")

	// overlap_expires_at must be present, non-empty, and a valid RFC3339 timestamp.
	overlapVal, hasOverlap := pushCmd.Command.Params["overlap_expires_at"]
	require.True(t, hasOverlap, "overlap_expires_at must be present in push_signing_cert params")
	overlapStr, isStr := overlapVal.(string)
	require.True(t, isStr, "overlap_expires_at must be a string")
	require.NotEmpty(t, overlapStr, "overlap_expires_at must be non-empty when rotation is in progress")
	_, parseErr := time.Parse(time.RFC3339, overlapStr)
	assert.NoError(t, parseErr, "overlap_expires_at must be a valid RFC3339 timestamp, got: %s", overlapStr)
}

// TestEnsureStewardCurrent_SignsWithRotatingCertAfterOverlapExpiry verifies that
// EnsureStewardCurrent signs push_signing_cert with the rotating (old) cert even
// when the overlap window has already expired. This prevents the bootstrapping
// deadlock described in Issue #1844: a steward that was offline during an
// overlap_days=0 rotation only trusts the rotating cert, so receiving a
// new-cert-signed push_signing_cert rejects it before the trust set can be updated.
//
// This reproduces the OfflinePastWindow e2e failure: after a zero-day-overlap
// rotation, EnsureStewardCurrent previously fell through to the DynamicSigner
// (new cert) because time.Now().Before(deadline) was FALSE at every call site.
func TestEnsureStewardCurrent_SignsWithRotatingCertAfterOverlapExpiry(t *testing.T) {
	t.Parallel()
	const stewardID = "steward-past-window-signing"

	dir := t.TempDir()
	certMgr := newTestCertManager(t, dir)

	// Capture the initial signing cert (cert v1) — it becomes the rotating serial
	// once we write a cursor that simulates a completed rotation.
	initialCert, err := certMgr.GetCurrentCertForPurpose(cert.PurposeSigning)
	require.NoError(t, err)
	initialCertPEM, _, err := certMgr.ExportCertificate(initialCert.SerialNumber, false, false)
	require.NoError(t, err)

	// Build a verifier backed by the initial (rotating) cert to assert the
	// delivered command was signed with it — not with the new cert.
	oldVerifier, verErr := signature.NewVerifier(&signature.VerifierConfig{CertificatePEM: initialCertPEM})
	require.NoError(t, verErr)

	// Generate cert v2 as the "current" cert without going through RotateSigningCertificate,
	// so we can write the cursor manually with explicit RotatingSerial and overlap=0.
	rotatedCert, genErr := certMgr.GenerateSigningCertificate(&cert.SigningCertConfig{
		CommonName:   "cfgms-config-signer-v2",
		ValidityDays: 30,
		KeySize:      2048,
	})
	require.NoError(t, genErr)

	// Write a cursor that mirrors a zero-overlap rotation that has ALREADY expired:
	// deadline = RotatedAt + 0 days = RotatedAt, so time.Now().Before(deadline) is
	// always FALSE (RotatedAt is in the past by definition once we write it).
	cursorToWrite := &cert.SigningCertCursor{
		CurrentSerial:     rotatedCert.SerialNumber,
		RotatingSerial:    initialCert.SerialNumber, // rotating = the cert a missed-steward still trusts
		OverlapWindowDays: 0,
		RotatedAt:         time.Now().Add(-time.Second).UTC(), // one second in the past → deadline expired
	}
	cursorJSON, marshalErr := json.Marshal(cursorToWrite)
	require.NoError(t, marshalErr)
	require.NoError(t, os.WriteFile(
		filepath.Join(certMgr.GetStoragePath(), "signing-cursor.json"),
		cursorJSON, 0600,
	))

	logger := logging.NewNoopLogger()
	svc := service.NewSigningRotationService(certMgr, logger)

	serverTLS, clientTLS := tlsForTest(t, stewardID)
	reg := registry.NewRegistry()

	serverProvider := grpcCP.New(grpcCP.ModeServer)
	require.NoError(t, serverProvider.Initialize(context.Background(), map[string]interface{}{
		"mode": "server", "addr": "127.0.0.1:0", "tls_config": serverTLS, "registry": reg,
	}))
	require.NoError(t, serverProvider.Start(context.Background()))
	t.Cleanup(serverProvider.ForceStop)

	publisher, pubErr := commands.New(&commands.Config{ControlPlane: serverProvider, Logger: logger})
	require.NoError(t, pubErr)
	svc.SetPublisher(publisher)

	clientProvider := grpcCP.New(grpcCP.ModeClient)
	require.NoError(t, clientProvider.Initialize(context.Background(), map[string]interface{}{
		"mode": "client", "addr": serverProvider.ListenAddr(), "tls_config": clientTLS, "steward_id": stewardID,
	}))

	var mu sync.Mutex
	var receivedCmds []*types.SignedCommand
	require.NoError(t, clientProvider.SubscribeCommands(context.Background(), stewardID, func(_ context.Context, sc *types.SignedCommand) error {
		mu.Lock()
		receivedCmds = append(receivedCmds, sc)
		mu.Unlock()
		return nil
	}))
	require.NoError(t, clientProvider.Start(context.Background()))
	t.Cleanup(func() { _ = clientProvider.Stop(context.Background()) })

	require.Eventually(t, func() bool {
		_, ok := reg.Get(stewardID)
		return ok
	}, 5*time.Second, 10*time.Millisecond, "steward should be registered")

	require.NoError(t, svc.EnsureStewardCurrent(context.Background(), stewardID))

	var pushCmd *types.SignedCommand
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		for _, cmd := range receivedCmds {
			if cmd.Command.Type == types.CommandPushSigningCert {
				pushCmd = cmd
				return true
			}
		}
		return false
	}, 5*time.Second, 10*time.Millisecond, "push_signing_cert must be received")

	require.NotNil(t, pushCmd)
	require.NotNil(t, pushCmd.Signature, "push_signing_cert must be signed (unsigned means rotating signer was not used)")

	// The command must be verifiable with the OLD (rotating) cert, not the new cert.
	// Without the fix, EnsureStewardCurrent skips the rotating signer when
	// time.Now().Before(deadline) is FALSE (overlap=0 → deadline = RotatedAt, already past)
	// and falls back to the publisher's signer — causing a bootstrapping deadlock for any
	// steward that was offline during the rotation fan-out (Issue #1844).
	//
	// Use RawParams (proto-wire string map) for the canonical signing bytes, mirroring
	// HandleCommand — the serial number may be a large integer that stringMapToInterfaceMap
	// decodes as float64, causing InterfaceParamsToStringMap to re-encode it differently.
	rawParams := pushCmd.RawParams
	if rawParams == nil {
		rawParams = types.InterfaceParamsToStringMap(pushCmd.Command.Params)
	}
	cmdBytes, signBytesErr := types.CommandSigningBytes(&pushCmd.Command, rawParams)
	require.NoError(t, signBytesErr)
	require.NoError(t, oldVerifier.Verify(cmdBytes, pushCmd.Signature),
		"push_signing_cert must be verifiable with the rotating (old) cert so offline stewards can bootstrap (Issue #1844)")
}

// TestRotate_FanOutIgnoresCallerTenantScope verifies that the signing-cert
// rotation fan-out reaches every steward in the fleet even when Rotate runs on a
// tenant-scoped context.
//
// Rotate is invoked from handleRotateSigningCert with the HTTP request context,
// and authenticationMiddleware populates ctxkeys.TenantID from the authenticated
// admin principal's own tenant — the handler requires AssuranceStrong, not root
// scope. The signing CA is controller-wide, so a fan-out that honoured that scope
// would notify only the caller's tenant subtree and leave every other tenant's
// stewards unable to verify controller-signed commands once the overlap window
// closed. Both stewards below must receive push_signing_cert even though the
// caller is scoped to root/tenant-a.
func TestRotate_FanOutIgnoresCallerTenantScope(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	certMgr := newTestCertManager(t, t.TempDir())
	logger := logging.NewNoopLogger()

	bus := memory.NewBus()
	server := memory.New(memory.ModeServer)
	require.NoError(t, server.Initialize(ctx, map[string]interface{}{"bus": bus}))
	require.NoError(t, server.Start(ctx))
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Stop(stopCtx)
	})

	// Two stewards in sibling tenant subtrees; the caller is scoped to the first.
	stewardTenants := map[string]string{
		"steward-in-caller-tenant": "root/tenant-a",
		"steward-in-other-tenant":  "root/tenant-b",
	}

	controllerSvc := service.NewControllerService(logging.NewNoopLogger())
	received := make(map[string]chan *types.SignedCommand, len(stewardTenants))
	for stewardID, tenantID := range stewardTenants {
		require.NoError(t, controllerSvc.RegisterSteward(stewardID, tenantID, "", "active"))

		client := memory.New(memory.ModeClient)
		require.NoError(t, client.Initialize(ctx, map[string]interface{}{"bus": bus, "steward_id": stewardID}))
		require.NoError(t, client.Start(ctx))
		t.Cleanup(func() {
			stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = client.Stop(stopCtx)
		})

		ch := make(chan *types.SignedCommand, 4)
		received[stewardID] = ch
		require.NoError(t, client.SubscribeCommands(ctx, stewardID, func(_ context.Context, sc *types.SignedCommand) error {
			ch <- sc
			return nil
		}))
	}

	publisher, err := commands.New(&commands.Config{ControlPlane: server, Logger: logger})
	require.NoError(t, err)

	svc := service.NewSigningRotationService(certMgr, logger)
	svc.SetPublisher(publisher)
	svc.SetControllerService(controllerSvc)

	// A tenant-scoped admin context, exactly as the API middleware builds it.
	scopedCtx := context.WithValue(ctx, ctxkeys.TenantID, "root/tenant-a")

	result, err := svc.Rotate(scopedCtx, "operator-serial-scoped", 7, false)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, len(stewardTenants), result.StewardsNotified,
		"a controller-wide signing rotation must notify every steward in the fleet, not just the caller's tenant subtree")

	for stewardID := range stewardTenants {
		select {
		case sc := <-received[stewardID]:
			assert.Equal(t, types.CommandPushSigningCert, sc.Command.Type,
				"steward %s received the wrong command type", stewardID)
		case <-time.After(5 * time.Second):
			t.Fatalf("steward %s (tenant %s) never received push_signing_cert; the rotation fan-out was tenant-scoped",
				stewardID, stewardTenants[stewardID])
		}
	}
}

// TestRotateAuditLogNoPEMBody verifies that SigningRotationService.Rotate emits a
// structured audit log entry that contains no PEM block header ("-----BEGIN").
func TestRotateAuditLogNoPEMBody(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	rl := &recordingLogger{}
	certMgr := newTestCertManager(t, dir)

	svc := service.NewSigningRotationService(certMgr, rl)
	// Inject a controller service with no stewards so fan-out is a no-op.
	svc.SetControllerService(service.NewControllerService(logging.NewNoopLogger()))

	result, err := svc.Rotate(context.Background(), "operator-serial-test", 7, false)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.NewSerial)

	// The combined log output must not contain any PEM block header.
	allLog := rl.allText()
	assert.NotContains(t, allLog, "-----BEGIN",
		"audit log must not contain PEM body data; full log:\n%s", allLog)
}
