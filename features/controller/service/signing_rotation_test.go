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

	"github.com/cfgis/cfgms/features/controller/commands"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/pkg/cert"
	grpcCP "github.com/cfgis/cfgms/pkg/controlplane/providers/grpc"
	"github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
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

	result, err := svc.Rotate(context.Background(), "operator-serial-test", 7)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.NewSerial)

	// The combined log output must not contain any PEM block header.
	allLog := rl.allText()
	assert.NotContains(t, allLog, "-----BEGIN",
		"audit log must not contain PEM body data; full log:\n%s", allLog)
}
