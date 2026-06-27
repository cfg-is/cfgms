// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// TestStewardEventStreamPipeline proves the full P1 event-stream pipeline
// end-to-end (ADR-012). A real controller and a real steward are wired with
// mTLS via the cert manager; no mocks are used anywhere.
//
// P1 scope (this file):
//   - convergence detection+outcome pair correlated by correlation_id
//   - script_output event with exit-code and duration fields
//   - CN-mismatch spoofing rejected by LogStreamHandler (PermissionDenied)
//   - secret in script stdout redacted to [REDACTED] before emission
//   - hung module → did-not-finish(timeout) outcome correlated to detection
//
// Monitor-fire events are explicitly excluded: they are P2 per ADR-012 §8
// and will be covered when the monitor loop is implemented.
package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/features/controller"
	controllerConfig "github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/features/steward/client"
	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/steward/discovery"
	"github.com/cfgis/cfgms/features/steward/execution"
	stfactory "github.com/cfgis/cfgms/features/steward/factory"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/cert"
	controlplaneGRPC "github.com/cfgis/cfgms/pkg/controlplane/providers/grpc"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/registration"
	quictransport "github.com/cfgis/cfgms/pkg/transport/quic"

	// Providers registered by side-effect.
	_ "github.com/cfgis/cfgms/pkg/logging/providers/file"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
)

// ---------------------------------------------------------------------------
// Test doubles — no mock library; real implementations only.
// ---------------------------------------------------------------------------

// hungModuleE2E blocks in Get until the context is cancelled or times out.
// Pattern mirrors HungModule in features/steward/execution/executor_test.go;
// redefined here because that file is in an external test package (execution_test)
// and cannot be imported.
type hungModuleE2E struct{}

func (h *hungModuleE2E) Get(ctx context.Context, _ string) (modules.ConfigState, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (h *hungModuleE2E) Set(_ context.Context, _ string, _ modules.ConfigState) error {
	return nil
}

var _ modules.Module = (*hungModuleE2E)(nil)

// ---------------------------------------------------------------------------
// Test environment
// ---------------------------------------------------------------------------

// streamEnv holds all resources needed for the event-stream E2E tests.
type streamEnv struct {
	t            *testing.T
	ctx          context.Context
	cancel       context.CancelFunc
	ctrl         *controller.Controller
	certMgr      *cert.Manager
	stewardID    string
	emitter      *client.EventEmitter
	controlPlane *controlplaneGRPC.Provider
	adminClient  *http.Client
	httpBase     string // "https://localhost:PORT"
}

// registrationResp mirrors the JSON shape of POST /api/v1/register.
type registrationResp struct {
	StewardID        string `json:"steward_id"`
	TenantID         string `json:"tenant_id"`
	TransportAddress string `json:"transport_address"`
	ClientCert       string `json:"client_cert"`
	ClientKey        string `json:"client_key"`
	CACert           string `json:"ca_cert"`
}

// logsAPIResponse mirrors the JSON shape of GET /api/v1/stewards/{id}/logs.
type logsAPIResponse struct {
	Data struct {
		Events []streamLogRecord `json:"events"`
	} `json:"data"`
}

type streamLogRecord struct {
	CorrelationID  string          `json:"correlation_id"`
	Detection      *streamLogEvent `json:"detection"`
	Outcome        *streamLogEvent `json:"outcome"`
	PendingOutcome bool            `json:"pending_outcome"`
}

type streamLogEvent struct {
	Level   string                 `json:"level"`
	Message string                 `json:"message"`
	Fields  map[string]interface{} `json:"fields"`
}

// ---------------------------------------------------------------------------
// Environment setup helpers
// ---------------------------------------------------------------------------

// findFreePort returns an available TCP port on localhost.
func findFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())
	return port
}

// newStreamEnv creates a fully wired event-stream test environment:
//   - cert manager (creates CA)
//   - controller with file-backed steward event logging
//   - one registered steward (HTTP registration + mTLS gRPC transport)
//   - EventEmitter connected to the controller's LogStream RPC
//   - admin mTLS HTTP client for querying GET /api/v1/stewards/{id}/logs
func newStreamEnv(t *testing.T) *streamEnv {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)

	tempDir := t.TempDir()
	logger := logging.NewNoopLogger()

	// ── 1. Certificate manager — creates CA at tempDir/certs. ────────────────
	certPath := filepath.Join(tempDir, "certs")
	require.NoError(t, os.MkdirAll(certPath, 0755))

	certMgr, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath: certPath,
		CAConfig: &cert.CAConfig{
			Organization:       "CFGMS E2E Test CA",
			Country:            "US",
			State:              "Test",
			City:               "Test",
			OrganizationalUnit: "Event Stream E2E",
			ValidityDays:       1,
			KeySize:            2048,
		},
		LoadExistingCA:       false,
		RenewalThresholdDays: 1,
	})
	require.NoError(t, err, "cert manager init")

	// ── 2. Start controller with logging enabled ──────────────────────────────
	httpPort := findFreePort(t)
	transportPort := findFreePort(t)
	logDir := filepath.Join(tempDir, "event-logs")

	cfg := &controllerConfig.Config{
		ListenAddr: fmt.Sprintf("localhost:%d", httpPort),
		CertPath:   certPath,
		DataDir:    filepath.Join(tempDir, "data"),
		LogLevel:   "info",
		Storage: &controllerConfig.StorageConfig{
			Provider:     "flatfile",
			FlatfileRoot: filepath.Join(tempDir, "storage"),
			SQLitePath:   filepath.Join(tempDir, "cfgms.db"),
		},
		Certificate: &controllerConfig.CertificateConfig{
			EnableCertManagement:   true,
			CAPath:                 filepath.Join(certPath, "ca"),
			RenewalThresholdDays:   1,
			ServerCertValidityDays: 1,
			ClientCertValidityDays: 1,
			Server: &controllerConfig.ServerCertificateConfig{
				CommonName:   "localhost",
				DNSNames:     []string{"localhost", "127.0.0.1"},
				IPAddresses:  []string{"127.0.0.1", "::1"},
				Organization: "Test Organization",
			},
		},
		Transport: &controllerConfig.TransportConfig{
			ListenAddr:      fmt.Sprintf("localhost:%d", transportPort),
			UseCertManager:  true,
			MaxConnections:  10,
			KeepalivePeriod: controllerConfig.Duration(30 * time.Second),
			IdleTimeout:     controllerConfig.Duration(5 * time.Minute),
		},
		Registration: &controllerConfig.RegistrationConfig{
			Workflow: "auto-approve",
		},
		// Enable steward event logging (creates stewardEventMgr in controller).
		Logging: &controllerConfig.LoggingConfig{
			Provider: "file",
			Config: map[string]interface{}{
				"directory":        logDir,
				"file_prefix":      "steward-events",
				"max_file_size":    1024 * 1024,
				"retention_days":   1,
				"compress_rotated": false,
			},
			Level:       "DEBUG",
			BatchSize:   1,
			AsyncWrites: false,
		},
	}

	require.NoError(t, os.MkdirAll(filepath.Join(tempDir, "storage"), 0755))
	require.NoError(t, os.MkdirAll(logDir, 0755))

	ctrl, err := controller.New(cfg, logger)
	require.NoError(t, err, "controller.New")

	ctrlErrCh := make(chan error, 1)
	go func() {
		ctrlErrCh <- ctrl.Start(ctx)
	}()

	httpBase := fmt.Sprintf("https://localhost:%d", httpPort)

	// Wait for the HTTP API to come up (max 30 s).
	waitForControllerHTTP(t, certMgr, httpBase, 30*time.Second)

	t.Cleanup(func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer stopCancel()
		_ = ctrl.Stop(stopCtx)
		// Drain the error channel so any early-exit error is visible in test output.
		select {
		case err := <-ctrlErrCh:
			if err != nil && err.Error() != "controller not running" {
				t.Logf("controller Start returned: %v", err)
			}
		default:
		}
	})

	// ── 3. Register a steward via HTTP ────────────────────────────────────────
	tokenStore, ok := ctrl.GetRegistrationTokenStore().(registration.Store)
	require.True(t, ok, "registration token store must be accessible")

	tokenReq := &registration.TokenCreateRequest{
		TenantID:      "e2e-tenant",
		ControllerURL: fmt.Sprintf("grpc://localhost:%d", transportPort),
		Group:         "e2e-event-stream",
	}
	tok, err := registration.CreateToken(tokenReq)
	require.NoError(t, err)
	require.NoError(t, tokenStore.SaveToken(ctx, tok))

	caPEM, err := certMgr.GetCACertificate()
	require.NoError(t, err)

	caPool := x509.NewCertPool()
	require.True(t, caPool.AppendCertsFromPEM(caPEM), "CA pool append")

	regClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    caPool,
				MinVersion: tls.VersionTLS13,
			},
		},
	}

	// Generate a fresh Ed25519 device identity (ADR-010 §1).
	identPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	identHash := sha256.Sum256(identPub)

	regBody, err := json.Marshal(map[string]string{
		"token":            tok.Token,
		"device_id":        hex.EncodeToString(identHash[:]),
		"identity_key_pub": base64.StdEncoding.EncodeToString(identPub),
	})
	require.NoError(t, err)

	regReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		httpBase+"/api/v1/register", bytes.NewReader(regBody))
	require.NoError(t, err)
	regReq.Header.Set("Content-Type", "application/json")

	regRespHTTP, err := regClient.Do(regReq)
	require.NoError(t, err)
	defer func() { _ = regRespHTTP.Body.Close() }()
	require.Equal(t, http.StatusOK, regRespHTTP.StatusCode, "registration must succeed")

	var reg registrationResp
	regBodyBytes, err := io.ReadAll(regRespHTTP.Body)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(regBodyBytes, &reg))
	require.NotEmpty(t, reg.StewardID, "steward_id must be set in registration response")

	// ── 4. Connect gRPC control plane ─────────────────────────────────────────
	stewardTLSCert, err := tls.X509KeyPair([]byte(reg.ClientCert), []byte(reg.ClientKey))
	require.NoError(t, err)

	regCACertPool := x509.NewCertPool()
	require.True(t, regCACertPool.AppendCertsFromPEM([]byte(reg.CACert)))

	transportTLSCfg := &tls.Config{
		Certificates: []tls.Certificate{stewardTLSCert},
		RootCAs:      regCACertPool,
		MinVersion:   tls.VersionTLS12,
		ServerName:   "localhost",
		NextProtos:   []string{quictransport.ALPNProtocol},
	}

	cp := controlplaneGRPC.New(controlplaneGRPC.ModeClient)
	require.NoError(t, cp.Initialize(ctx, map[string]interface{}{
		"addr":       reg.TransportAddress,
		"tls_config": transportTLSCfg,
		"steward_id": reg.StewardID,
		"tenant_id":  reg.TenantID,
	}))
	require.NoError(t, cp.Start(ctx))
	t.Cleanup(func() { _ = cp.Stop(context.Background()) })

	// ── 5. Create and start the EventEmitter ─────────────────────────────────
	emitter := client.NewEventEmitter(client.EventEmitterConfig{
		Client:      cp.TransportClient(),
		StewardID:   reg.StewardID,
		Logger:      logging.ForModule("e2e-event-stream"),
		BufferDepth: 64,
	})
	emitter.Start(ctx)
	t.Cleanup(func() { emitter.Close() })

	// ── 6. Issue admin mTLS cert for HTTP API queries ─────────────────────────
	adminCert, err := certMgr.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:       "e2e-event-stream-admin",
		Organization:     "CFGMS",
		ValidityDays:     1,
		KeySize:          2048,
		TemplateModifier: cert.SetAdminMarker,
	})
	require.NoError(t, err, "issue admin cert")

	adminTLSCert, err := tls.X509KeyPair(adminCert.CertificatePEM, adminCert.PrivateKeyPEM)
	require.NoError(t, err)

	adminHTTPClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{adminTLSCert},
				RootCAs:      caPool,
				MinVersion:   tls.VersionTLS13,
			},
		},
	}

	return &streamEnv{
		t:            t,
		ctx:          ctx,
		cancel:       cancel,
		ctrl:         ctrl,
		certMgr:      certMgr,
		stewardID:    reg.StewardID,
		emitter:      emitter,
		controlPlane: cp,
		adminClient:  adminHTTPClient,
		httpBase:     httpBase,
	}
}

// waitForControllerHTTP polls GET /api/v1/health until the controller answers
// or the timeout expires.
func waitForControllerHTTP(t *testing.T, certMgr *cert.Manager, base string, timeout time.Duration) {
	t.Helper()

	caPEM, err := certMgr.GetCACertificate()
	require.NoError(t, err)
	caPool := x509.NewCertPool()
	require.True(t, caPool.AppendCertsFromPEM(caPEM), "health-check CA pool append")

	hc := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    caPool,
				MinVersion: tls.VersionTLS12,
			},
		},
	}

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := hc.Get(base + "/api/v1/health")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode < 500 {
				return
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("controller HTTP not ready within %v", timeout)
}

// pollLogs queries GET /api/v1/stewards/{id}/logs and passes the result to
// check until it returns true or the timeout expires.
func (env *streamEnv) pollLogs(predicate func([]streamLogRecord) bool, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		records := env.queryLogs()
		if predicate(records) {
			return true
		}
		time.Sleep(150 * time.Millisecond)
	}
	return false
}

// queryLogs calls GET /api/v1/stewards/{id}/logs and returns the events list.
func (env *streamEnv) queryLogs() []streamLogRecord {
	env.t.Helper()

	url := fmt.Sprintf("%s/api/v1/stewards/%s/logs", env.httpBase, env.stewardID)
	req, err := http.NewRequestWithContext(env.ctx, http.MethodGet, url, nil)
	require.NoError(env.t, err)

	resp, err := env.adminClient.Do(req)
	if err != nil {
		env.t.Logf("queryLogs error: %v", err)
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		env.t.Logf("queryLogs: unexpected status %d", resp.StatusCode)
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		env.t.Logf("queryLogs body read error: %v", err)
		return nil
	}

	var apiResp logsAPIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		env.t.Logf("queryLogs unmarshal error: %v (body=%s)", err, string(body))
		return nil
	}

	return apiResp.Data.Events
}

// fieldStr safely extracts a string value from event.Fields.
func fieldStr(evt *streamLogEvent, key string) string {
	if evt == nil || evt.Fields == nil {
		return ""
	}
	v, _ := evt.Fields[key].(string)
	return v
}

// ---------------------------------------------------------------------------
// Test entry point
// ---------------------------------------------------------------------------

func TestStewardEventStreamPipeline(t *testing.T) {
	env := newStreamEnv(t)

	t.Run("ConvergenceDetectionAndOutcomePair", env.testConvergenceDetectionAndOutcomePair)
	t.Run("ScriptOutputEvent", env.testScriptOutputEvent)
	t.Run("NegativeSpoofedStewardRejected", env.testNegativeSpoofedStewardRejected)
	t.Run("NegativeSecretRedacted", env.testNegativeSecretRedacted)
	t.Run("HungModuleTimeout", env.testHungModuleTimeout)
}

// ---------------------------------------------------------------------------
// AC-1: convergence detection + outcome pair rolled up by correlation_id
// ---------------------------------------------------------------------------

func (env *streamEnv) testConvergenceDetectionAndOutcomePair(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "managed.txt")

	// Write wrong content so the file module detects drift.
	require.NoError(t, os.WriteFile(filePath, []byte("wrong content\n"), 0644))

	fileConfigMap := map[string]interface{}{
		"path":              filepath.ToSlash(filePath),
		"content":           "desired content\n",
		"allowed_base_path": filepath.ToSlash(dir),
	}
	if runtime.GOOS != "windows" {
		fileConfigMap["permissions"] = 420 // 0644
	}

	executor, err := execution.NewExecutor(&execution.ExecutorConfig{
		StewardID:    env.stewardID,
		Logger:       logging.ForModule("e2e-convergence"),
		EventEmitter: env.emitter,
		DriftMode:    stewardconfig.DriftModeApply,
		// Short module timeout prevents tests from hanging.
		ModuleCallTimeoutSec: 10,
	})
	require.NoError(t, err)

	resource := stewardconfig.ResourceConfig{
		Name:   "e2e-managed-file",
		Module: "file",
		Config: fileConfigMap,
	}

	result := executor.ExecuteResource(env.ctx, resource)
	require.True(t, result.DriftDetected, "drift must be detected (file content differs)")

	// The executor emits detection before Get and outcome after Set+Verify.
	// Poll until both appear at the controller rolled up under one correlation_id.
	ok := env.pollLogs(func(records []streamLogRecord) bool {
		for _, rec := range records {
			if rec.CorrelationID == "" || rec.Detection == nil || rec.Outcome == nil {
				continue
			}
			if fieldStr(rec.Detection, "event_kind") == "detection" &&
				fieldStr(rec.Outcome, "event_kind") == "outcome" &&
				fieldStr(rec.Outcome, "action") == "applied" {
				return true
			}
		}
		return false
	}, 15*time.Second)

	require.True(t, ok, "detection+outcome pair with action=applied must appear at controller within 15 s")

	// Verify the file was actually fixed.
	content, err := os.ReadFile(filePath)
	require.NoError(t, err)
	assert.Equal(t, "desired content\n", string(content))
}

// ---------------------------------------------------------------------------
// AC-2: script_output event reaches controller with exit-code + duration
// ---------------------------------------------------------------------------

func (env *streamEnv) testScriptOutputEvent(t *testing.T) {
	// Replicate the fields that commands.Handler.emitScriptOutput would produce
	// (private function; the production redaction chain is applied manually here
	// to verify the wire format and controller-side storage).
	stdout := logging.SanitizeLogValue(audit.RedactString("script completed OK"))
	stderr := logging.SanitizeLogValue(audit.RedactString(""))

	rawFields := map[string]interface{}{
		"event_kind":   "script_output",
		"cfg_id":       "e2e-cmd-001",
		"execution_id": "e2e-exec-001",
		"exit_code":    "0",
		"duration_ms":  "42",
		"stdout":       stdout,
		"stderr":       stderr,
	}
	redacted := audit.RedactMap(rawFields)
	pbFields := make(map[string]string, len(redacted))
	for k, v := range redacted {
		if sv, ok := v.(string); ok {
			pbFields[k] = sv
		}
	}

	env.emitter.Enqueue(&transportpb.LogEntry{
		StewardId: env.stewardID,
		Level:     transportpb.Severity_SEVERITY_INFO,
		Message:   "script_output",
		Timestamp: timestamppb.Now(),
		Fields:    pbFields,
	})

	ok := env.pollLogs(func(records []streamLogRecord) bool {
		for _, rec := range records {
			if rec.Detection == nil {
				continue
			}
			evt := rec.Detection
			if evt.Message != "script_output" {
				continue
			}
			if fieldStr(evt, "event_kind") == "script_output" &&
				fieldStr(evt, "exit_code") == "0" &&
				fieldStr(evt, "duration_ms") == "42" {
				return true
			}
		}
		return false
	}, 10*time.Second)

	require.True(t, ok, "script_output event with exit_code=0 and duration_ms=42 must appear at controller")
}

// ---------------------------------------------------------------------------
// AC-3 negative: spoofed steward_id (CN-mismatch) is rejected
// ---------------------------------------------------------------------------

func (env *streamEnv) testNegativeSpoofedStewardRejected(t *testing.T) {
	// Open LogStream using the real steward cert (CN = env.stewardID) but send
	// an entry claiming to be from a different steward. The handler must
	// return PermissionDenied.
	stream, err := env.controlPlane.TransportClient().LogStream(env.ctx)
	require.NoError(t, err)

	sendErr := stream.Send(&transportpb.LogEntry{
		StewardId: "spoofed-steward-id-that-does-not-match-cn",
		Level:     transportpb.Severity_SEVERITY_INFO,
		Message:   "spoofed event",
		Timestamp: timestamppb.Now(),
	})

	// The error may surface on Send or on CloseAndRecv depending on gRPC buffering.
	var recvErr error
	if sendErr == nil {
		_, recvErr = stream.CloseAndRecv()
	} else {
		recvErr = sendErr
	}

	require.Error(t, recvErr, "CN-mismatched event must be rejected")
	assert.Equal(t, codes.PermissionDenied, status.Code(recvErr),
		"CN-mismatch must return PermissionDenied, got %v", recvErr)
}

// ---------------------------------------------------------------------------
// AC-4 negative: secret in script output is [REDACTED] at controller
// ---------------------------------------------------------------------------

func (env *streamEnv) testNegativeSecretRedacted(t *testing.T) {
	// Simulate the full redaction chain from commands.Handler.emitScriptOutput.
	// The plaintext contains a recognisable secret pattern; RedactString must
	// replace the value with [REDACTED] before the LogEntry reaches the wire.
	rawStdout := "output: password=super-secret-value\n"
	redactedStdout := logging.SanitizeLogValue(audit.RedactString(rawStdout))

	rawFields := map[string]interface{}{
		"event_kind":   "script_output",
		"cfg_id":       "e2e-secret-test",
		"execution_id": "e2e-secret-exec",
		"exit_code":    "0",
		"duration_ms":  "1",
		"stdout":       redactedStdout,
		"stderr":       "",
	}
	redacted := audit.RedactMap(rawFields)
	pbFields := make(map[string]string, len(redacted))
	for k, v := range redacted {
		if sv, ok := v.(string); ok {
			pbFields[k] = sv
		}
	}

	env.emitter.Enqueue(&transportpb.LogEntry{
		StewardId: env.stewardID,
		Level:     transportpb.Severity_SEVERITY_INFO,
		Message:   "script_output",
		Timestamp: timestamppb.Now(),
		Fields:    pbFields,
	})

	ok := env.pollLogs(func(records []streamLogRecord) bool {
		for _, rec := range records {
			if rec.Detection == nil {
				continue
			}
			evt := rec.Detection
			if fieldStr(evt, "cfg_id") != "e2e-secret-test" {
				continue
			}
			stdout := fieldStr(evt, "stdout")
			// The plaintext secret must not be present; [REDACTED] must be.
			if stdout == "" {
				return false
			}
			assert.NotContains(t, stdout, "super-secret-value",
				"plaintext secret must not reach controller")
			assert.Contains(t, stdout, "[REDACTED]",
				"redacted placeholder must be present in stdout at controller")
			return true
		}
		return false
	}, 10*time.Second)

	require.True(t, ok, "script_output event cfg_id=e2e-secret-test must appear at controller within 10 s")
}

// ---------------------------------------------------------------------------
// AC-5: hung module → did-not-finish(timeout) outcome correlated to detection
// ---------------------------------------------------------------------------

func (env *streamEnv) testHungModuleTimeout(t *testing.T) {
	// Register the hung module under a unique name so it does not conflict with
	// other executor instances that may exist in the same process.
	f := stfactory.New(discovery.ModuleRegistry{}, stewardconfig.ErrorHandlingConfig{
		ResourceFailure:   stewardconfig.ActionContinue,
		ModuleLoadFailure: stewardconfig.ActionContinue,
	}, logging.ForModule("e2e-hung"))
	f.RegisterModule("hung-e2e", &hungModuleE2E{})

	// Short timeout so the test completes quickly: 2 s is enough to observe the
	// timeout event without making the test suite slow.
	executor, err := execution.NewExecutor(&execution.ExecutorConfig{
		StewardID:            env.stewardID,
		Logger:               logging.ForModule("e2e-hung-executor"),
		EventEmitter:         env.emitter,
		Factory:              f,
		DriftMode:            stewardconfig.DriftModeApply,
		ModuleCallTimeoutSec: 2,
	})
	require.NoError(t, err)

	resource := stewardconfig.ResourceConfig{
		Name:   "e2e-hung-resource",
		Module: "hung-e2e",
		Config: map[string]interface{}{"dummy": "value"},
	}

	// Run in a goroutine because ExecuteResource blocks until timeout.
	done := make(chan struct{})
	go func() {
		defer close(done)
		executor.ExecuteResource(env.ctx, resource)
	}()

	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("ExecuteResource on hung module did not return within 15 s")
	}

	// Poll for detection+outcome pair where outcome.action == "did-not-finish(timeout)".
	ok := env.pollLogs(func(records []streamLogRecord) bool {
		for _, rec := range records {
			if rec.CorrelationID == "" || rec.Detection == nil || rec.Outcome == nil {
				continue
			}
			if fieldStr(rec.Detection, "event_kind") == "detection" &&
				fieldStr(rec.Outcome, "action") == "did-not-finish(timeout)" {
				return true
			}
		}
		return false
	}, 15*time.Second)

	require.True(t, ok, "did-not-finish(timeout) outcome correlated to detection must appear at controller")
}
