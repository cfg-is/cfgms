// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package commands

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/pkg/cert"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// ---------------------------------------------------------------------------
// In-memory CommandStore for tests (real implementation, no mocks)
// ---------------------------------------------------------------------------

// memCommandStore is a minimal in-memory CommandStore backed by maps.
// It is a real implementation — not a mock.
type memCommandStore struct {
	mu          sync.Mutex
	records     map[string]*business.CommandRecord
	transitions map[string][]*business.CommandTransition

	// updateErr, if non-nil, is returned by UpdateCommandStatus calls.
	// Used for error-path testing.
	updateErr error
}

func newMemCommandStore() *memCommandStore {
	return &memCommandStore{
		records:     make(map[string]*business.CommandRecord),
		transitions: make(map[string][]*business.CommandTransition),
	}
}

func (m *memCommandStore) CreateCommandRecord(_ context.Context, rec *business.CommandRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if rec == nil {
		return fmt.Errorf("record is nil")
	}
	if rec.ID == "" {
		return business.ErrCommandIDRequired
	}
	if rec.StewardID == "" {
		return business.ErrCommandStewardIDRequired
	}
	if _, exists := m.records[rec.ID]; exists {
		return fmt.Errorf("duplicate command ID: %s", rec.ID)
	}
	cp := *rec
	cp.Status = business.CommandStatusPending
	if cp.IssuedAt.IsZero() {
		cp.IssuedAt = time.Now()
	}
	m.records[rec.ID] = &cp
	m.transitions[rec.ID] = append(m.transitions[rec.ID], &business.CommandTransition{
		CommandID: rec.ID,
		Status:    business.CommandStatusPending,
		Timestamp: cp.IssuedAt,
	})
	return nil
}

func (m *memCommandStore) UpdateCommandStatus(_ context.Context, id string, status business.CommandStatus, result map[string]interface{}, errMsg string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.updateErr != nil {
		return m.updateErr
	}
	rec, ok := m.records[id]
	if !ok {
		return business.ErrCommandNotFound
	}
	rec.Status = status
	rec.ErrorMessage = errMsg
	rec.Result = result
	now := time.Now()
	switch status {
	case business.CommandStatusExecuting:
		rec.StartedAt = &now
	case business.CommandStatusCompleted, business.CommandStatusFailed, business.CommandStatusCancelled:
		rec.CompletedAt = &now
	}
	m.transitions[id] = append(m.transitions[id], &business.CommandTransition{
		CommandID:    id,
		Status:       status,
		Timestamp:    now,
		ErrorMessage: errMsg,
	})
	return nil
}

func (m *memCommandStore) GetCommandRecord(_ context.Context, id string) (*business.CommandRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.records[id]
	if !ok {
		return nil, business.ErrCommandNotFound
	}
	cp := *rec
	return &cp, nil
}

func (m *memCommandStore) ListCommandRecords(_ context.Context, filter *business.CommandFilter) ([]*business.CommandRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*business.CommandRecord
	for _, rec := range m.records {
		if filter != nil {
			if filter.Status != "" && rec.Status != filter.Status {
				continue
			}
			if filter.StewardID != "" && rec.StewardID != filter.StewardID {
				continue
			}
		}
		cp := *rec
		out = append(out, &cp)
	}
	return out, nil
}

func (m *memCommandStore) ListCommandsByDevice(ctx context.Context, stewardID string) ([]*business.CommandRecord, error) {
	return m.ListCommandRecords(ctx, &business.CommandFilter{StewardID: stewardID})
}

func (m *memCommandStore) ListCommandsByStatus(ctx context.Context, status business.CommandStatus) ([]*business.CommandRecord, error) {
	return m.ListCommandRecords(ctx, &business.CommandFilter{Status: status})
}

func (m *memCommandStore) GetCommandAuditTrail(_ context.Context, commandID string) ([]*business.CommandTransition, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	transitions := m.transitions[commandID]
	out := make([]*business.CommandTransition, len(transitions))
	copy(out, transitions)
	return out, nil
}

func (m *memCommandStore) PurgeExpiredRecords(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}

func (m *memCommandStore) HealthCheck(_ context.Context) error { return nil }
func (m *memCommandStore) Close() error                        { return nil }

// Compile-time assertion.
var _ business.CommandStore = (*memCommandStore)(nil)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func newTestLogger(t *testing.T) logging.Logger {
	t.Helper()
	return logging.NewLogger("debug")
}

func noopStatus(_ context.Context, _ *cpTypes.Event) {}

// newTestHandler builds a Handler with no signature verifier (verification skipped).
func newTestHandler(t *testing.T, store business.CommandStore) *Handler {
	t.Helper()
	h, err := New(&Config{
		StewardID: "steward-test",
		OnStatus:  noopStatus,
		Logger:    newTestLogger(t),
		Store:     store,
	})
	require.NoError(t, err)
	return h
}

// newTestSignerVerifier returns a real Signer + Verifier pair backed by a fresh
// in-process CA. No mocks — real cryptographic operations.
func newTestSignerVerifier(t *testing.T) (signature.Signer, signature.Verifier) {
	t.Helper()
	ca, err := cert.NewCA(&cert.CAConfig{
		Organization: "CFGMS Test",
		Country:      "US",
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)
	require.NoError(t, ca.Initialize(nil))

	sc, err := ca.GenerateServerCertificate(&cert.ServerCertConfig{
		CommonName:   "controller.test",
		DNSNames:     []string{"controller.test"},
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)

	signer, err := signature.NewSigner(&signature.SignerConfig{
		PrivateKeyPEM:  sc.PrivateKeyPEM,
		CertificatePEM: sc.CertificatePEM,
	})
	require.NoError(t, err)

	verifier, err := signature.NewVerifier(&signature.VerifierConfig{
		CertificatePEM: sc.CertificatePEM,
	})
	require.NoError(t, err)

	return signer, verifier
}

// newTestHandlerWithVerifier builds a Handler with a real Verifier.
func newTestHandlerWithVerifier(t *testing.T, store business.CommandStore, verifier signature.Verifier) *Handler {
	t.Helper()
	h, err := New(&Config{
		StewardID:    "steward-test",
		OnStatus:     noopStatus,
		Logger:       newTestLogger(t),
		Store:        store,
		Verifier:     verifier,
		ReplayWindow: 5 * time.Minute,
	})
	require.NoError(t, err)
	return h
}

// testSignedCommand builds a SignedCommand with no signature (used when verifier is nil).
func testSignedCommand(id string, cmdType cpTypes.CommandType) *cpTypes.SignedCommand {
	return &cpTypes.SignedCommand{
		Command: cpTypes.Command{
			ID:        id,
			Type:      cmdType,
			StewardID: "steward-test",
			Timestamp: time.Now(),
			Params:    map[string]interface{}{},
		},
	}
}

// signTestCommand signs cmd with signer using the canonical signing form.
func signTestCommand(t *testing.T, signer signature.Signer, cmd *cpTypes.Command) *cpTypes.SignedCommand {
	t.Helper()
	rawParams := cpTypes.InterfaceParamsToStringMap(cmd.Params)
	cmdBytes, err := cpTypes.CommandSigningBytes(cmd, rawParams)
	require.NoError(t, err)
	sig, err := signer.Sign(cmdBytes)
	require.NoError(t, err)
	return &cpTypes.SignedCommand{Command: *cmd, Signature: sig}
}

// ---------------------------------------------------------------------------
// Constructor tests
// ---------------------------------------------------------------------------

func TestNew_RequiresStewardID(t *testing.T) {
	_, err := New(&Config{
		OnStatus: noopStatus,
		Logger:   newTestLogger(t),
	})
	require.Error(t, err)
}

func TestNew_RequiresOnStatus(t *testing.T) {
	_, err := New(&Config{
		StewardID: "s1",
		Logger:    newTestLogger(t),
	})
	require.Error(t, err)
}

func TestNew_RequiresLogger(t *testing.T) {
	_, err := New(&Config{
		StewardID: "s1",
		OnStatus:  noopStatus,
	})
	require.Error(t, err)
}

func TestNew_NilStoreAllowed(t *testing.T) {
	h, err := New(&Config{
		StewardID: "s1",
		OnStatus:  noopStatus,
		Logger:    newTestLogger(t),
		Store:     nil,
	})
	require.NoError(t, err)
	assert.NotNil(t, h)
}

// ---------------------------------------------------------------------------
// Startup sweep test
// ---------------------------------------------------------------------------

func TestNew_SweepsStaleExecutingCommands(t *testing.T) {
	store := newMemCommandStore()
	ctx := context.Background()

	// Pre-populate an executing record to simulate a crashed previous run.
	rec := &business.CommandRecord{
		ID:        "stale-cmd",
		Type:      "sync_config",
		StewardID: "steward-test",
	}
	require.NoError(t, store.CreateCommandRecord(ctx, rec))
	require.NoError(t, store.UpdateCommandStatus(ctx, "stale-cmd",
		business.CommandStatusExecuting, nil, ""))

	// Creating the handler should trigger the startup sweep.
	_, err := New(&Config{
		StewardID: "steward-test",
		OnStatus:  noopStatus,
		Logger:    newTestLogger(t),
		Store:     store,
	})
	require.NoError(t, err)

	got, err := store.GetCommandRecord(ctx, "stale-cmd")
	require.NoError(t, err)
	assert.Equal(t, business.CommandStatusFailed, got.Status)
	assert.Equal(t, "controller_restart", got.ErrorMessage)
}

// ---------------------------------------------------------------------------
// HandleCommand / executeCommand tests (no verifier — skip signature check)
// Use h.Wait() for deterministic synchronization — no time.Sleep.
// ---------------------------------------------------------------------------

func TestHandleCommand_PersistsRecord(t *testing.T) {
	store := newMemCommandStore()
	h := newTestHandler(t, store)
	ctx := context.Background()

	sc := testSignedCommand("hc-001", cpTypes.CommandSyncConfig)

	h.RegisterHandler(cpTypes.CommandSyncConfig, func(ctx context.Context, c *cpTypes.Command) error {
		return nil
	})

	require.NoError(t, h.HandleCommand(ctx, sc))
	h.Wait()

	got, err := store.GetCommandRecord(ctx, "hc-001")
	require.NoError(t, err)
	assert.Equal(t, business.CommandStatusCompleted, got.Status)
}

func TestHandleCommand_NoHandlerMarkedFailed(t *testing.T) {
	store := newMemCommandStore()
	h := newTestHandler(t, store)
	ctx := context.Background()

	sc := testSignedCommand("hc-002", cpTypes.CommandSyncConfig)
	require.NoError(t, h.HandleCommand(ctx, sc))
	h.Wait()

	got, err := store.GetCommandRecord(ctx, "hc-002")
	require.NoError(t, err)
	assert.Equal(t, business.CommandStatusFailed, got.Status)
}

func TestHandleCommand_HandlerErrorMarkedFailed(t *testing.T) {
	store := newMemCommandStore()
	h := newTestHandler(t, store)
	ctx := context.Background()

	h.RegisterHandler(cpTypes.CommandSyncConfig, func(ctx context.Context, c *cpTypes.Command) error {
		return fmt.Errorf("something went wrong")
	})

	sc := testSignedCommand("hc-003", cpTypes.CommandSyncConfig)
	require.NoError(t, h.HandleCommand(ctx, sc))
	h.Wait()

	got, err := store.GetCommandRecord(ctx, "hc-003")
	require.NoError(t, err)
	assert.Equal(t, business.CommandStatusFailed, got.Status)
	assert.Contains(t, got.ErrorMessage, "something went wrong")
}

// ---------------------------------------------------------------------------
// UpdateCommandStatus error-path tests
// ---------------------------------------------------------------------------

func TestHandleCommand_StoreUpdateErrorOnExecuting_DoesNotPanic(t *testing.T) {
	store := newMemCommandStore()
	store.updateErr = fmt.Errorf("store unavailable")

	h := newTestHandler(t, store)
	ctx := context.Background()

	h.RegisterHandler(cpTypes.CommandSyncConfig, func(ctx context.Context, c *cpTypes.Command) error {
		return nil
	})

	sc := testSignedCommand("err-001", cpTypes.CommandSyncConfig)
	require.NoError(t, h.HandleCommand(ctx, sc))
	h.Wait()
}

func TestHandleCommand_StoreUpdateErrorOnFailed_DoesNotPanic(t *testing.T) {
	store := newMemCommandStore()
	store.updateErr = fmt.Errorf("store unavailable")

	h := newTestHandler(t, store)
	ctx := context.Background()
	sc := testSignedCommand("err-002", cpTypes.CommandSyncConfig)
	require.NoError(t, h.HandleCommand(ctx, sc))
	h.Wait()
}

func TestHandleCommand_StoreUpdateErrorOnCompleted_DoesNotPanic(t *testing.T) {
	store := newMemCommandStore()
	store.updateErr = fmt.Errorf("store unavailable")

	h := newTestHandler(t, store)
	ctx := context.Background()

	h.RegisterHandler(cpTypes.CommandSyncConfig, func(ctx context.Context, c *cpTypes.Command) error {
		return nil
	})

	sc := testSignedCommand("err-003", cpTypes.CommandSyncConfig)
	require.NoError(t, h.HandleCommand(ctx, sc))
	h.Wait()
}

// ---------------------------------------------------------------------------
// executionContext retains only CancelFunc — behavioral verification
// ---------------------------------------------------------------------------

func TestExecutionContext_CancelFuncIsInvokable(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ec := &executionContext{Cancel: cancel}

	select {
	case <-ctx.Done():
		t.Fatal("context should not be done before Cancel() is called")
	default:
	}

	ec.Cancel()

	select {
	case <-ctx.Done():
		// expected
	case <-time.After(100 * time.Millisecond):
		t.Fatal("context was not cancelled after executionContext.Cancel() was called")
	}
}

// ---------------------------------------------------------------------------
// Story #919: Authentication rejection path tests
// ---------------------------------------------------------------------------

func TestHandleCommand_NilSignedCommand_ReturnsErrUnauthenticated(t *testing.T) {
	h := newTestHandler(t, nil)
	ctx := context.Background()
	err := h.HandleCommand(ctx, nil)
	require.ErrorIs(t, err, ErrUnauthenticatedCommand)
}

func TestHandleCommand_VerifierSet_MissingSignature_ReturnsErrUnauthenticated(t *testing.T) {
	_, verifier := newTestSignerVerifier(t)
	h := newTestHandlerWithVerifier(t, nil, verifier)
	ctx := context.Background()

	sc := &cpTypes.SignedCommand{
		Command: cpTypes.Command{
			ID:        "auth-001",
			Type:      cpTypes.CommandSyncConfig,
			StewardID: "steward-test",
			Timestamp: time.Now(),
		},
		Signature: nil,
	}
	err := h.HandleCommand(ctx, sc)
	require.ErrorIs(t, err, ErrUnauthenticatedCommand)
}

func TestHandleCommand_VerifierSet_BadSignature_ReturnsErrUnauthenticated(t *testing.T) {
	signer, verifier := newTestSignerVerifier(t)
	h := newTestHandlerWithVerifier(t, nil, verifier)
	ctx := context.Background()

	cmd := &cpTypes.Command{
		ID:        "auth-002",
		Type:      cpTypes.CommandSyncConfig,
		StewardID: "steward-test",
		Timestamp: time.Now(),
	}
	sc := signTestCommand(t, signer, cmd)
	// Corrupt the signature bytes.
	sc.Signature.Signature = "AAAAAAAAAA=="

	err := h.HandleCommand(ctx, sc)
	require.ErrorIs(t, err, ErrUnauthenticatedCommand)
}

func TestHandleCommand_WrongStewardID_ReturnsErrWrongSteward(t *testing.T) {
	h := newTestHandler(t, nil)
	ctx := context.Background()

	sc := &cpTypes.SignedCommand{
		Command: cpTypes.Command{
			ID:        "auth-003",
			Type:      cpTypes.CommandSyncConfig,
			StewardID: "other-steward", // mismatch with handler's "steward-test"
			Timestamp: time.Now(),
		},
	}
	err := h.HandleCommand(ctx, sc)
	require.ErrorIs(t, err, ErrWrongSteward)
}

func TestHandleCommand_ExpiredTimestamp_ReturnsErrCommandReplay(t *testing.T) {
	h := newTestHandler(t, nil) // replayWindow defaults to 5 min
	ctx := context.Background()

	sc := &cpTypes.SignedCommand{
		Command: cpTypes.Command{
			ID:        "auth-004",
			Type:      cpTypes.CommandSyncConfig,
			StewardID: "steward-test",
			Timestamp: time.Now().Add(-10 * time.Minute), // 10 min > 5 min window
		},
	}
	err := h.HandleCommand(ctx, sc)
	require.ErrorIs(t, err, ErrCommandReplay)
}

func TestHandleCommand_DuplicateID_ReturnsErrCommandReplay(t *testing.T) {
	h := newTestHandler(t, nil)
	ctx := context.Background()

	h.RegisterHandler(cpTypes.CommandSyncConfig, func(ctx context.Context, c *cpTypes.Command) error {
		return nil
	})

	sc := testSignedCommand("dup-001", cpTypes.CommandSyncConfig)

	// First delivery succeeds.
	require.NoError(t, h.HandleCommand(ctx, sc))
	h.Wait()

	// Second delivery of same ID is a replay.
	err := h.HandleCommand(ctx, sc)
	require.ErrorIs(t, err, ErrCommandReplay)
}

func TestHandleCommand_ParamsTooLarge_ReturnsErrParamsTooLarge(t *testing.T) {
	h, err := New(&Config{
		StewardID:      "steward-test",
		OnStatus:       noopStatus,
		Logger:         newTestLogger(t),
		MaxParamsBytes: 16, // tiny limit for testing
	})
	require.NoError(t, err)
	ctx := context.Background()

	sc := &cpTypes.SignedCommand{
		Command: cpTypes.Command{
			ID:        "big-001",
			Type:      cpTypes.CommandSyncConfig,
			StewardID: "steward-test",
			Timestamp: time.Now(),
			Params: map[string]interface{}{
				"data": "this-string-is-definitely-longer-than-16-bytes",
			},
		},
	}
	handlerErr := h.HandleCommand(ctx, sc)
	require.ErrorIs(t, handlerErr, ErrParamsTooLarge)
}

func TestHandleCommand_ValidSignedCommand_Dispatches(t *testing.T) {
	signer, verifier := newTestSignerVerifier(t)
	h := newTestHandlerWithVerifier(t, nil, verifier)
	ctx := context.Background()

	dispatched := make(chan struct{}, 1)
	h.RegisterHandler(cpTypes.CommandSyncConfig, func(ctx context.Context, c *cpTypes.Command) error {
		dispatched <- struct{}{}
		return nil
	})

	cmd := &cpTypes.Command{
		ID:        "valid-001",
		Type:      cpTypes.CommandSyncConfig,
		StewardID: "steward-test",
		Timestamp: time.Now(),
	}
	sc := signTestCommand(t, signer, cmd)

	require.NoError(t, h.HandleCommand(ctx, sc))
	h.Wait()

	select {
	case <-dispatched:
		// expected
	case <-time.After(time.Second):
		t.Fatal("handler was not dispatched for a valid signed command")
	}
}

func TestHandleCommand_NilStore_StillWorks(t *testing.T) {
	h := newTestHandler(t, nil)
	ctx := context.Background()

	h.RegisterHandler(cpTypes.CommandSyncConfig, func(ctx context.Context, c *cpTypes.Command) error {
		return nil
	})

	sc := testSignedCommand("no-store-001", cpTypes.CommandSyncConfig)
	require.NoError(t, h.HandleCommand(ctx, sc))
	h.Wait()
}

// ---------------------------------------------------------------------------
// capturingLogger — real Logger implementation that records every log call.
// Used by execute_script security tests to assert on handler log output.
// ---------------------------------------------------------------------------

type capturingLogger struct {
	mu    sync.Mutex
	lines []string // all logged lines (message + all key-value args as strings)
}

func (l *capturingLogger) record(msg string, keysAndValues ...interface{}) {
	parts := []string{msg}
	for _, v := range keysAndValues {
		parts = append(parts, fmt.Sprintf("%v", v))
	}
	l.mu.Lock()
	l.lines = append(l.lines, strings.Join(parts, " "))
	l.mu.Unlock()
}

func (l *capturingLogger) Lines() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, len(l.lines))
	copy(out, l.lines)
	return out
}

func (l *capturingLogger) Debug(msg string, kv ...interface{}) { l.record(msg, kv...) }
func (l *capturingLogger) Info(msg string, kv ...interface{})  { l.record(msg, kv...) }
func (l *capturingLogger) Warn(msg string, kv ...interface{})  { l.record(msg, kv...) }
func (l *capturingLogger) Error(msg string, kv ...interface{}) { l.record(msg, kv...) }
func (l *capturingLogger) Fatal(msg string, kv ...interface{}) { l.record(msg, kv...) }

func (l *capturingLogger) DebugCtx(_ context.Context, msg string, kv ...interface{}) {
	l.record(msg, kv...)
}
func (l *capturingLogger) InfoCtx(_ context.Context, msg string, kv ...interface{}) {
	l.record(msg, kv...)
}
func (l *capturingLogger) WarnCtx(_ context.Context, msg string, kv ...interface{}) {
	l.record(msg, kv...)
}
func (l *capturingLogger) ErrorCtx(_ context.Context, msg string, kv ...interface{}) {
	l.record(msg, kv...)
}
func (l *capturingLogger) FatalCtx(_ context.Context, msg string, kv ...interface{}) {
	l.record(msg, kv...)
}

var _ logging.Logger = (*capturingLogger)(nil)

// collectEvents returns a StatusCallback + a function that returns all collected events.
func collectEvents() (StatusCallback, func() []*cpTypes.Event) {
	var mu sync.Mutex
	var events []*cpTypes.Event
	cb := func(_ context.Context, e *cpTypes.Event) {
		mu.Lock()
		events = append(events, e)
		mu.Unlock()
	}
	get := func() []*cpTypes.Event {
		mu.Lock()
		defer mu.Unlock()
		out := make([]*cpTypes.Event, len(events))
		copy(out, events)
		return out
	}
	return cb, get
}

// firstEventOfType returns the first event with the given type, or nil.
func firstEventOfType(events []*cpTypes.Event, typ cpTypes.EventType) *cpTypes.Event {
	for _, e := range events {
		if e.Type == typ {
			return e
		}
	}
	return nil
}

// testSignedCommandWithParams builds a SignedCommand with custom params (no signature).
func testSignedCommandWithParams(id string, cmdType cpTypes.CommandType, params map[string]interface{}) *cpTypes.SignedCommand {
	return &cpTypes.SignedCommand{
		Command: cpTypes.Command{
			ID:        id,
			Type:      cmdType,
			StewardID: "steward-test",
			Timestamp: time.Now(),
			Params:    params,
		},
	}
}

// ---------------------------------------------------------------------------
// execute_script handler tests
// ---------------------------------------------------------------------------

// platformShell returns the shell name the execute_script handler tests should use on
// the current OS. bash is unavailable on Windows, so Windows runners use powershell;
// both shells are recognised by script.ShellType and the script-module executor.
func platformShell() string {
	if runtime.GOOS == "windows" {
		return "powershell"
	}
	return "bash"
}

// echoScriptBody returns a script body that writes s (followed by a newline) to stdout,
// using the syntax of the current platform's shell (see platformShell).
func echoScriptBody(s string) string {
	if runtime.GOOS == "windows" {
		return "Write-Output '" + s + "'"
	}
	return "echo '" + s + "'"
}

// exitScriptBody returns a script body that terminates with the given exit code.
// The `exit N` syntax is identical in bash and PowerShell.
func exitScriptBody(code int) string {
	return fmt.Sprintf("exit %d", code)
}

// fixedSizeStdoutScriptBody returns a script body that writes exactly totalBytes bytes
// to stdout with no trailing newline. totalBytes must be a multiple of 10.
func fixedSizeStdoutScriptBody(totalBytes int) string {
	chunks := totalBytes / 10
	if runtime.GOOS == "windows" {
		return fmt.Sprintf("for ($i=0; $i -lt %d; $i++) { [Console]::Out.Write('AAAAAAAAAA') }", chunks)
	}
	return fmt.Sprintf("i=0; while [ $i -lt %d ]; do printf 'AAAAAAAAAA'; i=$((i+1)); done", chunks)
}

// TestExecuteScriptHandler_Success verifies that a zero-exit script produces
// EventScriptCompleted with exit_code 0 and the expected stdout_preview content.
func TestExecuteScriptHandler_Success(t *testing.T) {
	cb, getEvents := collectEvents()
	h, err := New(&Config{
		StewardID: "steward-test",
		OnStatus:  cb,
		Logger:    newTestLogger(t),
	})
	require.NoError(t, err)
	h.RegisterExecuteScriptHandler()

	scriptContent := base64.StdEncoding.EncodeToString([]byte(echoScriptBody("hello")))
	sc := testSignedCommandWithParams("es-001", cpTypes.CommandExecuteScript, map[string]interface{}{
		"script_content": scriptContent,
		"shell":          platformShell(),
		"execution_id":   "exec-001",
	})

	require.NoError(t, h.HandleCommand(context.Background(), sc))
	h.Wait()

	evt := firstEventOfType(getEvents(), cpTypes.EventScriptCompleted)
	require.NotNil(t, evt, "expected EventScriptCompleted event")
	assert.Equal(t, "steward-test", evt.StewardID)
	assert.Equal(t, "es-001", evt.CommandID)

	exitCode, ok := evt.Details["exit_code"].(int)
	require.True(t, ok, "exit_code must be an int")
	assert.Equal(t, 0, exitCode)

	stdoutPreview, ok := evt.Details["stdout_preview"].(string)
	require.True(t, ok, "stdout_preview must be a string")
	assert.Contains(t, stdoutPreview, "hello")
}

// TestExecuteScriptHandler_NonZeroExitCode verifies that a script exiting non-zero
// still produces EventScriptCompleted (not EventCommandFailed) with the actual exit code.
func TestExecuteScriptHandler_NonZeroExitCode(t *testing.T) {
	cb, getEvents := collectEvents()
	h, err := New(&Config{
		StewardID: "steward-test",
		OnStatus:  cb,
		Logger:    newTestLogger(t),
	})
	require.NoError(t, err)
	h.RegisterExecuteScriptHandler()

	// Script exits with code 42.
	scriptContent := base64.StdEncoding.EncodeToString([]byte(exitScriptBody(42)))
	sc := testSignedCommandWithParams("es-002", cpTypes.CommandExecuteScript, map[string]interface{}{
		"script_content": scriptContent,
		"shell":          platformShell(),
		"execution_id":   "exec-002",
	})

	require.NoError(t, h.HandleCommand(context.Background(), sc))
	h.Wait()

	events := getEvents()

	// Must emit EventScriptCompleted, not EventCommandFailed.
	failEvt := firstEventOfType(events, cpTypes.EventCommandFailed)
	assert.Nil(t, failEvt, "non-zero exit should not produce EventCommandFailed")

	evt := firstEventOfType(events, cpTypes.EventScriptCompleted)
	require.NotNil(t, evt, "expected EventScriptCompleted event")

	exitCode, ok := evt.Details["exit_code"].(int)
	require.True(t, ok, "exit_code must be an int")
	assert.Equal(t, 42, exitCode)
}

// TestExecuteScriptHandler_StdoutTruncated verifies that stdout longer than 4096 bytes
// is silently truncated to exactly 4096 bytes in the stdout_preview.
func TestExecuteScriptHandler_StdoutTruncated(t *testing.T) {
	cb, getEvents := collectEvents()
	h, err := New(&Config{
		StewardID: "steward-test",
		OnStatus:  cb,
		Logger:    newTestLogger(t),
	})
	require.NoError(t, err)
	h.RegisterExecuteScriptHandler()

	// Generate >4096 bytes of output (500 iterations × 10 bytes = 5000 bytes).
	scriptBody := fixedSizeStdoutScriptBody(5000)
	scriptContent := base64.StdEncoding.EncodeToString([]byte(scriptBody))
	sc := testSignedCommandWithParams("es-003", cpTypes.CommandExecuteScript, map[string]interface{}{
		"script_content": scriptContent,
		"shell":          platformShell(),
		"execution_id":   "exec-003",
	})

	require.NoError(t, h.HandleCommand(context.Background(), sc))
	h.Wait()

	evt := firstEventOfType(getEvents(), cpTypes.EventScriptCompleted)
	require.NotNil(t, evt, "expected EventScriptCompleted event")

	stdoutPreview, ok := evt.Details["stdout_preview"].(string)
	require.True(t, ok, "stdout_preview must be a string")
	assert.Equal(t, scriptPreviewMaxBytes, len(stdoutPreview),
		"stdout_preview must be exactly %d bytes", scriptPreviewMaxBytes)
}

// TestExecuteScriptHandler_NoContentLogged verifies that no log line emitted by the
// execute_script handler — including the script executor's own logger which writes to
// os.Stdout — contains raw script content, stdout output, or stderr output.
func TestExecuteScriptHandler_NoContentLogged(t *testing.T) {
	// Capture the handler's structured logs via capturingLogger.
	capLog := &capturingLogger{}
	cb, _ := collectEvents()

	h, err := New(&Config{
		StewardID: "steward-test",
		OnStatus:  cb,
		Logger:    capLog,
	})
	require.NoError(t, err)
	h.RegisterExecuteScriptHandler()

	// Redirect os.Stdout to capture the script executor's internal logger output
	// (script.NewExecutor creates its own logging.NewLogger("info") that writes to Stdout).
	origStdout := os.Stdout
	r, w, pipeErr := os.Pipe()
	require.NoError(t, pipeErr)
	os.Stdout = w

	// Use a recognizable marker that would be visible in logs if content were leaked.
	secretMarker := "CFGMS_SECRET_MARKER_XYZ_12345"
	scriptBody := echoScriptBody(secretMarker)
	scriptContent := base64.StdEncoding.EncodeToString([]byte(scriptBody))

	sc := testSignedCommandWithParams("es-004", cpTypes.CommandExecuteScript, map[string]interface{}{
		"script_content": scriptContent,
		"shell":          platformShell(),
		"execution_id":   "exec-004",
	})

	require.NoError(t, h.HandleCommand(context.Background(), sc))
	h.Wait()

	// Restore stdout and read captured output.
	require.NoError(t, w.Close())
	os.Stdout = origStdout
	stdoutBytes, readErr := io.ReadAll(r)
	require.NoError(t, readErr)
	allOutput := string(stdoutBytes)

	// Assert handler's own structured log lines.
	for _, line := range capLog.Lines() {
		assert.NotContains(t, line, scriptBody,
			"handler log line must not contain script body: %q", line)
		assert.NotContains(t, line, secretMarker,
			"handler log line must not contain stdout marker: %q", line)
	}

	// Assert captured os.Stdout output (executor's logger writes here).
	assert.NotContains(t, allOutput, scriptBody,
		"executor stdout log must not contain script body")
	assert.NotContains(t, allOutput, secretMarker,
		"executor stdout log must not contain stdout marker (script output)")
}
