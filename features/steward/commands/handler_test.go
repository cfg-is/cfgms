// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package commands

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/features/modules/stdlib/script"
	"github.com/cfgis/cfgms/pkg/cert"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/operatorpayload"
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
	if cp.DeliveryStatus == "" {
		cp.DeliveryStatus = business.DeliveryStatusPending
	}
	m.records[rec.ID] = &cp
	m.transitions[rec.ID] = append(m.transitions[rec.ID], &business.CommandTransition{
		CommandID: rec.ID,
		Status:    business.CommandStatusPending,
		Timestamp: cp.IssuedAt,
	})
	return nil
}

func (m *memCommandStore) CreateCommandRecords(ctx context.Context, records []*business.CommandRecord) error {
	// Real (non-mocked) atomic-batch semantics: validate every record before
	// writing any of them, so a mid-batch failure leaves nothing committed —
	// matching the SQL providers' single-transaction behavior.
	m.mu.Lock()
	for _, rec := range records {
		if rec == nil {
			m.mu.Unlock()
			return fmt.Errorf("record is nil")
		}
		if rec.ID == "" {
			m.mu.Unlock()
			return business.ErrCommandIDRequired
		}
		if rec.StewardID == "" {
			m.mu.Unlock()
			return business.ErrCommandStewardIDRequired
		}
		if _, exists := m.records[rec.ID]; exists {
			m.mu.Unlock()
			return fmt.Errorf("duplicate command ID: %s", rec.ID)
		}
	}
	m.mu.Unlock()

	for _, rec := range records {
		if err := m.CreateCommandRecord(ctx, rec); err != nil {
			return err
		}
	}
	return nil
}

func (m *memCommandStore) UpdateDeliveryStatus(_ context.Context, id string, status business.DeliveryStatus, detail string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.records[id]
	if !ok {
		return business.ErrCommandNotFound
	}
	rec.DeliveryStatus = status
	rec.DeliveryDetail = detail
	return nil
}

func (m *memCommandStore) ListPendingDeliveries(_ context.Context, stewardID string) ([]*business.CommandRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*business.CommandRecord
	for _, rec := range m.records {
		if rec.StewardID == stewardID && rec.DeliveryStatus == business.DeliveryStatusPending {
			cp := *rec
			out = append(out, &cp)
		}
	}
	return out, nil
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

	// Creating the handler should trigger the startup sweep. A negative timeout
	// guarantees the record (StartedAt = "now", set by UpdateCommandStatus above)
	// is immediately treated as past the in-flight boundary, regardless of clock
	// resolution — proving the sweep still fires for genuinely stale records.
	_, err := New(&Config{
		StewardID:               "steward-test",
		OnStatus:                noopStatus,
		Logger:                  newTestLogger(t),
		Store:                   store,
		ExecutingRestartTimeout: -1 * time.Second,
	})
	require.NoError(t, err)

	got, err := store.GetCommandRecord(ctx, "stale-cmd")
	require.NoError(t, err)
	assert.Equal(t, business.CommandStatusFailed, got.Status)
	assert.Equal(t, "controller_restart", got.ErrorMessage)
}

// TestNew_SweepLeavesRecentExecutingCommandAlone proves the timeout boundary:
// an executing record that started well within ExecutingRestartTimeout is left
// executing by the startup sweep rather than immediately failed, because a
// process restart that fast may not have genuinely interrupted it (Issue #3757).
func TestNew_SweepLeavesRecentExecutingCommandAlone(t *testing.T) {
	store := newMemCommandStore()
	ctx := context.Background()

	rec := &business.CommandRecord{
		ID:        "recent-executing",
		Type:      "sync_config",
		StewardID: "steward-test",
	}
	require.NoError(t, store.CreateCommandRecord(ctx, rec))
	require.NoError(t, store.UpdateCommandStatus(ctx, "recent-executing",
		business.CommandStatusExecuting, nil, ""))

	_, err := New(&Config{
		StewardID:               "steward-test",
		OnStatus:                noopStatus,
		Logger:                  newTestLogger(t),
		Store:                   store,
		ExecutingRestartTimeout: time.Hour,
	})
	require.NoError(t, err)

	got, err := store.GetCommandRecord(ctx, "recent-executing")
	require.NoError(t, err)
	assert.Equal(t, business.CommandStatusExecuting, got.Status,
		"a record started well within the timeout must not be failed by the sweep")
}

// TestNew_SweepNeverTouchesPendingCommands proves a pending delivery/command
// record survives the startup sweep untouched (Issue #3757 required test:
// restart-survival). Pending means no attempt was ever made, so a restart
// cannot have interrupted anything for the sweep to fail.
func TestNew_SweepNeverTouchesPendingCommands(t *testing.T) {
	store := newMemCommandStore()
	ctx := context.Background()

	rec := &business.CommandRecord{
		ID:        "pending-cmd",
		Type:      "sync_config",
		StewardID: "steward-test",
	}
	require.NoError(t, store.CreateCommandRecord(ctx, rec))

	// Even a zero/negative timeout must not touch a pending record — the sweep
	// only ever lists CommandStatusExecuting.
	_, err := New(&Config{
		StewardID:               "steward-test",
		OnStatus:                noopStatus,
		Logger:                  newTestLogger(t),
		Store:                   store,
		ExecutingRestartTimeout: -1 * time.Second,
	})
	require.NoError(t, err)

	got, err := store.GetCommandRecord(ctx, "pending-cmd")
	require.NoError(t, err)
	assert.Equal(t, business.CommandStatusPending, got.Status,
		"a pending command must survive the startup sweep unmodified")
	assert.Empty(t, got.ErrorMessage)
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

// TestUpdateVerifier_AcceptsCommandSignedWithNewCert verifies that UpdateVerifier
// allows the handler to accept commands signed with a cert that was not known at
// construction time. This is the push_signing_cert correctness path (Issue #1844):
// after the steward receives a new signing cert the command handler verifier must
// be refreshed so that subsequent controller commands (signed with the new cert via
// the DynamicSigner) are accepted without requiring a full reconnect.
func TestUpdateVerifier_AcceptsCommandSignedWithNewCert(t *testing.T) {
	_, oldVerifier := newTestSignerVerifier(t)
	newSigner, newVerifier := newTestSignerVerifier(t)

	// Handler starts with old-cert-only verifier.
	h := newTestHandlerWithVerifier(t, nil, oldVerifier)

	dispatched := make(chan struct{}, 1)
	h.RegisterHandler(cpTypes.CommandSyncConfig, func(_ context.Context, _ *cpTypes.Command) error {
		dispatched <- struct{}{}
		return nil
	})

	ctx := context.Background()

	// Command signed with the new cert must be rejected before the verifier update.
	cmd := &cpTypes.Command{
		ID:        "new-cert-before-update",
		Type:      cpTypes.CommandSyncConfig,
		StewardID: "steward-test",
		Timestamp: time.Now(),
	}
	sc := signTestCommand(t, newSigner, cmd)
	err := h.HandleCommand(ctx, sc)
	require.ErrorIs(t, err, ErrUnauthenticatedCommand, "command signed with unknown cert must be rejected before UpdateVerifier")

	// Replace the verifier to include the new cert.
	h.UpdateVerifier(newVerifier)

	// Same new-cert signer, fresh command ID (replay cache would reject the same ID).
	cmd2 := &cpTypes.Command{
		ID:        "new-cert-after-update",
		Type:      cpTypes.CommandSyncConfig,
		StewardID: "steward-test",
		Timestamp: time.Now(),
	}
	sc2 := signTestCommand(t, newSigner, cmd2)
	require.NoError(t, h.HandleCommand(ctx, sc2), "command signed with new cert must be accepted after UpdateVerifier")
	h.Wait()

	select {
	case <-dispatched:
	case <-time.After(time.Second):
		t.Fatal("handler was not dispatched after UpdateVerifier accepted the new-cert command")
	}
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

	params := signedInlineEnvelopeParams(t, []byte(echoScriptBody("hello")), platformShell(), "steward-test")
	params["execution_id"] = "exec-001"
	sc := testSignedCommandWithParams("es-001", cpTypes.CommandExecuteScript, params)

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
	params := signedInlineEnvelopeParams(t, []byte(exitScriptBody(42)), platformShell(), "steward-test")
	params["execution_id"] = "exec-002"
	sc := testSignedCommandWithParams("es-002", cpTypes.CommandExecuteScript, params)

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
	params := signedInlineEnvelopeParams(t, []byte(scriptBody), platformShell(), "steward-test")
	params["execution_id"] = "exec-003"
	sc := testSignedCommandWithParams("es-003", cpTypes.CommandExecuteScript, params)

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

	params := signedInlineEnvelopeParams(t, []byte(scriptBody), platformShell(), "steward-test")
	params["execution_id"] = "exec-004"
	sc := testSignedCommandWithParams("es-004", cpTypes.CommandExecuteScript, params)

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

// ---------------------------------------------------------------------------
// Story #1671: Script signature verification tests
// ---------------------------------------------------------------------------

// sigTestHelper groups helpers for script signature verification tests.

// sigTestRSAKey generates a fresh RSA-2048 key.
func sigTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return key
}

// sigTestPubKeyPEM encodes the RSA public key as PKIX PEM.
func sigTestPubKeyPEM(key *rsa.PrivateKey) string {
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		panic(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// sigTestSignRSASHA256 signs content with key using RSA-SHA256 and returns base64.
func sigTestSignRSASHA256(t *testing.T, key *rsa.PrivateKey, content []byte) string {
	t.Helper()
	h := sha256.Sum256(content)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(sig)
}

// sigTestNonce returns a fresh crypto/rand-generated, hex-encoded 16-byte nonce for
// operator envelope test fixtures (Issue #3694).
func sigTestNonce(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return hex.EncodeToString(b)
}

// signedInlineEnvelopeParams returns the cmd.Params entries preflightScriptSignature
// requires for an inline (ad-hoc) command as of Issue #3694: script_content, shell,
// plus a valid operator envelope — targeted at stewardID, a fresh nonce, and a
// 5-minute expiry — signed with a freshly generated (untrusted-CA) RSA key. It exists
// for execution-behavior tests that don't care about signing specifics but must
// supply a valid envelope now that inline verification is mandatory; tests that
// actually exercise signature/cert/target/expiry/nonce rejection build their params
// by hand instead.
func signedInlineEnvelopeParams(t *testing.T, content []byte, shell, stewardID string) map[string]interface{} {
	t.Helper()
	return signedInlineEnvelopeParamsWithKey(t, sigTestRSAKey(t), content, shell, stewardID)
}

// signedInlineEnvelopeParamsWithKey is signedInlineEnvelopeParams for a caller-supplied
// RSA key, so a test can sign an envelope built from one content value and later swap
// in different delivered params (e.g. tampered content) while keeping the same key.
func signedInlineEnvelopeParamsWithKey(t *testing.T, key *rsa.PrivateKey, content []byte, shell, stewardID string) map[string]interface{} {
	t.Helper()
	return signedInlineEnvelopeParamsFull(t, key, content, shell,
		[]string{stewardID}, sigTestNonce(t), time.Now().Add(5*time.Minute))
}

// signedInlineEnvelopeParamsFull is the fully-parameterized envelope builder every
// other signedInlineEnvelopeParams* helper delegates to. It exists directly for tests
// that must control targets, nonce, or expiry precisely — target mismatch, expiry,
// and nonce-replay coverage (Issue #3694).
func signedInlineEnvelopeParamsFull(t *testing.T, key *rsa.PrivateKey, content []byte, shell string, targets []string, nonce string, expiresAt time.Time) map[string]interface{} {
	t.Helper()
	env := operatorpayload.Envelope{
		Content:   content,
		Shell:     shell,
		Targets:   targets,
		Nonce:     nonce,
		ExpiresAt: expiresAt,
	}
	canonical, err := operatorpayload.CanonicalBytes(env)
	require.NoError(t, err)
	sigValue := sigTestSignRSASHA256(t, key, canonical)
	return map[string]interface{}{
		"script_content":       base64.StdEncoding.EncodeToString(content),
		"shell":                shell,
		"signature_algorithm":  "rsa-sha256",
		"signature_value":      sigValue,
		"signature_public_key": sigTestPubKeyPEM(key),
		"targets":              env.Targets,
		"nonce":                env.Nonce,
		"expires_at":           env.ExpiresAt.UTC().Format(time.RFC3339),
	}
}

// testSignedCommandForSteward is testSignedCommandWithParams for an outer
// SignedCommand.StewardID other than the fixed "steward-test" default — needed for
// target-mismatch coverage where the OUTER command legitimately routes to a
// specific steward while the INNER, operator-signed envelope names a different
// target list (Issue #3694).
func testSignedCommandForSteward(id, stewardID string, cmdType cpTypes.CommandType, params map[string]interface{}) *cpTypes.SignedCommand {
	return &cpTypes.SignedCommand{
		Command: cpTypes.Command{
			ID:        id,
			Type:      cmdType,
			StewardID: stewardID,
			Timestamp: time.Now(),
			Params:    params,
		},
	}
}

// sigTestCA creates a test CA and returns (CA, *x509.CertPool of CA cert).
func sigTestCA(t *testing.T) (*cert.CA, *x509.CertPool) {
	t.Helper()
	ca, err := cert.NewCA(&cert.CAConfig{
		Organization: "Test Controller CA",
		Country:      "US",
		ValidityDays: 365,
		KeySize:      2048,
	})
	require.NoError(t, err)
	require.NoError(t, ca.Initialize(nil))

	caCertPEM, err := ca.GetCACertificate()
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caCertPEM)
	return ca, pool
}

// sigTestOperatorCert creates a client cert signed by ca with optional TemplateModifier.
func sigTestOperatorCert(t *testing.T, ca *cert.CA, modifier func(*x509.Certificate)) *cert.Certificate {
	t.Helper()
	c, err := ca.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:       "operator.test",
		ValidityDays:     365,
		KeySize:          2048,
		TemplateModifier: modifier,
	})
	require.NoError(t, err)
	return c
}

// sigTestOperatorEnvelopeParams builds a valid operatorpayload.Envelope over content
// (targets=[stewardID], a fresh nonce, a 5-minute expiry), signs its canonical bytes
// with the RSA private key in keyPEM, and returns the full cmd.Params map
// preflightScriptSignature expects for an inline command, including the given
// signature_public_key (so callers can pass a cert whose PEM differs from a bare
// key, or intentionally mismatched material for negative tests).
func sigTestOperatorEnvelopeParams(t *testing.T, keyPEM []byte, publicKeyPEM string, content []byte, shell, stewardID string) map[string]interface{} {
	t.Helper()
	env := operatorpayload.Envelope{
		Content:   content,
		Shell:     shell,
		Targets:   []string{stewardID},
		Nonce:     sigTestNonce(t),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	canonical, err := operatorpayload.CanonicalBytes(env)
	require.NoError(t, err)
	sigValue := sigTestSignWithCert(t, keyPEM, canonical)
	return map[string]interface{}{
		"script_content":       base64.StdEncoding.EncodeToString(content),
		"shell":                shell,
		"signature_algorithm":  "rsa-sha256",
		"signature_value":      sigValue,
		"signature_public_key": publicKeyPEM,
		"targets":              env.Targets,
		"nonce":                env.Nonce,
		"expires_at":           env.ExpiresAt.UTC().Format(time.RFC3339),
	}
}

// sigTestSignWithCert signs content using the RSA private key in certPEM and keyPEM.
func sigTestSignWithCert(t *testing.T, keyPEM []byte, content []byte) string {
	t.Helper()
	block, _ := pem.Decode(keyPEM)
	require.NotNil(t, block)
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	require.NoError(t, err)
	return sigTestSignRSASHA256(t, key, content)
}

// newHandlerWithSigning creates a handler configured for script signature enforcement.
func newHandlerWithSigning(t *testing.T, trustedKeys []script.TrustedKeyEntry, requireSignedAdhoc bool, caRoots *x509.CertPool) *Handler {
	t.Helper()
	h, err := New(&Config{
		StewardID: "steward-test",
		OnStatus:  noopStatus,
		Logger:    newTestLogger(t),
		SigningConfig: script.ModuleSigningConfig{
			TrustMode:   script.TrustModeTrustedKeys,
			TrustedKeys: trustedKeys,
		},
		RequireSignedAdhoc: requireSignedAdhoc,
		ControllerCARoots:  caRoots,
	})
	require.NoError(t, err)
	h.RegisterExecuteScriptHandler()
	return h
}

// createMarkerScript returns a script body that creates a marker file,
// plus the path to the marker file.
func createMarkerScript(t *testing.T) (scriptBody string, markerPath string) {
	t.Helper()
	tmpDir := t.TempDir()
	markerPath = filepath.Join(tmpDir, "marker.txt")
	if runtime.GOOS == "windows" {
		scriptBody = fmt.Sprintf(`New-Item -ItemType File -Path "%s" -Force`, markerPath)
	} else {
		scriptBody = fmt.Sprintf("touch '%s'", markerPath)
	}
	return scriptBody, markerPath
}

// TestExecuteScriptHandler_RequireSignedAdhoc_Unsigned_Rejected verifies AC2:
// when require_signed_adhoc is true and no signature params are present,
// HandleCommand returns ErrUnauthenticatedCommand and the executor is never invoked.
// Verified by checking that a script that would write a temp file did not execute.
func TestExecuteScriptHandler_RequireSignedAdhoc_Unsigned_Rejected(t *testing.T) {
	h := newHandlerWithSigning(t, nil, true, nil)

	scriptBody, markerPath := createMarkerScript(t)
	scriptContent := base64.StdEncoding.EncodeToString([]byte(scriptBody))

	sc := testSignedCommandWithParams("sig-ac2-001", cpTypes.CommandExecuteScript, map[string]interface{}{
		"script_content": scriptContent,
		"shell":          platformShell(),
		"execution_id":   "sig-ac2-001",
		// No signature params — should be rejected
	})

	err := h.HandleCommand(context.Background(), sc)
	require.ErrorIs(t, err, ErrUnauthenticatedCommand)

	// The executor was never invoked — marker file must not exist.
	_, statErr := os.Stat(markerPath)
	assert.True(t, os.IsNotExist(statErr), "executor must not have run: marker file exists at %s", markerPath)
}

// TestExecuteScriptHandler_RequireSignedAdhoc_False_Unsigned_StillRejected verifies
// Issue #3694's AC that operator-signature verification for inline commands is now
// mandatory and unconditional: an unsigned inline command is rejected even when
// require_signed_adhoc is explicitly false. Before #3694, require_signed_adhoc=false
// skipped inline verification entirely (see git history for the prior
// "...Accepted" test this replaces); that skip is gone.
func TestExecuteScriptHandler_RequireSignedAdhoc_False_Unsigned_StillRejected(t *testing.T) {
	cb, getEvents := collectEvents()
	h, err := New(&Config{
		StewardID:          "steward-test",
		OnStatus:           cb,
		Logger:             newTestLogger(t),
		RequireSignedAdhoc: false,
	})
	require.NoError(t, err)
	h.RegisterExecuteScriptHandler()

	scriptContent := base64.StdEncoding.EncodeToString([]byte(echoScriptBody("hello")))
	sc := testSignedCommandWithParams("sig-notsigned-001", cpTypes.CommandExecuteScript, map[string]interface{}{
		"script_content": scriptContent,
		"shell":          platformShell(),
		"execution_id":   "sig-notsigned-001",
	})

	err = h.HandleCommand(context.Background(), sc)
	require.ErrorIs(t, err, ErrUnauthenticatedCommand,
		"inline verification must be mandatory regardless of require_signed_adhoc")

	evt := firstEventOfType(getEvents(), cpTypes.EventScriptCompleted)
	require.Nil(t, evt, "unsigned inline command must not execute even when require_signed_adhoc=false")
}

// TestExecuteScriptHandler_LibraryScript_UntrustedKey_Rejected verifies AC3:
// a library script (non-empty script_id) with a key NOT in TrustedKeys is rejected
// unexecuted, even when require_signed_adhoc is false; the library path forces trusted_keys.
func TestExecuteScriptHandler_LibraryScript_UntrustedKey_Rejected(t *testing.T) {
	// TrustedKeys holds a placeholder thumbprint that no real key will ever compute to.
	trustedEntry := script.TrustedKeyEntry{
		Name:       "trusted-ci-key",
		Thumbprint: "trusted-thumb",
	}
	h := newHandlerWithSigning(t, []script.TrustedKeyEntry{trustedEntry}, false, nil)

	// Sign with a key whose computed thumbprint won't match "trusted-thumb".
	untrustedKey := sigTestRSAKey(t)
	content := []byte("#!/bin/bash\necho library")
	scriptContent := base64.StdEncoding.EncodeToString(content)
	sigValue := sigTestSignRSASHA256(t, untrustedKey, content)

	sc := testSignedCommandWithParams("sig-lib-001", cpTypes.CommandExecuteScript, map[string]interface{}{
		"script_content":       scriptContent,
		"shell":                platformShell(),
		"execution_id":         "sig-lib-001",
		"script_id":            "lib-script-001", // non-empty → library script
		"signature_algorithm":  "rsa-sha256",
		"signature_value":      sigValue,
		"signature_public_key": sigTestPubKeyPEM(untrustedKey),
	})

	err := h.HandleCommand(context.Background(), sc)
	require.ErrorIs(t, err, ErrUnauthenticatedCommand,
		"library script with untrusted key must be rejected")
}

// TestExecuteScriptHandler_TamperedContent_Rejected verifies AC4:
// a signature_value that is valid base64 but is a signature over an envelope built
// from DIFFERENT content is rejected with ErrUnauthenticatedCommand; executor not
// invoked. The signature covers operatorpayload.CanonicalBytes (Issue #3694), so
// tampering with the delivered script_content changes the reconstructed envelope's
// canonical bytes and the signature no longer verifies.
func TestExecuteScriptHandler_TamperedContent_Rejected(t *testing.T) {
	key := sigTestRSAKey(t)
	h := newHandlerWithSigning(t, nil, true, nil)

	// Sign an envelope built from the original content, but deliver tampered content.
	original := []byte("#!/bin/bash\necho hello")
	tampered := []byte("#!/bin/bash\nrm -rf /")
	params := signedInlineEnvelopeParamsWithKey(t, key, original, platformShell(), "steward-test")
	params["script_content"] = base64.StdEncoding.EncodeToString(tampered) // different content than what was signed
	params["execution_id"] = "sig-tamper-001"

	sc := testSignedCommandWithParams("sig-tamper-001", cpTypes.CommandExecuteScript, params)

	err := h.HandleCommand(context.Background(), sc)
	require.ErrorIs(t, err, ErrUnauthenticatedCommand,
		"signature over an envelope built from different content must be rejected")
}

// TestExecuteScriptHandler_InlineScript_CertNotChainedToCA_Rejected verifies AC5 (part 1):
// an inline command signed by a cert that does NOT chain to the controller CA is rejected
// when require_signed_adhoc is true, even if cryptographic signature verification succeeds.
func TestExecuteScriptHandler_InlineScript_CertNotChainedToCA_Rejected(t *testing.T) {
	_, caPool := sigTestCA(t)

	// Create a DIFFERENT CA — certs from this CA will not chain to caPool.
	differentCA, _ := sigTestCA(t)
	operatorCert := sigTestOperatorCert(t, differentCA, nil)

	content := []byte(echoScriptBody("hello"))
	h := newHandlerWithSigning(t, nil, true, caPool) // caPool is the controller CA

	params := sigTestOperatorEnvelopeParams(t, operatorCert.PrivateKeyPEM, string(operatorCert.CertificatePEM), content, platformShell(), "steward-test")
	params["execution_id"] = "sig-wrongca-001"
	sc := testSignedCommandWithParams("sig-wrongca-001", cpTypes.CommandExecuteScript, params)

	err := h.HandleCommand(context.Background(), sc)
	require.ErrorIs(t, err, ErrUnauthenticatedCommand,
		"cert not chaining to controller CA must be rejected")
}

// TestExecuteScriptHandler_InlineScript_ExpiredCert_Rejected verifies AC5 (part 2):
// an inline command signed by an expired operator cert is rejected.
func TestExecuteScriptHandler_InlineScript_ExpiredCert_Rejected(t *testing.T) {
	ca, caPool := sigTestCA(t)

	// Create an operator cert that expired in the past.
	expiredCert := sigTestOperatorCert(t, ca, func(tmpl *x509.Certificate) {
		tmpl.NotBefore = time.Now().Add(-48 * time.Hour)
		tmpl.NotAfter = time.Now().Add(-24 * time.Hour) // already expired
	})

	content := []byte(echoScriptBody("hello"))
	h := newHandlerWithSigning(t, nil, true, caPool)

	params := sigTestOperatorEnvelopeParams(t, expiredCert.PrivateKeyPEM, string(expiredCert.CertificatePEM), content, platformShell(), "steward-test")
	params["execution_id"] = "sig-expired-001"
	sc := testSignedCommandWithParams("sig-expired-001", cpTypes.CommandExecuteScript, params)

	err := h.HandleCommand(context.Background(), sc)
	require.ErrorIs(t, err, ErrUnauthenticatedCommand,
		"expired operator cert must be rejected")
}

// TestExecuteScriptHandler_LibraryScript_ValidTrustedKey_Accepted verifies AC6 (library):
// a library script with a valid RSA-SHA256 detached signature from a TrustedKeys-enrolled
// key is accepted.
func TestExecuteScriptHandler_LibraryScript_ValidTrustedKey_Accepted(t *testing.T) {
	cb, getEvents := collectEvents()
	key := sigTestRSAKey(t)
	// Thumbprint is computed from the PEM the same way preflightScriptSignature does,
	// ensuring TrustedKeys contains the real SHA-256 fingerprint of the signing key.
	pubKeyPEM := sigTestPubKeyPEM(key)
	thumbprint := computeThumbprintFromPEM(pubKeyPEM)
	trustedEntry := script.TrustedKeyEntry{Name: "ci-signing-key", Thumbprint: thumbprint}

	h, err := New(&Config{
		StewardID: "steward-test",
		OnStatus:  cb,
		Logger:    newTestLogger(t),
		SigningConfig: script.ModuleSigningConfig{
			TrustMode:   script.TrustModeTrustedKeys,
			TrustedKeys: []script.TrustedKeyEntry{trustedEntry},
		},
		RequireSignedAdhoc: false,
	})
	require.NoError(t, err)
	h.RegisterExecuteScriptHandler()

	content := []byte(echoScriptBody("lib-hello"))
	scriptContent := base64.StdEncoding.EncodeToString(content)
	sigValue := sigTestSignRSASHA256(t, key, content)

	sc := testSignedCommandWithParams("sig-lib-valid-001", cpTypes.CommandExecuteScript, map[string]interface{}{
		"script_content":       scriptContent,
		"shell":                platformShell(),
		"execution_id":         "sig-lib-valid-001",
		"script_id":            "trusted-lib-001",
		"signature_algorithm":  "rsa-sha256",
		"signature_value":      sigValue,
		"signature_public_key": pubKeyPEM,
	})

	require.NoError(t, h.HandleCommand(context.Background(), sc))
	h.Wait()

	evt := firstEventOfType(getEvents(), cpTypes.EventScriptCompleted)
	require.NotNil(t, evt, "library script with valid trusted-key signature must be accepted and executed")
}

// TestExecuteScriptHandler_InlineScript_ValidOperatorCert_Accepted verifies AC6 (inline):
// an inline command signed by a cert chaining to the controller CA, with the admin
// marker (Issue #3689), is accepted.
func TestExecuteScriptHandler_InlineScript_ValidOperatorCert_Accepted(t *testing.T) {
	ca, caPool := sigTestCA(t)
	// Admin marker required (Issue #3689): verifyOperatorCert now rejects any cert
	// lacking cert.HasAdminMarker, matching the controller-side
	// validatePublicBetaCommandSignature check. Test files are exempt from
	// SetAdminMarker's restricted-caller allow-list (TestSetAdminMarker_Architecture).
	operatorCert := sigTestOperatorCert(t, ca, cert.SetAdminMarker) // valid, chained, not expired, admin-marked

	cb, getEvents := collectEvents()
	h, err := New(&Config{
		StewardID:          "steward-test",
		OnStatus:           cb,
		Logger:             newTestLogger(t),
		RequireSignedAdhoc: true,
		ControllerCARoots:  caPool,
	})
	require.NoError(t, err)
	h.RegisterExecuteScriptHandler()

	content := []byte(echoScriptBody("operator-hello"))
	params := sigTestOperatorEnvelopeParams(t, operatorCert.PrivateKeyPEM, string(operatorCert.CertificatePEM), content, platformShell(), "steward-test")
	params["execution_id"] = "sig-op-valid-001"
	sc := testSignedCommandWithParams("sig-op-valid-001", cpTypes.CommandExecuteScript, params)

	require.NoError(t, h.HandleCommand(context.Background(), sc))
	h.Wait()

	evt := firstEventOfType(getEvents(), cpTypes.EventScriptCompleted)
	require.NotNil(t, evt, "inline command signed by valid controller-CA-chained cert must be accepted")
}

// TestExecuteScriptHandler_InlineScript_NonAdminCert_Rejected verifies Issue #3689's
// acceptance criteria: a certificate chaining to controllerCARoots with valid
// ExtKeyUsageClientAuth but WITHOUT the admin marker is rejected by
// preflightScriptSignature when RequireSignedAdhoc is true. Before this fix,
// verifyOperatorCert checked only chain + EKU, so any client-auth cert issued by the
// controller CA — including a non-admin steward's own mTLS client cert — passed
// steward-side verification; the controller-side equivalent
// (validatePublicBetaCommandSignature) already enforced cert.HasAdminMarker.
func TestExecuteScriptHandler_InlineScript_NonAdminCert_Rejected(t *testing.T) {
	ca, caPool := sigTestCA(t)
	// No TemplateModifier: a validly chained, unexpired, client-auth cert with no
	// admin marker — e.g. an ordinary steward's own mTLS client certificate.
	nonAdminCert := sigTestOperatorCert(t, ca, nil)

	h := newHandlerWithSigning(t, nil, true, caPool)

	content := []byte(echoScriptBody("hello"))
	params := sigTestOperatorEnvelopeParams(t, nonAdminCert.PrivateKeyPEM, string(nonAdminCert.CertificatePEM), content, platformShell(), "steward-test")
	params["execution_id"] = "sig-nonadmin-001"
	sc := testSignedCommandWithParams("sig-nonadmin-001", cpTypes.CommandExecuteScript, params)

	err := h.HandleCommand(context.Background(), sc)
	require.ErrorIs(t, err, ErrUnauthenticatedCommand,
		"a chained, unexpired, client-auth cert WITHOUT the admin marker must be rejected")
}

// ---------------------------------------------------------------------------
// Issue #3694 — target binding, expiry, nonce replay, migration completeness.
// ---------------------------------------------------------------------------

// TestExecuteScriptHandler_TargetMismatch_Rejected is a required test (Issue #3694
// AC): an envelope signed for target list ["host-A"], delivered to a steward whose
// own ID is "host-B", is rejected even though the outer SignedCommand legitimately
// routes to "host-B" (StewardID match passes) and the signature itself is
// cryptographically valid.
func TestExecuteScriptHandler_TargetMismatch_Rejected(t *testing.T) {
	cb, getEvents := collectEvents()
	h, err := New(&Config{StewardID: "host-B", OnStatus: cb, Logger: newTestLogger(t)})
	require.NoError(t, err)
	h.RegisterExecuteScriptHandler()

	key := sigTestRSAKey(t)
	content := []byte(echoScriptBody("hello"))
	params := signedInlineEnvelopeParamsFull(t, key, content, platformShell(),
		[]string{"host-A"}, sigTestNonce(t), time.Now().Add(5*time.Minute))
	params["execution_id"] = "sig-targetmismatch-001"

	sc := testSignedCommandForSteward("sig-targetmismatch-001", "host-B", cpTypes.CommandExecuteScript, params)

	err = h.HandleCommand(context.Background(), sc)
	require.ErrorIs(t, err, ErrUnauthenticatedCommand,
		"a steward not named in the signed target list must reject the command")

	evt := firstEventOfType(getEvents(), cpTypes.EventScriptCompleted)
	require.Nil(t, evt, "executor must not run when the steward is not an authorized target")
}

// TestExecuteScriptHandler_ExpiredEnvelope_Rejected is a required test (Issue #3694
// AC): an envelope whose ExpiresAt is in the past is rejected even though the
// signature is cryptographically valid and the steward is a correct target.
func TestExecuteScriptHandler_ExpiredEnvelope_Rejected(t *testing.T) {
	h, err := New(&Config{StewardID: "steward-test", OnStatus: noopStatus, Logger: newTestLogger(t)})
	require.NoError(t, err)
	h.RegisterExecuteScriptHandler()

	key := sigTestRSAKey(t)
	content := []byte(echoScriptBody("hello"))
	params := signedInlineEnvelopeParamsFull(t, key, content, platformShell(),
		[]string{"steward-test"}, sigTestNonce(t), time.Now().Add(-1*time.Minute))
	params["execution_id"] = "sig-expiredenv-001"

	sc := testSignedCommandWithParams("sig-expiredenv-001", cpTypes.CommandExecuteScript, params)

	err = h.HandleCommand(context.Background(), sc)
	require.ErrorIs(t, err, ErrUnauthenticatedCommand, "an expired envelope must be rejected")
}

// TestExecuteScriptHandler_EnvelopeNonceReplay_RejectedIndependentlyOfOuterReplayCache
// is a required test (Issue #3694 AC): the identical valid envelope, delivered twice,
// is accepted the first time and rejected the second time via the nonce cache — and
// this holds even when the second delivery arrives wrapped in a FRESH outer
// SignedCommand (a different command ID and timestamp), which the outer replay
// cache (handler.go's replayCache, keyed by cmd.ID) would accept as new. This is the
// scenario a compromised controller or a captured-and-replayed operator payload
// produces: the outer envelope is fresh, but the inner operator-signed nonce is not.
func TestExecuteScriptHandler_EnvelopeNonceReplay_RejectedIndependentlyOfOuterReplayCache(t *testing.T) {
	cb, getEvents := collectEvents()
	h, err := New(&Config{StewardID: "steward-test", OnStatus: cb, Logger: newTestLogger(t)})
	require.NoError(t, err)
	h.RegisterExecuteScriptHandler()

	key := sigTestRSAKey(t)
	content := []byte(echoScriptBody("hello"))
	nonce := sigTestNonce(t)
	expiresAt := time.Now().Add(5 * time.Minute)
	params := signedInlineEnvelopeParamsFull(t, key, content, platformShell(),
		[]string{"steward-test"}, nonce, expiresAt)

	// First delivery: distinct outer command ID/timestamp, succeeds.
	first := map[string]interface{}{}
	for k, v := range params {
		first[k] = v
	}
	first["execution_id"] = "sig-noncereplay-001"
	sc1 := testSignedCommandWithParams("sig-noncereplay-001", cpTypes.CommandExecuteScript, first)
	require.NoError(t, h.HandleCommand(context.Background(), sc1))
	h.Wait()
	require.NotNil(t, firstEventOfType(getEvents(), cpTypes.EventScriptCompleted),
		"first delivery of a fresh envelope must execute")

	// Second delivery: a genuinely DIFFERENT outer command ID (so the outer
	// replayCache does NOT catch it) carrying the SAME inner envelope (same
	// content/targets/nonce/expiry/signature) — simulating a captured operator
	// payload rewrapped by a compromised controller or a stale relay.
	second := map[string]interface{}{}
	for k, v := range params {
		second[k] = v
	}
	second["execution_id"] = "sig-noncereplay-002"
	sc2 := testSignedCommandWithParams("sig-noncereplay-002-different-outer-id", cpTypes.CommandExecuteScript, second)

	err = h.HandleCommand(context.Background(), sc2)
	require.ErrorIs(t, err, ErrUnauthenticatedCommand,
		"a reused envelope nonce must be rejected even under a fresh outer command ID")
}

// TestExecuteScriptHandler_LegacyContentOnlySignature_Rejected is a required test
// (Issue #3694 AC — migration completeness): a signature computed over content alone
// (the pre-#3694 wire format) — rather than over operatorpayload.CanonicalBytes of
// the full envelope — is rejected, even when targets/nonce/expires_at are otherwise
// present and well-formed. This confirms no remaining code path in
// preflightScriptSignature accepts a content-only digest.
func TestExecuteScriptHandler_LegacyContentOnlySignature_Rejected(t *testing.T) {
	h, err := New(&Config{StewardID: "steward-test", OnStatus: noopStatus, Logger: newTestLogger(t)})
	require.NoError(t, err)
	h.RegisterExecuteScriptHandler()

	key := sigTestRSAKey(t)
	content := []byte(echoScriptBody("hello"))

	// Pre-#3694 format: sign content directly, not CanonicalBytes(envelope).
	legacySigValue := sigTestSignRSASHA256(t, key, content)

	sc := testSignedCommandWithParams("sig-legacyformat-001", cpTypes.CommandExecuteScript, map[string]interface{}{
		"script_content":       base64.StdEncoding.EncodeToString(content),
		"shell":                platformShell(),
		"execution_id":         "sig-legacyformat-001",
		"signature_algorithm":  "rsa-sha256",
		"signature_value":      legacySigValue,
		"signature_public_key": sigTestPubKeyPEM(key),
		"targets":              []string{"steward-test"},
		"nonce":                sigTestNonce(t),
		"expires_at":           time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339),
	})

	err = h.HandleCommand(context.Background(), sc)
	require.ErrorIs(t, err, ErrUnauthenticatedCommand,
		"a signature computed over content alone (pre-#3694 format) must be rejected")
}
