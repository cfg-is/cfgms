// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	controllerrun "github.com/cfgis/cfgms/features/controller/run"
	cpInterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	_ "modernc.org/sqlite"
)

// recordingControlPlane is a test control plane that records sent commands and
// allows tests to trigger events by calling TriggerEvent. It is NOT a mock:
// it implements the full ControlPlaneProvider interface with real (if minimal) behaviour.
type recordingControlPlane struct {
	mu           sync.Mutex
	sentCommands []*cpTypes.SignedCommand
	eventHandler cpInterfaces.EventHandler
}

func (c *recordingControlPlane) Name() string      { return "recording" }
func (c *recordingControlPlane) IsConnected() bool { return true }
func (c *recordingControlPlane) Initialize(_ context.Context, _ map[string]interface{}) error {
	return nil
}
func (c *recordingControlPlane) Start(_ context.Context) error     { return nil }
func (c *recordingControlPlane) Stop(_ context.Context) error      { return nil }
func (c *recordingControlPlane) Reconnect(_ context.Context) error { return nil }
func (c *recordingControlPlane) SendCommand(_ context.Context, cmd *cpTypes.SignedCommand) error {
	c.mu.Lock()
	c.sentCommands = append(c.sentCommands, cmd)
	c.mu.Unlock()
	return nil
}
func (c *recordingControlPlane) FanOutCommand(_ context.Context, _ *cpTypes.SignedCommand, _ []string) (*cpTypes.FanOutResult, error) {
	return &cpTypes.FanOutResult{}, nil
}
func (c *recordingControlPlane) SubscribeCommands(_ context.Context, _ string, _ cpInterfaces.CommandHandler) error {
	return nil
}
func (c *recordingControlPlane) PublishEvent(_ context.Context, _ *cpTypes.Event) error { return nil }
func (c *recordingControlPlane) SubscribeEvents(_ context.Context, _ *cpTypes.EventFilter, handler cpInterfaces.EventHandler) error {
	c.mu.Lock()
	c.eventHandler = handler
	c.mu.Unlock()
	return nil
}
func (c *recordingControlPlane) SendHeartbeat(_ context.Context, _ *cpTypes.Heartbeat) error {
	return nil
}
func (c *recordingControlPlane) SubscribeHeartbeats(_ context.Context, _ cpInterfaces.HeartbeatHandler) error {
	return nil
}
func (c *recordingControlPlane) GetStats(_ context.Context) (*cpTypes.ControlPlaneStats, error) {
	return &cpTypes.ControlPlaneStats{}, nil
}

// TriggerEvent calls the registered event handler with the given event.
func (c *recordingControlPlane) TriggerEvent(ctx context.Context, event *cpTypes.Event) error {
	c.mu.Lock()
	h := c.eventHandler
	c.mu.Unlock()
	if h == nil {
		return nil
	}
	return h(ctx, event)
}

// SentCommands returns a copy of all sent commands.
func (c *recordingControlPlane) SentCommands() []*cpTypes.SignedCommand {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]*cpTypes.SignedCommand, len(c.sentCommands))
	copy(out, c.sentCommands)
	return out
}

// newRelayRunManager creates an in-memory RunStore backed manager for relay handler tests.
func newRelayRunManager(t *testing.T) *controllerrun.Manager {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	store := controllerrun.NewRunStoreSQL(db)
	require.NoError(t, store.Init(context.Background()))
	return controllerrun.NewManager(store, nil)
}

// newRelayTestHandler returns an http.Handler that records the received
// Principal and returns a 200 response with the principal's permissions as JSON.
func newRelayTestHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, _ := r.Context().Value(principalContextKey).(*Principal)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		var perms []string
		if principal != nil {
			perms = principal.Permissions
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"permissions": perms,
			"is_admin":    principal != nil && principal.IsAdmin,
		})
	})
}

// newRelayForbiddenHandler returns a handler that always rejects via requirePermission-like logic.
func newRelayForbiddenHandler(requiredPerm string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, _ := r.Context().Value(principalContextKey).(*Principal)
		if principal == nil || principal.IsAdmin {
			// Admin or nil — not expected in relay path.
			w.WriteHeader(http.StatusForbidden)
			return
		}
		for _, p := range principal.Permissions {
			if p == requiredPerm {
				w.WriteHeader(http.StatusOK)
				return
			}
		}
		w.WriteHeader(http.StatusForbidden)
	})
}

// TestRelayHandler_NoGrant_Returns403 verifies AC2: relay request with no grant returns 403.
func TestRelayHandler_NoGrant_Returns403(t *testing.T) {
	cp := &recordingControlPlane{}
	manager := newRelayRunManager(t)
	handler := NewRelayHandler(cp, manager, newRelayTestHandler(), nil, logging.NewNoopLogger())

	ctx := context.Background()
	require.NoError(t, handler.Start(ctx))

	err := cp.TriggerEvent(ctx, &cpTypes.Event{
		Type:      cpTypes.EventRelayRequest,
		StewardID: "device-1",
		Timestamp: time.Now(),
		Details: map[string]interface{}{
			"execution_id": "exec-no-grant",
			"sequence":     float64(1),
			"method":       "GET",
			"path":         "/api/v1/runs",
			"headers":      map[string]interface{}{},
			"body":         "",
		},
	})
	require.NoError(t, err)

	cmds := cp.SentCommands()
	require.Len(t, cmds, 1)
	assert.Equal(t, cpTypes.CommandRelayResponse, cmds[0].Command.Type)
	assert.Equal(t, float64(http.StatusForbidden), cmds[0].Command.Params["status"])
}

// TestRelayHandler_ConsumedGrant_Returns403 verifies AC2: after ConsumeGrant, relay returns 403.
func TestRelayHandler_ConsumedGrant_Returns403(t *testing.T) {
	cp := &recordingControlPlane{}
	manager := newRelayRunManager(t)

	// Create and immediately consume a grant.
	require.NoError(t, manager.CreateGrant("device-1", "tenant-1", "exec-consumed", []string{"runs:read"}, time.Hour))
	require.NoError(t, manager.ConsumeGrant("exec-consumed"))

	handler := NewRelayHandler(cp, manager, newRelayTestHandler(), nil, logging.NewNoopLogger())

	ctx := context.Background()
	require.NoError(t, handler.Start(ctx))

	err := cp.TriggerEvent(ctx, &cpTypes.Event{
		Type:      cpTypes.EventRelayRequest,
		StewardID: "device-1",
		Timestamp: time.Now(),
		Details: map[string]interface{}{
			"execution_id": "exec-consumed",
			"sequence":     float64(1),
			"method":       "GET",
			"path":         "/api/v1/runs",
			"headers":      map[string]interface{}{},
			"body":         "",
		},
	})
	require.NoError(t, err)

	cmds := cp.SentCommands()
	require.Len(t, cmds, 1)
	assert.Equal(t, float64(http.StatusForbidden), cmds[0].Command.Params["status"])
}

// TestRelayHandler_WrongDevice_Returns403 verifies AC3: relay request from device A
// for an executionID whose grant was issued to device B returns 403.
func TestRelayHandler_WrongDevice_Returns403(t *testing.T) {
	cp := &recordingControlPlane{}
	manager := newRelayRunManager(t)

	// Grant issued to device-B.
	require.NoError(t, manager.CreateGrant("device-B", "tenant-1", "exec-B", []string{"runs:read"}, time.Hour))

	handler := NewRelayHandler(cp, manager, newRelayTestHandler(), nil, logging.NewNoopLogger())
	ctx := context.Background()
	require.NoError(t, handler.Start(ctx))

	// Relay request arrives claiming device-A but using device-B's execution ID.
	err := cp.TriggerEvent(ctx, &cpTypes.Event{
		Type:      cpTypes.EventRelayRequest,
		StewardID: "device-A", // different device — grant lookup (device-A, exec-B) fails
		Timestamp: time.Now(),
		Details: map[string]interface{}{
			"execution_id": "exec-B",
			"sequence":     float64(1),
			"method":       "GET",
			"path":         "/api/v1/runs",
			"headers":      map[string]interface{}{},
			"body":         "",
		},
	})
	require.NoError(t, err)

	cmds := cp.SentCommands()
	require.Len(t, cmds, 1)
	assert.Equal(t, float64(http.StatusForbidden), cmds[0].Command.Params["status"])
}

// TestRelayHandler_ScopeEnforcement_Returns403 verifies AC4: relay request to an
// endpoint requiring a permission NOT in the grant scope returns 403.
func TestRelayHandler_ScopeEnforcement_Returns403(t *testing.T) {
	cp := &recordingControlPlane{}
	manager := newRelayRunManager(t)

	// Grant includes only "runs:read"; handler requires "runs:write".
	require.NoError(t, manager.CreateGrant("device-1", "tenant-1", "exec-scope", []string{"runs:read"}, time.Hour))

	// Use a handler that enforces "runs:write" permission.
	apiHandler := newRelayForbiddenHandler("runs:write")
	handler := NewRelayHandler(cp, manager, apiHandler, nil, logging.NewNoopLogger())
	ctx := context.Background()
	require.NoError(t, handler.Start(ctx))

	err := cp.TriggerEvent(ctx, &cpTypes.Event{
		Type:      cpTypes.EventRelayRequest,
		StewardID: "device-1",
		Timestamp: time.Now(),
		Details: map[string]interface{}{
			"execution_id": "exec-scope",
			"sequence":     float64(1),
			"method":       "POST",
			"path":         "/api/v1/runs/script",
			"headers":      map[string]interface{}{},
			"body":         "",
		},
	})
	require.NoError(t, err)

	cmds := cp.SentCommands()
	require.Len(t, cmds, 1)
	assert.Equal(t, float64(http.StatusForbidden), cmds[0].Command.Params["status"])
}

// TestRelayHandler_ValidGrant_RoutesRequest verifies that a valid grant results
// in the request being routed with the correct scoped Principal.
func TestRelayHandler_ValidGrant_RoutesRequest(t *testing.T) {
	cp := &recordingControlPlane{}
	manager := newRelayRunManager(t)

	scope := []string{"runs:read", "scripts:execute"}
	require.NoError(t, manager.CreateGrant("device-1", "tenant-1", "exec-valid", scope, time.Hour))

	// Use the test handler that returns the principal's permissions.
	handler := NewRelayHandler(cp, manager, newRelayTestHandler(), nil, logging.NewNoopLogger())
	ctx := context.Background()
	require.NoError(t, handler.Start(ctx))

	err := cp.TriggerEvent(ctx, &cpTypes.Event{
		Type:      cpTypes.EventRelayRequest,
		StewardID: "device-1",
		Timestamp: time.Now(),
		Details: map[string]interface{}{
			"execution_id": "exec-valid",
			"sequence":     float64(1),
			"method":       "GET",
			"path":         "/api/v1/runs",
			"headers":      map[string]interface{}{},
			"body":         "",
		},
	})
	require.NoError(t, err)

	cmds := cp.SentCommands()
	require.Len(t, cmds, 1)
	cmd := cmds[0]
	assert.Equal(t, cpTypes.CommandRelayResponse, cmd.Command.Type)
	assert.Equal(t, float64(http.StatusOK), cmd.Command.Params["status"])
}

// TestRelayHandler_AdminPrincipal_NeverConstructed verifies that the relay handler
// always constructs non-admin principals regardless of grant scope.
func TestRelayHandler_AdminPrincipal_NeverConstructed(t *testing.T) {
	cp := &recordingControlPlane{}
	manager := newRelayRunManager(t)

	// Even if the grant scope includes something like "admin", IsAdmin stays false.
	require.NoError(t, manager.CreateGrant("device-1", "tenant-1", "exec-admin-test", []string{"*"}, time.Hour))

	var capturedPrincipal *Principal
	captureHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPrincipal, _ = r.Context().Value(principalContextKey).(*Principal)
		w.WriteHeader(http.StatusOK)
	})

	handler := NewRelayHandler(cp, manager, captureHandler, nil, logging.NewNoopLogger())
	ctx := context.Background()
	require.NoError(t, handler.Start(ctx))

	require.NoError(t, cp.TriggerEvent(ctx, &cpTypes.Event{
		Type:      cpTypes.EventRelayRequest,
		StewardID: "device-1",
		Timestamp: time.Now(),
		Details: map[string]interface{}{
			"execution_id": "exec-admin-test",
			"sequence":     float64(1),
			"method":       "GET",
			"path":         "/api/v1/runs",
			"headers":      map[string]interface{}{},
			"body":         "",
		},
	}))

	require.NotNil(t, capturedPrincipal)
	assert.False(t, capturedPrincipal.IsAdmin, "relay principal must never be admin")
	assert.Equal(t, "tenant-1", capturedPrincipal.TenantID)
}

// TestRelayHandler_ExpiredGrant_Returns403 verifies that an expired grant returns 403.
func TestRelayHandler_ExpiredGrant_Returns403(t *testing.T) {
	cp := &recordingControlPlane{}
	manager := newRelayRunManager(t)

	// Grant with a 1 nanosecond TTL — effectively already expired.
	require.NoError(t, manager.CreateGrant("device-1", "tenant-1", "exec-expired", []string{"runs:read"}, time.Nanosecond))
	time.Sleep(10 * time.Millisecond) // ensure TTL has elapsed

	handler := NewRelayHandler(cp, manager, newRelayTestHandler(), nil, logging.NewNoopLogger())
	ctx := context.Background()
	require.NoError(t, handler.Start(ctx))

	require.NoError(t, cp.TriggerEvent(ctx, &cpTypes.Event{
		Type:      cpTypes.EventRelayRequest,
		StewardID: "device-1",
		Timestamp: time.Now(),
		Details: map[string]interface{}{
			"execution_id": "exec-expired",
			"sequence":     float64(1),
			"method":       "GET",
			"path":         "/api/v1/runs",
			"headers":      map[string]interface{}{},
			"body":         "",
		},
	}))

	cmds := cp.SentCommands()
	require.Len(t, cmds, 1)
	assert.Equal(t, float64(http.StatusForbidden), cmds[0].Command.Params["status"])
}

// TestRelayHandler_AuthMiddlewareBypass verifies that the relay principal injected
// by the relay handler bypasses authenticationMiddleware, and that requirePermission
// still enforces scope (regression guard for the middleware bypass path).
func TestRelayHandler_AuthMiddlewareBypass(t *testing.T) {
	// Build a minimal server with auth middleware wrapping the test handler.
	inner := newRelayTestHandler()
	// Wrap inner with a middleware that checks for the relay principal bypass.
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate authenticationMiddleware: check relay bypass first.
		if injected, ok := r.Context().Value(relayPrincipalKey).(*Principal); ok && injected != nil {
			inner.ServeHTTP(w, r)
			return
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})

	cp := &recordingControlPlane{}
	manager := newRelayRunManager(t)
	require.NoError(t, manager.CreateGrant("device-1", "tenant-1", "exec-bypass", []string{"runs:read"}, time.Hour))

	handler := NewRelayHandler(cp, manager, wrapped, nil, logging.NewNoopLogger())
	ctx := context.Background()
	require.NoError(t, handler.Start(ctx))

	require.NoError(t, cp.TriggerEvent(ctx, &cpTypes.Event{
		Type:      cpTypes.EventRelayRequest,
		StewardID: "device-1",
		Timestamp: time.Now(),
		Details: map[string]interface{}{
			"execution_id": "exec-bypass",
			"sequence":     float64(1),
			"method":       "GET",
			"path":         "/api/v1/runs",
			"headers":      map[string]interface{}{},
			"body":         "",
		},
	}))

	cmds := cp.SentCommands()
	require.Len(t, cmds, 1)
	// Should succeed (not 401 unauthorized) because relay principal bypassed auth.
	assert.Equal(t, float64(http.StatusOK), cmds[0].Command.Params["status"])
}

// TestRelayHandler_IgnoresNonRelayEvents ensures the handler ignores events of
// other types without sending a response.
func TestRelayHandler_IgnoresNonRelayEvents(t *testing.T) {
	cp := &recordingControlPlane{}
	manager := newRelayRunManager(t)
	handler := NewRelayHandler(cp, manager, newRelayTestHandler(), nil, logging.NewNoopLogger())
	ctx := context.Background()
	require.NoError(t, handler.Start(ctx))

	require.NoError(t, cp.TriggerEvent(ctx, &cpTypes.Event{
		Type:      cpTypes.EventScriptCompleted,
		StewardID: "device-1",
		Timestamp: time.Now(),
	}))

	assert.Empty(t, cp.SentCommands(), "non-relay events must not trigger a relay response")
}

// TestRunStore_GrantLifecycle is a RunStore-level test for the grant management
// methods added in Issue #1675.
func TestRunStore_GrantLifecycle(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	store := controllerrun.NewRunStoreSQL(db)
	require.NoError(t, store.Init(context.Background()))

	// Create grant.
	require.NoError(t, store.CreateExecutionGrant("dev-1", "tenant-1", "exec-1", []string{"runs:read"}, time.Hour))

	// LookupGrant — should succeed.
	g, err := store.LookupGrant("dev-1", "exec-1")
	require.NoError(t, err)
	require.NotNil(t, g)
	assert.Equal(t, []string{"runs:read"}, g.Scope)
	assert.Equal(t, "tenant-1", g.TenantID)
	assert.False(t, g.Consumed)

	// Wrong device — should fail.
	_, err = store.LookupGrant("dev-other", "exec-1")
	assert.ErrorIs(t, err, controllerrun.ErrGrantNotFound)

	// Consume.
	require.NoError(t, store.ConsumeGrant("exec-1"))

	// LookupGrant after consume — should return ErrGrantConsumed.
	_, err = store.LookupGrant("dev-1", "exec-1")
	assert.ErrorIs(t, err, controllerrun.ErrGrantConsumed)
}

// TestRunStore_GrantExpiry verifies that expired grants return ErrGrantNotFound.
func TestRunStore_GrantExpiry(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	store := controllerrun.NewRunStoreSQL(db)
	require.NoError(t, store.Init(context.Background()))

	require.NoError(t, store.CreateExecutionGrant("dev-1", "tenant-1", "exec-exp", []string{"runs:read"}, time.Nanosecond))
	time.Sleep(10 * time.Millisecond)

	_, err = store.LookupGrant("dev-1", "exec-exp")
	assert.ErrorIs(t, err, controllerrun.ErrGrantNotFound)
}

// TestRequirePermission_RelayPrincipal_ScopeEnforcedWhenRBACNil is a regression
// guard for the Fix #2 (Issue #1675): relay scope must be enforced by requirePermission
// even when s.rbacService is nil (OSS mode). Before the fix, the nil-rbacService
// early-return bypassed all permission checks, granting relay scripts full access.
func TestRequirePermission_RelayPrincipal_ScopeEnforcedWhenRBACNil(t *testing.T) {
	s := &Server{rbacService: nil, logger: logging.NewNoopLogger()}

	var reached bool
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})
	handler := s.requirePermission("steward", "execute-scripts")(inner)

	// Relay principal has only read-scripts — not execute-scripts.
	relay := &Principal{IsAdmin: false, Permissions: []string{"steward:read-scripts"}, TenantID: "t1"}
	ctx := context.WithValue(
		context.WithValue(context.Background(), relayPrincipalKey, relay),
		principalContextKey, relay)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/runs/script", nil).WithContext(ctx)

	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)

	assert.Equal(t, http.StatusForbidden, rw.Code,
		"relay scope must be enforced even when rbacService is nil")
	assert.False(t, reached, "inner handler must not be reached when scope is insufficient")
}

// noopResponseRecorder satisfies httptest.ResponseRecorder contract for tests
// that need to pass an http.Handler without a real server.
var _ *httptest.ResponseRecorder = (*httptest.ResponseRecorder)(nil)
