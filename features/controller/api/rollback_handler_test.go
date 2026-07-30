// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/config/rollback"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/session"
)

// inMemoryRollbackManager is a real, in-process rollback.RollbackManager used by the
// handler-level tests. It is NOT a mock: it records no calls, has no configurable return
// values, and every response is derived from the request plus the operations it has actually
// persisted in a real rollback.InMemoryRollbackStore (the same store implementation the
// rollback package ships).
//
// It applies the decision rules of rollback.DefaultRollbackManager and
// rollback.DefaultRollbackValidator, minus the Git-backed diff computation (which needs an
// on-disk repository and is covered by the rollback package's own tests):
//
//   - request validation (target, rollback type, reason)  -> ROLLBACK_VALIDATION_FAILED
//   - permission gate for MSP-wide and emergency rollbacks -> ROLLBACK_PERMISSION_DENIED
//   - concurrency guard for a target with a live operation -> ROLLBACK_IN_PROGRESS
//   - risk-based approval gate on critical modules         -> APPROVAL_REQUIRED
//
// Whether a rollback was actually initiated is observable through the store
// (operationsFor), not through a call-recording flag.
type inMemoryRollbackManager struct {
	store rollback.RollbackStore

	mu sync.RWMutex
	// grants is the authorization table: actor ID -> permission IDs held. The permission
	// IDs match those checked by rollback.DefaultRollbackValidator.validatePermissions.
	grants map[string]map[string]bool
	// points is the rollback-point catalogue keyed by "<target_type>/<target_id>". It
	// stands in for the Git commit history the production manager reads.
	points map[string][]rollback.RollbackPoint
}

func newInMemoryRollbackManager() *inMemoryRollbackManager {
	return &inMemoryRollbackManager{
		store:  rollback.NewInMemoryRollbackStore(),
		grants: make(map[string]map[string]bool),
		points: make(map[string][]rollback.RollbackPoint),
	}
}

// grant authorizes an actor to hold a rollback permission (e.g. "rollback.msp").
func (m *inMemoryRollbackManager) grant(actor, permissionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.grants[actor] == nil {
		m.grants[actor] = make(map[string]bool)
	}
	m.grants[actor][permissionID] = true
}

// addRollbackPoint registers an available rollback point for a target.
func (m *inMemoryRollbackManager) addRollbackPoint(targetType rollback.TargetType, targetID string, point rollback.RollbackPoint) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := targetKey(targetType, targetID)
	m.points[key] = append(m.points[key], point)
}

// operationsFor returns the rollback operations recorded for a target. Handler tests use it
// to assert whether a rollback was genuinely initiated instead of inspecting a call flag.
func (m *inMemoryRollbackManager) operationsFor(t *testing.T, targetType rollback.TargetType, targetID string) []rollback.RollbackOperation {
	t.Helper()
	ops, err := m.ListRollbackHistory(context.Background(), targetType, targetID, 0)
	require.NoError(t, err)
	return ops
}

func targetKey(targetType rollback.TargetType, targetID string) string {
	return string(targetType) + "/" + targetID
}

func (m *inMemoryRollbackManager) hasPermission(actor, permissionID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.grants[actor][permissionID]
}

// rollbackPointsFor returns the registered rollback points for a target, newest first.
func (m *inMemoryRollbackManager) rollbackPointsFor(targetType rollback.TargetType, targetID string) []rollback.RollbackPoint {
	m.mu.RLock()
	defer m.mu.RUnlock()
	src := m.points[targetKey(targetType, targetID)]
	out := make([]rollback.RollbackPoint, len(src))
	copy(out, src)
	sort.Slice(out, func(i, j int) bool { return out[i].Timestamp.After(out[j].Timestamp) })
	return out
}

// criticalRollbackModules mirrors the module names rollback.DefaultRollbackValidator.AssessRisk
// classifies as high risk.
var criticalRollbackModules = []string{"authentication", "security", "network", "database"}

func isCriticalRollbackPath(path string) bool {
	for _, critical := range criticalRollbackModules {
		if strings.Contains(path, critical) {
			return true
		}
	}
	return false
}

// validateRollbackRequest applies rollback.DefaultRollbackManager.validateRequest and
// rollback.DefaultRollbackValidator.validateTarget/validateRollbackType.
func validateRollbackRequest(request rollback.RollbackRequest) error {
	switch request.TargetType {
	case rollback.TargetTypeDevice, rollback.TargetTypeGroup, rollback.TargetTypeClient,
		rollback.TargetTypeMSP, rollback.TargetTypeSteward:
	default:
		return fmt.Errorf("invalid target type: %s", request.TargetType)
	}

	if request.TargetID == "" {
		return errors.New("target ID is required")
	}
	if request.RollbackTo == "" {
		return errors.New("rollback target commit is required")
	}
	if request.Reason == "" && !request.Emergency {
		return errors.New("reason is required for non-emergency rollbacks")
	}

	switch request.RollbackType {
	case rollback.RollbackTypeFull:
	case rollback.RollbackTypePartial:
		if len(request.Configurations) == 0 {
			return errors.New("partial rollback requires at least one configuration")
		}
	case rollback.RollbackTypeModule:
		if len(request.Modules) == 0 {
			return errors.New("module rollback requires at least one module")
		}
	case rollback.RollbackTypeEmergency:
		if request.Reason == "" {
			return errors.New("emergency rollback requires a reason")
		}
	default:
		return fmt.Errorf("invalid rollback type: %s", request.RollbackType)
	}

	return nil
}

// requiresRollbackApproval mirrors rollback.DefaultRollbackManager.requiresApproval: emergency
// rollbacks bypass approval, high-risk ones (touching a critical module) require it.
func requiresRollbackApproval(request rollback.RollbackRequest) bool {
	if request.Emergency {
		return false
	}
	for _, path := range request.Configurations {
		if isCriticalRollbackPath(path) {
			return true
		}
	}
	for _, module := range request.Modules {
		if isCriticalRollbackPath(module) {
			return true
		}
	}
	return false
}

func actorFromContext(ctx context.Context) string {
	actor, _ := ctx.Value(ctxkeys.UserIDKey).(string)
	return actor
}

// checkPermissions mirrors rollback.DefaultRollbackValidator.validatePermissions.
func (m *inMemoryRollbackManager) checkPermissions(ctx context.Context, request rollback.RollbackRequest) error {
	actor := actorFromContext(ctx)

	if request.Emergency || request.RollbackType == rollback.RollbackTypeEmergency {
		if !m.hasPermission(actor, "rollback.emergency") {
			return rollback.ErrRollbackPermissionDenied
		}
	}
	if request.TargetType == rollback.TargetTypeMSP {
		if !m.hasPermission(actor, "rollback.msp") {
			return rollback.ErrRollbackPermissionDenied
		}
	}
	return nil
}

// checkNoRollbackInProgress mirrors rollback.DefaultRollbackManager.checkNoRollbackInProgress,
// treating every non-terminal status as live.
func (m *inMemoryRollbackManager) checkNoRollbackInProgress(ctx context.Context, request rollback.RollbackRequest) error {
	operations, err := m.store.ListOperations(ctx, rollback.RollbackFilters{
		TargetType: request.TargetType,
		TargetID:   request.TargetID,
	})
	if err != nil {
		return fmt.Errorf("failed to check for active rollbacks: %w", err)
	}
	for _, op := range operations {
		switch op.Status {
		case rollback.RollbackStatusPending, rollback.RollbackStatusValidating,
			rollback.RollbackStatusApprovalRequired, rollback.RollbackStatusInProgress:
			return rollback.ErrRollbackInProgress
		}
	}
	return nil
}

// affectedPaths derives the configuration paths a rollback touches from the request and,
// for full rollbacks, from the newest registered rollback point.
func (m *inMemoryRollbackManager) affectedPaths(request rollback.RollbackRequest) []string {
	switch request.RollbackType {
	case rollback.RollbackTypePartial:
		return request.Configurations
	case rollback.RollbackTypeModule:
		paths := make([]string, 0, len(request.Modules))
		for _, module := range request.Modules {
			paths = append(paths, fmt.Sprintf("modules/%s/config.yaml", module))
		}
		return paths
	default:
		points := m.rollbackPointsFor(request.TargetType, request.TargetID)
		if len(points) == 0 {
			return nil
		}
		return points[0].Configurations
	}
}

// headVersion returns the commit the target is currently on, i.e. the version a rollback
// moves away from. Empty when no rollback points are registered for the target.
func (m *inMemoryRollbackManager) headVersion(targetType rollback.TargetType, targetID string) string {
	points := m.rollbackPointsFor(targetType, targetID)
	if len(points) == 0 {
		return ""
	}
	return points[0].CommitSHA
}

func moduleFromPath(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) >= 2 && parts[0] == "modules" {
		return parts[1]
	}
	return ""
}

// ListRollbackPoints returns the registered rollback points for a target, newest first.
func (m *inMemoryRollbackManager) ListRollbackPoints(_ context.Context, targetType rollback.TargetType, targetID string, limit int) ([]rollback.RollbackPoint, error) {
	if targetID == "" {
		return nil, errors.New("target ID is required")
	}
	points := m.rollbackPointsFor(targetType, targetID)
	if limit > 0 && len(points) > limit {
		points = points[:limit]
	}
	return points, nil
}

// PreviewRollback computes the change set, risk and approval requirement for a request
// without persisting an operation.
func (m *inMemoryRollbackManager) PreviewRollback(_ context.Context, request rollback.RollbackRequest) (*rollback.RollbackPreview, error) {
	if err := validateRollbackRequest(request); err != nil {
		return nil, &rollback.RollbackError{Code: "ROLLBACK_VALIDATION_FAILED", Message: err.Error()}
	}

	currentVersion := m.headVersion(request.TargetType, request.TargetID)
	paths := m.affectedPaths(request)

	changes := make([]rollback.ConfigurationChange, 0, len(paths))
	modules := make([]string, 0, len(paths))
	seenModules := make(map[string]bool)
	overallRisk := rollback.RiskLevelLow

	for _, path := range paths {
		risk := rollback.RiskLevelMedium
		if isCriticalRollbackPath(path) {
			risk = rollback.RiskLevelHigh
			overallRisk = rollback.RiskLevelHigh
		}
		changes = append(changes, rollback.ConfigurationChange{
			Path:            path,
			CurrentVersion:  currentVersion,
			RollbackVersion: request.RollbackTo,
			Risk:            risk,
			Module:          moduleFromPath(path),
		})
		if module := moduleFromPath(path); module != "" && !seenModules[module] {
			seenModules[module] = true
			modules = append(modules, module)
		}
	}

	return &rollback.RollbackPreview{
		Changes:           changes,
		AffectedModules:   modules,
		ValidationResults: rollback.ValidationResults{Passed: true},
		EstimatedDuration: 40*time.Second + time.Duration(len(changes))*5*time.Second,
		RequiresApproval:  requiresRollbackApproval(request),
		RiskAssessment:    rollback.RiskAssessment{OverallRisk: overallRisk},
	}, nil
}

// ExecuteRollback validates, authorizes and records a rollback operation.
func (m *inMemoryRollbackManager) ExecuteRollback(ctx context.Context, request rollback.RollbackRequest) (*rollback.RollbackOperation, error) {
	if err := validateRollbackRequest(request); err != nil {
		return nil, &rollback.RollbackError{Code: "ROLLBACK_VALIDATION_FAILED", Message: err.Error()}
	}
	if err := m.checkPermissions(ctx, request); err != nil {
		return nil, err
	}
	if err := m.checkNoRollbackInProgress(ctx, request); err != nil {
		return nil, err
	}
	if requiresRollbackApproval(request) && request.ApprovalID == "" {
		return nil, &rollback.RollbackError{
			Code:    "APPROVAL_REQUIRED",
			Message: "This rollback requires approval",
		}
	}

	actor := actorFromContext(ctx)
	operation := &rollback.RollbackOperation{
		ID:          uuid.NewString(),
		Request:     request,
		Status:      rollback.RollbackStatusPending,
		InitiatedBy: actor,
		InitiatedAt: time.Now(),
		Progress: rollback.RollbackProgress{
			Stage:      "initializing",
			Percentage: 0,
		},
		AuditTrail: []rollback.AuditEntry{{
			Timestamp: time.Now(),
			EventType: "rollback_initiated",
			Actor:     actor,
			Action:    "Rollback operation initiated",
			Details: map[string]interface{}{
				"from_version": m.headVersion(request.TargetType, request.TargetID),
				"to_version":   request.RollbackTo,
			},
			Result: "success",
		}},
	}

	if err := m.store.SaveOperation(ctx, operation); err != nil {
		return nil, fmt.Errorf("failed to save operation: %w", err)
	}
	return operation, nil
}

// GetRollbackStatus returns a persisted operation.
func (m *inMemoryRollbackManager) GetRollbackStatus(ctx context.Context, rollbackID string) (*rollback.RollbackOperation, error) {
	operation, err := m.store.GetOperation(ctx, rollbackID)
	if err != nil {
		return nil, err
	}
	if operation == nil {
		return nil, rollback.ErrRollbackNotFound
	}
	return operation, nil
}

// CancelRollback cancels a cancellable operation, mirroring
// rollback.DefaultRollbackManager.CancelRollback.
func (m *inMemoryRollbackManager) CancelRollback(ctx context.Context, rollbackID string, reason string) error {
	operation, err := m.store.GetOperation(ctx, rollbackID)
	if err != nil {
		return err
	}
	if operation == nil {
		return rollback.ErrRollbackNotFound
	}

	switch operation.Status {
	case rollback.RollbackStatusPending, rollback.RollbackStatusValidating,
		rollback.RollbackStatusApprovalRequired:
	default:
		return &rollback.RollbackError{
			Code:    "CANNOT_CANCEL",
			Message: fmt.Sprintf("Cannot cancel rollback in status: %s", operation.Status),
		}
	}

	now := time.Now()
	operation.Status = rollback.RollbackStatusCancelled
	operation.CompletedAt = &now
	operation.AuditTrail = append(operation.AuditTrail, rollback.AuditEntry{
		Timestamp: now,
		EventType: "rollback_cancelled",
		Actor:     actorFromContext(ctx),
		Action:    reason,
		Result:    "success",
	})

	return m.store.UpdateOperation(ctx, operation)
}

// ListRollbackHistory returns the operations recorded for a target.
func (m *inMemoryRollbackManager) ListRollbackHistory(ctx context.Context, targetType rollback.TargetType, targetID string, limit int) ([]rollback.RollbackOperation, error) {
	return m.store.ListOperations(ctx, rollback.RollbackFilters{
		TargetType: targetType,
		TargetID:   targetID,
		Limit:      limit,
	})
}

// Compile-time proof the fixture satisfies the production interface.
var _ rollback.RollbackManager = (*inMemoryRollbackManager)(nil)

// scopedPrincipalExtractor returns an extractor that yields a principal with the given TenantID.
func scopedPrincipalExtractor(tenantID string) func(*http.Request) *Principal {
	return func(_ *http.Request) *Principal {
		return &Principal{
			ID:        "admin-api-key",
			TenantID:  tenantID,
			Assurance: session.AssuranceMachine,
		}
	}
}

func adminPrincipalExtractor() func(*http.Request) *Principal {
	return func(_ *http.Request) *Principal {
		return &Principal{
			ID:          "admin-cert-cn",
			Assurance:   session.AssuranceBasic,
			GlobalScope: true,
		}
	}
}

// newRollbackRequest builds a POST /api/v1/rollback/execute request carrying the given JSON
// body, with actor identity in the context exactly as authenticationMiddleware sets it.
func newRollbackRequest(body, actor string) *http.Request {
	req := httptest.NewRequest("POST", "/api/v1/rollback/execute", strings.NewReader(body))
	return req.WithContext(context.WithValue(req.Context(), ctxkeys.UserIDKey, actor))
}

func TestConfigRollback_RejectsCrossTenantVersion(t *testing.T) {
	// Principal scoped to "root/msp-a" must not reach stewards in "root/msp-b".
	mgr := newInMemoryRollbackManager()
	handler := NewRollbackHandler(mgr, scopedPrincipalExtractor("root/msp-a"), nil, nil)

	body := `{"target_type":"steward","target_id":"steward-msp-b","rollback_type":"full","rollback_to":"abc1234567890","reason":"revert bad config","dry_run":false,"steward_tenant_path":"root/msp-b"}`
	rec := httptest.NewRecorder()

	handler.ExecuteRollback(rec, newRollbackRequest(body, "admin-api-key"))

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "CROSS_TENANT_ROLLBACK", resp["code"])

	// No rollback operation may have been initiated.
	assert.Empty(t, mgr.operationsFor(t, rollback.TargetTypeSteward, "steward-msp-b"),
		"rollback must not be initiated after cross-tenant rejection")
}

func TestConfigRollback_BlocksSiblingTenant(t *testing.T) {
	// "root/msp-ab" is a sibling, not a child of "root/msp-a" — prefix matching
	// without a segment boundary would incorrectly allow this.
	mgr := newInMemoryRollbackManager()
	handler := NewRollbackHandler(mgr, scopedPrincipalExtractor("root/msp-a"), nil, nil)

	body := `{"target_type":"steward","target_id":"steward-msp-ab","rollback_type":"full","rollback_to":"abc1234567890","reason":"revert bad config","dry_run":false,"steward_tenant_path":"root/msp-ab"}`
	rec := httptest.NewRecorder()

	handler.ExecuteRollback(rec, newRollbackRequest(body, "admin-api-key"))

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "CROSS_TENANT_ROLLBACK", resp["code"])
	assert.Empty(t, mgr.operationsFor(t, rollback.TargetTypeSteward, "steward-msp-ab"))
}

func TestConfigRollback_AllowsSameTenant(t *testing.T) {
	mgr := newInMemoryRollbackManager()
	handler := NewRollbackHandler(mgr, scopedPrincipalExtractor("root/msp-a"), nil, nil)

	body := `{"target_type":"steward","target_id":"steward-x","rollback_type":"full","rollback_to":"abc1234567890","reason":"revert bad config","dry_run":false,"steward_tenant_path":"root/msp-a"}`
	rec := httptest.NewRecorder()

	handler.ExecuteRollback(rec, newRollbackRequest(body, "admin-api-key"))

	assert.Equal(t, http.StatusAccepted, rec.Code)
	ops := mgr.operationsFor(t, rollback.TargetTypeSteward, "steward-x")
	require.Len(t, ops, 1)
	assert.Equal(t, rollback.RollbackStatusPending, ops[0].Status)
	assert.Equal(t, "admin-api-key", ops[0].InitiatedBy)
}

func TestConfigRollback_AllowsChildTenant(t *testing.T) {
	mgr := newInMemoryRollbackManager()
	handler := NewRollbackHandler(mgr, scopedPrincipalExtractor("root/msp-a"), nil, nil)

	// "root/msp-a/client-1" is a child of "root/msp-a" — must be allowed.
	body := `{"target_type":"steward","target_id":"steward-client-1","rollback_type":"full","rollback_to":"abc1234567890","reason":"revert bad config","dry_run":false,"steward_tenant_path":"root/msp-a/client-1"}`
	rec := httptest.NewRecorder()

	handler.ExecuteRollback(rec, newRollbackRequest(body, "admin-api-key"))

	assert.Equal(t, http.StatusAccepted, rec.Code)
	assert.Len(t, mgr.operationsFor(t, rollback.TargetTypeSteward, "steward-client-1"), 1)
}

func TestConfigRollback_AdminPrincipalSkipsTenantCheck(t *testing.T) {
	// Full admin (Assurance >= AssuranceBasic, TenantID="") can access any tenant.
	mgr := newInMemoryRollbackManager()
	handler := NewRollbackHandler(mgr, adminPrincipalExtractor(), nil, nil)

	body := `{"target_type":"steward","target_id":"steward-any","rollback_type":"full","rollback_to":"abc1234567890","reason":"revert bad config","dry_run":false,"steward_tenant_path":"root/any-tenant"}`
	rec := httptest.NewRecorder()

	handler.ExecuteRollback(rec, newRollbackRequest(body, "admin-cert-cn"))

	assert.Equal(t, http.StatusAccepted, rec.Code)
	assert.Len(t, mgr.operationsFor(t, rollback.TargetTypeSteward, "steward-any"), 1)
}

func TestConfigRollback_NoTenantPathSkipsCheck(t *testing.T) {
	// When steward_tenant_path is omitted, the early-rejection check is skipped.
	// The rollback manager remains the authoritative access check.
	mgr := newInMemoryRollbackManager()
	handler := NewRollbackHandler(mgr, scopedPrincipalExtractor("root/msp-a"), nil, nil)

	body := `{"target_type":"steward","target_id":"steward-xyz","rollback_type":"full","rollback_to":"abc1234567890","reason":"revert bad config","dry_run":false}`
	rec := httptest.NewRecorder()

	handler.ExecuteRollback(rec, newRollbackRequest(body, "admin-api-key"))

	assert.Equal(t, http.StatusAccepted, rec.Code)
	assert.Len(t, mgr.operationsFor(t, rollback.TargetTypeSteward, "steward-xyz"), 1)
}

func TestConfigRollback_ApprovalRequired(t *testing.T) {
	// A rollback touching a critical module is high risk and requires an approval ID.
	mgr := newInMemoryRollbackManager()
	handler := NewRollbackHandler(mgr, adminPrincipalExtractor(), nil, nil)

	body := `{"target_type":"steward","target_id":"steward-x","rollback_type":"module","modules":["authentication"],"rollback_to":"abc123","reason":"revert auth change"}`
	rec := httptest.NewRecorder()

	handler.ExecuteRollback(rec, newRollbackRequest(body, "admin-cert-cn"))

	assert.Equal(t, http.StatusPreconditionFailed, rec.Code)
	assert.Empty(t, mgr.operationsFor(t, rollback.TargetTypeSteward, "steward-x"),
		"rollback awaiting approval must not be initiated")

	// The same request carrying an approval ID proceeds.
	rec = httptest.NewRecorder()
	approved := `{"target_type":"steward","target_id":"steward-x","rollback_type":"module","modules":["authentication"],"rollback_to":"abc123","reason":"revert auth change","approval_id":"approval-77"}`
	handler.ExecuteRollback(rec, newRollbackRequest(approved, "admin-cert-cn"))

	assert.Equal(t, http.StatusAccepted, rec.Code)
	assert.Len(t, mgr.operationsFor(t, rollback.TargetTypeSteward, "steward-x"), 1)
}

func TestConfigRollback_InProgress(t *testing.T) {
	// A second rollback for a target that already has a live operation is rejected.
	mgr := newInMemoryRollbackManager()
	handler := NewRollbackHandler(mgr, adminPrincipalExtractor(), nil, nil)

	body := `{"target_type":"steward","target_id":"steward-x","rollback_type":"full","rollback_to":"abc123","reason":"revert bad config"}`

	rec := httptest.NewRecorder()
	handler.ExecuteRollback(rec, newRollbackRequest(body, "admin-cert-cn"))
	require.Equal(t, http.StatusAccepted, rec.Code)

	rec = httptest.NewRecorder()
	handler.ExecuteRollback(rec, newRollbackRequest(body, "admin-cert-cn"))

	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.Len(t, mgr.operationsFor(t, rollback.TargetTypeSteward, "steward-x"), 1,
		"the conflicting second request must not create another operation")
}

func TestConfigRollback_PermissionDenied(t *testing.T) {
	// MSP-wide rollback requires the "rollback.msp" permission.
	mgr := newInMemoryRollbackManager()
	handler := NewRollbackHandler(mgr, adminPrincipalExtractor(), nil, nil)

	body := `{"target_type":"msp","target_id":"msp-global","rollback_type":"full","rollback_to":"abc123","reason":"revert fleet-wide change"}`

	rec := httptest.NewRecorder()
	handler.ExecuteRollback(rec, newRollbackRequest(body, "operator@example.com"))

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Empty(t, mgr.operationsFor(t, rollback.TargetTypeMSP, "msp-global"))

	// Granting the permission lets the same request through.
	mgr.grant("operator@example.com", "rollback.msp")
	rec = httptest.NewRecorder()
	handler.ExecuteRollback(rec, newRollbackRequest(body, "operator@example.com"))

	assert.Equal(t, http.StatusAccepted, rec.Code)
	assert.Len(t, mgr.operationsFor(t, rollback.TargetTypeMSP, "msp-global"), 1)
}

func TestConfigRollback_ValidationFailed(t *testing.T) {
	// A partial rollback must name at least one configuration.
	mgr := newInMemoryRollbackManager()
	handler := NewRollbackHandler(mgr, adminPrincipalExtractor(), nil, nil)

	body := `{"target_type":"steward","target_id":"steward-x","rollback_type":"partial","configurations":[],"rollback_to":"abc123","reason":"revert bad config"}`
	rec := httptest.NewRecorder()

	handler.ExecuteRollback(rec, newRollbackRequest(body, "admin-cert-cn"))

	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Empty(t, mgr.operationsFor(t, rollback.TargetTypeSteward, "steward-x"))
}

func TestConfigRollback_InvalidBody(t *testing.T) {
	mgr := newInMemoryRollbackManager()
	handler := NewRollbackHandler(mgr, adminPrincipalExtractor(), nil, nil)

	rec := httptest.NewRecorder()
	handler.ExecuteRollback(rec, newRollbackRequest("not json", "admin-cert-cn"))

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Empty(t, mgr.operationsFor(t, rollback.TargetTypeSteward, "steward-x"))
}

func TestConfigRollback_ListRollbackPoints(t *testing.T) {
	// The points endpoint returns the target's rollback points newest first, honouring limit.
	mgr := newInMemoryRollbackManager()
	handler := NewRollbackHandler(mgr, adminPrincipalExtractor(), nil, nil)

	base := time.Now()
	mgr.addRollbackPoint(rollback.TargetTypeSteward, "steward-x", rollback.RollbackPoint{
		CommitSHA:      "older123",
		Timestamp:      base.Add(-2 * time.Hour),
		Author:         "ops@example.com",
		Message:        "tighten firewall",
		Configurations: []string{"modules/firewall/config.yaml"},
		CanRollback:    true,
	})
	mgr.addRollbackPoint(rollback.TargetTypeSteward, "steward-x", rollback.RollbackPoint{
		CommitSHA:      "newer456",
		Timestamp:      base.Add(-1 * time.Hour),
		Author:         "ops@example.com",
		Message:        "add package baseline",
		Configurations: []string{"modules/package/config.yaml"},
		CanRollback:    true,
	})

	req := httptest.NewRequest("GET", "/api/v1/rollback/points?target_type=steward&target_id=steward-x", nil)
	rec := httptest.NewRecorder()
	handler.ListRollbackPoints(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		RollbackPoints []rollback.RollbackPoint `json:"rollback_points"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.Len(t, resp.RollbackPoints, 2)
	assert.Equal(t, "newer456", resp.RollbackPoints[0].CommitSHA, "points must be newest first")
	assert.Equal(t, "older123", resp.RollbackPoints[1].CommitSHA)

	// limit=1 truncates to the newest point.
	req = httptest.NewRequest("GET", "/api/v1/rollback/points?target_type=steward&target_id=steward-x&limit=1", nil)
	rec = httptest.NewRecorder()
	handler.ListRollbackPoints(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	resp.RollbackPoints = nil
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.Len(t, resp.RollbackPoints, 1)
	assert.Equal(t, "newer456", resp.RollbackPoints[0].CommitSHA)

	// The head commit is recorded as from_version when a rollback is initiated.
	body := `{"target_type":"steward","target_id":"steward-x","rollback_type":"full","rollback_to":"older123","reason":"revert package baseline"}`
	rec = httptest.NewRecorder()
	handler.ExecuteRollback(rec, newRollbackRequest(body, "admin-cert-cn"))

	require.Equal(t, http.StatusAccepted, rec.Code)
	ops := mgr.operationsFor(t, rollback.TargetTypeSteward, "steward-x")
	require.Len(t, ops, 1)
	require.NotEmpty(t, ops[0].AuditTrail)
	assert.Equal(t, "newer456", ops[0].AuditTrail[0].Details["from_version"])
}

func TestConfigRollback_ServerSideTenantLookup(t *testing.T) {
	// When stewardTenantLookup returns a different tenant from the principal's scope,
	// the handler must reject the request even if steward_tenant_path is absent or
	// matches the correct tenant — the server-side check is authoritative.
	t.Run("rejects cross-tenant steward via server-side lookup", func(t *testing.T) {
		mgr := newInMemoryRollbackManager()
		lookup := func(_ string) string { return "root/msp-b" }
		handler := NewRollbackHandler(mgr, scopedPrincipalExtractor("root/msp-a"), lookup, nil)

		// No steward_tenant_path in body — server-side lookup must catch this anyway.
		body := `{"target_type":"steward","target_id":"steward-msp-b","rollback_type":"full","rollback_to":"abc123","reason":"revert bad config"}`
		rec := httptest.NewRecorder()

		handler.ExecuteRollback(rec, newRollbackRequest(body, "admin-api-key"))

		assert.Equal(t, http.StatusBadRequest, rec.Code)
		var resp map[string]interface{}
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		assert.Equal(t, "CROSS_TENANT_ROLLBACK", resp["code"])
		assert.Empty(t, mgr.operationsFor(t, rollback.TargetTypeSteward, "steward-msp-b"))
	})

	t.Run("allows same-tenant steward via server-side lookup", func(t *testing.T) {
		mgr := newInMemoryRollbackManager()
		lookup := func(_ string) string { return "root/msp-a" }
		handler := NewRollbackHandler(mgr, scopedPrincipalExtractor("root/msp-a"), lookup, nil)

		body := `{"target_type":"steward","target_id":"steward-msp-a","rollback_type":"full","rollback_to":"abc123","reason":"revert bad config"}`
		rec := httptest.NewRecorder()

		handler.ExecuteRollback(rec, newRollbackRequest(body, "admin-api-key"))

		assert.Equal(t, http.StatusAccepted, rec.Code)
		assert.Len(t, mgr.operationsFor(t, rollback.TargetTypeSteward, "steward-msp-a"), 1)
	})

	t.Run("lookup returns empty string skips check", func(t *testing.T) {
		// Steward not in registry yet (pre-registration edge case): lookup returns "".
		// The handler must NOT block — the rollback manager is the authoritative gatekeeper.
		mgr := newInMemoryRollbackManager()
		lookup := func(_ string) string { return "" }
		handler := NewRollbackHandler(mgr, scopedPrincipalExtractor("root/msp-a"), lookup, nil)

		body := `{"target_type":"steward","target_id":"steward-unknown","rollback_type":"full","rollback_to":"abc123","reason":"revert bad config"}`
		rec := httptest.NewRecorder()

		handler.ExecuteRollback(rec, newRollbackRequest(body, "admin-api-key"))

		assert.Equal(t, http.StatusAccepted, rec.Code)
		assert.Len(t, mgr.operationsFor(t, rollback.TargetTypeSteward, "steward-unknown"), 1)
	})

	t.Run("admin principal skips server-side lookup entirely", func(t *testing.T) {
		mgr := newInMemoryRollbackManager()
		// lookup would return a cross-tenant result but admin bypasses the check
		lookup := func(_ string) string { return "root/msp-z" }
		handler := NewRollbackHandler(mgr, adminPrincipalExtractor(), lookup, nil)

		body := `{"target_type":"steward","target_id":"steward-any","rollback_type":"full","rollback_to":"abc123","reason":"revert bad config"}`
		rec := httptest.NewRecorder()

		handler.ExecuteRollback(rec, newRollbackRequest(body, "admin-cert-cn"))

		assert.Equal(t, http.StatusAccepted, rec.Code)
		assert.Len(t, mgr.operationsFor(t, rollback.TargetTypeSteward, "steward-any"), 1)
	})
}

// sessionPrincipalExtractor returns an extractor that yields a session principal with
// GlobalScope=true (as set by middleware) but a non-empty TenantID. This mirrors
// the middleware.go bug described in Issue #3143.
func sessionPrincipalExtractor(tenantID string) func(*http.Request) *Principal {
	return func(_ *http.Request) *Principal {
		return &Principal{
			ID:          "web-session-" + tenantID,
			GlobalScope: true, // middleware.go bug: hardcoded true for all session principals
			TenantID:    tenantID,
			Assurance:   session.AssuranceBasic,
		}
	}
}

// TestConfigRollback_SessionPrincipal_CrossTenantBlocked verifies the Issue #3143 fix
// for rollback_handler.go: a web-session principal has GlobalScope=true set by middleware
// even when scoped to a specific tenant. Before the fix, the !principal.GlobalScope guard
// would always pass (GlobalScope=true → !true=false → check skipped), allowing a session
// caller to roll back any tenant's steward. After the fix, only principal.TenantID governs
// the cross-tenant check.
func TestConfigRollback_SessionPrincipal_CrossTenantBlocked(t *testing.T) {
	mgr := newInMemoryRollbackManager()
	// Session principal scoped to "root/msp-a" with GlobalScope=true (the bug).
	handler := NewRollbackHandler(mgr, sessionPrincipalExtractor("root/msp-a"), nil, nil)

	// Target steward belongs to "root/msp-b" — a sibling tenant, not a child.
	body := `{"target_type":"steward","target_id":"steward-msp-b","rollback_type":"full","rollback_to":"abc1234567890","reason":"revert bad config","dry_run":false,"steward_tenant_path":"root/msp-b"}`
	rec := httptest.NewRecorder()

	handler.ExecuteRollback(rec, newRollbackRequest(body, "web-session-root/msp-a"))

	assert.Equal(t, http.StatusBadRequest, rec.Code,
		"session principal scoped to root/msp-a must not roll back stewards in root/msp-b (body: %s)", rec.Body.String())
	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "CROSS_TENANT_ROLLBACK", resp["code"])
	assert.Empty(t, mgr.operationsFor(t, rollback.TargetTypeSteward, "steward-msp-b"),
		"rollback must not be initiated after cross-tenant rejection")
}
