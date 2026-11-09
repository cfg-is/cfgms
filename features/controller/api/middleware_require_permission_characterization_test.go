// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/session"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Characterization tests for Server.requirePermission (Issue #5868). They pin what a
// client sees from each stage of the returned handler — authorization-service wiring,
// principal lookup, permission check, assurance floor, user-presence token, the ADR-025
// root<->MSP boundary, tenant isolation and the grant — and the order of those stages,
// so the function can be restructured without changing behavior. Fixtures come from the
// existing tests in this package (middleware_test.go, middleware_tenant_boundary_test.go).

const (
	// Test-only permissions registered in permissionAssurance for the duration of a test.
	middlewarerequirepermissionCharFloorPerm    = "mrpchar:floor"
	middlewarerequirepermissionCharMachinePerm  = "mrpchar:machine"
	middlewarerequirepermissionCharPresencePerm = "mrpchar:presence"
	middlewarerequirepermissionCharExemptPerm   = "mrpchar:exempt"
)

// middlewarerequirepermissionCharRegister installs req for permissionID in
// permissionAssurance and removes it on cleanup.
func middlewarerequirepermissionCharRegister(t *testing.T, permissionID string, req Requirement) {
	t.Helper()
	permissionAssurance[permissionID] = req
	t.Cleanup(func() { delete(permissionAssurance, permissionID) })
}

// middlewarerequirepermissionCharRegisterAll registers the test-only permissions that need no router entry.
func middlewarerequirepermissionCharRegisterAll(t *testing.T) {
	t.Helper()
	middlewarerequirepermissionCharRegister(t, middlewarerequirepermissionCharFloorPerm,
		Requirement{Min: session.AssuranceStrong})
	middlewarerequirepermissionCharRegister(t, middlewarerequirepermissionCharMachinePerm,
		Requirement{Min: session.AssuranceStrong, RequireUserPresence: true, AllowMachine: true})
	middlewarerequirepermissionCharRegister(t, middlewarerequirepermissionCharPresencePerm,
		Requirement{Min: session.AssuranceStrong, RequireUserPresence: true})
}

// middlewarerequirepermissionCharRegisterExempt registers the presence-exempt permission.
// It must run AFTER the server is built: New validates every PresenceExemptRoutes entry
// against the real router and would refuse to start on this test-only route.
func middlewarerequirepermissionCharRegisterExempt(t *testing.T) {
	t.Helper()
	middlewarerequirepermissionCharRegister(t, middlewarerequirepermissionCharExemptPerm,
		Requirement{
			Min:                  session.AssuranceStrong,
			RequireUserPresence:  true,
			PresenceExemptRoutes: []string{"POST /mrpchar/exempt"},
		})
}

// middlewarerequirepermissionCharCall describes one request through requirePermission.
type middlewarerequirepermissionCharCall struct {
	resourceType string
	action       string
	principal    *Principal // nil leaves the principal out of the context
	relay        bool       // marks the principal as a relay principal
	method       string
	target       string
	body         string
	vars         map[string]string
	header       map[string]string
	userID       string
	tenantID     string
	route        string // when set, the request is dispatched through a mux route with this template
}

// middlewarerequirepermissionCharResult is what the request produced: the recorder and
// the request the wrapped handler saw (nil when it was rejected before the handler).
type middlewarerequirepermissionCharResult struct {
	rec  *httptest.ResponseRecorder
	seen *http.Request
}

func (c middlewarerequirepermissionCharCall) request() *http.Request {
	method, target := c.method, c.target
	if method == "" {
		method = http.MethodPost
	}
	if target == "" {
		target = "/mrpchar/resource"
	}
	req := httptest.NewRequest(method, target, strings.NewReader(c.body))
	for k, v := range c.header {
		req.Header.Set(k, v)
	}
	if c.vars != nil {
		req = mux.SetURLVars(req, c.vars)
	}
	ctx := req.Context()
	if c.principal != nil {
		ctx = context.WithValue(ctx, principalContextKey, c.principal)
		if c.relay {
			ctx = context.WithValue(ctx, relayPrincipalKey, c.principal)
		}
	}
	if c.userID != "" {
		ctx = context.WithValue(ctx, ctxkeys.UserIDKey, c.userID)
	}
	if c.tenantID != "" {
		ctx = context.WithValue(ctx, ctxkeys.TenantID, c.tenantID)
	}
	return req.WithContext(ctx)
}

func middlewarerequirepermissionCharServe(srv *Server, c middlewarerequirepermissionCharCall) middlewarerequirepermissionCharResult {
	var res middlewarerequirepermissionCharResult
	res.rec = httptest.NewRecorder()
	handler := srv.requirePermission(c.resourceType, c.action)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		res.seen = r
		w.WriteHeader(http.StatusOK)
	}))
	req := c.request()
	if c.route == "" {
		handler.ServeHTTP(res.rec, req)
		return res
	}
	router := mux.NewRouter()
	router.Handle(c.route, handler).Methods(req.Method)
	// Dispatch through the router so mux.CurrentRoute resolves; carry the principal over.
	routed := httptest.NewRequest(req.Method, req.URL.String(), strings.NewReader(c.body))
	routed.Header = req.Header
	routed = routed.WithContext(req.Context())
	router.ServeHTTP(res.rec, routed)
	return res
}

func middlewarerequirepermissionCharPerm(resourceType, action string) middlewarerequirepermissionCharCall {
	return middlewarerequirepermissionCharCall{resourceType: resourceType, action: action}
}

// middlewarerequirepermissionCharHuman is a session-style principal holding permissions.
func middlewarerequirepermissionCharHuman(id string, level session.AssuranceLevel, perms ...string) *Principal {
	return &Principal{ID: id, Name: id, Assurance: level, GlobalScope: true, Permissions: perms}
}

// middlewarerequirepermissionCharAPIKey is an API-key principal (AssuranceMachine).
func middlewarerequirepermissionCharAPIKey(id string, perms ...string) *Principal {
	return &Principal{ID: id, Name: id, Assurance: session.AssuranceMachine, GlobalScope: true, Permissions: perms}
}

func middlewarerequirepermissionCharJSON(t *testing.T, res middlewarerequirepermissionCharResult) map[string]interface{} {
	t.Helper()
	var out map[string]interface{}
	require.NoError(t, json.Unmarshal(res.rec.Body.Bytes(), &out), res.rec.Body.String())
	return out
}

func middlewarerequirepermissionCharRequireReject(t *testing.T, res middlewarerequirepermissionCharResult, status int, code string) {
	t.Helper()
	require.Equal(t, status, res.rec.Code, res.rec.Body.String())
	assert.Equal(t, code, errCode(t, res.rec.Body.Bytes()))
	assert.Nil(t, res.seen, "a rejected request must not reach the handler")
}

// middlewarerequirepermissionCharRequireAuthzBody pins the authorization-error body: the
// message and the one disclosed field, the missing permission.
func middlewarerequirepermissionCharRequireAuthzBody(t *testing.T, res middlewarerequirepermissionCharResult, message, permissionID string) {
	t.Helper()
	body := middlewarerequirepermissionCharJSON(t, res)
	apiErr, ok := body["error"].(map[string]interface{})
	require.True(t, ok, res.rec.Body.String())
	assert.Equal(t, message, apiErr["message"])
	assert.Equal(t, map[string]interface{}{"permission_id": permissionID}, apiErr["details"])
	assert.Equal(t, "application/json", res.rec.Header().Get("Content-Type"))
}

func middlewarerequirepermissionCharRequireAdmitted(t *testing.T, res middlewarerequirepermissionCharResult) {
	t.Helper()
	require.Equal(t, http.StatusOK, res.rec.Code, res.rec.Body.String())
	require.NotNil(t, res.seen, "the handler must be reached")
}

// middlewarerequirepermissionCharAuditEntry returns the first captured entry with msg.
func middlewarerequirepermissionCharAuditEntry(log *auditCapturingLogger, msg string) *auditLogEntry {
	log.mu.Lock()
	defer log.mu.Unlock()
	for i := range log.entries {
		if log.entries[i].msg == msg {
			e := log.entries[i]
			return &e
		}
	}
	return nil
}

func (e auditLogEntry) value(key string) interface{} {
	for i := 0; i+1 < len(e.kvs); i += 2 {
		if k, _ := e.kvs[i].(string); k == key {
			return e.kvs[i+1]
		}
	}
	return nil
}

// middlewarerequirepermissionCharPresenceCall is a call for the presence-gated permission
// with a principal that clears the assurance floor.
func middlewarerequirepermissionCharPresenceCall(principal *Principal) middlewarerequirepermissionCharCall {
	c := middlewarerequirepermissionCharPerm("mrpchar", "presence")
	c.principal = principal
	c.target = "/mrpchar/presence-action?x=1"
	c.body = `{"k":"v"}`
	return c
}

// middlewarerequirepermissionCharBoundToken mints a presence token bound to c's request
// for permissionID, owned by ownerID.
func middlewarerequirepermissionCharBoundToken(t *testing.T, srv *Server, ownerID string, c middlewarerequirepermissionCharCall, permissionID string) string {
	t.Helper()
	return mintPresenceTokenFor(t, srv, ownerID, c.request(), permissionID)
}

func middlewarerequirepermissionCharRequirePresenceChallenge(t *testing.T, res middlewarerequirepermissionCharResult, errorCode string) {
	t.Helper()
	require.Equal(t, http.StatusUnauthorized, res.rec.Code, res.rec.Body.String())
	assert.Equal(t,
		`CFGMS-StepUp realm="cfgms", required="strong", presence="required", permission="`+middlewarerequirepermissionCharPresencePerm+`"`,
		res.rec.Header().Get("WWW-Authenticate"))
	assert.Equal(t, "application/json", res.rec.Header().Get("Content-Type"))
	body := middlewarerequirepermissionCharJSON(t, res)
	assert.Equal(t, errorCode, body["error"])
	assert.Equal(t, true, body["presence_required"])
	assert.Nil(t, res.seen, "a rejected request must not reach the handler")
}

// --- authorization service wiring ---

func TestMiddlewareRequirePermissionChar_NoAuthorizationService(t *testing.T) {
	logger := &auditCapturingLogger{}
	srv := setupTestServerWithLogger(t, logger)
	srv.rbacService = nil

	t.Run("non-relay request fails closed with 503", func(t *testing.T) {
		c := middlewarerequirepermissionCharPerm("steward", "read")
		c.principal = middlewarerequirepermissionCharHuman("admin-1", session.AssuranceStrong, "steward:read")

		res := middlewarerequirepermissionCharServe(srv, c)

		middlewarerequirepermissionCharRequireReject(t, res, http.StatusServiceUnavailable, "AUTHORIZATION_UNAVAILABLE")
		assert.Contains(t, res.rec.Body.String(), "Authorization service unavailable")
		entry := middlewarerequirepermissionCharAuditEntry(logger, "RBAC service not available; denying request")
		require.NotNil(t, entry, "the fail-closed branch must log the error")
		assert.Equal(t, "ERROR", entry.level)
	})

	t.Run("relay principal holding the permission is admitted", func(t *testing.T) {
		c := middlewarerequirepermissionCharPerm("steward", "read")
		c.principal = &Principal{ID: "relay-1", Permissions: []string{"steward:read"}}
		c.relay = true

		res := middlewarerequirepermissionCharServe(srv, c)

		middlewarerequirepermissionCharRequireAdmitted(t, res)
		_, hasDecision := res.seen.Context().Value(authDecisionContextKey).(*AuthorizationDecision)
		assert.False(t, hasDecision, "the relay path hands the request on without an authorization decision")
	})

	t.Run("relay principal lacking the permission gets 403", func(t *testing.T) {
		c := middlewarerequirepermissionCharPerm("steward", "write")
		c.principal = &Principal{ID: "relay-1", Permissions: []string{"steward:read"}}
		c.relay = true

		res := middlewarerequirepermissionCharServe(srv, c)

		middlewarerequirepermissionCharRequireReject(t, res, http.StatusForbidden, "INSUFFICIENT_PERMISSIONS")
		assert.Contains(t, res.rec.Body.String(), "Insufficient permissions")
	})

	t.Run("relay marker without a principal in context gets 403", func(t *testing.T) {
		c := middlewarerequirepermissionCharPerm("steward", "read")
		req := c.request()
		req = req.WithContext(context.WithValue(req.Context(), relayPrincipalKey, &Principal{ID: "relay-1"}))
		res := middlewarerequirepermissionCharResult{rec: httptest.NewRecorder()}
		srv.requirePermission("steward", "read")(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			res.seen = req
		})).ServeHTTP(res.rec, req)

		middlewarerequirepermissionCharRequireReject(t, res, http.StatusForbidden, "INSUFFICIENT_PERMISSIONS")
	})
}

// --- principal ---

func TestMiddlewareRequirePermissionChar_MissingPrincipal(t *testing.T) {
	srv := setupTestServer(t)

	res := middlewarerequirepermissionCharServe(srv, middlewarerequirepermissionCharPerm("steward", "read"))

	middlewarerequirepermissionCharRequireReject(t, res, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED")
	assert.Contains(t, res.rec.Body.String(), "Authentication required")
}

// --- permission ---

func TestMiddlewareRequirePermissionChar_PermissionDenied(t *testing.T) {
	logger := &auditCapturingLogger{}
	srv := setupTestServerWithLogger(t, logger)

	c := middlewarerequirepermissionCharPerm("steward", "write")
	c.principal = middlewarerequirepermissionCharHuman("viewer-1", session.AssuranceStrong, "steward:read")
	c.userID = "viewer-1"
	c.tenantID = "tenant-x"
	c.vars = map[string]string{"id": "st-9"}
	logger.mu.Lock()
	logger.entries = nil
	logger.mu.Unlock()

	res := middlewarerequirepermissionCharServe(srv, c)

	middlewarerequirepermissionCharRequireReject(t, res, http.StatusForbidden, "INSUFFICIENT_PERMISSIONS")
	middlewarerequirepermissionCharRequireAuthzBody(t, res, "Insufficient permissions", "steward:write")

	entry := middlewarerequirepermissionCharAuditEntry(logger, "Authorization audit - access denied")
	require.NotNil(t, entry, "a denied permission must be audited")
	assert.Equal(t, "WARN", entry.level)
	assert.Equal(t, "DENY", entry.value("decision"))
	assert.Equal(t, "Principal lacks required permission: steward:write", entry.value("reason"))
	assert.Equal(t, "steward:st-9", entry.value("resource"))
	assert.Equal(t, "viewer-1", entry.value("subject_id"))
	assert.Equal(t, "tenant-x", entry.value("tenant_id"))
	assert.Equal(t, "write", entry.value("action"))
}

func TestMiddlewareRequirePermissionChar_ImplicitAdminHoldsEveryPermission(t *testing.T) {
	srv := setupTestServer(t)
	c := middlewarerequirepermissionCharPerm("steward", "write")
	c.principal = &Principal{ID: "root-admin", Assurance: session.AssuranceStrong, GlobalScope: true, ImplicitAdmin: true}

	middlewarerequirepermissionCharRequireAdmitted(t, middlewarerequirepermissionCharServe(srv, c))
}

// The permission check runs before the assurance check: a caller lacking the permission
// is told 403 even when it would also fail the floor.
func TestMiddlewareRequirePermissionChar_PermissionCheckPrecedesAssuranceCheck(t *testing.T) {
	middlewarerequirepermissionCharRegisterAll(t)
	srv := setupTestServer(t)
	c := middlewarerequirepermissionCharPerm("mrpchar", "floor")
	c.principal = middlewarerequirepermissionCharAPIKey("key-1")

	res := middlewarerequirepermissionCharServe(srv, c)

	middlewarerequirepermissionCharRequireReject(t, res, http.StatusForbidden, "INSUFFICIENT_PERMISSIONS")
	assert.Empty(t, res.rec.Header().Get("WWW-Authenticate"))
}

// --- assurance floor ---

func TestMiddlewareRequirePermissionChar_AssuranceFloor(t *testing.T) {
	middlewarerequirepermissionCharRegisterAll(t)
	const perm = middlewarerequirepermissionCharFloorPerm

	t.Run("API-key principal below the floor gets a plain 403 with no challenge", func(t *testing.T) {
		logger := &auditCapturingLogger{}
		srv := setupTestServerWithLogger(t, logger)
		c := middlewarerequirepermissionCharPerm("mrpchar", "floor")
		c.principal = middlewarerequirepermissionCharAPIKey("key-1", perm)
		c.userID = "key-1"

		res := middlewarerequirepermissionCharServe(srv, c)

		middlewarerequirepermissionCharRequireReject(t, res, http.StatusForbidden, "INSUFFICIENT_PERMISSIONS")
		assert.Empty(t, res.rec.Header().Get("WWW-Authenticate"), "an API key can never step up")
		middlewarerequirepermissionCharRequireAuthzBody(t, res, "Insufficient permissions", perm)
		entry := middlewarerequirepermissionCharAuditEntry(logger, "Authorization audit - access denied")
		require.NotNil(t, entry)
		assert.Equal(t, "Insufficient assurance: machine < strong required for "+perm, entry.value("reason"))
	})

	t.Run("human principal below the floor gets the step-up challenge", func(t *testing.T) {
		srv := setupTestServer(t)
		c := middlewarerequirepermissionCharPerm("mrpchar", "floor")
		c.principal = middlewarerequirepermissionCharHuman("user-1", session.AssuranceBasic, perm)

		res := middlewarerequirepermissionCharServe(srv, c)

		require.Equal(t, http.StatusUnauthorized, res.rec.Code, res.rec.Body.String())
		assert.Nil(t, res.seen)
		assert.Equal(t, `CFGMS-StepUp realm="cfgms", required="strong"`, res.rec.Header().Get("WWW-Authenticate"))
		assert.Equal(t, "application/json", res.rec.Header().Get("Content-Type"))
		body := middlewarerequirepermissionCharJSON(t, res)
		assert.Equal(t, map[string]interface{}{"error": "step_up_required", "required_assurance": "strong"}, body)
	})

	t.Run("principal at the floor is admitted", func(t *testing.T) {
		srv := setupTestServer(t)
		c := middlewarerequirepermissionCharPerm("mrpchar", "floor")
		c.principal = middlewarerequirepermissionCharHuman("user-1", session.AssuranceStrong, perm)

		middlewarerequirepermissionCharRequireAdmitted(t, middlewarerequirepermissionCharServe(srv, c))
	})

	t.Run("a permission with no assurance entry has no floor", func(t *testing.T) {
		srv := setupTestServer(t)
		c := middlewarerequirepermissionCharPerm("mrpchar", "unregistered")
		c.principal = middlewarerequirepermissionCharAPIKey("key-1", "mrpchar:unregistered")

		middlewarerequirepermissionCharRequireAdmitted(t, middlewarerequirepermissionCharServe(srv, c))
	})
}

func TestMiddlewareRequirePermissionChar_AllowMachineSkipsFloorAndPresence(t *testing.T) {
	middlewarerequirepermissionCharRegisterAll(t)
	const perm = middlewarerequirepermissionCharMachinePerm
	srv := setupTestServer(t)

	t.Run("API-key principal skips both the floor and the presence check", func(t *testing.T) {
		c := middlewarerequirepermissionCharPerm("mrpchar", "machine")
		c.principal = middlewarerequirepermissionCharAPIKey("key-1", perm)

		res := middlewarerequirepermissionCharServe(srv, c)

		middlewarerequirepermissionCharRequireAdmitted(t, res)
	})

	t.Run("API-key principal still needs the permission", func(t *testing.T) {
		c := middlewarerequirepermissionCharPerm("mrpchar", "machine")
		c.principal = middlewarerequirepermissionCharAPIKey("key-1")

		middlewarerequirepermissionCharRequireReject(t,
			middlewarerequirepermissionCharServe(srv, c), http.StatusForbidden, "INSUFFICIENT_PERMISSIONS")
	})

	t.Run("human principal below the floor is not exempt", func(t *testing.T) {
		c := middlewarerequirepermissionCharPerm("mrpchar", "machine")
		c.principal = middlewarerequirepermissionCharHuman("user-1", session.AssuranceBasic, perm)

		res := middlewarerequirepermissionCharServe(srv, c)

		require.Equal(t, http.StatusUnauthorized, res.rec.Code)
		assert.Equal(t, `CFGMS-StepUp realm="cfgms", required="strong"`, res.rec.Header().Get("WWW-Authenticate"))
	})

	t.Run("human principal at the floor still owes the presence token", func(t *testing.T) {
		c := middlewarerequirepermissionCharPerm("mrpchar", "machine")
		c.principal = middlewarerequirepermissionCharHuman("user-1", session.AssuranceStrong, perm)

		res := middlewarerequirepermissionCharServe(srv, c)

		require.Equal(t, http.StatusUnauthorized, res.rec.Code)
		assert.Contains(t, res.rec.Header().Get("WWW-Authenticate"), `presence="required"`)
	})
}

func TestMiddlewareRequirePermissionChar_AssuranceResolutionFailsClosed(t *testing.T) {
	middlewarerequirepermissionCharRegisterAll(t)
	logger := &auditCapturingLogger{}
	srv := setupTestServerWithLogger(t, logger)
	srv.SetAssurancePolicyStore(newTestAssurancePolicyStore())
	srv.SetTenantStore(newTestTenantStoreWithPath(map[string][]string{}))
	c := middlewarerequirepermissionCharPerm("mrpchar", "floor")
	c.principal = middlewarerequirepermissionCharHuman("user-1", session.AssuranceStrong, middlewarerequirepermissionCharFloorPerm)
	c.tenantID = "mrpchar-no-such-tenant"

	res := middlewarerequirepermissionCharServe(srv, c)

	middlewarerequirepermissionCharRequireReject(t, res, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE")
	assert.Contains(t, res.rec.Body.String(), "Authorization data is temporarily unavailable")
	entry := middlewarerequirepermissionCharAuditEntry(logger, "Failed to resolve assurance requirement")
	require.NotNil(t, entry)
	assert.Equal(t, "ERROR", entry.level)
	assert.Equal(t, middlewarerequirepermissionCharFloorPerm, entry.value("permission_id"))
	assert.Equal(t, "mrpchar-no-such-tenant", entry.value("tenant_id"))
}

func TestMiddlewareRequirePermissionChar_TenantOverrideRaisesRequirement(t *testing.T) {
	srv := setupTestServer(t)
	apStore := newTestAssurancePolicyStore()
	strong := int(session.AssuranceStrong)
	require.NoError(t, apStore.SetPolicy(context.Background(), &business.AssurancePolicy{
		TenantID: "mrpchar-t",
		Overrides: []business.AssurancePolicyOverride{
			{PermissionID: "mrpchar:override", MinOverride: &strong, RequireUserPresence: true},
		},
	}))
	srv.SetAssurancePolicyStore(apStore)
	srv.SetTenantStore(newTestTenantStoreWithPath(map[string][]string{"mrpchar-t": {"mrpchar-t"}}))

	c := middlewarerequirepermissionCharPerm("mrpchar", "override")
	c.tenantID = "mrpchar-t"
	c.principal = middlewarerequirepermissionCharHuman("user-1", session.AssuranceBasic, "mrpchar:override")

	t.Run("a permission absent from the global map is gated by the override floor", func(t *testing.T) {
		res := middlewarerequirepermissionCharServe(srv, c)

		require.Equal(t, http.StatusUnauthorized, res.rec.Code, res.rec.Body.String())
		assert.Equal(t, `CFGMS-StepUp realm="cfgms", required="strong"`, res.rec.Header().Get("WWW-Authenticate"))
	})

	t.Run("at the floor the override demands the presence token", func(t *testing.T) {
		c.principal = middlewarerequirepermissionCharHuman("user-1", session.AssuranceStrong, "mrpchar:override")

		res := middlewarerequirepermissionCharServe(srv, c)

		require.Equal(t, http.StatusUnauthorized, res.rec.Code, res.rec.Body.String())
		assert.Equal(t,
			`CFGMS-StepUp realm="cfgms", required="strong", presence="required", permission="mrpchar:override"`,
			res.rec.Header().Get("WWW-Authenticate"))
	})
}

// --- user presence ---

func TestMiddlewareRequirePermissionChar_Presence(t *testing.T) {
	middlewarerequirepermissionCharRegisterAll(t)
	const perm = middlewarerequirepermissionCharPresencePerm
	principalA := middlewarerequirepermissionCharHuman("principal-a", session.AssuranceStrong, perm)

	t.Run("missing token gets the presence challenge", func(t *testing.T) {
		srv := setupTestServer(t)
		res := middlewarerequirepermissionCharServe(srv, middlewarerequirepermissionCharPresenceCall(principalA))

		middlewarerequirepermissionCharRequirePresenceChallenge(t, res, "step_up_required")
		body := middlewarerequirepermissionCharJSON(t, res)
		assert.Equal(t, "strong", body["required_assurance"])
	})

	t.Run("unknown token is rejected as invalid", func(t *testing.T) {
		srv := setupTestServer(t)
		c := middlewarerequirepermissionCharPresenceCall(principalA)
		c.header = map[string]string{presenceTokenHeader: "never-issued"}

		middlewarerequirepermissionCharRequirePresenceChallenge(t,
			middlewarerequirepermissionCharServe(srv, c), "presence_token_invalid")
	})

	t.Run("valid bound token is admitted", func(t *testing.T) {
		srv := setupTestServer(t)
		c := middlewarerequirepermissionCharPresenceCall(principalA)
		c.header = map[string]string{presenceTokenHeader: middlewarerequirepermissionCharBoundToken(t, srv, principalA.ID, c, perm)}

		middlewarerequirepermissionCharRequireAdmitted(t, middlewarerequirepermissionCharServe(srv, c))
	})

	t.Run("a token is single use", func(t *testing.T) {
		srv := setupTestServer(t)
		c := middlewarerequirepermissionCharPresenceCall(principalA)
		c.header = map[string]string{presenceTokenHeader: middlewarerequirepermissionCharBoundToken(t, srv, principalA.ID, c, perm)}

		middlewarerequirepermissionCharRequireAdmitted(t, middlewarerequirepermissionCharServe(srv, c))
		middlewarerequirepermissionCharRequirePresenceChallenge(t,
			middlewarerequirepermissionCharServe(srv, c), "presence_token_invalid")
	})

	t.Run("expired token is rejected and consumed", func(t *testing.T) {
		srv := setupTestServer(t)
		c := middlewarerequirepermissionCharPresenceCall(principalA)
		bodyHash, err := hashRequestBodyForPresenceBinding(c.request())
		require.NoError(t, err)
		token := "expired-token"
		storePresenceTokenForTest(t, srv, hashPresenceToken(token), &presenceTokenRecord{
			principalID:       principalA.ID,
			expires:           time.Now().Add(-time.Second),
			boundMethod:       c.request().Method,
			boundPath:         canonicalRequestTarget("/mrpchar/presence-action", "x=1"),
			boundBodyHash:     bodyHash,
			boundPermissionID: perm,
		})
		c.header = map[string]string{presenceTokenHeader: token}

		middlewarerequirepermissionCharRequirePresenceChallenge(t,
			middlewarerequirepermissionCharServe(srv, c), "presence_token_expired")
		middlewarerequirepermissionCharRequirePresenceChallenge(t,
			middlewarerequirepermissionCharServe(srv, c), "presence_token_invalid")
	})

	t.Run("token without an action binding is refused", func(t *testing.T) {
		srv := setupTestServer(t)
		c := middlewarerequirepermissionCharPresenceCall(principalA)
		c.header = map[string]string{presenceTokenHeader: mintPresenceToken(t, srv, principalA.ID)}

		middlewarerequirepermissionCharRequirePresenceChallenge(t,
			middlewarerequirepermissionCharServe(srv, c), "presence_token_action_mismatch")
	})

	t.Run("token bound to another action is refused and consumed", func(t *testing.T) {
		srv := setupTestServer(t)
		other := middlewarerequirepermissionCharPresenceCall(principalA)
		other.target = "/mrpchar/other-action"
		c := middlewarerequirepermissionCharPresenceCall(principalA)
		c.header = map[string]string{presenceTokenHeader: middlewarerequirepermissionCharBoundToken(t, srv, principalA.ID, other, perm)}

		middlewarerequirepermissionCharRequirePresenceChallenge(t,
			middlewarerequirepermissionCharServe(srv, c), "presence_token_action_mismatch")
		middlewarerequirepermissionCharRequirePresenceChallenge(t,
			middlewarerequirepermissionCharServe(srv, c), "presence_token_invalid")
	})

	t.Run("token bound to another permission is refused", func(t *testing.T) {
		srv := setupTestServer(t)
		c := middlewarerequirepermissionCharPresenceCall(principalA)
		c.header = map[string]string{presenceTokenHeader: middlewarerequirepermissionCharBoundToken(t, srv, principalA.ID, c, "mrpchar:other")}

		middlewarerequirepermissionCharRequirePresenceChallenge(t,
			middlewarerequirepermissionCharServe(srv, c), "presence_token_action_mismatch")
	})

	t.Run("an unreadable request body fails the binding check with 500", func(t *testing.T) {
		srv := setupTestServer(t)
		c := middlewarerequirepermissionCharPresenceCall(principalA)
		c.header = map[string]string{presenceTokenHeader: middlewarerequirepermissionCharBoundToken(t, srv, principalA.ID, c, perm)}
		req := c.request()
		req.Body = io.NopCloser(iotest.ErrReader(assert.AnError))
		res := middlewarerequirepermissionCharResult{rec: httptest.NewRecorder()}
		srv.requirePermission("mrpchar", "presence")(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			res.seen = req
		})).ServeHTTP(res.rec, req)

		middlewarerequirepermissionCharRequireReject(t, res, http.StatusInternalServerError, "PRESENCE_TOKEN_BINDING_ERROR")
		assert.Contains(t, res.rec.Body.String(), "Failed to verify presence token")
	})

	t.Run("a route the requirement exempts skips the presence check", func(t *testing.T) {
		srv := setupTestServer(t)
		middlewarerequirepermissionCharRegisterExempt(t)
		c := middlewarerequirepermissionCharPerm("mrpchar", "exempt")
		c.principal = middlewarerequirepermissionCharHuman("principal-a", session.AssuranceStrong, middlewarerequirepermissionCharExemptPerm)
		c.target = "/mrpchar/exempt"
		c.route = "/mrpchar/exempt"

		middlewarerequirepermissionCharRequireAdmitted(t, middlewarerequirepermissionCharServe(srv, c))
	})

	t.Run("the same permission on a non-exempt route still needs the token", func(t *testing.T) {
		srv := setupTestServer(t)
		middlewarerequirepermissionCharRegisterExempt(t)
		c := middlewarerequirepermissionCharPerm("mrpchar", "exempt")
		c.principal = middlewarerequirepermissionCharHuman("principal-a", session.AssuranceStrong, middlewarerequirepermissionCharExemptPerm)
		c.target = "/mrpchar/not-exempt"
		c.route = "/mrpchar/not-exempt"

		res := middlewarerequirepermissionCharServe(srv, c)

		require.Equal(t, http.StatusUnauthorized, res.rec.Code)
		assert.Contains(t, res.rec.Header().Get("WWW-Authenticate"), `presence="required"`)
	})
}

// [REQUIRED] A presence token minted for principal A is refused for principal B, and the
// failed attempt consumes it, so it cannot be retried — not even by principal A.
func TestMiddlewareRequirePermissionChar_PresenceTokenBoundToPrincipal(t *testing.T) {
	middlewarerequirepermissionCharRegisterAll(t)
	const perm = middlewarerequirepermissionCharPresencePerm
	logger := &auditCapturingLogger{}
	srv := setupTestServerWithLogger(t, logger)
	principalA := middlewarerequirepermissionCharHuman("principal-a", session.AssuranceStrong, perm)
	principalB := middlewarerequirepermissionCharHuman("principal-b", session.AssuranceStrong, perm)

	callB := middlewarerequirepermissionCharPresenceCall(principalB)
	callA := middlewarerequirepermissionCharPresenceCall(principalA)
	token := middlewarerequirepermissionCharBoundToken(t, srv, principalA.ID, callA, perm)
	callA.header = map[string]string{presenceTokenHeader: token}
	callB.header = map[string]string{presenceTokenHeader: token}

	res := middlewarerequirepermissionCharServe(srv, callB)

	middlewarerequirepermissionCharRequirePresenceChallenge(t, res, "presence_token_principal_mismatch")
	entry := middlewarerequirepermissionCharAuditEntry(logger, "Presence token principal mismatch")
	require.NotNil(t, entry, "a principal mismatch must be logged")
	assert.Equal(t, "WARN", entry.level)
	assert.Equal(t, "principal-a", entry.value("token_principal_id"))
	assert.Equal(t, "principal-b", entry.value("request_principal_id"))
	assert.Equal(t, perm, entry.value("permission_id"))

	// The failed attempt consumed the token: B cannot retry, and neither can A.
	middlewarerequirepermissionCharRequirePresenceChallenge(t,
		middlewarerequirepermissionCharServe(srv, callB), "presence_token_invalid")
	middlewarerequirepermissionCharRequirePresenceChallenge(t,
		middlewarerequirepermissionCharServe(srv, callA), "presence_token_invalid")
}

// The presence gate runs before the tenant checks: a caller that would be refused by
// tenant isolation is still asked for the presence token first.
func TestMiddlewareRequirePermissionChar_PresenceCheckPrecedesTenantIsolation(t *testing.T) {
	middlewarerequirepermissionCharRegisterAll(t)
	srv := boundaryTestServer(t)
	p := &Principal{ID: "msp-user", Assurance: session.AssuranceStrong, TenantID: "msp-a",
		Permissions: []string{middlewarerequirepermissionCharPresencePerm}}
	c := middlewarerequirepermissionCharPerm("mrpchar", "presence")
	c.principal = p
	c.vars = map[string]string{"tenant_id": "root"}

	res := middlewarerequirepermissionCharServe(srv, c)

	middlewarerequirepermissionCharRequirePresenceChallenge(t, res, "step_up_required")
}

// --- ADR-025 root<->MSP boundary ---

func TestMiddlewareRequirePermissionChar_RootBoundary(t *testing.T) {
	srv := boundaryTestServer(t)
	operator := boundaryTestPrincipal("operator-1")

	t.Run("no crossing yields the tenant-crossing challenge", func(t *testing.T) {
		c := middlewarerequirepermissionCharPerm("tenant", "read")
		c.principal = operator
		c.vars = map[string]string{"id": "msp-a"}

		res := middlewarerequirepermissionCharServe(srv, c)

		require.Equal(t, http.StatusUnauthorized, res.rec.Code, res.rec.Body.String())
		assert.Nil(t, res.seen)
		assert.Equal(t, `CFGMS-StepUp realm="cfgms", required="tenant-crossing"`, res.rec.Header().Get("WWW-Authenticate"))
	})

	t.Run("the root tenant itself is admitted", func(t *testing.T) {
		c := middlewarerequirepermissionCharPerm("tenant", "read")
		c.principal = operator
		c.vars = map[string]string{"id": "root"}

		middlewarerequirepermissionCharRequireAdmitted(t, middlewarerequirepermissionCharServe(srv, c))
	})

	t.Run("an unknown tenant is a 404 on the tenant resource", func(t *testing.T) {
		c := middlewarerequirepermissionCharPerm("tenant", "read")
		c.principal = operator
		c.vars = map[string]string{"id": "mrpchar-no-such-tenant"}

		middlewarerequirepermissionCharRequireReject(t,
			middlewarerequirepermissionCharServe(srv, c), http.StatusNotFound, "TENANT_NOT_FOUND")
	})

	t.Run("an unknown tenant is a 403 on any other resource", func(t *testing.T) {
		c := middlewarerequirepermissionCharPerm("steward", "read")
		c.principal = operator
		c.vars = map[string]string{"tenant_id": "mrpchar-no-such-tenant"}

		middlewarerequirepermissionCharRequireReject(t,
			middlewarerequirepermissionCharServe(srv, c), http.StatusForbidden, "CROSS_TENANT_ACCESS_DENIED")
	})

	t.Run("a crossing-remedy permission is not pre-empted", func(t *testing.T) {
		c := middlewarerequirepermissionCharPerm("tenant", "crossing-break-glass")
		c.principal = operator
		c.vars = map[string]string{"id": "msp-a"}

		middlewarerequirepermissionCharRequireAdmitted(t, middlewarerequirepermissionCharServe(srv, c))
	})

	t.Run("a request naming no tenant is not subject to the boundary", func(t *testing.T) {
		c := middlewarerequirepermissionCharPerm("steward", "read")
		c.principal = operator

		middlewarerequirepermissionCharRequireAdmitted(t, middlewarerequirepermissionCharServe(srv, c))
	})
}

// --- tenant isolation ---

func TestMiddlewareRequirePermissionChar_TenantIsolation(t *testing.T) {
	srv := boundaryTestServer(t)
	scoped := func(perms ...string) *Principal {
		return &Principal{ID: "msp-user", Assurance: session.AssuranceStrong, TenantID: "msp-a", Permissions: perms}
	}

	t.Run("a target in the caller's own tenant is admitted", func(t *testing.T) {
		c := middlewarerequirepermissionCharPerm("steward", "read")
		c.principal = scoped("steward:read")
		c.vars = map[string]string{"tenant_id": "msp-a"}

		middlewarerequirepermissionCharRequireAdmitted(t, middlewarerequirepermissionCharServe(srv, c))
	})

	t.Run("a request naming no tenant is admitted", func(t *testing.T) {
		c := middlewarerequirepermissionCharPerm("steward", "read")
		c.principal = scoped("steward:read")

		middlewarerequirepermissionCharRequireAdmitted(t, middlewarerequirepermissionCharServe(srv, c))
	})

	t.Run("a target outside the subtree is a 403 and is audited", func(t *testing.T) {
		logger := &auditCapturingLogger{}
		srv := boundaryTestServerWithLogger(t, logger)
		c := middlewarerequirepermissionCharPerm("steward", "read")
		c.principal = scoped("steward:read")
		c.vars = map[string]string{"tenant_id": "root"}
		logger.mu.Lock()
		logger.entries = nil
		logger.mu.Unlock()

		res := middlewarerequirepermissionCharServe(srv, c)

		middlewarerequirepermissionCharRequireReject(t, res, http.StatusForbidden, "CROSS_TENANT_ACCESS_DENIED")
		entry := middlewarerequirepermissionCharAuditEntry(logger, "Authorization audit - access denied")
		require.NotNil(t, entry)
		assert.Equal(t, "Target tenant is outside principal tenant subtree", entry.value("reason"))
	})

	for _, action := range []string{"read", "update", "manage", "billing-read"} {
		t.Run("tenant:"+action+" outside the subtree is a 404", func(t *testing.T) {
			c := middlewarerequirepermissionCharPerm("tenant", action)
			c.principal = scoped("tenant:" + action)
			c.vars = map[string]string{"id": "root"}

			middlewarerequirepermissionCharRequireReject(t,
				middlewarerequirepermissionCharServe(srv, c), http.StatusNotFound, "TENANT_NOT_FOUND")
		})
	}

	t.Run("tenant:delete outside the subtree is a 403", func(t *testing.T) {
		c := middlewarerequirepermissionCharPerm("tenant", "delete")
		c.principal = scoped("tenant:delete")
		c.vars = map[string]string{"id": "root"}

		middlewarerequirepermissionCharRequireReject(t,
			middlewarerequirepermissionCharServe(srv, c), http.StatusForbidden, "CROSS_TENANT_ACCESS_DENIED")
	})

	t.Run("the context target tenant is honoured ahead of path variables", func(t *testing.T) {
		c := middlewarerequirepermissionCharPerm("steward", "read")
		c.principal = scoped("steward:read")
		c.vars = map[string]string{"tenant_id": "msp-a"}
		req := c.request()
		req = req.WithContext(context.WithValue(req.Context(), targetTenantContextKey, "root"))
		res := middlewarerequirepermissionCharResult{rec: httptest.NewRecorder()}
		srv.requirePermission("steward", "read")(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			res.seen = req
		})).ServeHTTP(res.rec, req)

		middlewarerequirepermissionCharRequireReject(t, res, http.StatusForbidden, "CROSS_TENANT_ACCESS_DENIED")
	})
}

// --- grant ---

func TestMiddlewareRequirePermissionChar_Grant(t *testing.T) {
	t.Run("API-key principal is granted with the API-key reason", func(t *testing.T) {
		logger := &auditCapturingLogger{}
		srv := setupTestServerWithLogger(t, logger)
		c := middlewarerequirepermissionCharPerm("steward", "read")
		c.principal = middlewarerequirepermissionCharAPIKey("key-1", "steward:read")
		c.userID = "key-1"
		c.tenantID = "tenant-x"
		c.vars = map[string]string{"id": "st-1"}
		logger.mu.Lock()
		logger.entries = nil
		logger.mu.Unlock()

		res := middlewarerequirepermissionCharServe(srv, c)

		middlewarerequirepermissionCharRequireAdmitted(t, res)
		decision, ok := res.seen.Context().Value(authDecisionContextKey).(*AuthorizationDecision)
		require.True(t, ok, "the decision must be placed in the context")
		assert.True(t, decision.Granted)
		assert.Equal(t, "ALLOW", decision.Decision)
		assert.Equal(t, "steward:read", decision.PermissionID)
		assert.Equal(t, "steward:st-1", decision.Resource)
		assert.Equal(t, "read", decision.Action)
		assert.Equal(t, "API key has required permission: steward:read", decision.Reason)
		assert.Equal(t, "key-1", decision.SubjectID)
		assert.Equal(t, "tenant-x", decision.TenantID)

		entry := middlewarerequirepermissionCharAuditEntry(logger, "Authorization audit")
		require.NotNil(t, entry, "a grant must be audited")
		assert.Equal(t, "INFO", entry.level)
		assert.Equal(t, "ALLOW", entry.value("decision"))
	})

	t.Run("principal at basic assurance or above gets the full-access reason", func(t *testing.T) {
		srv := setupTestServer(t)
		c := middlewarerequirepermissionCharPerm("steward", "read")
		c.principal = middlewarerequirepermissionCharHuman("user-1", session.AssuranceBasic, "steward:read")

		res := middlewarerequirepermissionCharServe(srv, c)

		middlewarerequirepermissionCharRequireAdmitted(t, res)
		decision, ok := res.seen.Context().Value(authDecisionContextKey).(*AuthorizationDecision)
		require.True(t, ok)
		assert.Equal(t, "principal assurance sufficient for full access", decision.Reason)
	})
}

// --- ceremony store unavailable ---

// A ClusterMode node whose NonceStore is not wired cannot consume a presence token, and
// must answer 503 rather than treat the token as merely unknown.
func TestMiddlewareRequirePermissionChar_PresenceStoreUnavailable(t *testing.T) {
	middlewarerequirepermissionCharRegisterAll(t)
	srv := setupTestServer(t)
	srv.haManager = newClusterFixture(t).manager // NonceStore deliberately not wired
	c := middlewarerequirepermissionCharPresenceCall(
		middlewarerequirepermissionCharHuman("principal-a", session.AssuranceStrong, middlewarerequirepermissionCharPresencePerm))
	c.header = map[string]string{presenceTokenHeader: "any-token"}

	res := middlewarerequirepermissionCharServe(srv, c)

	middlewarerequirepermissionCharRequireReject(t, res, http.StatusServiceUnavailable, "WEBAUTHN_CEREMONY_STORE_UNAVAILABLE")
}

// --- isolation engine ---

// A tenant-scoped caller whose target is inside its subtree is still checked against the
// isolation engine when one is wired; the engine's default rules deny cross-tenant access.
func TestMiddlewareRequirePermissionChar_IsolationEngineDenial(t *testing.T) {
	srv := setupTestServerWithIsolationEngine(t)
	seedTenantTree(t, srv)
	c := middlewarerequirepermissionCharPerm("steward", "read")
	c.principal = &Principal{ID: "msp-user", Assurance: session.AssuranceStrong, TenantID: "msp-a",
		Permissions: []string{"steward:read"}}
	c.vars = map[string]string{"tenant_id": "client-1"}

	res := middlewarerequirepermissionCharServe(srv, c)

	middlewarerequirepermissionCharRequireReject(t, res, http.StatusForbidden, "CROSS_TENANT_ACCESS_DENIED")
	middlewarerequirepermissionCharRequireAuthzBody(t, res, "Cross-tenant access denied", "steward:read")
}
