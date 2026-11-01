// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/features/controller/transport"
	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/session"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// newTerminalScopeTestServer builds a minimal Server with a real ControllerService
// registry seeded with the given stewards (id → tenant). Only the fields the
// terminal tenant-scoping wrapper touches are populated.
func newTerminalScopeTestServer(t *testing.T, stewards map[string]string) *Server {
	t.Helper()
	cs := service.NewControllerService(logging.NewNoopLogger())
	for id, tenant := range stewards {
		require.NoError(t, cs.RegisterSteward(id, tenant, "addr", "active"))
	}
	return &Server{controllerService: cs, logger: logging.NewNoopLogger()}
}

// seedScopeTenants creates the real tenant tree the scope tests use, through the
// server's tenant manager: msp-a with child client-1, a sibling msp-b, and msp-ab,
// a sibling whose ID merely shares msp-a's prefix. It also wires the manager's
// ancestry into the controller service so fleet listing resolves descendants.
func seedScopeTenants(t *testing.T, server *Server) {
	t.Helper()
	createTestTenant(t, server, "msp-a", "")
	createTestTenant(t, server, "client-1", "msp-a")
	createTestTenant(t, server, "msp-b", "")
	createTestTenant(t, server, "msp-ab", "")
	server.controllerService.SetTenantAncestry(server.tenantManager.IsTenantAncestor)
}

// newTerminalScopeTenantServer builds a full test Server (real tenant manager and
// ControllerService) with seedScopeTenants applied and the given stewards
// (id → tenant) registered.
func newTerminalScopeTenantServer(t *testing.T, stewards map[string]string) *Server {
	t.Helper()
	s := setupTestServer(t)
	seedScopeTenants(t, s)
	for id, tenantID := range stewards {
		require.NoError(t, s.controllerService.RegisterSteward(id, tenantID, "addr", "active"))
	}
	return s
}

// serveTerminalScope drives a request through the wrapper with a sentinel
// downstream handler and returns the recorder plus whether the downstream ran.
func serveTerminalScope(s *Server, callerTenant, stewardID string) (*httptest.ResponseRecorder, *bool) {
	reached := new(bool)
	wrapped := s.tenantScopedTerminalWrapper(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		*reached = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/terminal/ws/"+stewardID, nil)
	req = mux.SetURLVars(req, map[string]string{"steward_id": stewardID})
	req = req.WithContext(withCallerTenant(req.Context(), callerTenant))
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)
	return rec, reached
}

// TestTerminalScope_SameTenantAllowed verifies a caller reaches a steward owned
// by its own tenant.
func TestTerminalScope_SameTenantAllowed(t *testing.T) {
	s := newTerminalScopeTenantServer(t, map[string]string{"steward-a": "msp-a"})
	rec, reached := serveTerminalScope(s, "msp-a", "steward-a")
	assert.True(t, *reached, "same-tenant steward must reach the terminal handler")
	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestTerminalScope_DescendantTenantAllowed verifies a caller reaches a steward
// in a descendant tenant subtree.
func TestTerminalScope_DescendantTenantAllowed(t *testing.T) {
	s := newTerminalScopeTenantServer(t, map[string]string{"steward-child": "client-1"})
	rec, reached := serveTerminalScope(s, "msp-a", "steward-child")
	assert.True(t, *reached, "descendant-tenant steward must reach the terminal handler")
	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestTerminalScope_CrossTenantRejected verifies the core isolation guarantee: a
// scoped caller in tenant A cannot open a terminal to a steward owned by tenant B.
// The response is 404 (not 403) so steward existence is not disclosed cross-tenant.
func TestTerminalScope_CrossTenantRejected(t *testing.T) {
	s := newTerminalScopeTenantServer(t, map[string]string{"steward-b": "msp-b"})
	rec, reached := serveTerminalScope(s, "msp-a", "steward-b")
	assert.False(t, *reached, "cross-tenant steward must NOT reach the terminal handler")
	assert.Equal(t, http.StatusNotFound, rec.Code,
		"cross-tenant terminal access must be rejected with 404")
}

// TestTerminalScope_UnknownStewardRejected verifies an unknown steward yields 404.
func TestTerminalScope_UnknownStewardRejected(t *testing.T) {
	s := newTerminalScopeTestServer(t, nil)
	rec, reached := serveTerminalScope(s, "msp-a", "ghost")
	assert.False(t, *reached)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// TestTerminalScope_SiblingPrefixNotAncestor verifies that a tenant string which
// merely shares a prefix (msp-a vs msp-ab) is not treated as ancestry.
func TestTerminalScope_SiblingPrefixNotAncestor(t *testing.T) {
	s := newTerminalScopeTenantServer(t, map[string]string{"steward-ab": "msp-ab"})
	rec, reached := serveTerminalScope(s, "msp-a", "steward-ab")
	assert.False(t, *reached, "prefix-sharing sibling tenant must not be treated as descendant")
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// serveTerminalScopeAsRootScoped drives a request through the wrapper with a root-scoped
// principal in context (ADR-025 Amendment 1 A1.3), carrying the root scope and root
// tenant the authentication middleware sets for it (Issue #4665).
func serveTerminalScopeAsRootScoped(s *Server, principal *Principal, stewardID string) (*httptest.ResponseRecorder, *bool) {
	reached := new(bool)
	wrapped := s.tenantScopedTerminalWrapper(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		*reached = true
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/terminal/ws/"+stewardID, nil)
	req = mux.SetURLVars(req, map[string]string{"steward_id": stewardID})
	ctx := req.Context()
	ctx = context.WithValue(withCallerTenant(ctx, ""), principalContextKey, principal)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req.WithContext(ctx))
	return rec, reached
}

// TestTerminalScope_RootScoped_NilTenantManager_Returns401Challenge verifies the
// ADR-025 Decision 1 root-scoped guard (Issue #3303): when tenantManager is nil,
// the wrapper fails closed with a tenant-crossing challenge rather than allowing
// access, matching authorizeRootScopedTenantAccess's nil-store stance.
func TestTerminalScope_RootScoped_NilTenantManager_Returns401Challenge(t *testing.T) {
	s := newTerminalScopeTestServer(t, map[string]string{"steward-msp": "msp-a"})
	// tenantManager is nil by default in the minimal test server.
	principal := rootScopedPrincipal("root-op")
	rec, reached := serveTerminalScopeAsRootScoped(s, principal, "steward-msp")
	assert.False(t, *reached, "root-scoped caller with nil tenantManager must not reach handler")
	assert.Equal(t, http.StatusUnauthorized, rec.Code,
		"root-scoped caller with nil tenantManager must receive a crossing challenge")
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `required="tenant-crossing"`,
		"challenge must advertise the tenant-crossing remedy")
}

// TestTerminalScope_RootScoped_NoCrossing_Returns401Challenge verifies the
// REQUIRED TEST from ADR-025 Decision 1 (Issue #3303, AC "asserts the guard denies
// a foreign-tenant/foreign-subtree request"): a root-scoped principal without an
// active crossing for the steward's tenant receives a step-up-shaped challenge.
func TestTerminalScope_RootScoped_NoCrossing_Returns401Challenge(t *testing.T) {
	// Full server with a real tenantManager and crossing store — mirrors
	// setupCrossingTestServer but also seeds a steward in controllerService.
	server := setupCrossingTestServer(t)
	ctx := context.Background()
	err := ensureTestRootTenant(ctx, server.tenantManager)
	require.NoError(t, err)
	_, err = server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "msp-a", ParentID: "root"})
	require.NoError(t, err)

	require.NoError(t, server.controllerService.RegisterSteward("steward-msp", "msp-a", "addr", "active"))

	principal := rootScopedPrincipal("root-op")
	rec, reached := serveTerminalScopeAsRootScoped(server, principal, "steward-msp")
	assert.False(t, *reached, "root-scoped caller without crossing must not reach handler")
	assert.Equal(t, http.StatusUnauthorized, rec.Code,
		"root-scoped caller without crossing must receive a tenant-crossing challenge")
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `required="tenant-crossing"`)
}

// TestTerminalScope_EmptyTenantNoRootScope_Refused is the REQUIRED TEST for Issue
// #4337's fall-through fix: a principal with an empty tenant (callerTenant == "") that
// is also not subject to the root-scope crossing boundary (RootScoped == false,
// GlobalScope == false) used to match no branch in tenantScopedTerminalWrapper and fall
// through to the handler unconditionally. Account creation ties an empty tenant to an
// explicit root-scope grant, so an ordinary caller cannot normally reach this shape —
// but the wrapper must refuse it outright rather than rely on that invariant.
func TestTerminalScope_EmptyTenantNoRootScope_Refused(t *testing.T) {
	s := newTerminalScopeTestServer(t, map[string]string{"steward-msp": "msp-a"})
	principal := &Principal{ID: "neither-scoped-1", TenantID: "", RootScoped: false, GlobalScope: false}
	rec, reached := serveTerminalScopeAsRootScoped(s, principal, "steward-msp")

	assert.False(t, *reached,
		"a principal with no tenant scope and no root scope must not reach the terminal handler")
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// TestTerminalScope_AccountBoundLowAssurance_NoCrossing_Returns401Challenge verifies
// the GlobalScope-binding half of Issue #4337 on the terminal wrapper specifically: a
// root-scope account's session below phishing-resistant assurance (RootScoped == false,
// AccountBound + GlobalScope == true) must still hit the crossing check — not the
// fall-through this story closes, and not an unconditional bypass.
func TestTerminalScope_AccountBoundLowAssurance_NoCrossing_Returns401Challenge(t *testing.T) {
	server := setupCrossingTestServer(t)
	ctx := context.Background()
	err := ensureTestRootTenant(ctx, server.tenantManager)
	require.NoError(t, err)
	_, err = server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "msp-a", ParentID: "root"})
	require.NoError(t, err)

	require.NoError(t, server.controllerService.RegisterSteward("steward-msp", "msp-a", "addr", "active"))

	principal := accountBoundLowAssuranceRootPrincipal("low-assurance-op-terminal")
	rec, reached := serveTerminalScopeAsRootScoped(server, principal, "steward-msp")
	assert.False(t, *reached, "low-assurance account-bound caller without crossing must not reach handler")
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `required="tenant-crossing"`)
}

// TestTerminalScope_AccountBoundLowAssurance_WithCrossing_Allowed is the positive
// counterpart: an active grant lets the same low-assurance account-bound caller through.
func TestTerminalScope_AccountBoundLowAssurance_WithCrossing_Allowed(t *testing.T) {
	server := setupCrossingTestServer(t)
	ctx := context.Background()
	err := ensureTestRootTenant(ctx, server.tenantManager)
	require.NoError(t, err)
	_, err = server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "msp-a", ParentID: "root"})
	require.NoError(t, err)

	require.NoError(t, server.controllerService.RegisterSteward("steward-msp", "msp-a", "addr", "active"))

	principal := accountBoundLowAssuranceRootPrincipal("low-assurance-op-terminal-2")
	now := time.Now().UTC()
	require.NoError(t, server.tenantCrossingStore.CreateTenantCrossing(ctx, &business.TenantCrossing{
		ID:        "grant-terminal-low-assurance-1",
		TenantID:  "msp-a",
		Kind:      business.TenantCrossingKindGrant,
		GrantedBy: "msp-a-admin",
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}))

	rec, reached := serveTerminalScopeAsRootScoped(server, principal, "steward-msp")
	assert.True(t, *reached, "active crossing must admit the low-assurance account-bound caller")
	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestTerminalScope_RootScoped_WithCrossing_Allowed verifies the REQUIRED TEST
// counterpart (Issue #3303, AC "allows an in-scope one"): a root-scoped principal
// with an active crossing grant for the steward's tenant reaches the downstream handler.
func TestTerminalScope_RootScoped_WithCrossing_Allowed(t *testing.T) {
	server := setupCrossingTestServer(t)
	ctx := context.Background()
	err := ensureTestRootTenant(ctx, server.tenantManager)
	require.NoError(t, err)
	_, err = server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "msp-b", ParentID: "root"})
	require.NoError(t, err)

	require.NoError(t, server.controllerService.RegisterSteward("steward-msp-b", "msp-b", "addr", "active"))

	// Grant a crossing for the root-scoped operator to msp-b.
	principal := rootScopedPrincipal("root-op-2")
	now := time.Now().UTC()
	require.NoError(t, server.tenantCrossingStore.CreateTenantCrossing(ctx, &business.TenantCrossing{
		ID:        "grant-terminal-1",
		TenantID:  "msp-b",
		Kind:      business.TenantCrossingKindGrant,
		GrantedBy: "msp-b-admin",
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}))

	rec, reached := serveTerminalScopeAsRootScoped(server, principal, "steward-msp-b")
	assert.True(t, *reached, "root-scoped caller with active crossing must reach the handler")
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ---------------------------------------------------------------------------
// One-time ticket redemption on GET /terminal/ws/{steward_id}
// ---------------------------------------------------------------------------

// wsNode is a ticketNode whose terminal handler records the proof it receives.
type wsNode struct {
	*ticketNode
	reached int
	proof   *transport.TerminalProof
	recheck transport.SessionRecheck
	authRef *authSessionRef // when set, connect marks the request as session-authenticated
	// credRecheck, when set, is carried in the request context as the re-check of an
	// API-key or admin-certificate principal.
	credRecheck authRecheck
	// refresh, when set, replaces the default principal refresh (which returns the
	// connecting principal unchanged).
	refresh principalRefresh
}

func newWSNode(t *testing.T) *wsNode {
	t.Helper()
	n := &wsNode{ticketNode: newTicketX509Node(t)}
	n.credRecheck = func(context.Context) bool { return true }
	n.server.SetTerminalHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.reached++
		n.proof, _ = transport.TerminalProofFromContext(r.Context())
		n.recheck = transport.SessionRecheckFromContext(r.Context())
		w.WriteHeader(http.StatusSwitchingProtocols)
	}))
	return n
}

// seed stores a ticket bound to the given principal ID, steward and web session, in the
// tenant of the steward, and returns the plaintext ticket.
func (n *wsNode) seed(principalID, stewardID, webSession string) string {
	n.t.Helper()
	ticket, hash, err := newTerminalTicket()
	require.NoError(n.t, err)
	rec := &terminalTicketRecord{
		principalID: principalID, tenantID: saTenant, webSessionID: webSession, stewardID: stewardID,
		terminalShell: "bash", expires: time.Now().Add(time.Minute),
		targets: []string{stewardID}, nonce: "n-1", expiresAt: time.Now().Add(time.Minute).UTC().Truncate(time.Second),
		x509: &OperatorX509Proof{Algorithm: "ed25519", Value: "v", PublicKey: "k"},
	}
	require.Equal(n.t, ceremonyOK, n.server.putTerminalTicket(context.Background(), hash, rec))
	return ticket
}

func (n *wsNode) connect(p *Principal, stewardID, webSession, protocols string, query string) *httptest.ResponseRecorder {
	n.t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/terminal/ws/"+stewardID+query, nil)
	if protocols != "" {
		req.Header.Set("Sec-WebSocket-Protocol", protocols)
	}
	req = withPrincipal(req, p)
	if webSession != "" {
		req = req.WithContext(context.WithValue(req.Context(), webSessionIDContextKey, webSession))
	}
	if n.authRef != nil {
		req = req.WithContext(context.WithValue(req.Context(), authSessionContextKey, *n.authRef))
	}
	if n.credRecheck != nil {
		req = req.WithContext(context.WithValue(req.Context(), authRecheckContextKey, n.credRecheck))
	}
	refresh := n.refresh
	if refresh == nil {
		refresh = func(context.Context) (*Principal, bool) { cp := *p; return &cp, true }
	}
	req = req.WithContext(context.WithValue(req.Context(), principalRefreshContextKey, refresh))
	rec := httptest.NewRecorder()
	n.router.ServeHTTP(rec, req)
	return rec
}

func ticketProtocols(ticket string) string { return "cfgms.terminal.v1, cfgms.ticket." + ticket }

// [REQUIRED] Redemption refusals are 403 and never reach the handler.
func TestTerminalWS_TicketRefusals(t *testing.T) {
	n := newWSNode(t)
	require.NoError(t, n.server.controllerService.RegisterSteward("steward-2", saTenant, "addr", "active"))
	user := actionPrincipal("op-1")

	t.Run("no ticket", func(t *testing.T) {
		assert.Equal(t, http.StatusForbidden, n.connect(user, ttSteward, "", "cfgms.terminal.v1", "").Code)
	})
	t.Run("unknown ticket", func(t *testing.T) {
		assert.Equal(t, http.StatusForbidden, n.connect(user, ttSteward, "", ticketProtocols("nope"), "").Code)
	})
	t.Run("ticket in query string is ignored", func(t *testing.T) {
		tk := n.seed("op-1", ttSteward, "")
		assert.Equal(t, http.StatusForbidden, n.connect(user, ttSteward, "", "cfgms.terminal.v1", "?ticket="+tk).Code)
	})
	t.Run("replay", func(t *testing.T) {
		tk := n.seed("op-1", ttSteward, "")
		assert.Equal(t, http.StatusSwitchingProtocols, n.connect(user, ttSteward, "", ticketProtocols(tk), "").Code)
		assert.Equal(t, http.StatusForbidden, n.connect(user, ttSteward, "", ticketProtocols(tk), "").Code)
	})
	t.Run("expired", func(t *testing.T) {
		tk, hash, err := newTerminalTicket()
		require.NoError(t, err)
		n.server.putTerminalTicket(context.Background(), hash, &terminalTicketRecord{
			principalID: "op-1", tenantID: saTenant, stewardID: ttSteward, terminalShell: "bash", expires: time.Now().Add(-time.Second)})
		assert.Equal(t, http.StatusForbidden, n.connect(user, ttSteward, "", ticketProtocols(tk), "").Code)
	})
	t.Run("cross user", func(t *testing.T) {
		tk := n.seed("op-1", ttSteward, "")
		assert.Equal(t, http.StatusForbidden, n.connect(actionPrincipal("op-2"), ttSteward, "", ticketProtocols(tk), "").Code)
	})
	t.Run("other web session of the same user", func(t *testing.T) {
		tk := n.seed("op-1", ttSteward, "sess-a")
		assert.Equal(t, http.StatusForbidden, n.connect(user, ttSteward, "sess-b", ticketProtocols(tk), "").Code)
	})
	t.Run("ticket for steward A on steward B", func(t *testing.T) {
		tk := n.seed("op-1", ttSteward, "")
		assert.Equal(t, http.StatusForbidden, n.connect(user, "steward-2", "", ticketProtocols(tk), "").Code)
	})
	t.Run("two tickets presented", func(t *testing.T) {
		tk := n.seed("op-1", ttSteward, "")
		assert.Equal(t, http.StatusForbidden, n.connect(user, ttSteward, "", ticketProtocols(tk)+", cfgms.ticket.other", "").Code)
	})
	assert.Equal(t, 1, n.reached, "only the replay's first use may reach the handler")
}

// [REQUIRED] Principal IDs that SanitizeLogValue maps to one string are still distinct.
func TestTerminalWS_SanitisedIDCollisionRefused(t *testing.T) {
	n := newWSNode(t)
	minted, caller := "op\n1", "op_1"
	require.Equal(t, logging.SanitizeLogValue(minted), logging.SanitizeLogValue(caller), "test needs a real collision")
	tk := n.seed(minted, ttSteward, "")
	assert.Equal(t, http.StatusForbidden, n.connect(actionPrincipal(caller), ttSteward, "", ticketProtocols(tk), "").Code)
	assert.Zero(t, n.reached)
}

// [REQUIRED] A principal whose ID sanitisation would change redeems its own ticket.
func TestTerminalWS_RawIDRedeemsOwnTicket(t *testing.T) {
	n := newWSNode(t)
	id := "op\n1"
	require.NotEqual(t, id, logging.SanitizeLogValue(id))
	tk := n.seed(id, ttSteward, "")
	assert.Equal(t, http.StatusSwitchingProtocols, n.connect(actionPrincipal(id), ttSteward, "", ticketProtocols(tk), "").Code)
	assert.Equal(t, 1, n.reached)
}

// A valid ticket reaches the handler with the verified proof in context.
func TestTerminalWS_ValidTicketForwardsProof(t *testing.T) {
	n := newWSNode(t)
	tk := n.seed("op-1", ttSteward, "sess-a")
	rec := n.connect(actionPrincipal("op-1"), ttSteward, "sess-a", ticketProtocols(tk), "")
	require.Equal(t, http.StatusSwitchingProtocols, rec.Code)
	require.NotNil(t, n.proof)
	assert.Equal(t, ttSteward, n.proof.StewardID)
	assert.Equal(t, "bash", n.proof.TerminalShell)
	assert.Equal(t, "op-1", n.proof.UserID)
	assert.Equal(t, "ed25519", n.proof.Params["signature_algorithm"])
	assert.Equal(t, "n-1", n.proof.Params["nonce"])
	assert.NotContains(t, rec.Header().Get("Sec-WebSocket-Protocol"), tk)
}

// An out-of-tenant request is stopped before redemption and does not consume the ticket.
func TestTerminalWS_OutOfTenantDoesNotConsumeTicket(t *testing.T) {
	n := newWSNode(t)
	tk := n.seed("op-1", ttSteward, "")
	outsider := actionPrincipal("op-1")
	outsider.TenantID = "msp-b"
	assert.Equal(t, http.StatusNotFound, n.connect(outsider, ttSteward, "", ticketProtocols(tk), "").Code)
	assert.Equal(t, 1, ticketCount(n.server), "ticket must survive an out-of-tenant attempt")
	assert.Equal(t, http.StatusSwitchingProtocols, n.connect(actionPrincipal("op-1"), ttSteward, "", ticketProtocols(tk), "").Code)
}

// A session-authenticated upgrade hands the handler a re-check that follows the shared
// store.
func TestTerminalWS_SessionRecheckFollowsSessionStore(t *testing.T) {
	n := newWSNode(t)
	cfg := session.Config{IdleTimeout: time.Minute, AbsoluteTimeout: time.Hour, GraceWindow: time.Second}
	store := session.NewMemStore(cfg, time.Now)
	t.Cleanup(store.Close)
	sm := session.NewManager(cfg, store, time.Now)
	sess, _, err := sm.Issue(context.Background(), "op-1", "web", saTenant)
	require.NoError(t, err)

	n.authRef = &authSessionRef{manager: sm, id: sess.ID}
	tk := n.seed("op-1", ttSteward, "")
	require.Equal(t, http.StatusSwitchingProtocols, n.connect(actionPrincipal("op-1"), ttSteward, "", ticketProtocols(tk), "").Code)
	require.NotNil(t, n.recheck)
	assert.True(t, n.recheck(context.Background()))
	require.NoError(t, sm.Revoke(context.Background(), sess.ID))
	assert.False(t, n.recheck(context.Background()), "a revoked session must fail the re-check")
}

// An API-key principal's relay is re-checked against the key: the handler's context
// carries a re-check that turns false once the key is revoked.
func TestTerminalWS_APIKeyRecheckFollowsKeyRevocation(t *testing.T) {
	n := newWSNode(t)
	key := &APIKey{ID: "k-1", Key: "terminal-test-key", Name: "k", TenantID: saTenant}
	n.server.mu.Lock()
	n.server.apiKeys[key.Key] = key
	n.server.mu.Unlock()
	n.credRecheck = n.server.apiKeyRecheck(key)

	tk := n.seed("op-1", ttSteward, "")
	require.Equal(t, http.StatusSwitchingProtocols, n.connect(actionPrincipal("op-1"), ttSteward, "", ticketProtocols(tk), "").Code)
	require.NotNil(t, n.recheck, "an API-key relay must carry a re-check")
	assert.True(t, n.recheck(context.Background()))

	n.server.mu.Lock()
	delete(n.server.apiKeys, key.Key)
	n.server.mu.Unlock()
	assert.False(t, n.recheck(context.Background()), "a revoked API key must fail the re-check")
}

// An admin-certificate principal's relay is re-checked against the certificate manager.
func TestTerminalWS_AdminCertRecheckFollowsRevocation(t *testing.T) {
	n := newWSNode(t)
	require.NotNil(t, n.server.certManager)
	issued, err := n.server.certManager.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName: "terminal-admin", ValidityDays: 1, KeySize: 2048, ClientID: "terminal-admin",
		TemplateModifier: cert.SetAdminMarker,
	})
	require.NoError(t, err)
	block, _ := pem.Decode(issued.CertificatePEM)
	require.NotNil(t, block)
	peer, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	n.credRecheck = n.server.adminCertRecheck(peer)

	tk := n.seed("op-1", ttSteward, "")
	require.Equal(t, http.StatusSwitchingProtocols, n.connect(actionPrincipal("op-1"), ttSteward, "", ticketProtocols(tk), "").Code)
	require.NotNil(t, n.recheck, "an admin-certificate relay must carry a re-check")
	assert.True(t, n.recheck(context.Background()))

	require.NoError(t, n.server.certManager.Revoke(issued.SerialNumber))
	assert.False(t, n.recheck(context.Background()), "a revoked certificate must fail the re-check")
}

// A request with a valid ticket but no credential re-check is refused before the handler.
func TestTerminalWS_NoRecheckRefused(t *testing.T) {
	n := newWSNode(t)
	n.credRecheck = nil
	tk := n.seed("op-1", ttSteward, "")
	rec := n.connect(actionPrincipal("op-1"), ttSteward, "", ticketProtocols(tk), "")
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, "TERMINAL_RECHECK_UNAVAILABLE", errorCode(t, rec))
	assert.Equal(t, 1, ticketCount(n.server), "a refused request must not burn the ticket")
	assert.Zero(t, n.reached, "the handler must not run without a re-check")
}

// Ending the ADR-025 crossing that admitted a root caller to a client tenant's steward
// ends an open relay on the next re-check, and so does removing terminal:create.
func TestTerminalWS_RecheckFollowsCrossingAndPermission(t *testing.T) {
	t.Run("crossing ended", func(t *testing.T) {
		n := newWSNode(t)
		wireCrossingStore(t, n.server)
		require.NoError(t, ensureTestRootTenant(context.Background(), n.server.tenantManager))
		now := time.Now().UTC()
		require.NoError(t, n.server.tenantCrossingStore.CreateTenantCrossing(context.Background(), &business.TenantCrossing{
			ID: "grant-terminal-recheck", TenantID: saTenant, Kind: business.TenantCrossingKindGrant,
			GrantedBy: "msp-a-admin", CreatedAt: now, ExpiresAt: now.Add(time.Hour),
		}))

		tk := n.seed("root-op", ttSteward, "")
		require.Equal(t, http.StatusSwitchingProtocols, n.connect(rootScopedPrincipal("root-op"), ttSteward, "", ticketProtocols(tk), "").Code)
		require.NotNil(t, n.recheck)
		assert.True(t, n.recheck(context.Background()), "an active crossing keeps the relay open")

		require.NoError(t, n.server.tenantCrossingStore.RevokeTenantCrossing(context.Background(), "grant-terminal-recheck"))
		assert.False(t, n.recheck(context.Background()), "an ended crossing must end the relay")
	})

	t.Run("terminal:create removed", func(t *testing.T) {
		n := newWSNode(t)
		perm := true
		n.refresh = func(context.Context) (*Principal, bool) {
			p := &Principal{ID: "op-1", TenantID: saTenant, Assurance: session.AssuranceStrong}
			if perm {
				p.Permissions = []string{"terminal:create"}
			}
			return p, true
		}
		tk := n.seed("op-1", ttSteward, "")
		require.Equal(t, http.StatusSwitchingProtocols, n.connect(actionPrincipal("op-1"), ttSteward, "", ticketProtocols(tk), "").Code)
		require.NotNil(t, n.recheck)
		assert.True(t, n.recheck(context.Background()))

		perm = false
		assert.False(t, n.recheck(context.Background()), "removing terminal:create must end the relay")
	})
}
