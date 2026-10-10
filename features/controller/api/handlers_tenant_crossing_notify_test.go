// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"io"
	"mime/quotedprintable"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/tenant"
	notifif "github.com/cfgis/cfgms/pkg/notification/interfaces"
	_ "github.com/cfgis/cfgms/pkg/notification/providers/smtp" // register the smtp provider
	"github.com/cfgis/cfgms/pkg/session"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

const loudJustification = "Client lost all admin passkeys, ticket INC-4821 SECRET-MARKER"

// attachEmail points the server's notifier at the in-process SMTP server.
func attachEmail(t *testing.T, server *Server, smtp *emailTestSMTPServer) {
	t.Helper()
	n, err := notifif.CreateNotifierFromConfig("smtp", map[string]interface{}{
		"host": "localhost", "port": smtp.Port, "security": "implicit_tls",
		"from": "cfgms@acme-corp.example", "username": testSMTPUser, "password": testSMTPPassword,
		"root_ca_pem": smtp.CAPEM,
	})
	require.NoError(t, err)
	server.emailMu.Lock()
	server.emailNotifier = n
	server.emailMu.Unlock()
}

// seedRootOperator creates a root-scoped account and returns a principal bound to its
// ID, so the invoker's username resolves in the email and the feed.
func seedRootOperator(t *testing.T, server *Server, username string) *Principal {
	t.Helper()
	rec := postAccount(t, server, testAdminPrincipal(), AccountRequest{Username: username, RootScope: true, Permissions: []string{"tenant:read"}})
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	acct, err := server.getAccount(context.Background(), username)
	require.NoError(t, err)
	require.NotNil(t, acct)
	return rootScopedPrincipal(acct.ID)
}

func invokeAs(t *testing.T, server *Server, caller *Principal, category string) *httptest.ResponseRecorder {
	t.Helper()
	req := requestAsPrincipal(t, http.MethodPost, "/api/v1/tenants/msp-a/break-glass", "msp-a", caller, breakGlassBody(t, category, loudJustification))
	rec := httptest.NewRecorder()
	server.handleTenantBreakGlass(rec, req)
	return rec
}

func setContacts(t *testing.T, server *Server, addrs ...string) {
	t.Helper()
	_, err := server.tenantManager.SetAdminContacts(context.Background(), "msp-a", addrs)
	require.NoError(t, err)
}

// auditEntries flushes the audit manager (after the announcements finish) and
// returns the entries of one scope.
func auditEntries(t *testing.T, server *Server, scope string) []*business.AuditEntry {
	t.Helper()
	server.crossingNotifyWG.Wait()
	require.NoError(t, server.auditManager.Flush(context.Background()))
	entries, err := server.auditManager.QueryEntries(context.Background(), &business.AuditFilter{TenantID: scope})
	require.NoError(t, err)
	return entries
}

func hasAction(entries []*business.AuditEntry, action string) bool {
	for _, e := range entries {
		if e.Action == action {
			return true
		}
	}
	return false
}

func countAction(entries []*business.AuditEntry, action string) int {
	n := 0
	for _, e := range entries {
		if e.Action == action {
			n++
		}
	}
	return n
}

func invokeLoud(t *testing.T, server *Server, category string) *httptest.ResponseRecorder {
	t.Helper()
	return invokeBreakGlass(t, server, breakGlassBody(t, category, loudJustification), "")
}

func activeFeed(t *testing.T, server *Server, caller *Principal) []ActiveTenantCrossingResponse {
	t.Helper()
	req := requestAsPrincipal(t, http.MethodGet, "/api/v1/tenant-crossings/active", "", caller, nil)
	req = mux.SetURLVars(req, nil)
	rec := httptest.NewRecorder()
	server.handleListActiveTenantCrossings(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var resp struct {
		Data []ActiveTenantCrossingResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	return resp.Data
}

func notifiedOutcome(t *testing.T, server *Server) string {
	t.Helper()
	entries := auditEntries(t, server, "msp-a")
	e := findAuditEntryByAction(t, entries, "tenant.crossing_break_glass_notified")
	outcome, _ := e.Details["outcome"].(string)
	return outcome
}

func TestBreakGlassLoud_EveryCategory_AuditMetaLogAndFeed(t *testing.T) {
	for _, cat := range []business.TenantCrossingReasonCategory{
		business.TenantCrossingReasonAccountRecovery,
		business.TenantCrossingReasonSecurityIncident,
		business.TenantCrossingReasonLegalRequest,
		business.TenantCrossingReasonBillingDispute,
	} {
		t.Run(string(cat), func(t *testing.T) {
			server := breakGlassServer(t)
			rec := invokeLoud(t, server, string(cat))
			require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
			created := decodeCrossing(t, rec)

			tenantEntry := findAuditEntryByAction(t, auditEntries(t, server, "msp-a"), "tenant.crossing_break_glass_invoked")
			assert.Equal(t, business.AuditSeverityCritical, tenantEntry.Severity)

			rootEntry := findAuditEntryByAction(t, auditEntries(t, server, testRootTenantID), "tenant.crossing_break_glass_invoked")
			assert.Equal(t, "msp-a", rootEntry.Details["target_tenant"])
			assert.Equal(t, "break-glass", rootEntry.Details["kind"])
			assert.Equal(t, string(cat), rootEntry.Details["reason_category"])
			assert.Equal(t, "root-operator-1", rootEntry.Details["actor"])
			assert.Equal(t, created.ExpiresAt.Format(time.RFC3339), rootEntry.Details["expires_at"])
			assert.NotContains(t, strings.Join(detailValues(rootEntry), "|"), "SECRET-MARKER", "root meta-log carries no justification text")

			feed := activeFeed(t, server, rootScopedPrincipal("root-operator-1"))
			require.Len(t, feed, 1)
			assert.Equal(t, created.ID, feed[0].ID)
		})
	}
}

func detailValues(e *business.AuditEntry) []string {
	var out []string
	for _, v := range e.Details {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func TestBreakGlassLoud_EmailSent_NamesTenantCategoryExpiryNotJustification(t *testing.T) {
	smtp := newEmailTestSMTPServer(t)
	server := breakGlassServer(t)
	attachEmail(t, server, smtp)
	setContacts(t, server, "ops@acme-corp.example", "sec@acme-corp.example")
	operator := seedRootOperator(t, server, "alice-root")

	rec := invokeAs(t, server, operator, "legal_request")
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	created := decodeCrossing(t, rec)

	assert.Equal(t, "sent", notifiedOutcome(t, server))
	msgs := smtp.Messages()
	require.Len(t, msgs, 1, "exactly one email for the MSP contacts")
	raw := msgs[0]
	assert.Contains(t, raw, "ops@acme-corp.example")
	assert.Contains(t, raw, "sec@acme-corp.example")
	assert.Contains(t, raw, "Subject: Break-glass access started on tenant msp-a")

	_, body, ok := strings.Cut(raw, "\r\n\r\n")
	require.True(t, ok)
	decoded, err := io.ReadAll(quotedprintable.NewReader(strings.NewReader(body)))
	require.NoError(t, err)
	text := string(decoded)
	assert.Contains(t, text, "msp-a")
	assert.Contains(t, text, "legal_request")
	assert.Contains(t, text, "alice-root", "invoking operator")
	assert.Contains(t, text, created.ExpiresAt.UTC().Format(time.RFC3339))
	assert.Contains(t, text, "DELETE /api/v1/tenants/msp-a/access-grants/"+created.ID)
	assert.NotContains(t, text, "SECRET-MARKER")
	assert.NotContains(t, text, "INC-4821")
}

func TestBreakGlassLoud_EmailNotConfigured_OtherChannelsStillFire(t *testing.T) {
	server := breakGlassServer(t)
	setContacts(t, server, "ops@acme-corp.example")
	require.Nil(t, server.EmailNotifier())

	rec := invokeLoud(t, server, "account_recovery")
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	assert.Equal(t, "not_configured", notifiedOutcome(t, server))
	assert.True(t, hasAction(auditEntries(t, server, "msp-a"), "tenant.crossing_break_glass_invoked"))
	assert.True(t, hasAction(auditEntries(t, server, testRootTenantID), "tenant.crossing_break_glass_invoked"))
	assert.Len(t, activeFeed(t, server, rootScopedPrincipal("root-operator-1")), 1)
}

func TestBreakGlassLoud_NoContacts(t *testing.T) {
	smtp := newEmailTestSMTPServer(t)
	server := breakGlassServer(t)
	attachEmail(t, server, smtp)

	rec := invokeLoud(t, server, "account_recovery")
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	assert.Equal(t, "no_contacts", notifiedOutcome(t, server))
	assert.Empty(t, smtp.Messages())
}

func TestBreakGlassLoud_SMTPRejects_Failed_RequestStill201(t *testing.T) {
	smtp := newEmailTestSMTPServer(t)
	smtp.rejectRcpt = true
	server := breakGlassServer(t)
	attachEmail(t, server, smtp)
	setContacts(t, server, "ops@acme-corp.example")

	rec := invokeLoud(t, server, "billing_dispute")
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	assert.Equal(t, "failed", notifiedOutcome(t, server))
	assert.Empty(t, smtp.Messages())
	stored, err := server.tenantCrossingStore.GetTenantCrossing(context.Background(), decodeCrossing(t, rec).ID)
	require.NoError(t, err)
	assert.Nil(t, stored.RevokedAt, "a failed announcement never undoes the crossing")
}

func TestBreakGlassLoud_SecondApprover_PendingAnnouncesNothing_ApprovalOnce(t *testing.T) {
	smtp := newEmailTestSMTPServer(t)
	server := secondApproverServer(t, true)
	attachEmail(t, server, smtp)
	setContacts(t, server, "ops@acme-corp.example")

	c := invokePending(t, server)
	entries := auditEntries(t, server, "msp-a")
	assert.Equal(t, 0, countAction(entries, "tenant.crossing_break_glass_notified"))
	assert.Empty(t, smtp.Messages())
	assert.Empty(t, activeFeed(t, server, rootScopedPrincipal("root-operator-1")), "pending is not an active elevation")
	assert.True(t, hasAction(auditEntries(t, server, testRootTenantID), "tenant.crossing_break_glass_requested"))

	rec := approveBreakGlass(t, server, c.ID, rootScopedPrincipal("root-operator-2"))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	entries = auditEntries(t, server, "msp-a")
	assert.Equal(t, 1, countAction(entries, "tenant.crossing_break_glass_notified"))
	assert.Len(t, smtp.Messages(), 1)
	assert.True(t, hasAction(auditEntries(t, server, testRootTenantID), "tenant.crossing_break_glass_approved"))

	// A repeated approval is refused and announces nothing more.
	rec = approveBreakGlass(t, server, c.ID, rootScopedPrincipal("root-operator-3"))
	require.Equal(t, http.StatusConflict, rec.Code)
	assert.Equal(t, 1, countAction(auditEntries(t, server, "msp-a"), "tenant.crossing_break_glass_notified"))
	assert.Len(t, smtp.Messages(), 1)
}

func TestBreakGlassLoud_StoreFailureAnnouncesNothing(t *testing.T) {
	smtp := newEmailTestSMTPServer(t)
	server := breakGlassServer(t)
	attachEmail(t, server, smtp)
	setContacts(t, server, "ops@acme-corp.example")

	rec := invokeBreakGlass(t, server, breakGlassBody(t, "legal_request", "short"), "")
	require.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, 0, countAction(auditEntries(t, server, "msp-a"), "tenant.crossing_break_glass_notified"))
	assert.Empty(t, smtp.Messages())
}

func TestActiveFeed_Visibility(t *testing.T) {
	server := seedRootTenant(t, setupCrossingTestServer(t))
	ctx := context.Background()
	for _, spec := range []struct{ id, parent string }{
		{"msp-a", testRootTenantID}, {"client-a1", "msp-a"}, {"msp-b", testRootTenantID},
	} {
		_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: spec.id, Name: spec.id, ParentID: spec.parent})
		require.NoError(t, err)
	}
	op1 := seedRootOperator(t, server, "alice-root")
	now := time.Now().UTC()
	add := func(c *business.TenantCrossing) {
		c.CreatedAt, c.ExpiresAt = now, now.Add(time.Hour)
		require.NoError(t, server.tenantCrossingStore.CreateTenantCrossing(ctx, c))
	}
	add(&business.TenantCrossing{ID: "grant-a", TenantID: "msp-a", Kind: business.TenantCrossingKindGrant, GrantedBy: "msp-a-admin"})
	add(&business.TenantCrossing{ID: "grant-b", TenantID: "msp-b", Kind: business.TenantCrossingKindGrant, GrantedBy: "msp-b-admin"})
	add(&business.TenantCrossing{ID: "bg-op1-client", TenantID: "client-a1", Kind: business.TenantCrossingKindBreakGlass,
		PrincipalID: op1.ID, GrantedBy: op1.ID, ReasonCategory: business.TenantCrossingReasonLegalRequest})
	add(&business.TenantCrossing{ID: "bg-op1-msp", TenantID: "msp-a", Kind: business.TenantCrossingKindBreakGlass,
		PrincipalID: op1.ID, GrantedBy: op1.ID, ReasonCategory: business.TenantCrossingReasonLegalRequest})
	add(&business.TenantCrossing{ID: "bg-op2-msp-b", TenantID: "msp-b", Kind: business.TenantCrossingKindBreakGlass,
		PrincipalID: "root-operator-2", GrantedBy: "root-operator-2", ReasonCategory: business.TenantCrossingReasonLegalRequest})
	add(&business.TenantCrossing{ID: "bg-pending", TenantID: "msp-a", Kind: business.TenantCrossingKindBreakGlass,
		PrincipalID: op1.ID, GrantedBy: op1.ID, ApprovalState: business.TenantCrossingApprovalPending,
		ReasonCategory: business.TenantCrossingReasonLegalRequest})

	byID := func(feed []ActiveTenantCrossingResponse) map[string]ActiveTenantCrossingResponse {
		m := map[string]ActiveTenantCrossingResponse{}
		for _, e := range feed {
			m[e.ID] = e
		}
		return m
	}

	t.Run("msp admin sees its subtree only", func(t *testing.T) {
		got := byID(activeFeed(t, server, &Principal{ID: "msp-a-admin", TenantID: "msp-a", Assurance: session.AssuranceStrong}))
		assert.Len(t, got, 3)
		for _, id := range []string{"grant-a", "bg-op1-client", "bg-op1-msp"} {
			assert.Contains(t, got, id)
		}
		assert.Equal(t, "msp-a", got["grant-a"].TenantName)
		assert.Equal(t, "client-a1", got["bg-op1-client"].TenantName)
	})

	t.Run("root caller sees own break-glass plus every grant", func(t *testing.T) {
		got := byID(activeFeed(t, server, op1))
		assert.Len(t, got, 4)
		for _, id := range []string{"grant-a", "grant-b", "bg-op1-client", "bg-op1-msp"} {
			assert.Contains(t, got, id)
		}
		assert.NotContains(t, got, "bg-op2-msp-b", "another operator's break-glass is not shown")
		assert.NotContains(t, got, "bg-pending")
		assert.Equal(t, "msp-a", got["grant-a"].TenantName, "an MSP is named to root")
		assert.Equal(t, "", got["bg-op1-client"].TenantName, "root never sees a client tenant name")
		assert.Equal(t, "client-a1", got["bg-op1-client"].TenantID)
		assert.Equal(t, "alice-root", got["bg-op1-msp"].PrincipalName)
	})

	t.Run("drops a crossing at end and at expiry", func(t *testing.T) {
		require.NoError(t, server.tenantCrossingStore.RevokeTenantCrossing(ctx, "grant-a"))
		got := byID(activeFeed(t, server, op1))
		assert.NotContains(t, got, "grant-a")

		expired := &business.TenantCrossing{ID: "bg-short", TenantID: "msp-a", Kind: business.TenantCrossingKindBreakGlass,
			PrincipalID: op1.ID, GrantedBy: op1.ID, ReasonCategory: business.TenantCrossingReasonLegalRequest,
			CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(300 * time.Millisecond)}
		require.NoError(t, server.tenantCrossingStore.CreateTenantCrossing(ctx, expired))
		assert.Contains(t, byID(activeFeed(t, server, op1)), "bg-short")
		time.Sleep(400 * time.Millisecond)
		assert.NotContains(t, byID(activeFeed(t, server, op1)), "bg-short")
	})
}

func TestGrantCreateAndEnd_WriteRootMetaLog_SendNoEmail(t *testing.T) {
	smtp := newEmailTestSMTPServer(t)
	server := breakGlassServer(t)
	attachEmail(t, server, smtp)
	setContacts(t, server, "ops@acme-corp.example")
	mspAdmin := &Principal{ID: "msp-a-admin", TenantID: "msp-a", Assurance: session.AssuranceStrong}

	req := requestAsPrincipal(t, http.MethodPost, "/api/v1/tenants/msp-a/access-grants", "msp-a", mspAdmin, []byte(`{"duration_minutes": 30}`))
	rec := httptest.NewRecorder()
	server.handleCreateTenantCrossingGrant(rec, req)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	grant := decodeCrossing(t, rec)

	req = requestAsPrincipal(t, http.MethodDelete, "/x", "msp-a", mspAdmin, nil)
	req = mux.SetURLVars(req, map[string]string{"id": "msp-a", "crossing_id": grant.ID})
	rec = httptest.NewRecorder()
	server.handleEndTenantCrossing(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	rootEntries := auditEntries(t, server, testRootTenantID)
	created := findAuditEntryByAction(t, rootEntries, "tenant.crossing_grant_created")
	assert.Equal(t, "msp-a", created.Details["target_tenant"])
	assert.Equal(t, "grant", created.Details["kind"])
	assert.True(t, hasAction(rootEntries, "tenant.crossing_grant_ended"))
	assert.Equal(t, 0, countAction(auditEntries(t, server, "msp-a"), "tenant.crossing_break_glass_notified"))
	assert.Empty(t, smtp.Messages(), "grants are never emailed")
}

func TestServerClose_WaitsForInFlightBreakGlassNotification(t *testing.T) {
	smtp := newEmailTestSMTPServer(t)
	server := breakGlassServer(t)
	attachEmail(t, server, smtp)
	setContacts(t, server, "ops@acme-corp.example")

	rec := invokeLoud(t, server, "account_recovery")
	require.Equal(t, http.StatusCreated, rec.Code)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	require.NoError(t, server.Close(ctx))
	assert.Len(t, smtp.Messages(), 1, "Close returns only after the announcement finished")
}
