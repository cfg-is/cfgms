// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/quotedprintable"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Issue #4726: the whole root-read policy of epic #4701, proven end to end. Genuine
// bearer sessions (an MSP administrator and root-scope operators) are sent through
// the real router, tenant manager, crossing store and audit manager, with the
// break-glass email delivered to an in-process TLS SMTP server. Each scenario is a
// named sub-test so a failure points at the policy clause it breaks. The fixture
// (a client tenant below an MSP, holding a steward, account, job and entity) is the
// one the #4722 no-leak sweep uses.

// e2eRead is one representative by-ID read the scenarios repeat.
type e2eRead struct {
	name string
	url  string
}

type e2eRootRead struct {
	*rootReadSweepFixture
	mspAdminToken string
	rootSteward   string
	clientSteward string
}

func newE2ERootRead(t *testing.T) *e2eRootRead {
	t.Helper()
	f := newRootReadSweepFixture(t)
	e := &e2eRootRead{rootReadSweepFixture: f, clientSteward: f.vars["id"]}

	const mspAdmin = "e2e-msp-admin"
	f.server.cacheAccount(&account{
		ID: mspAdmin, Username: mspAdmin, TenantID: sweepMSP,
		Permissions: []string{"tenant:crossing-grant", "tenant:crossing-end", "tenant:crossing-list", "audit:list"},
	})
	ctx := context.Background()
	sess, _, err := f.sessMgr.Issue(ctx, mspAdmin, "cfg-cli", sweepMSP)
	require.NoError(t, err)
	_, e.mspAdminToken, err = f.sessMgr.Elevate(ctx, sess.ID, []byte("e2e-msp-credential"), "192.0.2.1")
	require.NoError(t, err)

	// The root tenant's own steward, found through the same list a root operator reads.
	rec := f.get(f.rootSession(t, "e2e-discovery-root"), "/api/v1/stewards")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var list struct {
		Data []struct {
			ID       string `json:"id"`
			TenantID string `json:"tenant_id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &list))
	for _, s := range list.Data {
		if s.TenantID == testRootTenantID {
			e.rootSteward = s.ID
		}
	}
	require.NotEmpty(t, e.rootSteward, "the root tenant's steward must be listed")
	return e
}

func (e *e2eRootRead) do(token, method, url string, body interface{}) *httptest.ResponseRecorder {
	return e.doWithPresence(nil, token, "", method, url, body)
}

// doWithPresence is do with an X-Presence-Token, for the routes that demand a fresh
// WebAuthn proof of presence. presenceFor is the principal ID the token is minted
// for; the token is bound to this request's method, path, body and the
// break-glass approval permission (Issue #5142).
func (e *e2eRootRead) doWithPresence(t *testing.T, token, presenceFor, method, url string, body interface{}) *httptest.ResponseRecorder {
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	req := httptest.NewRequest(method, url, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	if presenceFor != "" {
		req.Header.Set(presenceTokenHeader, mintPresenceTokenFor(t, e.server, presenceFor, req, "tenant:crossing-approve-break-glass"))
	}
	rec := httptest.NewRecorder()
	e.server.router.ServeHTTP(rec, req)
	return rec
}

// byIDReads are the by-ID reads of the client tenant's steward, account, job and entity.
func (e *e2eRootRead) byIDReads() []e2eRead {
	return []e2eRead{
		{"steward", "/api/v1/stewards/" + e.clientSteward},
		{"account", "/api/v1/accounts/" + e.vars["username"]},
		{"job", "/api/v1/jobs/job-" + sweepMarker},
		{"entity", "/api/v1/entities/" + e.vars["eid"]},
	}
}

// e2eLists are the list reads that must omit client rows without a crossing.
var e2eLists = []string{"/api/v1/stewards", "/api/v1/accounts", "/api/v1/jobs", "/api/v1/entities"}

// assertE2EChallenged requires the tenant-crossing challenge: 401, the token in
// WWW-Authenticate, a break-glass endpoint and the four reason categories.
func assertE2EChallenged(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	require.Equal(t, http.StatusUnauthorized, rec.Code, "expected the crossing challenge: %s", rec.Body.String())
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `required="tenant-crossing"`)
	var challenge struct {
		Error    string   `json:"error"`
		Endpoint string   `json:"break_glass_endpoint"`
		Reasons  []string `json:"reason_categories"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &challenge))
	assert.Equal(t, "tenant_crossing_required", challenge.Error)
	assert.Equal(t, "/api/v1/tenants/"+sweepMSP+"/break-glass", challenge.Endpoint,
		"challenge must name the covering MSP, never the client tenant")
	assert.NotContains(t, rec.Body.String(), sweepClient)
	assert.ElementsMatch(t, []string{"account_recovery", "security_incident", "legal_request", "billing_dispute"}, challenge.Reasons)
}

func (e *e2eRootRead) assertAllChallenged(t *testing.T, token string) {
	t.Helper()
	for _, rd := range e.byIDReads() {
		t.Run(rd.name+" by ID", func(t *testing.T) {
			assertE2EChallenged(t, e.do(token, http.MethodGet, rd.url, nil))
		})
	}
}

func (e *e2eRootRead) assertAllAdmitted(t *testing.T, token string) {
	t.Helper()
	for _, rd := range e.byIDReads() {
		t.Run(rd.name+" by ID", func(t *testing.T) {
			rec := e.do(token, http.MethodGet, rd.url, nil)
			assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			assert.NotContains(t, rec.Header().Get("WWW-Authenticate"), "tenant-crossing")
		})
	}
	t.Run("steward list includes the client row", func(t *testing.T) {
		rec := e.do(token, http.MethodGet, "/api/v1/stewards", nil)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Contains(t, rec.Body.String(), e.clientSteward)
		assert.Contains(t, rec.Body.String(), e.rootSteward)
	})
}

func (e *e2eRootRead) grant(t *testing.T, minutes int) *TenantCrossingResponse {
	t.Helper()
	rec := e.do(e.mspAdminToken, http.MethodPost, "/api/v1/tenants/"+sweepMSP+"/access-grants",
		map[string]int{"duration_minutes": minutes})
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	return decodeCrossing(t, rec)
}

func (e *e2eRootRead) breakGlass(t *testing.T, token, category string) *httptest.ResponseRecorder {
	t.Helper()
	return e.do(token, http.MethodPost, "/api/v1/tenants/"+sweepMSP+"/break-glass",
		map[string]string{"reason_category": category, "justification": loudJustification})
}

// settledAudit returns one scope's entries once the break-glass announcements finish.
func (e *e2eRootRead) settledAudit(t *testing.T, scope string) []*business.AuditEntry {
	t.Helper()
	return auditEntries(t, e.server, scope)
}

// newE2EAuditEvent is an audit event carrying detail a carve-out projection must drop.
func newE2EAuditEvent(tenantID string, et business.AuditEventType, action string, result business.AuditResult) *audit.AuditEventBuilder {
	return audit.NewEventBuilder().
		Tenant(tenantID).
		Type(et).
		Action(action).
		User("msp-admin-user", business.AuditUserTypeHuman).
		Resource("account", "secret-id", "secret-name").
		Result(result).
		Severity(business.AuditSeverityMedium).
		Request("req", "POST", "/secret/path", "203.0.113.9", "agent").
		Detail("business_note", "client-name-leak")
}

func activeFeedIDs(t *testing.T, e *e2eRootRead, token string) []string {
	t.Helper()
	rec := e.do(token, http.MethodGet, "/api/v1/tenant-crossings/active", nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var resp struct {
		Data []ActiveTenantCrossingResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	ids := make([]string, 0, len(resp.Data))
	for _, c := range resp.Data {
		ids = append(ids, c.ID)
	}
	return ids
}

func TestRootReadPolicy_EndToEnd(t *testing.T) {
	t.Run("1 denied without a crossing", func(t *testing.T) {
		e := newE2ERootRead(t)
		token := e.rootSession(t, "e2e-root-denied")

		e.assertAllChallenged(t, token)

		for _, list := range e2eLists {
			t.Run("list "+list+" omits client rows", func(t *testing.T) {
				rec := e.do(token, http.MethodGet, list, nil)
				require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
				for _, leaked := range []string{sweepMarker, sweepClient, e.clientSteward} {
					assert.NotContains(t, rec.Body.String(), leaked)
				}
			})
		}

		t.Run("root tenant own records stay readable", func(t *testing.T) {
			rec := e.do(token, http.MethodGet, "/api/v1/stewards/"+e.rootSteward, nil)
			assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			rec = e.do(token, http.MethodGet, "/api/v1/stewards", nil)
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			assert.Contains(t, rec.Body.String(), e.rootSteward)
		})
	})

	t.Run("2 allowed under an MSP grant", func(t *testing.T) {
		e := newE2ERootRead(t)
		rootA, rootB := "e2e-root-grant-a", "e2e-root-grant-b"
		tokenA, tokenB := e.rootSession(t, rootA), e.rootSession(t, rootB)
		e.assertAllChallenged(t, tokenA)

		grant := e.grant(t, 30)
		assert.Equal(t, "grant", grant.Kind)
		assert.Empty(t, grant.PrincipalID, "a grant names no person")
		assert.Equal(t, sweepMSP, grant.TenantID)

		for id, token := range map[string]string{rootA: tokenA, rootB: tokenB} {
			t.Run("admits "+id, func(t *testing.T) {
				e.assertAllAdmitted(t, token)
			})
		}

		t.Run("each principal's first read is audited once", func(t *testing.T) {
			used := map[string]int{}
			for _, entry := range e.settledAudit(t, sweepMSP) {
				if entry.Action == "tenant.crossing_grant_used" {
					actor, _ := entry.Details["actor"].(string)
					used[actor]++
				}
			}
			assert.Equal(t, map[string]int{rootA: 1, rootB: 1}, used)
		})

		t.Run("revoked by the MSP, the next read is challenged again", func(t *testing.T) {
			rec := e.do(e.mspAdminToken, http.MethodDelete, "/api/v1/tenants/"+sweepMSP+"/access-grants/"+grant.ID, nil)
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			assert.Equal(t, "revoked", decodeCrossing(t, rec).Status)
			e.assertAllChallenged(t, tokenA)
			e.assertAllChallenged(t, tokenB)
		})
	})

	t.Run("3 allowed under break-glass and the MSP is notified", func(t *testing.T) {
		for _, category := range []string{"account_recovery", "security_incident", "legal_request", "billing_dispute"} {
			t.Run(category, func(t *testing.T) {
				e := newE2ERootRead(t)
				smtp := newEmailTestSMTPServer(t)
				attachEmail(t, e.server, smtp)
				_, err := e.server.tenantManager.SetAdminContacts(context.Background(), sweepMSP,
					[]string{"ops@acme-corp.example", "sec@acme-corp.example"})
				require.NoError(t, err)

				const operator = "e2e-root-bg"
				token := e.rootSession(t, operator)
				e.assertAllChallenged(t, token)

				rec := e.breakGlass(t, token, category)
				require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
				crossing := decodeCrossing(t, rec)
				assert.Equal(t, "active", crossing.Status)
				assert.Equal(t, category, crossing.ReasonCategory)

				e.assertAllAdmitted(t, token)

				t.Run("one email to the MSP contacts, no justification", func(t *testing.T) {
					e.server.crossingNotifyWG.Wait()
					msgs := smtp.Messages()
					require.Len(t, msgs, 1, "exactly one email")
					raw := msgs[0]
					assert.Contains(t, raw, "ops@acme-corp.example")
					assert.Contains(t, raw, "sec@acme-corp.example")
					assert.Contains(t, raw, "Subject: Break-glass access started on tenant Sweep-MSP")
					_, body, ok := strings.Cut(raw, "\r\n\r\n")
					require.True(t, ok)
					decoded, err := io.ReadAll(quotedprintable.NewReader(strings.NewReader(body)))
					require.NoError(t, err)
					assert.Contains(t, string(decoded), "Sweep-MSP")
					assert.Contains(t, string(decoded), category)
					assert.NotContains(t, string(decoded), "SECRET-MARKER")
					assert.NotContains(t, string(decoded), "INC-4821")
				})

				t.Run("active feeds list the crossing", func(t *testing.T) {
					assert.Contains(t, activeFeedIDs(t, e, e.mspAdminToken), crossing.ID)
					assert.Contains(t, activeFeedIDs(t, e, token), crossing.ID)
				})

				t.Run("tenant-scoped and root-scope audit entries", func(t *testing.T) {
					tenantEntry := findAuditEntryByAction(t, e.settledAudit(t, sweepMSP), "tenant.crossing_break_glass_invoked")
					assert.Equal(t, business.AuditSeverityCritical, tenantEntry.Severity)
					rootEntry := findAuditEntryByAction(t, e.settledAudit(t, testRootTenantID), "tenant.crossing_break_glass_invoked")
					assert.Equal(t, sweepMSP, rootEntry.Details["target_tenant"])
					assert.Equal(t, category, rootEntry.Details["reason_category"])
					assert.Equal(t, operator, rootEntry.Details["actor"])
					assert.NotContains(t, strings.Join(detailValues(rootEntry), "|"), "SECRET-MARKER")

					notified := findAuditEntryByAction(t, e.settledAudit(t, sweepMSP), "tenant.crossing_break_glass_notified")
					assert.Equal(t, "sent", notified.Details["outcome"])
				})

				t.Run("the MSP reads its entry through the audit endpoint", func(t *testing.T) {
					rec := e.do(e.mspAdminToken, http.MethodGet, "/api/v1/audit/entries?action=tenant.crossing_break_glass_invoked", nil)
					require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
					var resp auditResp
					require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
					require.NotEmpty(t, resp.Data.Entries)
					assert.Equal(t, sweepMSP, resp.Data.Entries[0].TenantID)
					assert.Equal(t, business.AuditSeverityCritical, resp.Data.Entries[0].Severity)
				})
			})
		}
	})

	t.Run("4 break-glass with email not configured", func(t *testing.T) {
		e := newE2ERootRead(t)
		require.Nil(t, e.server.EmailNotifier(), "email must be unconfigured for this scenario")
		token := e.rootSession(t, "e2e-root-noemail")

		rec := e.breakGlass(t, token, "security_incident")
		require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
		crossing := decodeCrossing(t, rec)
		assert.Equal(t, "active", crossing.Status)

		e.assertAllAdmitted(t, token)
		assert.Contains(t, activeFeedIDs(t, e, token), crossing.ID)
		assert.Contains(t, activeFeedIDs(t, e, e.mspAdminToken), crossing.ID)
		assert.True(t, hasAction(e.settledAudit(t, sweepMSP), "tenant.crossing_break_glass_invoked"), "tenant-scoped entry")
		assert.True(t, hasAction(e.settledAudit(t, testRootTenantID), "tenant.crossing_break_glass_invoked"), "root meta-log entry")
		notified := findAuditEntryByAction(t, e.settledAudit(t, sweepMSP), "tenant.crossing_break_glass_notified")
		assert.Equal(t, "not_configured", notified.Details["outcome"])
	})

	t.Run("4b break-glass on the endpoint the challenge names admits the by-ID read", func(t *testing.T) {
		e := newE2ERootRead(t)
		token := e.rootSession(t, "e2e-root-follow")
		read := e.byIDReads()[0]

		challenged := e.do(token, http.MethodGet, read.url, nil)
		assertE2EChallenged(t, challenged)
		var challenge struct {
			Endpoint string `json:"break_glass_endpoint"`
		}
		require.NoError(t, json.Unmarshal(challenged.Body.Bytes(), &challenge))

		rec := e.do(token, http.MethodPost, challenge.Endpoint,
			map[string]string{"reason_category": "security_incident", "justification": loudJustification})
		require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
		admitted := e.do(token, http.MethodGet, read.url, nil)
		assert.Equal(t, http.StatusOK, admitted.Code, admitted.Body.String())
	})

	t.Run("5 second approver", func(t *testing.T) {
		t.Run("on: pending until a different root operator approves", func(t *testing.T) {
			e := newE2ERootRead(t)
			on := true
			e.server.cfg.TenantAdmin = &config.TenantAdminConfig{BreakGlassRequiresSecondApprover: &on}
			invoker, approver := e.rootSession(t, "e2e-root-invoker"), e.rootSession(t, "e2e-root-approver")

			rec := e.breakGlass(t, invoker, "account_recovery")
			require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
			pending := decodeCrossing(t, rec)
			assert.Equal(t, "pending", pending.Status)
			e.assertAllChallenged(t, invoker)

			approvePath := "/api/v1/tenants/" + sweepMSP + "/break-glass/" + pending.ID + "/approve"
			// The presence proof is minted for the acting principal, so each approval
			// attempt reaches the handler and is decided on its merits.
			self := e.doWithPresence(t, invoker, "e2e-root-invoker", http.MethodPost, approvePath, nil)
			assert.Equal(t, http.StatusForbidden, self.Code, self.Body.String())
			assert.Equal(t, "SAME_APPROVER", crossingErrorCode(t, self))
			e.assertAllChallenged(t, invoker)

			rec = e.doWithPresence(t, approver, "e2e-root-approver", http.MethodPost, approvePath, nil)
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			assert.Equal(t, "active", decodeCrossing(t, rec).Status)
			e.assertAllAdmitted(t, invoker)
		})

		t.Run("off by default: active immediately", func(t *testing.T) {
			e := newE2ERootRead(t)
			token := e.rootSession(t, "e2e-root-immediate")
			rec := e.breakGlass(t, token, "account_recovery")
			require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
			assert.Equal(t, "active", decodeCrossing(t, rec).Status)
			e.assertAllAdmitted(t, token)
		})
	})

	t.Run("6 always visible without a crossing", func(t *testing.T) {
		e := newE2ERootRead(t)
		token := e.rootSession(t, "e2e-root-carveout")
		ctx := context.Background()

		// An MSP administrator failed login, and a grant that was created and ended, so
		// the crossing meta-log has entries while root holds no crossing.
		require.NoError(t, e.server.auditManager.RecordEvent(ctx, newE2EAuditEvent(sweepMSP,
			business.AuditEventAuthentication, "web.passkey.login.failure", business.AuditResultFailure)))
		grant := e.grant(t, 30)
		rec := e.do(e.mspAdminToken, http.MethodDelete, "/api/v1/tenants/"+sweepMSP+"/access-grants/"+grant.ID, nil)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		require.NoError(t, e.server.auditManager.Flush(ctx))
		e.assertAllChallenged(t, token)

		t.Run("audit carve-out with reduced detail", func(t *testing.T) {
			rec := e.do(token, http.MethodGet, "/api/v1/audit/entries", nil)
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			var resp auditResp
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
			var failedLogin, metaLog bool
			for _, entry := range resp.Data.Entries {
				assert.NotEqual(t, sweepClient, entry.TenantID, "no client-tenant entry")
				if entry.TenantID != sweepMSP {
					continue
				}
				switch {
				case entry.Action == "web.passkey.login.failure":
					failedLogin = true
				case strings.HasPrefix(entry.Action, "tenant.crossing_"):
					metaLog = true
				default:
					t.Errorf("MSP entry %q is outside the carve-out", entry.Action)
				}
				assert.ElementsMatch(t, []string{"actor", "action", "result", "time", "source_address"}, mapKeys(entry.Details))
				assert.Empty(t, entry.ResourceID)
				assert.Empty(t, entry.ResourceType)
				assert.Nil(t, entry.Changes)
			}
			assert.True(t, failedLogin, "the MSP admin failed login is visible")
			assert.True(t, metaLog, "the crossing meta-log is visible")
		})

		t.Run("anonymized dashboard aggregates", func(t *testing.T) {
			for _, path := range []string{"/api/v1/reports/dashboard/overview", "/api/v1/reports/dashboard/trends"} {
				rec := e.do(token, http.MethodGet, path, nil)
				require.Equal(t, http.StatusOK, rec.Code, "%s: %s", path, rec.Body.String())
				var body struct {
					Fleet *FleetAnonymizedMetrics `json:"anonymized_fleet"`
				}
				require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
				require.NotNil(t, body.Fleet, path)
				assert.Equal(t, 1, body.Fleet.Online, path)
				for _, leaked := range []string{e.clientSteward, sweepClient, sweepMarker} {
					assert.NotContains(t, rec.Body.String(), leaked, path)
				}
			}
		})

		t.Run("platform health and monitoring", func(t *testing.T) {
			for _, path := range []string{"/api/v1/health", "/api/v1/monitoring/health"} {
				rec := e.do(token, http.MethodGet, path, nil)
				assert.Equal(t, http.StatusOK, rec.Code, "%s: %s", path, rec.Body.String())
				assert.NotContains(t, rec.Header().Get("WWW-Authenticate"), "tenant-crossing")
				assert.NotContains(t, rec.Body.String(), e.clientSteward)
			}
		})

		// TODO(#4579): billing views are not built yet. Extend this scenario with the
		// billing-label and billing-aggregation assertions (a root operator reads the
		// anonymized billing aggregate, never a client's per-tenant billing detail) when
		// the billing label and aggregation stories of epic #4579 land.
	})

	t.Run("7 access ends at expiry without a revoke", func(t *testing.T) {
		for _, kind := range []business.TenantCrossingKind{business.TenantCrossingKindGrant, business.TenantCrossingKindBreakGlass} {
			t.Run(string(kind), func(t *testing.T) {
				e := newE2ERootRead(t)
				const operator = "e2e-root-expiry"
				token := e.rootSession(t, operator)
				now := time.Now().UTC()
				crossing := &business.TenantCrossing{
					ID: "e2e-expiring-" + string(kind), TenantID: sweepMSP, Kind: kind,
					GrantedBy: "e2e-msp-admin", CreatedAt: now, ExpiresAt: now.Add(3 * time.Second),
				}
				if kind == business.TenantCrossingKindBreakGlass {
					crossing.PrincipalID, crossing.GrantedBy = operator, operator
					crossing.ReasonCategory = business.TenantCrossingReasonAccountRecovery
					crossing.Justification = "expiry fixture without a revoke"
				}
				require.NoError(t, e.server.tenantCrossingStore.CreateTenantCrossing(context.Background(), crossing))

				rec := e.do(token, http.MethodGet, "/api/v1/jobs/job-"+sweepMarker, nil)
				require.Equal(t, http.StatusOK, rec.Code, "the crossing admits before expiry: %s", rec.Body.String())

				require.Eventually(t, func() bool {
					return e.do(token, http.MethodGet, "/api/v1/jobs/job-"+sweepMarker, nil).Code == http.StatusUnauthorized
				}, 15*time.Second, 250*time.Millisecond, "access must end at expiry")
				e.assertAllChallenged(t, token)

				stored, err := e.server.tenantCrossingStore.GetTenantCrossing(context.Background(), crossing.ID)
				require.NoError(t, err)
				assert.Nil(t, stored.RevokedAt, "the crossing expired on its own; nothing revoked it")
			})
		}
	})
}
