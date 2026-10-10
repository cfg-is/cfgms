// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// crossingTestScope is a TenantReadScope driven by a fixed set of readable
// tenants. A tenant outside the set needs a crossing, except those in denied.
// unrestricted models a caller the crossing boundary does not apply to.
type crossingTestScope struct {
	unrestricted bool
	readable     []string
	denied       []string
	aggregate    any
}

func (c crossingTestScope) Unrestricted() bool { return c.unrestricted }

func (c crossingTestScope) Decide(tenantID string) ReadDecision {
	if c.unrestricted {
		return ReadAllowed
	}
	for _, id := range c.readable {
		if id == tenantID {
			return ReadAllowed
		}
	}
	for _, id := range c.denied {
		if id == tenantID {
			return ReadDenied
		}
	}
	return ReadNeedsCrossing
}

func (c crossingTestScope) ReadableTenants() []string { return c.readable }
func (c crossingTestScope) AnonymizedFleet() any      { return c.aggregate }
func (c crossingTestScope) WriteCrossingChallenge(w http.ResponseWriter, _ string) {
	w.Header().Set("WWW-Authenticate", `CFGMS-StepUp realm="cfgms", required="tenant-crossing"`)
	w.WriteHeader(http.StatusUnauthorized)
}

func withScope(h *Handler, sc TenantReadScope) *Handler {
	h.SetTenantReadScope(func(*http.Request, string) TenantReadScope { return sc })
	return h
}

// Issue #4720: a root caller subject to the crossing boundary.
func TestRootReports_TenantSelection(t *testing.T) {
	h := newReportsStack(t).handler
	scope := crossingTestScope{readable: []string{"root", "tenant-granted"}}

	t.Run("no tenant named covers only readable tenants", func(t *testing.T) {
		ids, err := h.parseTenantIDs(request("GET", "/", "", nil), scope)
		require.NoError(t, err)
		assert.Equal(t, []string{"root", "tenant-granted"}, ids)
	})
	t.Run("naming a client tenant without a crossing answers the challenge", func(t *testing.T) {
		_, err := h.parseTenantIDs(request("GET", "/?tenant_id=tenant-b", "", nil), scope)
		var crossing *crossingRequiredError
		require.ErrorAs(t, err, &crossing)
		assert.Equal(t, "tenant-b", crossing.tenant)
	})
	t.Run("naming a readable tenant passes", func(t *testing.T) {
		ids, err := h.parseTenantIDs(request("GET", "/?tenant_id=tenant-granted", "", nil), scope)
		require.NoError(t, err)
		assert.Equal(t, []string{"tenant-granted"}, ids)
	})
	t.Run("one unreadable tenant among several refuses the request", func(t *testing.T) {
		_, err := h.parseTenantIDs(request("GET", "/?tenant_id=tenant-granted&tenant_id=tenant-b", "", nil), scope)
		require.Error(t, err)
	})
	t.Run("a tenant outside the hierarchy is not found", func(t *testing.T) {
		sc := crossingTestScope{readable: []string{"root"}, denied: []string{"stranger"}}
		_, err := h.parseTenantIDs(request("GET", "/?tenant_id=stranger", "", nil), sc)
		require.ErrorIs(t, err, errTenantOutsideScope)
	})
	t.Run("a tenant-scoped caller is unchanged", func(t *testing.T) {
		ids, err := h.parseTenantIDs(request("GET", "/?tenant_id=tenant-b", "tenant-a", nil), scope)
		require.NoError(t, err)
		assert.Equal(t, []string{"tenant-a"}, ids)
	})
}

func TestRootReports_NilDecisionFailsClosed(t *testing.T) {
	stack := newReportsStack(t)
	stack.addDevice(t, "steward-b1", "tenant-b")
	h := stack.handler
	h.readScope = nil

	t.Run("no tenant named covers only the root tenant", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.getComplianceStatus(rec, request("GET", "/reports/compliance/status", "", nil))
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	})
	t.Run("a client tenant answers the crossing challenge", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.getComplianceStatus(rec, request("GET", "/reports/compliance/status?tenant_id=tenant-b", "", nil))
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Contains(t, rec.Header().Get("WWW-Authenticate"), "tenant-crossing")
	})
	t.Run("a client device answers the crossing challenge", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.getDriftSummary(rec, request("GET", "/reports/drift/summary?device_id=steward-b1", "", nil))
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})
	t.Run("generate with a client tenant answers the challenge", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.generateReport(rec, request("POST", "/reports/generate", "",
			generateBody(t, []string{"tenant-b"}, nil)))
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})
}

func TestRootReports_DeviceSelection(t *testing.T) {
	stack := newReportsStack(t)
	stack.addDevice(t, "steward-root", "root")
	stack.addDevice(t, "steward-b1", "tenant-b")
	stack.addDevice(t, "steward-granted", "tenant-granted")
	withScope(stack.handler, crossingTestScope{readable: []string{"root", "tenant-granted"}, denied: []string{}})
	h := stack.handler

	for _, rt := range deviceScopedRoutes {
		t.Run(rt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			rt.handler(h)(rec, request("GET", rt.path+"?device_id=steward-b1", "", nil))
			assert.Equal(t, http.StatusUnauthorized, rec.Code, "client device needs a crossing")
			assert.NotContains(t, rec.Body.String(), "steward-b1")
			assert.NotContains(t, rec.Body.String(), "tenant-b")

			rec = httptest.NewRecorder()
			rt.handler(h)(rec, request("GET", rt.path+"?device_id=steward-granted", "", nil))
			assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		})
	}

	t.Run("an unknown device is not found", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.getDriftSummary(rec, request("GET", "/reports/drift/summary?device_id=nope", "", nil))
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
	t.Run("generate names a client device", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.generateReport(rec, request("POST", "/reports/generate", "",
			generateBody(t, nil, []string{"steward-b1"})))
		assert.Equal(t, http.StatusUnauthorized, rec.Code)

		rec = httptest.NewRecorder()
		h.generateReport(rec, request("POST", "/reports/generate", "",
			generateBody(t, nil, []string{"steward-granted"})))
		assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	})
}

func TestRootReports_DashboardAnonymizedFleet(t *testing.T) {
	aggregate := map[string]any{"online": 3, "offline": 1}
	stack := newReportsStack(t)
	withScope(stack.handler, crossingTestScope{readable: []string{"root"}, aggregate: aggregate})

	for name, handler := range map[string]http.HandlerFunc{
		"overview": stack.handler.getDashboardOverview,
		"trends":   stack.handler.getDashboardTrends,
	} {
		t.Run(name+" carries the anonymized aggregate", func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler(rec, request("GET", "/reports/dashboard/"+name, "", nil))
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			var body map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
			assert.JSONEq(t, `{"online":3,"offline":1}`, string(body["anonymized_fleet"]))
		})
	}

	t.Run("a caller outside the boundary gets no aggregate", func(t *testing.T) {
		withScope(stack.handler, crossingTestScope{unrestricted: true, aggregate: aggregate})
		rec := httptest.NewRecorder()
		stack.handler.getDashboardOverview(rec, request("GET", "/reports/dashboard/overview?tenant_id=tenant-b", "", nil))
		require.Equal(t, http.StatusOK, rec.Code)
		assert.NotContains(t, rec.Body.String(), "anonymized_fleet")
	})
	t.Run("a tenant-scoped caller gets no aggregate", func(t *testing.T) {
		withScope(stack.handler, crossingTestScope{readable: []string{"root"}, aggregate: aggregate})
		rec := httptest.NewRecorder()
		stack.handler.getDashboardOverview(rec, request("GET", "/reports/dashboard/overview", "tenant-a", nil))
		require.Equal(t, http.StatusOK, rec.Code)
		assert.NotContains(t, rec.Body.String(), "anonymized_fleet")
	})
}
