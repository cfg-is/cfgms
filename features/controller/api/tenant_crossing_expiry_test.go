// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

const (
	expiredGrantAction      = "tenant.crossing_grant_expired"
	expiredBreakGlassAction = "tenant.crossing_break_glass_expired"
)

// expirySweepServer is a server with a root, the MSP "msp-a" and a real crossing store.
func expirySweepServer(t *testing.T) *Server {
	t.Helper()
	return breakGlassServer(t)
}

func seedExpiryCrossing(t *testing.T, server *Server, id string, kind business.TenantCrossingKind, expiresIn time.Duration, mutate func(*business.TenantCrossing)) *business.TenantCrossing {
	t.Helper()
	now := time.Now().UTC()
	c := &business.TenantCrossing{
		ID: id, TenantID: "msp-a", Kind: kind, GrantedBy: "admin",
		CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(expiresIn),
	}
	if kind == business.TenantCrossingKindBreakGlass {
		c.PrincipalID = "root-op"
		c.GrantedBy = "root-op"
		c.Justification = "j"
		c.ReasonCategory = business.TenantCrossingReasonSecurityIncident
	}
	if mutate != nil {
		mutate(c)
	}
	require.NoError(t, server.tenantCrossingStore.CreateTenantCrossing(context.Background(), c))
	return c
}

func expiredEntries(t *testing.T, server *Server, scope string) []*business.AuditEntry {
	t.Helper()
	var out []*business.AuditEntry
	for _, e := range auditEntries(t, server, scope) {
		if e.Action == expiredGrantAction || e.Action == expiredBreakGlassAction {
			out = append(out, e)
		}
	}
	return out
}

func TestSweepExpiredTenantCrossings_WritesBothScopes(t *testing.T) {
	server := expirySweepServer(t)
	grant := seedExpiryCrossing(t, server, "exp-grant", business.TenantCrossingKindGrant, -time.Minute, nil)
	bg := seedExpiryCrossing(t, server, "exp-bg", business.TenantCrossingKindBreakGlass, -time.Minute, nil)

	server.sweepExpiredTenantCrossings(context.Background())

	for _, scope := range []string{"msp-a", testRootTenantID} {
		entries := expiredEntries(t, server, scope)
		require.Len(t, entries, 2, "scope %s", scope)

		g := findAuditEntryByAction(t, entries, expiredGrantAction)
		assert.Equal(t, grant.ID, g.ResourceID)
		assert.Equal(t, business.AuditSeverityHigh, g.Severity)
		assert.Equal(t, business.AuditUserTypeSystem, g.UserType)
		assert.Equal(t, "grant", g.Details["crossing_kind"])

		b := findAuditEntryByAction(t, entries, expiredBreakGlassAction)
		assert.Equal(t, bg.ID, b.ResourceID)
		assert.Equal(t, business.AuditSeverityCritical, b.Severity)
		assert.Equal(t, business.AuditUserTypeSystem, b.UserType)
		assert.Equal(t, "security_incident", b.Details["reason_category"])
		assert.Equal(t, "approved", b.Details["approval_state"])
	}
}

func TestSweepExpiredTenantCrossings_Idempotent(t *testing.T) {
	server := expirySweepServer(t)
	seedExpiryCrossing(t, server, "exp-grant", business.TenantCrossingKindGrant, -time.Minute, nil)

	server.sweepExpiredTenantCrossings(context.Background())
	require.Len(t, expiredEntries(t, server, "msp-a"), 1)

	server.sweepExpiredTenantCrossings(context.Background())

	// A restarted controller is a second Server over the same store and audit trail.
	restarted := setupTestServer(t)
	restarted.tenantCrossingStore = server.tenantCrossingStore
	restarted.tenantManager = server.tenantManager
	restarted.auditManager = server.auditManager
	restarted.sweepExpiredTenantCrossings(context.Background())

	assert.Len(t, expiredEntries(t, server, "msp-a"), 1)
	assert.Len(t, expiredEntries(t, server, testRootTenantID), 1)
}

func TestSweepExpiredTenantCrossings_TwoServersSameStore(t *testing.T) {
	server := expirySweepServer(t)
	other := setupTestServer(t)
	other.tenantCrossingStore = server.tenantCrossingStore
	other.tenantManager = server.tenantManager
	other.auditManager = server.auditManager

	const n = 5
	for i := 0; i < n; i++ {
		seedExpiryCrossing(t, server, fmt.Sprintf("exp-%d", i), business.TenantCrossingKindGrant, -time.Minute, nil)
	}

	var wg sync.WaitGroup
	start := make(chan struct{})
	for _, s := range []*Server{server, other} {
		wg.Add(1)
		go func(s *Server) {
			defer wg.Done()
			<-start
			s.sweepExpiredTenantCrossings(context.Background())
		}(s)
	}
	close(start)
	wg.Wait()

	for _, scope := range []string{"msp-a", testRootTenantID} {
		perCrossing := map[string]int{}
		for _, e := range expiredEntries(t, server, scope) {
			perCrossing[e.ResourceID]++
		}
		require.Len(t, perCrossing, n, "scope %s", scope)
		for id, count := range perCrossing {
			assert.Equal(t, 1, count, "crossing %s in scope %s", id, scope)
		}
	}
}

func TestSweepExpiredTenantCrossings_SkipsRevokedAndUnexpired(t *testing.T) {
	server := expirySweepServer(t)
	seedExpiryCrossing(t, server, "live", business.TenantCrossingKindGrant, time.Hour, nil)
	revoked := seedExpiryCrossing(t, server, "revoked", business.TenantCrossingKindGrant, -time.Minute, nil)
	require.NoError(t, server.tenantCrossingStore.RevokeTenantCrossing(context.Background(), revoked.ID))

	server.sweepExpiredTenantCrossings(context.Background())

	assert.Empty(t, expiredEntries(t, server, "msp-a"))
	assert.Empty(t, expiredEntries(t, server, testRootTenantID))
}

func TestSweepExpiredTenantCrossings_NoRootClaimsNothing(t *testing.T) {
	server := wireCrossingStore(t, setupTestServer(t))
	server.tenantManager = nil
	require.Empty(t, server.rootTenantID(context.Background()), "precondition: no root resolvable")
	c := seedExpiryCrossing(t, server, "exp-grant", business.TenantCrossingKindGrant, -time.Minute, nil)

	server.sweepExpiredTenantCrossings(context.Background())

	assert.Empty(t, expiredEntries(t, server, "msp-a"))
	unrecorded, err := server.tenantCrossingStore.ListUnrecordedExpiredTenantCrossings(context.Background(), time.Now().UTC())
	require.NoError(t, err)
	ids := map[string]bool{}
	for _, u := range unrecorded {
		ids[u.ID] = true
	}
	assert.True(t, ids[c.ID], "the crossing stays unmarked so a later tick retries")
}

func TestSweepExpiredTenantCrossings_PendingBreakGlass(t *testing.T) {
	server := expirySweepServer(t)
	seedExpiryCrossing(t, server, "exp-pending", business.TenantCrossingKindBreakGlass, -time.Minute, func(c *business.TenantCrossing) {
		c.ApprovalState = business.TenantCrossingApprovalPending
	})

	server.sweepExpiredTenantCrossings(context.Background())

	entry := findAuditEntryByAction(t, expiredEntries(t, server, "msp-a"), expiredBreakGlassAction)
	assert.Equal(t, "pending", entry.Details["approval_state"])
}
