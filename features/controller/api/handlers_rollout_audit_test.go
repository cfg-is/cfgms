// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	controllerconfig "github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/version"
)

const rolloutAuditVersion = "v0.5.21"

// rolloutAuditSteward builds a steward in the named ring.
func rolloutAuditSteward(id, tenantID, ring, runningVersion string) fleet.StewardData {
	attrs := map[string]string{"deployment_ring": ring}
	if runningVersion != "" {
		attrs["steward.version"] = runningVersion
	}
	return fleet.StewardData{ID: id, TenantID: tenantID, Status: "online", DNAAttributes: attrs}
}

// ringHealthFailingFleet is a real in-memory fleet query that fails every
// per-ring search (the ring health query) and answers every other search. Rollout
// start reads the fleet to check approval, so a nil fleet query now refuses the
// start; this makes only the ring health query fail.
type ringHealthFailingFleet struct{ fleet.FleetQuery }

func (f ringHealthFailingFleet) Search(ctx context.Context, filter fleet.Filter) ([]fleet.StewardResult, error) {
	if _, ring := filter.DNAAttributes["deployment_ring"]; ring {
		return nil, errors.New("ring health query unavailable")
	}
	return f.FleetQuery.Search(ctx, filter)
}

// runAuditedRollout starts a rollout as tenantID's principal and waits for its terminal
// state, returning the rollout id.
func runAuditedRollout(t *testing.T, server *Server, store *testRolloutStore, tenantID string) string {
	t.Helper()
	rec := doStartRollout(server, tenantID, rolloutAuditVersion)
	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())
	id := parseStartRolloutID(t, rec)
	waitForRolloutStatus(t, store, id, 2*time.Second)
	return id
}

// markerRows returns the system-tenant marker rows with the given action.
func markerRows(t *testing.T, mgr *audit.Manager, action string) []*business.AuditEntry {
	t.Helper()
	return queryRolloutAudit(t, mgr, audit.SystemTenantID, action)
}

func requireRevisionAndController(t *testing.T, e *business.AuditEntry, revision string) {
	t.Helper()
	assert.Equal(t, revision, e.Details["revision"])
	assert.Equal(t, version.Revision(), e.Details["controller_revision"])
}

func TestRolloutCompletedAudited(t *testing.T) {
	const tenantID = "tenant-a"
	stewards := []fleet.StewardData{
		rolloutAuditSteward("s1", tenantID, "pre-release", rolloutAuditVersion),
		rolloutAuditSteward("s2", tenantID, "stable", rolloutAuditVersion),
	}
	server, store, _ := setupRolloutServer(t, tenantID, stewards)
	mgr := attachRolloutAuditManager(t, server)

	id := runAuditedRollout(t, server, store, tenantID)

	entries := queryRolloutAudit(t, mgr, tenantID, "rollout_completed")
	require.Len(t, entries, 1)
	e := entries[0]
	assert.Equal(t, id, e.ResourceID)
	assert.Equal(t, "api-key:"+tenantID, e.UserID, "attributes the principal that started the rollout")
	assert.Equal(t, business.AuditResultSuccess, e.Result)
	assert.EqualValues(t, 2, e.Details["rings_completed"])
	assert.Equal(t, rolloutAuditVersion, e.Details["target_version"])
	requireRevisionAndController(t, e, rolloutAuditVersion)
	assert.Empty(t, queryRolloutAudit(t, mgr, tenantID, "rollout_auto_halted"))
}

func TestRolloutAutoHaltAuditedOnFailureRate(t *testing.T) {
	const tenantID = "tenant-a"
	stewards := []fleet.StewardData{
		rolloutAuditSteward("steward-1", tenantID, "pre-release", ""),
		rolloutAuditSteward("steward-2", tenantID, "pre-release", ""),
	}
	server, store, upgrades := setupRolloutServer(t, tenantID, stewards)
	mgr := attachRolloutAuditManager(t, server)
	seedFailedUpgradeRecords(t, upgrades, tenantID, rolloutAuditVersion, "steward-1", "steward-2")

	id := runAuditedRollout(t, server, store, tenantID)

	entries := queryRolloutAudit(t, mgr, tenantID, "rollout_auto_halted")
	require.Len(t, entries, 1)
	e := entries[0]
	assert.Equal(t, id, e.ResourceID)
	assert.Equal(t, "api-key:"+tenantID, e.UserID)
	assert.Equal(t, "failure_rate_exceeded", e.Details["halt_reason_class"])
	assert.Equal(t, "pre-release", e.Details["ring"])
	assert.EqualValues(t, 2, e.Details["failed"])
	assert.EqualValues(t, 0, e.Details["on_version"])
	assert.EqualValues(t, 0, e.Details["pending"])
	requireRevisionAndController(t, e, rolloutAuditVersion)
	assert.Empty(t, queryRolloutAudit(t, mgr, tenantID, "rollout_completed"))
}

func TestRolloutAutoHaltAuditedOnHealthQueryFailure(t *testing.T) {
	const tenantID = "tenant-a"
	server, store, _ := setupRolloutServer(t, tenantID, nil)
	server.fleetQuery = ringHealthFailingFleet{server.fleetQuery} // every ring health query now fails
	mgr := attachRolloutAuditManager(t, server)

	id := runAuditedRollout(t, server, store, tenantID)

	entries := queryRolloutAudit(t, mgr, tenantID, "rollout_auto_halted")
	require.Len(t, entries, 1)
	e := entries[0]
	assert.Equal(t, id, e.ResourceID)
	assert.Equal(t, "ring_health_query_failed", e.Details["halt_reason_class"])
	assert.Equal(t, "pre-release", e.Details["ring"])
	assert.EqualValues(t, 0, e.Details["rings_completed"])
	requireRevisionAndController(t, e, rolloutAuditVersion)
	for _, m := range markerRows(t, mgr, "marker_rollout_auto_halted") {
		assert.NotContains(t, m.Details, "error", "marker rows carry no failure text")
	}
}

func TestUpgradeDispatchAndRollbackAudited(t *testing.T) {
	const tenantID = "tenant-a"
	stewards := []fleet.StewardData{{ID: "steward-1", TenantID: tenantID, Status: "online"}}
	server, upgrades := setupUpgradeServer(t, tenantID, stewards)
	mgr := attachRolloutAuditManager(t, server)
	publishApprovedBinary(t, server, tenantID, "v0.5.12", "linux", "amd64")
	publishApprovedBinary(t, server, tenantID, "v0.5.11", "linux", "amd64")

	rec := doDispatchUpgrade(server, tenantID, "id:steward-1", "v0.5.12", "linux", "amd64")
	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())
	var resp struct {
		Data dispatchUpgradeResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	upgradeID := resp.Data.UpgradeID
	require.NoError(t, upgrades.UpdateUpgradeStatus(context.Background(), upgradeID, business.UpgradeStatusCommitted, ""))

	dispatched := queryRolloutAudit(t, mgr, tenantID, "steward_upgrade_dispatched")
	require.Len(t, dispatched, 1)
	d := dispatched[0]
	assert.Equal(t, upgradeID, d.ResourceID)
	assert.Equal(t, "api-key:"+tenantID, d.UserID)
	assert.Equal(t, "v0.5.12", d.Details["version"])
	assert.EqualValues(t, 1, d.Details["steward_count"])
	requireRevisionAndController(t, d, "v0.5.12")

	rb := doUpgradeRollback(server, tenantID, upgradeID, "v0.5.11")
	require.Equal(t, http.StatusAccepted, rb.Code, rb.Body.String())
	var rbResp struct {
		Data dispatchUpgradeResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rb.Body.Bytes(), &rbResp))

	rolledBack := queryRolloutAudit(t, mgr, tenantID, "steward_upgrade_rolled_back")
	require.Len(t, rolledBack, 1)
	r := rolledBack[0]
	assert.Equal(t, rbResp.Data.UpgradeID, r.ResourceID)
	assert.Equal(t, "api-key:"+tenantID, r.UserID)
	assert.Equal(t, "v0.5.11", r.Details["version"])
	assert.EqualValues(t, 1, r.Details["steward_count"])
	requireRevisionAndController(t, r, "v0.5.11")

	assert.Len(t, markerRows(t, mgr, "marker_upgrade_dispatched"), 1)
	assert.Len(t, markerRows(t, mgr, "marker_upgrade_rolled_back"), 1)
}

func TestRolloutAuditCarriesRevisionAndPrincipal(t *testing.T) {
	const tenantID = "tenant-a"
	server, store, _ := setupRolloutServer(t, tenantID, nil)
	server.cfg.DeploymentRings.Rings[0].Soak = 30_000_000_000 // 30s, so the halt lands mid-soak
	mgr := attachRolloutAuditManager(t, server)

	rec := doStartRollout(server, tenantID, rolloutAuditVersion)
	require.Equal(t, http.StatusAccepted, rec.Code)
	id := parseStartRolloutID(t, rec)
	select {
	case <-store.soakC:
	case <-time.After(2 * time.Second):
		t.Fatal("rollout goroutine did not reach soak within 2s")
	}
	require.Equal(t, http.StatusOK, doHaltRollout(server, tenantID, id).Code)

	for _, action := range []string{"rollout_started", "rollout_halted"} {
		entries := queryRolloutAudit(t, mgr, tenantID, action)
		require.Len(t, entries, 1, action)
		assert.Equal(t, "api-key:"+tenantID, entries[0].UserID, action)
		assert.Equal(t, "api-key:"+tenantID, entries[0].Details["principal"], action)
		requireRevisionAndController(t, entries[0], rolloutAuditVersion)
	}
}

func TestTenantScopedRolloutEmitsSystemMarker(t *testing.T) {
	const tenantID = "tenant-a"
	stewards := []fleet.StewardData{
		rolloutAuditSteward("s1", tenantID, "pre-release", rolloutAuditVersion),
		rolloutAuditSteward("s2", tenantID, "stable", rolloutAuditVersion),
	}
	server, store, _ := setupRolloutServer(t, tenantID, stewards)
	mgr := attachRolloutAuditManager(t, server)

	id := runAuditedRollout(t, server, store, tenantID)

	for _, action := range []string{"marker_rollout_started", "marker_rollout_completed"} {
		rows := markerRows(t, mgr, action)
		require.Len(t, rows, 1, action)
		m := rows[0]
		assert.Equal(t, audit.SystemTenantID, m.TenantID)
		assert.Equal(t, id, m.ResourceID)
		assert.Equal(t, rolloutAuditVersion, m.Details["revision"])
		assert.Equal(t, "api-key:"+tenantID, m.Details["principal"])
		assert.Len(t, m.Details, 2, "a marker carries only revision and principal: %v", m.Details)
		assert.NotContains(t, m.ResourceID, tenantID)
	}
	// The tenant audit row stays under the tenant and is not visible under the system tenant.
	assert.Len(t, queryRolloutAudit(t, mgr, tenantID, "rollout_started"), 1)
	assert.Empty(t, queryRolloutAudit(t, mgr, audit.SystemTenantID, "rollout_started"))
}

func TestUnscopedRolloutAlsoEmitsMarker(t *testing.T) {
	server, store, _ := setupRolloutServer(t, "", nil)
	mgr := attachRolloutAuditManager(t, server)

	// An mTLS admin with no tenant starts an unscoped rollout.
	b, err := json.Marshal(startRolloutRequest{TargetVersion: rolloutAuditVersion})
	require.NoError(t, err)
	req := withAdminPrincipal(httptest.NewRequest(http.MethodPost, "/api/v1/rollout", bytes.NewReader(b)))
	rec := httptest.NewRecorder()
	server.handleStartRollout(rec, req)
	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())
	id := parseStartRolloutID(t, rec)
	waitForRolloutStatus(t, store, id, 2*time.Second)

	// An unscoped rollout is audited under the system tenant, and still gets its marker row.
	assert.Len(t, queryRolloutAudit(t, mgr, audit.SystemTenantID, "rollout_started"), 1)
	rows := markerRows(t, mgr, "marker_rollout_started")
	require.Len(t, rows, 1)
	assert.Equal(t, id, rows[0].ResourceID)
	assert.Equal(t, rolloutAuditVersion, rows[0].Details["revision"])
	assert.Equal(t, "mtls-admin:cn", rows[0].Details["principal"])
}

func TestMarkersListRolloutAndUpgradeEvents(t *testing.T) {
	const tenantID = "tenant-a"
	stewards := []fleet.StewardData{{ID: "steward-1", TenantID: tenantID, Status: "online"}}
	server, upgrades := setupUpgradeServer(t, tenantID, stewards)
	mgr := attachRolloutAuditManager(t, server)

	rolloutStore := newTestRolloutStore()
	server.rolloutStore = rolloutStore
	server.cfg.DeploymentRings = &controllerconfig.DeploymentRingConfig{
		Rings:        []controllerconfig.RingSpec{{Name: "pre-release"}},
		FallbackRing: "pre-release",
	}
	// With a failing ring health query the rollout halts automatically.
	fleetQuery := server.fleetQuery
	server.fleetQuery = ringHealthFailingFleet{fleetQuery}
	server.onRolloutTerminal = func(id string) { rolloutStore.terminalC <- id }
	publishApprovedBinary(t, server, tenantID, "v0.5.12", "linux", "amd64")
	publishApprovedBinary(t, server, tenantID, "v0.5.11", "linux", "amd64")

	rolloutID := runAuditedRollout(t, server, rolloutStore, tenantID)
	server.fleetQuery = fleetQuery

	rec := doDispatchUpgrade(server, tenantID, "id:steward-1", "v0.5.12", "linux", "amd64")
	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())
	var resp struct {
		Data dispatchUpgradeResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.NoError(t, upgrades.UpdateUpgradeStatus(context.Background(), resp.Data.UpgradeID, business.UpgradeStatusCommitted, ""))
	require.Equal(t, http.StatusAccepted, doUpgradeRollback(server, tenantID, resp.Data.UpgradeID, "v0.5.11").Code)
	require.NoError(t, mgr.Flush(context.Background()))

	req := httptest.NewRequest(http.MethodGet, markersPath, nil)
	w := httptest.NewRecorder()
	server.handleListMarkers(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var list struct {
		Data struct {
			Markers []markerResponse `json:"markers"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &list))

	kinds := map[string]markerResponse{}
	for _, m := range list.Data.Markers {
		kinds[m.Kind] = m
		assert.NotEmpty(t, m.Principal)
		assert.NotContains(t, m.Resource, tenantID)
	}
	for _, kind := range []string{"rollout_started", "rollout_auto_halted", "upgrade_dispatched", "upgrade_rolled_back"} {
		assert.Contains(t, kinds, kind)
	}
	assert.Equal(t, rolloutID, kinds["rollout_started"].Resource)
	assert.Equal(t, rolloutAuditVersion, kinds["rollout_started"].Revision)
	assert.Equal(t, "v0.5.12", kinds["upgrade_dispatched"].Revision)
	assert.Equal(t, "v0.5.11", kinds["upgrade_rolled_back"].Revision)
}

// TestRolloutAuditFailureDoesNotBlockRollout verifies a failing audit manager cannot fail
// the rollout: a stopped manager rejects every write, and the rollout still completes.
func TestRolloutAuditFailureDoesNotBlockRollout(t *testing.T) {
	const tenantID = "tenant-a"
	stewards := []fleet.StewardData{
		rolloutAuditSteward("s1", tenantID, "pre-release", rolloutAuditVersion),
		rolloutAuditSteward("s2", tenantID, "stable", rolloutAuditVersion),
	}
	server, store, _ := setupRolloutServer(t, tenantID, stewards)
	mgr := attachRolloutAuditManager(t, server)
	require.NoError(t, mgr.Stop(context.Background()))

	id := runAuditedRollout(t, server, store, tenantID)

	rec, err := store.GetRollout(context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, business.RolloutStatusCompleted, rec.Status)
}

// TestRolloutWithoutAuditManagerIsNoop verifies the emitters are no-ops without an audit manager.
func TestRolloutWithoutAuditManagerIsNoop(t *testing.T) {
	server := newMinimalServerForRollout(t)
	server.logger = logging.NewNoopLogger()
	assert.NotPanics(t, func() {
		server.emitSystemRolloutEvent(context.Background(), &business.RolloutRecord{ID: "r1"},
			auditRolloutCompleted, markerKindRolloutCompleted, business.AuditSeverityHigh, nil)
	})
}
