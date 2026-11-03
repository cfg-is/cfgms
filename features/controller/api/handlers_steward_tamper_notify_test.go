// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/cfgis/cfgms/features/controller/heartbeat"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/controlplane/providers/memory"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

var tamperReasons = []controlplaneTypes.HealthReason{
	{Component: "integrity", Code: controlplaneTypes.ReasonCodeTamperDataDir, Message: "data dir changed"},
}

// tamperFixture is a server with a shared steward store and one registered steward.
type tamperFixture struct {
	server *Server
	store  business.StewardStore
}

func newTamperFixture(t *testing.T) *tamperFixture {
	t.Helper()
	server := setupTestServer(t)
	seedTenantTree(t, server)
	return &tamperFixture{server: server, store: wireSharedStewardStore(t, server)}
}

// steward registers a node-local steward and its durable record in status.
func (f *tamperFixture) steward(t *testing.T, host, tenantID string, status business.StewardStatus) string {
	t.Helper()
	id := registerTestStewardWithDNA(t, f.server, map[string]string{"hostname": host, "os": "linux"}, tenantID)
	seedSteward(t, f.store, &business.StewardRecord{ID: id, TenantID: tenantID, Status: status})
	return id
}

func (f *tamperFixture) status(t *testing.T, id string) business.StewardStatus {
	t.Helper()
	rec, err := f.store.GetSteward(context.Background(), id)
	require.NoError(t, err)
	return rec.Status
}

// alarmEvents waits for in-flight announcements, flushes the audit manager and
// returns the steward_tamper_alarm events of one tenant for one steward.
func alarmEvents(t *testing.T, server *Server, tenantID, stewardID string) []*business.AuditEntry {
	t.Helper()
	var out []*business.AuditEntry
	for _, e := range auditEntries(t, server, tenantID) {
		if e.Action == auditActionStewardTamperAlarm && e.ResourceID == stewardID {
			out = append(out, e)
		}
	}
	return out
}

func listSteward(t *testing.T, server *Server, key, query, id string) (StewardInfo, bool) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards"+query, nil)
	req.Header.Set("X-API-Key", key)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var resp struct {
		Data []StewardInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	for _, s := range resp.Data {
		if s.ID == id {
			return s, true
		}
	}
	return StewardInfo{}, false
}

// listDirect calls the unfiltered list handler as a caller with no tenant filter.
func listDirect(t *testing.T, server *Server, query string) map[string]StewardInfo {
	t.Helper()
	req := withTenant(httptest.NewRequest(http.MethodGet, "/api/v1/stewards"+query, nil), "")
	rec := httptest.NewRecorder()
	server.handleListStewards(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var resp struct {
		Data []StewardInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	out := make(map[string]StewardInfo, len(resp.Data))
	for _, s := range resp.Data {
		out[s.ID] = s
	}
	return out
}

func TestHandleStewardTamperAlarm_TransitionsAuditsAndNotifiesOnce(t *testing.T) {
	f := newTamperFixture(t)
	smtp := newEmailTestSMTPServer(t)
	attachEmail(t, f.server, smtp)
	setContacts(t, f.server, "admin@acme-corp.example")
	id := f.steward(t, "tamper-1", "msp-a", business.StewardStatusActive)

	f.server.HandleStewardTamperAlarm(context.Background(), id, tamperReasons)
	f.server.HandleStewardTamperAlarm(context.Background(), id, tamperReasons)

	assert.Equal(t, business.StewardStatusTampered, f.status(t, id))
	info, ok := f.server.controllerService.GetStewardInfo(id)
	require.True(t, ok)
	assert.Equal(t, "tampered", info.Status, "node-local shadow must follow the durable status")

	events := alarmEvents(t, f.server, "msp-a", id)
	require.Len(t, events, 1, "a repeated alarm must not be audited or announced again")
	assert.Equal(t, "sent", events[0].Details["notification"])
	assert.Equal(t, id, events[0].Details["steward_id"])
	assert.Equal(t, []string{controlplaneTypes.ReasonCodeTamperDataDir}, auditStringSlice(events[0].Details["codes"]))
	msgs := smtp.Messages()
	require.Len(t, msgs, 1)
	assert.Contains(t, msgs[0], controlplaneTypes.ReasonCodeTamperDataDir)
}

func TestHandleStewardTamperAlarm_NotConfigured_StillTransitionsAndAudits(t *testing.T) {
	f := newTamperFixture(t)
	require.Nil(t, f.server.EmailNotifier())
	id := f.steward(t, "tamper-nc", "msp-a", business.StewardStatusActive)

	f.server.HandleStewardTamperAlarm(context.Background(), id, tamperReasons)

	assert.Equal(t, business.StewardStatusTampered, f.status(t, id))
	events := alarmEvents(t, f.server, "msp-a", id)
	require.Len(t, events, 1)
	assert.Equal(t, "not_configured", events[0].Details["notification"])
}

func TestHandleStewardTamperAlarm_NoContacts(t *testing.T) {
	f := newTamperFixture(t)
	attachEmail(t, f.server, newEmailTestSMTPServer(t))
	id := f.steward(t, "tamper-nc2", "msp-a", business.StewardStatusActive)

	f.server.HandleStewardTamperAlarm(context.Background(), id, tamperReasons)

	events := alarmEvents(t, f.server, "msp-a", id)
	require.Len(t, events, 1)
	assert.Equal(t, "no_contacts", events[0].Details["notification"])
}

func TestHandleStewardTamperAlarm_SourceStates(t *testing.T) {
	f := newTamperFixture(t)
	for _, tc := range []struct {
		status business.StewardStatus
		want   business.StewardStatus
	}{
		{business.StewardStatusRegistered, business.StewardStatusTampered},
		{business.StewardStatusActive, business.StewardStatusTampered},
		{business.StewardStatusLost, business.StewardStatusTampered},
		{business.StewardStatusArchived, business.StewardStatusTampered},
		{business.StewardStatusRevoked, business.StewardStatusRevoked},
		{business.StewardStatusDeregistered, business.StewardStatusDeregistered},
		{business.StewardStatusDormant, business.StewardStatusDormant},
		{business.StewardStatus("quarantined"), business.StewardStatus("quarantined")},
	} {
		t.Run(string(tc.status), func(t *testing.T) {
			id := f.steward(t, "src-"+string(tc.status), "msp-a", tc.status)
			f.server.HandleStewardTamperAlarm(context.Background(), id, tamperReasons)
			assert.Equal(t, tc.want, f.status(t, id))
			wantEvents := 0
			if tc.want == business.StewardStatusTampered {
				wantEvents = 1
			}
			assert.Len(t, alarmEvents(t, f.server, "msp-a", id), wantEvents)
		})
	}
}

func TestHandleStewardTamperAlarm_UnknownTamperCodeDoesNotTransition(t *testing.T) {
	f := newTamperFixture(t)
	id := f.steward(t, "tamper-unknown", "msp-a", business.StewardStatusActive)

	f.server.HandleStewardTamperAlarm(context.Background(), id, []controlplaneTypes.HealthReason{
		{Code: "tamper.invented"}, {Code: "tamper"}, {Code: "TAMPER.DATA_DIR"}, {Code: "tamper.data_dir "}, {Code: "disk.low"},
	})

	assert.Equal(t, business.StewardStatusActive, f.status(t, id))
	assert.Empty(t, alarmEvents(t, f.server, "msp-a", id))
}

func TestHandleStewardTamperAlarm_AlarmRestoreRealarmInsideCooldown(t *testing.T) {
	f := newTamperFixture(t)
	smtp := newEmailTestSMTPServer(t)
	attachEmail(t, f.server, smtp)
	setContacts(t, f.server, "admin@acme-corp.example")
	id := f.steward(t, "tamper-flap", "msp-a", business.StewardStatusActive)

	f.server.HandleStewardTamperAlarm(context.Background(), id, tamperReasons)
	// An operator restore (not built yet) is a write back to a source state.
	require.NoError(t, f.store.UpdateStewardStatus(context.Background(), id, business.StewardStatusActive))
	f.server.HandleStewardTamperAlarm(context.Background(), id, tamperReasons)

	assert.Equal(t, business.StewardStatusTampered, f.status(t, id))
	events := alarmEvents(t, f.server, "msp-a", id)
	require.Len(t, events, 2, "every transition is audited")
	outcomes := []interface{}{events[0].Details["notification"], events[1].Details["notification"]}
	assert.ElementsMatch(t, []interface{}{"sent", "cooldown"}, outcomes)
	assert.Len(t, smtp.Messages(), 1, "the second alarm is inside the cooldown")
}

func TestHandleStewardTamperAlarm_AuditWriteFailureDoesNotBlockTransition(t *testing.T) {
	f := newTamperFixture(t)
	id := f.steward(t, "tamper-audit-fail", "msp-a", business.StewardStatusActive)
	// A stopped audit manager refuses every write.
	require.NoError(t, f.server.auditManager.Stop(context.Background()))
	require.Error(t, f.server.auditManager.RecordEvent(context.Background(),
		audit.NewEventBuilder().Tenant("msp-a").Type(business.AuditEventSecurityEvent).Action("probe").
			User("u", business.AuditUserTypeSystem).Resource("steward", id, "").Result(business.AuditResultSuccess).Severity(business.AuditSeverityLow)),
		"precondition: audit writes fail")

	f.server.HandleStewardTamperAlarm(context.Background(), id, tamperReasons)
	f.server.crossingNotifyWG.Wait()

	assert.Equal(t, business.StewardStatusTampered, f.status(t, id))
}

func TestHandleStewardTamperAlarm_HealthyReasonsDoNothing(t *testing.T) {
	f := newTamperFixture(t)
	id := f.steward(t, "tamper-healthy", "msp-a", business.StewardStatusActive)
	f.server.HandleStewardTamperAlarm(context.Background(), id, nil)
	f.server.HandleStewardTamperAlarm(context.Background(), id, []controlplaneTypes.HealthReason{{Code: "disk.low"}})
	assert.Equal(t, business.StewardStatusActive, f.status(t, id))
}

// TestStewardTamperAlarm_RealControlPlaneHeartbeat sends heartbeats from a steward
// client over a real (in-process) control plane to a real heartbeat service and
// asserts the whole chain: status, audit event, notification.
func TestStewardTamperAlarm_RealControlPlaneHeartbeat(t *testing.T) {
	f := newTamperFixture(t)
	smtp := newEmailTestSMTPServer(t)
	attachEmail(t, f.server, smtp)
	setContacts(t, f.server, "admin@acme-corp.example")
	id := f.steward(t, "tamper-e2e", "msp-a", business.StewardStatusActive)

	ctx := context.Background()
	bus := memory.NewBus()
	cpServer := memory.New(memory.ModeServer)
	require.NoError(t, cpServer.Initialize(ctx, map[string]interface{}{"bus": bus}))
	require.NoError(t, cpServer.Start(ctx))
	t.Cleanup(func() { _ = cpServer.Stop(context.Background()) })
	cpClient := memory.New(memory.ModeClient)
	require.NoError(t, cpClient.Initialize(ctx, map[string]interface{}{"bus": bus, "steward_id": id, "tenant_id": "msp-a"}))
	require.NoError(t, cpClient.Start(ctx))
	t.Cleanup(func() { _ = cpClient.Stop(context.Background()) })

	hb, err := heartbeat.New(&heartbeat.Config{
		ControlPlane: cpServer,
		OnHeartbeatReceived: func(stewardID string, reasons []controlplaneTypes.HealthReason) {
			f.server.HandleStewardTamperAlarm(context.Background(), stewardID, reasons)
		},
		Logger: logging.NewNoopLogger(),
	})
	require.NoError(t, err)
	require.NoError(t, hb.Start(ctx))
	t.Cleanup(func() { _ = hb.Stop(context.Background()) })

	require.NoError(t, cpClient.SendHeartbeat(ctx, &controlplaneTypes.Heartbeat{
		StewardID: id, Status: controlplaneTypes.StatusError, Timestamp: time.Now(), Reasons: tamperReasons,
	}))
	require.Eventually(t, func() bool { return f.status(t, id) == business.StewardStatusTampered },
		5*time.Second, 20*time.Millisecond, "a tamper-code heartbeat must move the steward to tampered")

	// A healthy heartbeat afterwards does not clear it.
	require.NoError(t, cpClient.SendHeartbeat(ctx, &controlplaneTypes.Heartbeat{
		StewardID: id, Status: controlplaneTypes.StatusHealthy, Timestamp: time.Now(),
	}))
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, business.StewardStatusTampered, f.status(t, id))

	events := alarmEvents(t, f.server, "msp-a", id)
	require.Len(t, events, 1)
	assert.Len(t, smtp.Messages(), 1)
}

func TestTamperedSteward_RESTVisibility(t *testing.T) {
	f := newTamperFixture(t)
	key := NewEphemeralTestKey(t, f.server, []string{"steward:read", "steward:list"}, "msp-a", 5*time.Minute)

	tampered := f.steward(t, "rest-tampered", "msp-a", business.StewardStatusActive)
	hidden := registerTestStewardWithDNA(t, f.server, map[string]string{"hostname": "rest-hidden", "os": "linux"}, "msp-a")
	seedSteward(t, f.store, &business.StewardRecord{ID: hidden, TenantID: "msp-a", Status: business.StewardStatusActive, Hidden: true})
	quarantined := f.steward(t, "rest-quarantined", "msp-a", business.StewardStatusActive)
	healthy := f.steward(t, "rest-healthy", "msp-a", business.StewardStatusActive)

	require.NoError(t, f.server.controllerService.SetStewardHidden(hidden, true))
	require.NoError(t, f.server.controllerService.UpdateStewardStatus(quarantined, "quarantined"))
	require.NoError(t, f.store.UpdateStewardStatus(context.Background(), quarantined, business.StewardStatus("quarantined")))

	f.server.HandleStewardTamperAlarm(context.Background(), tampered, tamperReasons)
	f.server.HandleStewardTamperAlarm(context.Background(), hidden, tamperReasons)
	// A healthy heartbeat replaces the live reasons and reconnects the steward.
	f.server.controllerService.RecordHealthReasons(tampered, nil)
	f.server.controllerService.EnsureSteward(tampered, "msp-a", "active")
	_ = alarmEvents(t, f.server, "msp-a", tampered) // wait + flush

	t.Run("default list keeps tampered, hidden tampered and drops quarantined", func(t *testing.T) {
		got, ok := listSteward(t, f.server, key, "", tampered)
		require.True(t, ok)
		assert.Equal(t, "tampered", got.Status, "a reconnect must not turn tampered back into active")
		assert.Equal(t, []string{controlplaneTypes.ReasonCodeTamperDataDir}, got.TamperCodes,
			"codes of the last alarm stay after a healthy heartbeat replaced the live reasons")
		assert.Empty(t, got.HealthReasons)

		got, ok = listSteward(t, f.server, key, "", hidden)
		require.True(t, ok, "a hidden steward that becomes tampered still appears in the default list")
		assert.Equal(t, "tampered", got.Status)

		// The unfiltered (fleet-wide) list is where the quarantined default applies.
		all := listDirect(t, f.server, "")
		require.Contains(t, all, tampered)
		assert.Equal(t, "tampered", all[tampered].Status)
		assert.Contains(t, all, hidden, "hidden tampered steward appears in the fleet-wide default list")
		assert.NotContains(t, all, quarantined, "quarantined stays hidden by default")
		assert.Contains(t, listDirect(t, f.server, "?include_quarantined=true"), quarantined)

		got, ok = listSteward(t, f.server, key, "", healthy)
		require.True(t, ok)
		assert.Empty(t, got.TamperCodes)
	})

	t.Run("status=tampered filter", func(t *testing.T) {
		got, ok := listSteward(t, f.server, key, "?status=tampered", tampered)
		require.True(t, ok)
		assert.Equal(t, "tampered", got.Status)
		_, ok = listSteward(t, f.server, key, "?status=tampered", healthy)
		assert.False(t, ok)
	})

	t.Run("GET by id", func(t *testing.T) {
		code, got := getStewardJSON(t, f.server, key, tampered)
		require.Equal(t, http.StatusOK, code)
		assert.Equal(t, "tampered", got.Status)
		assert.Equal(t, []string{controlplaneTypes.ReasonCodeTamperDataDir}, got.TamperCodes)
	})

	t.Run("a caller without scope on the tenant gets no codes", func(t *testing.T) {
		other := NewEphemeralTestKey(t, f.server, []string{"steward:read", "steward:list"}, "msp-b", 5*time.Minute)
		_, ok := listSteward(t, f.server, other, "", tampered)
		assert.False(t, ok)
		code, got := getStewardJSON(t, f.server, other, tampered)
		assert.Equal(t, http.StatusNotFound, code)
		assert.Empty(t, got.TamperCodes)
	})
}

func TestTamperedSteward_CodesReadBackAreCappedAndSanitized(t *testing.T) {
	f := newTamperFixture(t)
	key := NewEphemeralTestKey(t, f.server, []string{"steward:read", "steward:list"}, "msp-a", 5*time.Minute)
	id := f.steward(t, "rest-caps", "msp-a", business.StewardStatusTampered)

	codes := []string{strings.Repeat("z", 3000), "tamper.data_dir\nforged line\x1b[2J"}
	for i := 0; i < 40; i++ {
		codes = append(codes, "tamper.extra")
	}
	require.NoError(t, f.server.auditManager.RecordEvent(context.Background(),
		audit.NewEventBuilder().Tenant("msp-a").Type(business.AuditEventSecurityEvent).Action(auditActionStewardTamperAlarm).
			User(id, business.AuditUserTypeSystem).Resource("steward", id, "").Result(business.AuditResultSuccess).
			Severity(business.AuditSeverityCritical).Detail("codes", codes)))
	_ = alarmEvents(t, f.server, "msp-a", id)

	code, got := getStewardJSON(t, f.server, key, id)
	require.Equal(t, http.StatusOK, code)
	require.LessOrEqual(t, len(got.TamperCodes), controlplaneTypes.MaxHealthReasons)
	for _, c := range got.TamperCodes {
		assert.LessOrEqual(t, len(c), controlplaneTypes.MaxHealthReasonCode+len("[truncated]"))
		assert.NotContains(t, c, "\n")
		assert.NotContains(t, c, "\x1b")
	}
	assert.Len(t, got.TamperCodes, controlplaneTypes.MaxHealthReasons)
}

func TestTamperCodes_AuditEventOfAnotherTenantIsIgnored(t *testing.T) {
	f := newTamperFixture(t)
	id := f.steward(t, "rest-xtenant", "msp-a", business.StewardStatusTampered)
	require.NoError(t, f.server.auditManager.RecordEvent(context.Background(),
		audit.NewEventBuilder().Tenant("msp-b").Type(business.AuditEventSecurityEvent).Action(auditActionStewardTamperAlarm).
			User(id, business.AuditUserTypeSystem).Resource("steward", id, "").Result(business.AuditResultSuccess).
			Severity(business.AuditSeverityCritical).Detail("codes", []string{"tamper.ca_mismatch"})))
	require.NoError(t, f.server.auditManager.Flush(context.Background()))

	assert.Empty(t, f.server.tamperCodesFromAudit(context.Background(), map[string]string{id: "msp-a"})[id])
}

func TestHandleFleetHealth_TamperedListedFirst(t *testing.T) {
	now := time.Now()
	server := setupTestServer(t)
	server.fleetQuery = fleet.NewMemoryQuery(&fleetTestStewardProvider{
		stewards: []fleet.StewardData{
			{ID: "a-ok", TenantID: "tenant-a", Status: "active", LastHeartbeat: now},
			{ID: "z-tampered", TenantID: "tenant-a", Status: "tampered", LastHeartbeat: now},
			{ID: "m-hidden-tampered", TenantID: "tenant-a", Status: "tampered", LastHeartbeat: now, Hidden: true},
		},
	})
	server.recordStewardTamperAudit(context.Background(), "z-tampered", "tenant-a", []string{"tamper.ca_mismatch"}, "sent")
	require.NoError(t, server.auditManager.Flush(context.Background()))

	rec := getFleetHealth(server)
	require.Equal(t, http.StatusOK, rec.Code)
	raw := rec.Body.String()
	var resp struct {
		Data FleetHealthResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, 2, resp.Data.Tampered)
	assert.Equal(t, 1, resp.Data.Healthy)
	require.Len(t, resp.Data.TamperedStewards, 2)
	assert.Equal(t, "m-hidden-tampered", resp.Data.TamperedStewards[0].ID)
	assert.Equal(t, []string{"tamper.ca_mismatch"}, resp.Data.TamperedStewards[1].TamperCodes)
	assert.Less(t, strings.Index(raw, `"tampered"`), strings.Index(raw, `"healthy"`), "tampered comes first in the payload")
}

func TestTamperedStewardStillCountsTowardBilling(t *testing.T) {
	assert.True(t, stewardCountsTowardBilling(business.StewardStatusTampered))
	var m billingMetrics
	m.addSteward(&business.StewardRecord{Status: business.StewardStatusTampered})
	assert.Equal(t, 1, m.EndpointsOnline)
}
