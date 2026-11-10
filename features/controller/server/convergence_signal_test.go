// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// convergenceHarness is a Server with a real health collector whose convergence
// signals were registered by the real signal source, over a real command store.
type convergenceHarness struct {
	srv   *Server
	store business.CommandStore
	obs   *convergenceObserver
}

func newConvergenceHarness(t *testing.T, store business.CommandStore) *convergenceHarness {
	t.Helper()
	srv := newSignalSourceTestServer(t)
	require.NoError(t, registerConvergenceSignals(srv))
	t.Cleanup(func() { convergenceObservers.Delete(srv) })
	o, ok := convergenceObservers.Load(srv)
	require.True(t, ok, "the signal source must register an observer for the server")
	obs := o.(*convergenceObserver)
	obs.store = func() business.CommandStore { return store }
	return &convergenceHarness{srv: srv, store: store, obs: obs}
}

func newRealCommandStore(t *testing.T) business.CommandStore {
	t.Helper()
	store := pkgtesting.SetupTestStorage(t).GetCommandStore()
	require.NotNil(t, store)
	return store
}

func (h *convergenceHarness) scrape(t *testing.T) string {
	t.Helper()
	var sb strings.Builder
	require.NoError(t, h.srv.healthCollector.Signals().WriteText(&sb))
	return sb.String()
}

// metricValue returns the value of an unlabelled series, 0 when it is absent.
func metricValue(t *testing.T, text, series string) float64 {
	t.Helper()
	for _, line := range strings.Split(text, "\n") {
		if rest, ok := strings.CutPrefix(line, series+" "); ok {
			v, err := strconv.ParseFloat(strings.TrimSpace(rest), 64)
			require.NoError(t, err)
			return v
		}
	}
	return 0
}

func (h *convergenceHarness) observations(t *testing.T) float64 {
	return metricValue(t, h.scrape(t), convergenceSecondsMetric+"_count")
}

func (h *convergenceHarness) failures(t *testing.T) float64 {
	return metricValue(t, h.scrape(t), applyFailedMetric)
}

func (h *convergenceHarness) seedDelivery(t *testing.T, id, cmdType string, payload map[string]interface{}, issuedAt time.Time) {
	t.Helper()
	require.NoError(t, h.store.CreateCommandRecord(context.Background(), &business.CommandRecord{
		ID:        id,
		Type:      cmdType,
		StewardID: "steward-1",
		TenantID:  "tenant-a",
		Payload:   payload,
		IssuedAt:  issuedAt,
	}))
}

func pushPayload() map[string]interface{} {
	return map[string]interface{}{"push_id": "push-1", "config_id": "cfg-1", "version": "free text"}
}

func completionEvent(commandID string, typ controlplaneTypes.EventType) *controlplaneTypes.Event {
	return &controlplaneTypes.Event{
		ID:        "evt-" + commandID,
		Type:      typ,
		StewardID: "steward-1",
		CommandID: commandID,
		// Steward-supplied, must not feed the measurement.
		Timestamp: time.Unix(0, 0),
		Details:   map[string]interface{}{"config_version": "v7"},
	}
}

func (h *convergenceHarness) deliver(t *testing.T, ev *controlplaneTypes.Event) {
	t.Helper()
	require.NoError(t, h.srv.handleEventFromProvider(context.Background(), ev))
}

func TestConvergenceObservedOnce(t *testing.T) {
	h := newConvergenceHarness(t, newRealCommandStore(t))
	h.obs.now = func() time.Time { return time.Date(2026, 1, 1, 0, 0, 10, 0, time.UTC) }
	h.seedDelivery(t, "push-1-steward-1", "sync_config", pushPayload(), time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))

	ev := completionEvent("push-1-steward-1", controlplaneTypes.EventCommandCompleted)
	h.deliver(t, ev)
	h.deliver(t, ev) // duplicate / outbox redelivery

	text := h.scrape(t)
	assert.Equal(t, 1.0, metricValue(t, text, convergenceSecondsMetric+"_count"))
	assert.Equal(t, 10.0, metricValue(t, text, convergenceSecondsMetric+"_sum"),
		"latency is receipt time minus IssuedAt, not the steward timestamp")

	rec, err := h.store.GetCommandRecord(context.Background(), "push-1-steward-1")
	require.NoError(t, err)
	assert.Equal(t, business.CommandStatusCompleted, rec.Status)

	// A failed event after completion is also a non-transition.
	h.deliver(t, completionEvent("push-1-steward-1", controlplaneTypes.EventCommandFailed))
	assert.Equal(t, 0.0, h.failures(t))
	assert.Equal(t, 1.0, h.observations(t))
}

func TestConvergenceFailedApplyCounted(t *testing.T) {
	h := newConvergenceHarness(t, newRealCommandStore(t))
	h.seedDelivery(t, "push-1-steward-1", "sync_config", pushPayload(), time.Now().Add(-time.Second))

	ev := completionEvent("push-1-steward-1", controlplaneTypes.EventCommandFailed)
	h.deliver(t, ev)
	h.deliver(t, ev)

	assert.Equal(t, 1.0, h.failures(t))
	assert.Equal(t, 0.0, h.observations(t), "a failed apply is not a convergence observation")
	rec, err := h.store.GetCommandRecord(context.Background(), "push-1-steward-1")
	require.NoError(t, err)
	assert.Equal(t, business.CommandStatusFailed, rec.Status)
	assert.Equal(t, convergenceFailedMessage, rec.ErrorMessage)
}

func TestConvergenceUnknownCommandIgnored(t *testing.T) {
	h := newConvergenceHarness(t, newRealCommandStore(t))
	h.seedDelivery(t, "other-cmd", "execute_script", pushPayload(), time.Now())
	h.seedDelivery(t, "sync-no-push", "sync_config", map[string]interface{}{"config_id": "cfg-1"}, time.Now())

	for _, id := range []string{"other-cmd", "sync-no-push", "no-such-command", ""} {
		h.deliver(t, completionEvent(id, controlplaneTypes.EventCommandCompleted))
		h.deliver(t, completionEvent(id, controlplaneTypes.EventCommandFailed))
	}

	assert.Equal(t, 0.0, h.observations(t))
	assert.Equal(t, 0.0, h.failures(t))
	for _, id := range []string{"other-cmd", "sync-no-push"} {
		rec, err := h.store.GetCommandRecord(context.Background(), id)
		require.NoError(t, err)
		assert.Equal(t, business.CommandStatusPending, rec.Status, "an ignored command must not be marked terminal")
	}
}

func TestConvergenceSurvivesRestart(t *testing.T) {
	store := newRealCommandStore(t)
	first := newConvergenceHarness(t, store)
	first.seedDelivery(t, "push-1-steward-1", "sync_config", pushPayload(), time.Now().Add(-time.Second))
	ev := completionEvent("push-1-steward-1", controlplaneTypes.EventCommandCompleted)
	first.deliver(t, ev)
	require.Equal(t, 1.0, first.observations(t))

	// A new server and observer (empty in-memory state) over the same store.
	second := newConvergenceHarness(t, store)
	second.deliver(t, ev)
	assert.Equal(t, 0.0, second.observations(t), "a redelivery after restart must not re-observe")
	assert.Equal(t, 0.0, second.failures(t))
}

// failingCommandStore wraps a real store and fails the selected calls.
type failingCommandStore struct {
	business.CommandStore
	failGet    bool
	failUpdate bool
}

func (f *failingCommandStore) GetCommandRecord(ctx context.Context, id string) (*business.CommandRecord, error) {
	if f.failGet {
		return nil, errors.New("store unavailable\nforged log line")
	}
	return f.CommandStore.GetCommandRecord(ctx, id)
}

func (f *failingCommandStore) UpdateCommandStatus(ctx context.Context, id string, s business.CommandStatus, r map[string]interface{}, msg string) error {
	if f.failUpdate {
		return errors.New("store write failed")
	}
	return f.CommandStore.UpdateCommandStatus(ctx, id, s, r, msg)
}

func TestConvergenceStoreErrorDoesNotFailEvent(t *testing.T) {
	store := &failingCommandStore{CommandStore: newRealCommandStore(t), failGet: true}
	h := newConvergenceHarness(t, store)
	h.seedDelivery(t, "push-1-steward-1", "sync_config", pushPayload(), time.Now().Add(-time.Second))
	ev := completionEvent("push-1-steward-1", controlplaneTypes.EventCommandCompleted)

	h.deliver(t, ev) // read error: handler still returns nil
	assert.Equal(t, 0.0, h.observations(t))

	store.failGet, store.failUpdate = false, true
	h.deliver(t, ev) // write error: nothing recorded, handler still returns nil
	h.deliver(t, completionEvent("push-1-steward-1", controlplaneTypes.EventCommandFailed))
	assert.Equal(t, 0.0, h.observations(t))
	assert.Equal(t, 0.0, h.failures(t))

	// The row stayed non-terminal, so the next delivery, with the store healthy, records once.
	store.failUpdate = false
	h.deliver(t, ev)
	h.deliver(t, ev)
	assert.Equal(t, 1.0, h.observations(t))
}

func TestConvergenceNegativeLatencyClamped(t *testing.T) {
	h := newConvergenceHarness(t, newRealCommandStore(t))
	issued := time.Now().Add(time.Hour)
	h.seedDelivery(t, "push-1-steward-1", "sync_config", pushPayload(), issued)

	h.deliver(t, completionEvent("push-1-steward-1", controlplaneTypes.EventCommandCompleted))

	text := h.scrape(t)
	assert.Equal(t, 1.0, metricValue(t, text, convergenceSecondsMetric+"_count"))
	assert.Equal(t, 0.0, metricValue(t, text, convergenceSecondsMetric+"_sum"))
}

func TestConvergenceSignalsCarryNoLabels(t *testing.T) {
	h := newConvergenceHarness(t, newRealCommandStore(t))
	h.seedDelivery(t, "push-1-steward-1", "sync_config", pushPayload(), time.Now().Add(-time.Second))
	h.deliver(t, completionEvent("push-1-steward-1", controlplaneTypes.EventCommandCompleted))
	h.seedDelivery(t, "push-2-steward-1", "sync_config", pushPayload(), time.Now().Add(-time.Second))
	h.deliver(t, completionEvent("push-2-steward-1", controlplaneTypes.EventCommandFailed))

	for _, line := range strings.Split(h.scrape(t), "\n") {
		if strings.HasPrefix(line, "cfgms_config_") && !strings.HasPrefix(line, "#") {
			if !strings.Contains(line, "_bucket{") {
				assert.NotContains(t, line, "{", "series %q must have no labels", line)
			}
			for _, id := range []string{"steward-1", "tenant-a", "push-1", "cfg-1"} {
				assert.NotContains(t, line, id)
			}
		}
	}
}

func TestObserveConvergenceWithoutObserverIsNoop(t *testing.T) {
	srv := &Server{logger: logging.NewNoopLogger()}
	require.NoError(t, srv.handleEventFromProvider(context.Background(),
		completionEvent("push-1-steward-1", controlplaneTypes.EventCommandCompleted)))

	// An observer with no command store (deployment without one) is also a no-op.
	h := newConvergenceHarness(t, nil)
	h.obs.store = func() business.CommandStore { return nil }
	h.deliver(t, completionEvent("push-1-steward-1", controlplaneTypes.EventCommandCompleted))
	assert.Equal(t, 0.0, h.observations(t))
}

func TestConvergenceSourceRegistersOnCollector(t *testing.T) {
	srv := newSignalSourceTestServer(t)
	require.Equal(t, 0, srv.runSignalSources())
	t.Cleanup(func() { convergenceObservers.Delete(srv) })
	_, ok := convergenceObservers.Load(srv)
	assert.True(t, ok, "the init-registered source must register the convergence observer")

	var sb strings.Builder
	require.NoError(t, srv.healthCollector.Signals().WriteText(&sb))
	assert.Contains(t, sb.String(), convergenceSecondsMetric)
	assert.Contains(t, sb.String(), applyFailedMetric)

	// A second registration on the same collector collides and is reported.
	assert.Error(t, registerConvergenceSignals(srv))
}

// pushWiringServer builds a real controller Server (command store on a
// t.TempDir() SQLite file) with a seeded key allowed to push configs.
func pushWiringServer(t *testing.T, tenant string) (*Server, string) {
	t.Helper()
	keyBytes := make([]byte, 16)
	_, err := rand.Read(keyBytes)
	require.NoError(t, err)
	key := "convergence-" + hex.EncodeToString(keyBytes)
	t.Setenv("CFGMS_SECRETS_REPO_PATH", t.TempDir())
	t.Setenv("CFGMS_SEED_TEST_API_KEYS", "1")
	t.Setenv("CFGMS_API_KEY_EAST", key)

	srv := servernewCharNewServer(t, servernewCharConfig(t), logging.NewNoopLogger())
	require.NotNil(t, srv.httpServer)
	require.NotNil(t, srv.storageManager.GetCommandStore())
	mustCreateTenantForWiring(t, srv.storageManager.GetTenantStore(), tenant, tenant, "")
	return srv, key
}

func TestConvergenceObservedFromRealPushCommandID(t *testing.T) {
	const tenant = "test-tenant-integration"
	srv, key := pushWiringServer(t, tenant)
	registerResumeStewardInTenant(t, srv, "convergence-dna-1", tenant)
	require.Equal(t, 0, srv.runSignalSources())
	t.Cleanup(func() { convergenceObservers.Delete(srv) })

	body, err := json.Marshal(map[string]interface{}{
		"selector":  "all",
		"config_id": "cfg-convergence",
		"version":   "free-text-version",
		"tenant_id": tenant,
	})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/push", bytes.NewReader(body))
	req.Header.Set("X-API-Key", key)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.httpServer.GetRouter().ServeHTTP(rec, req)
	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())

	var resp struct {
		PushID     string `json:"push_id"`
		Deliveries []struct {
			StewardID string `json:"steward_id"`
			CommandID string `json:"command_id"`
		} `json:"deliveries"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.Len(t, resp.Deliveries, 1, "the registered steward must be targeted: %s", rec.Body.String())
	commandID := resp.Deliveries[0].CommandID
	require.Equal(t, fmt.Sprintf("%s-%s", resp.PushID, resp.Deliveries[0].StewardID), commandID)

	// What a steward publishes after its sync handler ran: the config service
	// version (never the pushed free text) and the command id.
	srv.obsCompletion(t, commandID, resp.Deliveries[0].StewardID)

	var sb strings.Builder
	require.NoError(t, srv.healthCollector.Signals().WriteText(&sb))
	text := sb.String()
	assert.Equal(t, 1.0, metricValue(t, text, convergenceSecondsMetric+"_count"))
	assert.GreaterOrEqual(t, metricValue(t, text, convergenceSecondsMetric+"_sum"), 0.0)

	// An outbox redelivery of the same completion records nothing more.
	srv.obsCompletion(t, commandID, resp.Deliveries[0].StewardID)
	sb.Reset()
	require.NoError(t, srv.healthCollector.Signals().WriteText(&sb))
	assert.Equal(t, 1.0, metricValue(t, sb.String(), convergenceSecondsMetric+"_count"))
}

func (s *Server) obsCompletion(t *testing.T, commandID, stewardID string) {
	t.Helper()
	require.NoError(t, s.handleEventFromProvider(context.Background(), &controlplaneTypes.Event{
		ID:        "evt-" + commandID,
		Type:      controlplaneTypes.EventCommandCompleted,
		StewardID: stewardID,
		CommandID: commandID,
		Timestamp: time.Now(),
		Details:   map[string]interface{}{"config_version": "v1"},
	}))
}
