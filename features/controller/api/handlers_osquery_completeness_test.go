// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/features/controller/fleet"
	stewardosquery "github.com/cfgis/cfgms/features/controller/osquery"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// Answer-completeness tests for POST /api/v1/osquery/query (Epic #6439): the
// response carries a summary and a per-steward outcome.

// routedOsqueryDispatcher is a real dispatcher that routes each steward ID to a
// fixed behaviour: offline stewards go to the real controller OsqueryHandler
// (which has no open streams and so returns the real ErrStewardNotConnected),
// failing stewards return their configured error, every other steward answers
// with rows. It holds no mutable state, so concurrent fan-out calls are safe.
type routedOsqueryDispatcher struct {
	offline map[string]bool
	failing map[string]error
	real    *stewardosquery.OsqueryHandler
	rows    []*transportpb.OsqueryRow
}

func newRoutedOsqueryDispatcher(offline []string, failing map[string]error) *routedOsqueryDispatcher {
	off := make(map[string]bool, len(offline))
	for _, id := range offline {
		off[id] = true
	}
	return &routedOsqueryDispatcher{
		offline: off,
		failing: failing,
		real:    stewardosquery.NewOsqueryHandler(nil, ""),
		rows:    []*transportpb.OsqueryRow{{Columns: map[string]string{"hostname": "h"}}},
	}
}

func (d *routedOsqueryDispatcher) QuerySteward(ctx context.Context, stewardID, catalogID string, params map[string]string) ([]*transportpb.OsqueryRow, error) {
	if d.offline[stewardID] {
		return d.real.QuerySteward(ctx, stewardID, catalogID, params)
	}
	if err, ok := d.failing[stewardID]; ok {
		return nil, err
	}
	return d.rows, nil
}

// completenessResponse is the decoded data of a query response, both typed and raw.
type completenessResponse struct {
	typed osqueryQueryResponse
	raw   map[string]interface{}
}

// rawResult returns the raw JSON object of the result for stewardID.
func (c completenessResponse) rawResult(t *testing.T, stewardID string) map[string]interface{} {
	t.Helper()
	results, ok := c.raw["results"].([]interface{})
	require.True(t, ok, "results must be a JSON array")
	for _, r := range results {
		m, ok := r.(map[string]interface{})
		require.True(t, ok)
		if m["steward_id"] == stewardID {
			return m
		}
	}
	t.Fatalf("no result for steward %q", stewardID)
	return nil
}

// result returns the typed result for stewardID.
func (c completenessResponse) result(t *testing.T, stewardID string) osqueryStewardResult {
	t.Helper()
	for _, r := range c.typed.Results {
		if r.StewardID == stewardID {
			return r
		}
	}
	t.Fatalf("no result for steward %q", stewardID)
	return osqueryStewardResult{}
}

// runCompletenessQuery posts a host_info query against the given fleet and
// dispatcher and decodes the 200 response through APIResponse.
func runCompletenessQuery(t *testing.T, disp stewardOsqueryDispatcher, stewards ...fleet.StewardData) (*Server, completenessResponse) {
	t.Helper()
	server := setupTestServer(t)
	server.SetOsqueryDispatcher(disp)
	server.fleetQuery = seededFleetQuery(stewards...)

	rec := postOsqueryQuery(t, server, osqueryQueryRequest{CatalogID: "host_info", Selector: "all"})
	require.Equal(t, http.StatusOK, rec.Code)

	var resp APIResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	raw, err := json.Marshal(resp.Data)
	require.NoError(t, err)

	var out completenessResponse
	require.NoError(t, json.Unmarshal(raw, &out.typed))
	require.NoError(t, json.Unmarshal(raw, &out.raw))
	return server, out
}

func onlineSteward(id string, lastHeartbeat time.Time) fleet.StewardData {
	return fleet.StewardData{ID: id, TenantID: "root", Status: "online", LastHeartbeat: lastHeartbeat}
}

func offlineSteward(id string, lastHeartbeat time.Time) fleet.StewardData {
	return fleet.StewardData{ID: id, TenantID: "root", Status: "offline", LastHeartbeat: lastHeartbeat}
}

// assertSummaryInvariant checks matched == len(results) and that the outcome
// counts add up to matched and agree with the per-result outcomes.
func assertSummaryInvariant(t *testing.T, resp osqueryQueryResponse) {
	t.Helper()
	s := resp.Summary
	assert.Equal(t, len(resp.Results), s.Matched, "matched must equal the number of results")
	assert.Equal(t, s.Matched, s.Answered+s.NotConnected+s.Failed, "answered + not_connected + failed must equal matched")
	counts := map[string]int{}
	for _, r := range resp.Results {
		counts[r.Outcome]++
	}
	assert.Equal(t, counts[osqueryResultAnswered], s.Answered)
	assert.Equal(t, counts[osqueryResultNotConnected], s.NotConnected)
	assert.Equal(t, counts[osqueryResultFailed], s.Failed)
}

func TestOsqueryCompleteness_OfflineVsFailing(t *testing.T) {
	hb := time.Date(2026, 11, 20, 8, 30, 0, 0, time.UTC)
	disp := newRoutedOsqueryDispatcher([]string{"s-offline"},
		map[string]error{"s-failing": errors.New("osquery execution failed")})

	_, resp := runCompletenessQuery(t, disp,
		offlineSteward("s-offline", hb), onlineSteward("s-failing", hb), onlineSteward("s-ok", hb))

	off := resp.result(t, "s-offline")
	assert.Equal(t, osqueryResultNotConnected, off.Outcome)
	assert.Equal(t, stewardosquery.ErrStewardNotConnected.Error(), off.Error)
	assert.Empty(t, off.Rows)

	fail := resp.result(t, "s-failing")
	assert.Equal(t, osqueryResultFailed, fail.Outcome)
	assert.Equal(t, "osquery execution failed", fail.Error)
	assert.Empty(t, fail.Rows)

	ok := resp.result(t, "s-ok")
	assert.Equal(t, osqueryResultAnswered, ok.Outcome)
	assert.Empty(t, ok.Error)
	require.Len(t, ok.Rows, 1)
	assert.Equal(t, "h", ok.Rows[0]["hostname"])
}

func TestOsqueryCompleteness_SentinelMatchedByIdentityNotText(t *testing.T) {
	hb := time.Date(2026, 11, 20, 8, 30, 0, 0, time.UTC)
	disp := newRoutedOsqueryDispatcher(nil, map[string]error{
		"s-wrapped": fmt.Errorf("node x: %w", stewardosquery.ErrStewardNotConnected),
		"s-text":    errors.New("steward not connected to osquery stream"),
	})

	_, resp := runCompletenessQuery(t, disp, onlineSteward("s-wrapped", hb), onlineSteward("s-text", hb))

	wrapped := resp.result(t, "s-wrapped")
	assert.Equal(t, osqueryResultNotConnected, wrapped.Outcome, "a wrapped sentinel is still not_connected")
	assert.NotEmpty(t, wrapped.Error)

	text := resp.result(t, "s-text")
	assert.Equal(t, osqueryResultFailed, text.Outcome, "matching error text without the sentinel is failed")
	assert.Equal(t, "steward not connected to osquery stream", text.Error)
}

func TestOsqueryCompleteness_LastSeenOnlyOnNotConnected(t *testing.T) {
	hb := time.Date(2026, 11, 20, 8, 30, 0, 0, time.UTC)
	otherHB := time.Date(2026, 11, 22, 9, 0, 0, 0, time.UTC)
	disp := newRoutedOsqueryDispatcher([]string{"s-offline"},
		map[string]error{"s-failing": errors.New("osquery execution failed")})

	server, resp := runCompletenessQuery(t, disp,
		offlineSteward("s-offline", hb), onlineSteward("s-failing", otherHB), onlineSteward("s-ok", otherHB))

	// Expected value read back from the fleet record the handler resolved.
	matched, err := server.fleetQuery.Search(context.Background(), fleet.Filter{})
	require.NoError(t, err)
	var fleetHB time.Time
	for _, sr := range matched {
		if sr.ID == "s-offline" {
			fleetHB = sr.LastHeartbeat
		}
	}
	require.False(t, fleetHB.IsZero(), "fleet record must carry the seeded heartbeat")

	off := resp.result(t, "s-offline")
	require.NotNil(t, off.LastSeen, "not_connected result must carry last_seen")
	assert.True(t, off.LastSeen.Equal(fleetHB), "last_seen must match the fleet record heartbeat")
	assert.True(t, off.LastSeen.Equal(hb))
	assert.Equal(t, time.UTC, off.LastSeen.Location(), "last_seen must be UTC")
	assert.Contains(t, resp.rawResult(t, "s-offline"), "last_seen")

	assert.NotContains(t, resp.rawResult(t, "s-ok"), "last_seen", "answered result must not carry last_seen")
	assert.NotContains(t, resp.rawResult(t, "s-failing"), "last_seen", "failed result must not carry last_seen")
}

func TestOsqueryCompleteness_NeverHeardFromHasNoLastSeen(t *testing.T) {
	disp := newRoutedOsqueryDispatcher([]string{"s-new"}, nil)

	_, resp := runCompletenessQuery(t, disp, offlineSteward("s-new", time.Time{}))

	res := resp.result(t, "s-new")
	assert.Equal(t, osqueryResultNotConnected, res.Outcome)
	assert.Nil(t, res.LastSeen)
	assert.NotContains(t, resp.rawResult(t, "s-new"), "last_seen")
}

func TestOsqueryCompleteness_SummaryMixed(t *testing.T) {
	hb := time.Date(2026, 11, 20, 8, 30, 0, 0, time.UTC)
	disp := newRoutedOsqueryDispatcher([]string{"s-off-1", "s-off-2"},
		map[string]error{"s-fail": errors.New("osquery execution failed")})

	before := time.Now()
	_, resp := runCompletenessQuery(t, disp,
		onlineSteward("s-ok-1", hb), onlineSteward("s-ok-2", hb),
		offlineSteward("s-off-1", hb), offlineSteward("s-off-2", hb),
		onlineSteward("s-fail", hb))
	after := time.Now()

	s := resp.typed.Summary
	assert.Equal(t, 5, s.Matched)
	assert.Equal(t, 2, s.Answered)
	assert.Equal(t, 2, s.NotConnected)
	assert.Equal(t, 1, s.Failed)
	assertSummaryInvariant(t, resp.typed)

	require.False(t, s.QueriedAt.IsZero(), "queried_at must be set")
	assert.Equal(t, time.UTC, s.QueriedAt.Location(), "queried_at must be UTC")
	assert.False(t, s.QueriedAt.Before(before.Truncate(time.Microsecond)), "queried_at must not precede the request")
	assert.False(t, s.QueriedAt.After(after), "queried_at must not follow the response")

	summary, ok := resp.raw["summary"].(map[string]interface{})
	require.True(t, ok, "summary must be a JSON object")
	for _, key := range []string{"matched", "answered", "not_connected", "failed", "queried_at"} {
		assert.Contains(t, summary, key)
	}
}

func TestOsqueryCompleteness_SummaryAllAnswered(t *testing.T) {
	hb := time.Date(2026, 11, 20, 8, 30, 0, 0, time.UTC)
	_, resp := runCompletenessQuery(t, newRoutedOsqueryDispatcher(nil, nil),
		onlineSteward("s-1", hb), onlineSteward("s-2", hb))

	assert.Equal(t, 2, resp.typed.Summary.Matched)
	assert.Equal(t, 2, resp.typed.Summary.Answered)
	assertSummaryInvariant(t, resp.typed)
}

func TestOsqueryCompleteness_SummaryAllNotConnected(t *testing.T) {
	hb := time.Date(2026, 11, 20, 8, 30, 0, 0, time.UTC)
	_, resp := runCompletenessQuery(t, newRoutedOsqueryDispatcher([]string{"s-1", "s-2"}, nil),
		offlineSteward("s-1", hb), offlineSteward("s-2", hb))

	assert.Equal(t, 2, resp.typed.Summary.Matched)
	assert.Equal(t, 2, resp.typed.Summary.NotConnected)
	assert.Equal(t, 0, resp.typed.Summary.Answered)
	assertSummaryInvariant(t, resp.typed)
}

func TestOsqueryCompleteness_SummaryZeroMatched(t *testing.T) {
	_, resp := runCompletenessQuery(t, newRoutedOsqueryDispatcher(nil, nil))

	s := resp.typed.Summary
	assert.Equal(t, 0, s.Matched)
	assert.Equal(t, 0, s.Answered)
	assert.Equal(t, 0, s.NotConnected)
	assert.Equal(t, 0, s.Failed)
	assert.False(t, s.QueriedAt.IsZero(), "queried_at must be set even with no matched steward")
	assertSummaryInvariant(t, resp.typed)

	results, ok := resp.raw["results"].([]interface{})
	require.True(t, ok, "results must be a JSON array, not null")
	assert.Empty(t, results)
}

func TestOsqueryCompleteness_ExistingFieldsUnchanged(t *testing.T) {
	hb := time.Date(2026, 11, 20, 8, 30, 0, 0, time.UTC)
	disp := newRoutedOsqueryDispatcher(nil,
		map[string]error{"s-fail": errors.New("osquery execution failed")})

	_, resp := runCompletenessQuery(t, disp, onlineSteward("s-ok", hb), onlineSteward("s-fail", hb))

	ok := resp.rawResult(t, "s-ok")
	assert.Equal(t, "s-ok", ok["steward_id"])
	assert.Equal(t, []interface{}{map[string]interface{}{"hostname": "h"}}, ok["rows"])
	assert.NotContains(t, ok, "error", "an answered result has no error key")
	assert.Equal(t, osqueryResultAnswered, ok["outcome"])

	fail := resp.rawResult(t, "s-fail")
	assert.Equal(t, "s-fail", fail["steward_id"])
	assert.Equal(t, "osquery execution failed", fail["error"])
	assert.NotContains(t, fail, "rows", "a failed result has no rows key")
	assert.Equal(t, osqueryResultFailed, fail["outcome"])
}

func TestOsqueryCompleteness_SignalsPartialWithNotConnected(t *testing.T) {
	disp := newRoutedOsqueryDispatcher([]string{"steward-2"}, nil)
	server, collector := osquerySignalsServer(t, disp, true, "steward-1", "steward-2")

	rec := postOsqueryQuery(t, server, osqueryQueryRequest{CatalogID: "host_info", Selector: "all"})
	require.Equal(t, http.StatusOK, rec.Code)

	text := osquerySignalText(t, collector)
	assert.Contains(t, text, `cfgms_osquery_queries_total{outcome="partial"} 1`)
	assert.Contains(t, text, `cfgms_osquery_steward_results_total{result="steward_ok"} 1`)
	assert.Contains(t, text, `cfgms_osquery_steward_results_total{result="steward_failed"} 1`)
}

func TestOsqueryCompleteness_SignalsAllNotConnectedIsFailed(t *testing.T) {
	disp := newRoutedOsqueryDispatcher([]string{"steward-1", "steward-2"}, nil)
	server, collector := osquerySignalsServer(t, disp, true, "steward-1", "steward-2")

	rec := postOsqueryQuery(t, server, osqueryQueryRequest{CatalogID: "host_info", Selector: "all"})
	require.Equal(t, http.StatusOK, rec.Code)

	text := osquerySignalText(t, collector)
	assert.Contains(t, text, `cfgms_osquery_queries_total{outcome="failed"} 1`)
	assert.Contains(t, text, `cfgms_osquery_steward_results_total{result="steward_failed"} 2`)
	assert.NotContains(t, text, `result="steward_ok"`)
}

// A steward the lockdown gate refuses is failed even when it is also offline:
// the gate answers before the stream lookup, so the dispatcher does not return
// ErrStewardNotConnected for it. The dispatcher is the real controller handler
// with the real lockdown predicate over a real steward store.
func TestOsqueryCompleteness_LockedDownOfflineStewardIsFailed(t *testing.T) {
	store := pkgtesting.SetupTestStorage(t).GetStewardStore()
	require.NotNil(t, store)
	for id, status := range map[string]business.StewardStatus{
		"s-tampered": business.StewardStatusTampered,
		"s-plain":    business.StewardStatusActive,
	} {
		require.NoError(t, store.RegisterSteward(context.Background(), &business.StewardRecord{
			ID: id, TenantID: "root", Hostname: id, Platform: "linux", Status: status,
			RegisteredAt: time.Now(), LastSeen: time.Now(),
		}))
	}
	disp := stewardosquery.NewOsqueryHandler(logging.NewNoopLogger(), "").
		WithLockdown(fleet.NewLockdown(store, logging.NewNoopLogger()))
	hb := time.Date(2026, 11, 20, 8, 30, 0, 0, time.UTC)

	_, resp := runCompletenessQuery(t, disp, offlineSteward("s-tampered", hb), offlineSteward("s-plain", hb))

	tampered := resp.result(t, "s-tampered")
	assert.Equal(t, osqueryResultFailed, tampered.Outcome, "a refused steward is failed, not not_connected")
	assert.NotEmpty(t, tampered.Error)
	assert.NotContains(t, resp.rawResult(t, "s-tampered"), "last_seen")

	plain := resp.result(t, "s-plain")
	assert.Equal(t, osqueryResultNotConnected, plain.Outcome)
	require.NotNil(t, plain.LastSeen)
	assert.True(t, plain.LastSeen.Equal(hb))
	assertSummaryInvariant(t, resp.typed)
}

// last_seen and queried_at are UTC on the wire whatever zone the source time
// carries.
func TestOsqueryCompleteness_TimesAreUTCOnTheWire(t *testing.T) {
	east := time.FixedZone("east", 2*60*60)
	disp := newRoutedOsqueryDispatcher([]string{"s-offline"}, nil)

	_, resp := runCompletenessQuery(t, disp,
		offlineSteward("s-offline", time.Date(2026, 11, 20, 10, 30, 0, 0, east)))

	assert.Equal(t, "2026-11-20T08:30:00Z", resp.rawResult(t, "s-offline")["last_seen"])

	raw, err := json.Marshal(summarizeOsqueryResults(nil, time.Date(2026, 11, 22, 16, 3, 5, 0, east)))
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"queried_at":"2026-11-22T14:03:05Z"`)
}

// A request refused because a matched steward is outside what the caller may
// act on returns no summary, no result and no last_seen, and nothing is
// dispatched: completeness data exists only after target authorization.
func TestOsqueryCompleteness_RefusedTargetGetsNoCompletenessData(t *testing.T) {
	hb := time.Date(2026, 11, 20, 8, 30, 0, 0, time.UTC)
	disp := &stubOsqueryDispatcher{rows: []*transportpb.OsqueryRow{{Columns: map[string]string{"hostname": "h"}}}}
	server := setupTestServer(t)
	server.SetOsqueryDispatcher(disp)
	server.fleetQuery = seededFleetQuery(
		onlineSteward("s-ok", hb),
		fleet.StewardData{ID: "s-no-tenant", Status: "offline", LastHeartbeat: hb})

	rec := postOsqueryQuery(t, server, osqueryQueryRequest{CatalogID: "host_info", Selector: "all"})

	require.Equal(t, http.StatusNotFound, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "STEWARD_NOT_FOUND")
	for _, leaked := range []string{"summary", "matched", "outcome", "last_seen", "s-ok", "s-no-tenant"} {
		assert.NotContains(t, body, leaked)
	}
	assert.Empty(t, dispatchedStewardIDs(disp), "nothing may be dispatched for a refused request")
}
