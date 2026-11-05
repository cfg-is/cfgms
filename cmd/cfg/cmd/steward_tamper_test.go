// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setTamperFlags(t *testing.T, serverURL string, yes bool, reason string) {
	t.Helper()
	setCloneVerbFlags(t, serverURL, yes)
	orig := stewardTamperReason
	t.Cleanup(func() { stewardTamperReason = orig })
	stewardTamperReason = reason
}

func TestStewardTamperRestore_SendsPostWithReason(t *testing.T) {
	srv, seen := newCloneVerbServer(t, http.StatusOK, map[string]interface{}{
		"id": "steward-1", "status": "active", "note": "Restored: the steward is trusted again",
	})
	setTamperFlags(t, srv.URL, true, "reimaged")

	out := captureStdout(t, func() {
		require.NoError(t, runStewardTamperRestore(stewardTamperRestoreCmd, []string{"steward-1"}))
	})
	reqs := seen()
	require.Len(t, reqs, 1)
	assert.Equal(t, http.MethodPost, reqs[0].Method)
	assert.Equal(t, "/api/v1/stewards/steward-1/tamper/restore", reqs[0].Path)
	assert.JSONEq(t, `{"reason":"reimaged"}`, reqs[0].Body)
	assert.Contains(t, out, "restored")
	assert.Contains(t, out, "status: active")
}

func TestStewardTamperBan_SendsPostAndPrintsSerials(t *testing.T) {
	srv, seen := newCloneVerbServer(t, http.StatusOK, map[string]interface{}{
		"id": "steward-1", "status": "revoked", "revoked_serials": []string{"1001", "1002"},
		"note": "Banned: affects only this identity",
	})
	setTamperFlags(t, srv.URL, true, "")

	out := captureStdout(t, func() {
		require.NoError(t, runStewardTamperBan(stewardTamperBanCmd, []string{"steward-1"}))
	})
	reqs := seen()
	require.Len(t, reqs, 1)
	assert.Equal(t, "/api/v1/stewards/steward-1/tamper/ban", reqs[0].Path)
	assert.Empty(t, reqs[0].Body, "no reason, no body")
	for _, want := range []string{"banned", "status: revoked", "1001", "1002", "only this identity"} {
		assert.Contains(t, out, want)
	}
}

func TestStewardTamperVerbs_ConfirmGateSendsNothingWithoutYes(t *testing.T) {
	srv, seen := newCloneVerbServer(t, http.StatusOK, map[string]interface{}{})
	setTamperFlags(t, srv.URL, false, "")

	for name, run := range map[string]func() error{
		"restore": func() error { return runStewardTamperRestore(stewardTamperRestoreCmd, []string{"steward-1"}) },
		"ban":     func() error { return runStewardTamperBan(stewardTamperBanCmd, []string{"steward-1"}) },
	} {
		err := run()
		require.Error(t, err, name)
		assert.Contains(t, err.Error(), "--yes", name)
	}
	assert.Empty(t, seen(), "no request may be sent before confirmation")
}

func TestStewardTamperVerbs_ServerRefusalSurfaced(t *testing.T) {
	srv, _ := newCloneVerbServer(t, http.StatusNotFound, nil)
	setTamperFlags(t, srv.URL, true, "")
	for name, run := range map[string]func() error{
		"restore": func() error { return runStewardTamperRestore(stewardTamperRestoreCmd, []string{"steward-1"}) },
		"ban":     func() error { return runStewardTamperBan(stewardTamperBanCmd, []string{"steward-1"}) },
	} {
		err := run()
		require.Error(t, err, name)
		assert.Contains(t, err.Error(), "refused by controller", name)
	}
}

func TestStewardTamperRestore_FaultStillReportedNamesCodes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "fault_still_reported", "codes": []string{"tamper.data_dir"},
			"message": "The steward still reports a fault. It must be repaired and restored instead.",
		})
	}))
	t.Cleanup(srv.Close)
	setTamperFlags(t, srv.URL, true, "")

	err := runStewardTamperRestore(stewardTamperRestoreCmd, []string{"steward-1"})
	require.Error(t, err)
	var fault *stewardFaultStillReportedError
	require.ErrorAs(t, err, &fault)
	assert.Equal(t, []string{"tamper.data_dir"}, fault.Codes)
	assert.Contains(t, err.Error(), "fault_still_reported")
	assert.Contains(t, err.Error(), "tamper.data_dir")
	assert.Contains(t, err.Error(), "repaired and restored")
	assert.Contains(t, err.Error(), "cfg steward tamper repair steward-1", "the refusal names the repair command")
}

func TestStewardTamperCommands_RegisteredWithHelpAndNoForce(t *testing.T) {
	for _, path := range [][]string{{"tamper"}, {"tamper", "restore"}, {"tamper", "ban"}, {"tamper", "repair"}, {"tamper", "repair-status"}} {
		c, _, err := stewardCmd.Find(path)
		require.NoError(t, err, path)
		assert.Equal(t, path[len(path)-1], c.Name())
		assert.NotEmpty(t, c.Long, path)
	}
	for _, c := range stewardTamperCmd.Commands() {
		assert.NotNil(t, c.Flags().Lookup("reason"), c.Name())
		assert.Nil(t, c.Flags().Lookup("force"), "there is no override of the live-fault check: "+c.Name())
	}
	// Every command named in the help text exists.
	for _, ref := range [][]string{{"run-command"}} {
		c, _, err := stewardCmd.Find(ref)
		require.NoError(t, err, ref)
		assert.Equal(t, ref[0], c.Name())
	}
}

// repairServer serves a steward with the given health reason codes and records
// the repair POSTs it receives.
func newRepairServer(t *testing.T, reasonCodes []string, postStatus int, postBody interface{}) (*httptest.Server, func() []recordedCloneRequest) {
	t.Helper()
	var mu sync.Mutex
	var seen []recordedCloneRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		seen = append(seen, recordedCloneRequest{Method: r.Method, Path: r.URL.Path, Body: string(b)})
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/stewards/steward-1":
			reasons := []map[string]string{}
			for _, c := range reasonCodes {
				reasons = append(reasons, map[string]string{"component": "repair", "code": c})
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{"id": "steward-1", "health_reasons": reasons}})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/stewards/steward-1/tamper/repair":
			w.WriteHeader(postStatus)
			_ = json.NewEncoder(w).Encode(postBody)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/stewards/steward-1/tamper/repair":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{
				"repair_id": "r1", "state": "running", "requested_by": "operator", "requested_at": "2026-11-01T10:00:00Z",
				"loss_codes": []string{"repair.loss.local_logs"}, "outcome_codes": []string{"repair.running"},
			}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, func() []recordedCloneRequest {
		mu.Lock()
		defer mu.Unlock()
		return append([]recordedCloneRequest(nil), seen...)
	}
}

func setRepairFlags(t *testing.T, serverURL string, yes bool, approve []string) {
	t.Helper()
	setTamperFlags(t, serverURL, yes, "lost the data folder")
	orig := stewardTamperApproveLoss
	t.Cleanup(func() { stewardTamperApproveLoss = orig })
	stewardTamperApproveLoss = approve
}

func repairPosts(reqs []recordedCloneRequest) []recordedCloneRequest {
	var out []recordedCloneRequest
	for _, r := range reqs {
		if r.Method == http.MethodPost {
			out = append(out, r)
		}
	}
	return out
}

var acceptedRepair = map[string]interface{}{"data": map[string]interface{}{
	"repair_id": "r1", "state": "waiting", "delivered": true, "loss_codes": []string{"repair.loss.local_logs"},
	"note": "Repair requested",
}}

func TestStewardTamperRepair_ListsLossAndRefusesWithoutExactApproval(t *testing.T) {
	loss := []string{"repair.loss.local_logs", "tamper.data_dir"}
	for name, approve := range map[string][]string{
		"none":      nil,
		"different": {"repair.loss.action_history"},
		"partial":   {"repair.loss.action_history", "repair.loss.local_logs"},
	} {
		srv, seen := newRepairServer(t, loss, http.StatusAccepted, acceptedRepair)
		setRepairFlags(t, srv.URL, true, approve)
		var err error
		out := captureStdout(t, func() { err = runStewardTamperRepair(stewardTamperRepairCmd, []string{"steward-1"}) })
		require.Error(t, err, name)
		var gate *stewardLossApprovalRequiredError
		require.ErrorAs(t, err, &gate, name)
		assert.Equal(t, []string{"repair.loss.local_logs"}, gate.LossCodes, name)
		assert.Contains(t, out, "repair.loss.local_logs", name+": the loss is printed")
		assert.Contains(t, err.Error(), "--approve-loss repair.loss.local_logs", name)
		assert.Empty(t, repairPosts(seen()), name+": nothing is sent without the exact approval")
	}
}

func TestStewardTamperRepair_ExactApprovalSendsRequest(t *testing.T) {
	srv, seen := newRepairServer(t, []string{"repair.loss.action_history", "repair.loss.local_logs"}, http.StatusAccepted, acceptedRepair)
	setRepairFlags(t, srv.URL, true, []string{"repair.loss.local_logs", "repair.loss.action_history"})
	out := captureStdout(t, func() {
		require.NoError(t, runStewardTamperRepair(stewardTamperRepairCmd, []string{"steward-1"}))
	})
	posts := repairPosts(seen())
	require.Len(t, posts, 1)
	assert.Equal(t, "/api/v1/stewards/steward-1/tamper/repair", posts[0].Path)
	assert.JSONEq(t, `{"reason":"lost the data folder","approved_loss_codes":["repair.loss.action_history","repair.loss.local_logs"]}`, posts[0].Body)
	assert.Contains(t, out, "Repair r1 requested")
	assert.Contains(t, out, "sent to the connected steward")
	assert.Contains(t, out, "repair-status steward-1")
}

func TestStewardTamperRepair_NoLossProceedsWithEmptyApproval(t *testing.T) {
	srv, seen := newRepairServer(t, []string{"tamper.data_dir"}, http.StatusAccepted, acceptedRepair)
	setRepairFlags(t, srv.URL, true, nil)
	out := captureStdout(t, func() {
		require.NoError(t, runStewardTamperRepair(stewardTamperRepairCmd, []string{"steward-1"}))
	})
	posts := repairPosts(seen())
	require.Len(t, posts, 1)
	assert.JSONEq(t, `{"reason":"lost the data folder","approved_loss_codes":[]}`, posts[0].Body)
	assert.Contains(t, out, "no local data")
}

func TestStewardTamperRepair_ConfirmGateSendsNothingWithoutYes(t *testing.T) {
	srv, seen := newRepairServer(t, nil, http.StatusAccepted, acceptedRepair)
	setRepairFlags(t, srv.URL, false, nil)
	err := runStewardTamperRepair(stewardTamperRepairCmd, []string{"steward-1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--yes")
	assert.Empty(t, repairPosts(seen()))
}

func TestStewardTamperRepair_ServerGateAndRefusalSurfaced(t *testing.T) {
	// The steward's loss changed between the read and the request: the controller's 409 is surfaced.
	srv, _ := newRepairServer(t, nil, http.StatusConflict, map[string]interface{}{
		"error": "loss_approval_required", "loss_codes": []string{"repair.loss.local_logs"},
	})
	setRepairFlags(t, srv.URL, true, nil)
	err := runStewardTamperRepair(stewardTamperRepairCmd, []string{"steward-1"})
	var gate *stewardLossApprovalRequiredError
	require.ErrorAs(t, err, &gate)
	assert.Equal(t, []string{"repair.loss.local_logs"}, gate.LossCodes)

	srv2, _ := newRepairServer(t, nil, http.StatusConflict, map[string]interface{}{
		"error": map[string]string{"code": "STEWARD_NOT_TAMPERED", "message": "Steward is active, not tampered"},
	})
	setRepairFlags(t, srv2.URL, true, nil)
	err = runStewardTamperRepair(stewardTamperRepairCmd, []string{"steward-1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not tampered")
}

func TestStewardTamperRepairStatus_PrintsState(t *testing.T) {
	srv, seen := newRepairServer(t, nil, http.StatusAccepted, acceptedRepair)
	setRepairFlags(t, srv.URL, true, nil)
	out := captureStdout(t, func() {
		require.NoError(t, runStewardTamperRepairStatus(stewardTamperRepairStatusCmd, []string{"steward-1"}))
	})
	for _, want := range []string{"Repair r1", "running", "operator", "repair.loss.local_logs", "repair.running"} {
		assert.Contains(t, out, want)
	}
	assert.Empty(t, repairPosts(seen()))
}

func TestStewardTamperRepair_Flags(t *testing.T) {
	f := stewardTamperRepairCmd.Flags()
	require.NotNil(t, f.Lookup("approve-loss"))
	require.NotNil(t, f.Lookup("reason"))
	assert.Nil(t, f.Lookup("force"))
}
