// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
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
}

func TestStewardTamperCommands_RegisteredWithHelpAndNoForce(t *testing.T) {
	for _, path := range [][]string{{"tamper"}, {"tamper", "restore"}, {"tamper", "ban"}} {
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
