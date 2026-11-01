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

type recordedCloneRequest struct {
	Method string
	Path   string
	Body   string
}

// newCloneVerbServer is a real HTTP server standing in for the controller; it
// records every request the real API client sends.
func newCloneVerbServer(t *testing.T, status int, data interface{}) (*httptest.Server, func() []recordedCloneRequest) {
	t.Helper()
	var mu sync.Mutex
	var seen []recordedCloneRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		seen = append(seen, recordedCloneRequest{Method: r.Method, Path: r.URL.Path, Body: string(b)})
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if status == http.StatusOK {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": data})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": map[string]string{"code": "X", "message": "refused by controller"}})
	}))
	t.Cleanup(srv.Close)
	return srv, func() []recordedCloneRequest {
		mu.Lock()
		defer mu.Unlock()
		return append([]recordedCloneRequest(nil), seen...)
	}
}

func setCloneVerbFlags(t *testing.T, serverURL string, yes bool) {
	t.Helper()
	origURL, origInsecure, origYes := stewardURL, stewardTLSInsecure, stewardYes
	origFormat, origTo := stewardClonesFormat, stewardMoveIdentTo
	t.Cleanup(func() {
		stewardURL, stewardTLSInsecure, stewardYes = origURL, origInsecure, origYes
		stewardClonesFormat, stewardMoveIdentTo = origFormat, origTo
	})
	stewardURL = serverURL
	stewardTLSInsecure = true
	stewardYes = yes
}

var sampleClones = map[string]interface{}{"clones": []map[string]interface{}{{
	"steward_id": "steward-1", "tenant_id": "t1", "detection_count": 2,
	"first_detected": "2026-10-01T10:00:00Z", "last_detected": "2026-10-01T11:00:00Z",
	"existing_peer": "192.0.2.10:5000", "other_peer": "192.0.2.20:6000",
	"queued_copies": []map[string]interface{}{{"pending_id": "pending-9", "hostname": "copy-host", "source_ip": "10.0.0.9"}},
}}}

func TestStewardClonesList_SendsGetAndPrintsColumns(t *testing.T) {
	srv, seen := newCloneVerbServer(t, http.StatusOK, sampleClones)
	setCloneVerbFlags(t, srv.URL, false)
	stewardClonesFormat = "table"

	out := captureStdout(t, func() {
		require.NoError(t, runStewardClonesList(stewardClonesListCmd, nil))
	})
	reqs := seen()
	require.Len(t, reqs, 1)
	assert.Equal(t, http.MethodGet, reqs[0].Method)
	assert.Equal(t, "/api/v1/stewards/identity-clones", reqs[0].Path)
	for _, want := range []string{"STEWARD", "DETECTED", "LAST SEEN", "EXISTING PEER", "OTHER PEER", "QUEUED COPY", "HOSTNAME",
		"steward-1", "192.0.2.10:5000", "192.0.2.20:6000", "pending-9", "copy-host"} {
		assert.Contains(t, out, want)
	}
}

func TestStewardClonesList_JSONFormat(t *testing.T) {
	srv, _ := newCloneVerbServer(t, http.StatusOK, sampleClones)
	setCloneVerbFlags(t, srv.URL, false)
	stewardClonesFormat = "json"

	out := captureStdout(t, func() {
		require.NoError(t, runStewardClonesList(stewardClonesListCmd, nil))
	})
	var got []APIIdentityClone
	require.NoError(t, json.Unmarshal([]byte(out), &got))
	require.Len(t, got, 1)
	assert.Equal(t, "pending-9", got[0].QueuedCopies[0].PendingID)
}

func TestStewardClonesList_EmptyAndBadFormat(t *testing.T) {
	srv, _ := newCloneVerbServer(t, http.StatusOK, map[string]interface{}{"clones": []interface{}{}})
	setCloneVerbFlags(t, srv.URL, false)
	stewardClonesFormat = "table"
	out := captureStdout(t, func() { require.NoError(t, runStewardClonesList(stewardClonesListCmd, nil)) })
	assert.Contains(t, out, "No identity clones detected")

	stewardClonesFormat = "yaml"
	assert.Error(t, runStewardClonesList(stewardClonesListCmd, nil))
}

func TestStewardRotateCredentials_SendsPostWithYes(t *testing.T) {
	srv, seen := newCloneVerbServer(t, http.StatusOK, map[string]interface{}{
		"id": "steward-1", "status": "archived", "revoked_serials": []string{"1001", "1002"},
		"next_step": "complete with cfg refresh approve",
	})
	setCloneVerbFlags(t, srv.URL, true)

	out := captureStdout(t, func() {
		require.NoError(t, runStewardRotateCredentials(stewardRotateCredentialsCmd, []string{"steward-1"}))
	})
	reqs := seen()
	require.Len(t, reqs, 1)
	assert.Equal(t, http.MethodPost, reqs[0].Method)
	assert.Equal(t, "/api/v1/stewards/steward-1/credentials/rotate", reqs[0].Path)
	assert.Contains(t, out, "1001")
	assert.Contains(t, out, "1002")
	assert.Contains(t, out, "cfg refresh approve")
}

func TestStewardRotateCredentials_WithoutYesNonInteractiveSendsNothing(t *testing.T) {
	srv, seen := newCloneVerbServer(t, http.StatusOK, map[string]interface{}{})
	setCloneVerbFlags(t, srv.URL, false)

	err := runStewardRotateCredentials(stewardRotateCredentialsCmd, []string{"steward-1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--yes")
	assert.Empty(t, seen(), "no request may be sent before confirmation")
}

func TestStewardRotateCredentials_ServerRefusalSurfaced(t *testing.T) {
	srv, _ := newCloneVerbServer(t, http.StatusNotFound, nil)
	setCloneVerbFlags(t, srv.URL, true)
	err := runStewardRotateCredentials(stewardRotateCredentialsCmd, []string{"steward-1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refused by controller")
}

func TestStewardMoveIdentity_SendsPendingIDWithYes(t *testing.T) {
	srv, seen := newCloneVerbServer(t, http.StatusOK, map[string]interface{}{
		"id": "steward-1", "pending_id": "pending-9", "status": "approved",
		"revoked_serials": []string{"1001"}, "next_step": "queued machine claims",
	})
	setCloneVerbFlags(t, srv.URL, true)
	stewardMoveIdentTo = "pending-9"

	out := captureStdout(t, func() {
		require.NoError(t, runStewardMoveIdentity(stewardMoveIdentityCmd, []string{"steward-1"}))
	})
	reqs := seen()
	require.Len(t, reqs, 1)
	assert.Equal(t, http.MethodPost, reqs[0].Method)
	assert.Equal(t, "/api/v1/stewards/steward-1/identity/move", reqs[0].Path)
	assert.JSONEq(t, `{"pending_id":"pending-9"}`, reqs[0].Body)
	assert.Contains(t, out, "1001")
}

func TestStewardMoveIdentity_RequiresToAndConfirmation(t *testing.T) {
	srv, seen := newCloneVerbServer(t, http.StatusOK, map[string]interface{}{})
	setCloneVerbFlags(t, srv.URL, true)
	stewardMoveIdentTo = ""
	require.Error(t, runStewardMoveIdentity(stewardMoveIdentityCmd, []string{"steward-1"}))

	setCloneVerbFlags(t, srv.URL, false)
	stewardMoveIdentTo = "pending-9"
	err := runStewardMoveIdentity(stewardMoveIdentityCmd, []string{"steward-1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--yes")
	assert.Empty(t, seen())
}

func TestStewardCloneVerbs_RegisteredWithHelp(t *testing.T) {
	for _, path := range [][]string{{"clones", "list"}, {"rotate-credentials"}, {"move-identity"}} {
		c, _, err := stewardCmd.Find(path)
		require.NoError(t, err, path)
		assert.Equal(t, path[len(path)-1], c.Name())
		assert.NotEmpty(t, c.Long, path)
	}
	assert.NotNil(t, stewardMoveIdentityCmd.Flags().Lookup("to"))
	assert.NotNil(t, stewardClonesListCmd.Flags().Lookup("format"))
	assert.NotNil(t, stewardCmd.PersistentFlags().Lookup("yes"))
}
