// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package graph

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/modules/m365/auth"
)

// newTestClientWithServer creates an HTTPClient pointed at the given test server
func newTestClientWithServer(srv *httptest.Server) *HTTPClient {
	c := NewHTTPClient()
	c.baseURL = srv.URL
	c.httpClient = srv.Client()
	c.teamPollMaxRetries = 3
	c.teamPollBackoff = 1 * time.Millisecond
	return c
}

func testToken() *auth.AccessToken {
	return &auth.AccessToken{
		Token:     "test-token",
		TokenType: "Bearer",
		ExpiresAt: time.Now().Add(1 * time.Hour),
		TenantID:  "test-tenant",
	}
}

// writeJSON encodes v as JSON to w; uses t.Errorf (goroutine-safe) on failure.
func writeJSON(t *testing.T, w http.ResponseWriter, v interface{}) {
	t.Helper()
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Errorf("writeJSON: %v", err)
	}
}

func TestHTTPClient_CreateTeam_ProvisionedAfterPolling(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "PUT" && r.URL.Path == "/groups/group-1/team":
			w.WriteHeader(http.StatusAccepted)
		case r.Method == "GET" && r.URL.Path == "/teams/group-1":
			callCount++
			if callCount < 2 {
				w.WriteHeader(http.StatusNotFound)
				writeJSON(t, w, map[string]interface{}{
					"error": map[string]interface{}{
						"code": "Request_ResourceNotFound", "message": "team not found yet",
					},
				})
				return
			}
			w.WriteHeader(http.StatusOK)
			writeJSON(t, w, Team{ID: "group-1"})
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	c := newTestClientWithServer(srv)
	err := c.CreateTeam(context.Background(), testToken(), "group-1", &CreateTeamRequest{})
	require.NoError(t, err)
	assert.Equal(t, 2, callCount)
}

func TestHTTPClient_CreateTeam_TimeoutWhenAlwaysNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "PUT":
			w.WriteHeader(http.StatusAccepted)
		case "GET":
			w.WriteHeader(http.StatusNotFound)
			writeJSON(t, w, map[string]interface{}{
				"error": map[string]interface{}{
					"code": "Request_ResourceNotFound", "message": "still provisioning",
				},
			})
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	c := newTestClientWithServer(srv)
	c.teamPollMaxRetries = 2
	err := c.CreateTeam(context.Background(), testToken(), "group-1", &CreateTeamRequest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timed out")
}

func TestHTTPClient_CreateTeam_ContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PUT" {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		writeJSON(t, w, map[string]interface{}{
			"error": map[string]interface{}{
				"code": "Request_ResourceNotFound", "message": "still provisioning",
			},
		})
	}))
	defer srv.Close()

	c := newTestClientWithServer(srv)
	c.teamPollBackoff = 50 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	err := c.CreateTeam(ctx, testToken(), "group-1", &CreateTeamRequest{})
	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestHTTPClient_CreateTeam_HardFailureOnNonNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PUT" {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.WriteHeader(http.StatusForbidden)
		writeJSON(t, w, map[string]interface{}{
			"error": map[string]interface{}{
				"code": "Authorization_RequestDenied", "message": "access denied",
			},
		})
	}))
	defer srv.Close()

	c := newTestClientWithServer(srv)
	err := c.CreateTeam(context.Background(), testToken(), "group-1", &CreateTeamRequest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "provisioning failed")
}

func TestHTTPClient_GetTeam_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/teams/group-1", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		writeJSON(t, w, Team{ID: "group-1", DisplayName: "My Team"})
	}))
	defer srv.Close()

	c := newTestClientWithServer(srv)
	team, err := c.GetTeam(context.Background(), testToken(), "group-1")
	require.NoError(t, err)
	require.NotNil(t, team)
	assert.Equal(t, "group-1", team.ID)
	assert.Equal(t, "My Team", team.DisplayName)
}

func TestHTTPClient_GetTeam_NotFoundError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		writeJSON(t, w, map[string]interface{}{
			"error": map[string]interface{}{
				"code": "Request_ResourceNotFound", "message": "team not found",
			},
		})
	}))
	defer srv.Close()

	c := newTestClientWithServer(srv)
	team, err := c.GetTeam(context.Background(), testToken(), "no-team")
	assert.Nil(t, team)
	require.Error(t, err)
	assert.True(t, IsNotFoundError(err))
}

func TestHTTPClient_UpdateTeamSettings_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "PATCH", r.Method)
		assert.Equal(t, "/teams/team-1", r.URL.Path)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := newTestClientWithServer(srv)
	err := c.UpdateTeamSettings(context.Background(), testToken(), "team-1", &UpdateTeamSettingsRequest{})
	assert.NoError(t, err)
}

func TestHTTPClient_UpdateTeamSettings_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		writeJSON(t, w, map[string]interface{}{
			"error": map[string]interface{}{
				"code": "Authorization_RequestDenied", "message": "insufficient privileges",
			},
		})
	}))
	defer srv.Close()

	c := newTestClientWithServer(srv)
	err := c.UpdateTeamSettings(context.Background(), testToken(), "team-1", &UpdateTeamSettingsRequest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to update team settings")
}
