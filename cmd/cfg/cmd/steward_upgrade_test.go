// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// saveStewardUpgradeGlobals captures all upgrade-command global vars and restores
// them via t.Cleanup so tests cannot pollute each other's state.
func saveStewardUpgradeGlobals(t *testing.T) {
	t.Helper()
	origURL := stewardURL
	origAPIKey := stewardAPIKey
	origTLSCACert := stewardTLSCACert
	origInsecure := stewardTLSInsecure
	origVersion := stewardUpgradeVersion
	origPlatform := stewardUpgradePlatform
	origArch := stewardUpgradeArch
	origWait := stewardUpgradeWait
	origWaitTimeout := stewardUpgradeWaitTimeout
	origUpgradeID := stewardUpgradeID
	origToVersion := stewardUpgradeToVersion
	origPollInterval := upgradeWaitPollInterval
	origBP := bundlePath
	origNoBundle := noBundle
	origUserConfigDir := userConfigDirFn
	origSystemBundle := systemBundlePathFn
	t.Cleanup(func() {
		stewardURL = origURL
		stewardAPIKey = origAPIKey
		stewardTLSCACert = origTLSCACert
		stewardTLSInsecure = origInsecure
		stewardUpgradeVersion = origVersion
		stewardUpgradePlatform = origPlatform
		stewardUpgradeArch = origArch
		stewardUpgradeWait = origWait
		stewardUpgradeWaitTimeout = origWaitTimeout
		stewardUpgradeID = origUpgradeID
		stewardUpgradeToVersion = origToVersion
		upgradeWaitPollInterval = origPollInterval
		bundlePath = origBP
		noBundle = origNoBundle
		userConfigDirFn = origUserConfigDir
		systemBundlePathFn = origSystemBundle
	})
}

// writeUpgradeDispatchResponse writes a canned dispatch 202 response.
func writeUpgradeDispatchResponse(w http.ResponseWriter, upgradeID string, stewardCount int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(APIDispatchUpgradeResponse{
		UpgradeID:    upgradeID,
		StewardCount: stewardCount,
		Status:       "accepted",
	})
}

// writeUpgradeStatusResponse writes a canned upgrade status response.
func writeUpgradeStatusResponse(w http.ResponseWriter, upgradeID string, stewards []APIUpgradeStewardStatus) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(APIUpgradeStatusResponse{
		UpgradeID: upgradeID,
		Stewards:  stewards,
	})
}

// ---------------------------------------------------------------------------
// [REQUIRED TEST] TestRunStewardUpgrade_RequiresVersion
// ---------------------------------------------------------------------------

func TestRunStewardUpgrade_RequiresVersion(t *testing.T) {
	// Track whether the server was called — it must NOT be.
	var serverCalled bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		serverCalled = true
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	saveStewardUpgradeGlobals(t)
	stewardURL = server.URL
	stewardTLSInsecure = true
	stewardUpgradeVersion = "" // omit --version

	err := runStewardUpgrade(stewardUpgradeCmd, []string{"id:steward-abc"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "version")
	assert.False(t, serverCalled, "no HTTP call must be made when --version is missing")
}

// ---------------------------------------------------------------------------
// [REQUIRED TEST] TestRunStewardUpgrade_Wait
// ---------------------------------------------------------------------------

// TestRunStewardUpgrade_Wait verifies that:
//   - The polling loop exits when all stewards reach terminal state (committed).
//   - The loop aborts immediately on the first 401 without retry.
func TestRunStewardUpgrade_Wait(t *testing.T) {
	t.Run("exits when all stewards committed", func(t *testing.T) {
		var pollCount int32

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodPost && r.URL.Path == "/api/v1/stewards/upgrade":
				writeUpgradeDispatchResponse(w, "upgrade-wait-id", 2)
			case r.Method == http.MethodGet:
				n := atomic.AddInt32(&pollCount, 1)
				stewards := []APIUpgradeStewardStatus{
					{Device: "device-1", Status: "dispatched"},
					{Device: "device-2", Status: "dispatched"},
				}
				if n >= 2 {
					stewards[0].Status = "committed"
					stewards[1].Status = "committed"
				}
				writeUpgradeStatusResponse(w, "upgrade-wait-id", stewards)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		saveStewardUpgradeGlobals(t)
		stewardURL = server.URL
		stewardTLSInsecure = true
		stewardUpgradeVersion = "v0.5.12"
		stewardUpgradeWait = true
		stewardUpgradeWaitTimeout = 30 * time.Second
		upgradeWaitPollInterval = time.Millisecond

		output := captureStdout(t, func() {
			err := runStewardUpgrade(stewardUpgradeCmd, []string{"id:steward-abc"})
			require.NoError(t, err)
		})

		assert.GreaterOrEqual(t, atomic.LoadInt32(&pollCount), int32(2), "must poll at least twice")
		assert.Contains(t, output, "committed")
	})

	t.Run("aborts immediately on 401", func(t *testing.T) {
		var pollCount int32

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodPost && r.URL.Path == "/api/v1/stewards/upgrade":
				writeUpgradeDispatchResponse(w, "upgrade-auth-id", 1)
			case r.Method == http.MethodGet:
				atomic.AddInt32(&pollCount, 1)
				// Always return 401
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		saveStewardUpgradeGlobals(t)
		stewardURL = server.URL
		stewardTLSInsecure = true
		stewardUpgradeVersion = "v0.5.12"
		stewardUpgradeWait = true
		stewardUpgradeWaitTimeout = 30 * time.Second
		upgradeWaitPollInterval = time.Millisecond

		_ = captureStdout(t, func() {
			err := runStewardUpgrade(stewardUpgradeCmd, []string{"id:steward-abc"})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "401")
		})

		// Exactly one poll — no retry after 401.
		assert.Equal(t, int32(1), atomic.LoadInt32(&pollCount), "must abort on first 401 without retry")
	})

	t.Run("aborts immediately on 403", func(t *testing.T) {
		var pollCount int32

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodPost && r.URL.Path == "/api/v1/stewards/upgrade":
				writeUpgradeDispatchResponse(w, "upgrade-forbidden-id", 1)
			case r.Method == http.MethodGet:
				atomic.AddInt32(&pollCount, 1)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "forbidden"})
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		saveStewardUpgradeGlobals(t)
		stewardURL = server.URL
		stewardTLSInsecure = true
		stewardUpgradeVersion = "v0.5.12"
		stewardUpgradeWait = true
		stewardUpgradeWaitTimeout = 30 * time.Second
		upgradeWaitPollInterval = time.Millisecond

		_ = captureStdout(t, func() {
			err := runStewardUpgrade(stewardUpgradeCmd, []string{"id:steward-abc"})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "403")
		})

		assert.Equal(t, int32(1), atomic.LoadInt32(&pollCount), "must abort on first 403 without retry")
	})
}

// ---------------------------------------------------------------------------
// Dispatch tests
// ---------------------------------------------------------------------------

func TestRunStewardUpgrade_AsyncSuccess(t *testing.T) {
	var requestPath, requestMethod string
	var requestBody []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPath = r.URL.Path
		requestMethod = r.Method
		requestBody, _ = io.ReadAll(r.Body)
		writeUpgradeDispatchResponse(w, "upgrade-async-id", 3)
	}))
	defer server.Close()

	saveStewardUpgradeGlobals(t)
	stewardURL = server.URL
	stewardTLSInsecure = true
	stewardUpgradeVersion = "v0.5.12"
	stewardUpgradeWait = false

	output := captureStdout(t, func() {
		err := runStewardUpgrade(stewardUpgradeCmd, []string{"id:steward-abc"})
		require.NoError(t, err)
	})

	assert.Equal(t, http.MethodPost, requestMethod)
	assert.Equal(t, "/api/v1/stewards/upgrade", requestPath)
	assert.Contains(t, output, "upgrade-async-id")
	assert.Contains(t, output, "3")

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(requestBody, &body))
	assert.Equal(t, "id:steward-abc", body["selector"])
	assert.Equal(t, "v0.5.12", body["version"])
}

func TestRunStewardUpgrade_PlatformArchIncludedInBody(t *testing.T) {
	var requestBody []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestBody, _ = io.ReadAll(r.Body)
		writeUpgradeDispatchResponse(w, "upgrade-plat-id", 1)
	}))
	defer server.Close()

	saveStewardUpgradeGlobals(t)
	stewardURL = server.URL
	stewardTLSInsecure = true
	stewardUpgradeVersion = "v0.5.12"
	stewardUpgradePlatform = "linux"
	stewardUpgradeArch = "amd64"

	_ = captureStdout(t, func() {
		require.NoError(t, runStewardUpgrade(stewardUpgradeCmd, []string{"group:prod"}))
	})

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(requestBody, &body))
	assert.Equal(t, "linux", body["platform"])
	assert.Equal(t, "amd64", body["arch"])
}

func TestRunStewardUpgrade_NonAcceptedStatusReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid selector"})
	}))
	defer server.Close()

	saveStewardUpgradeGlobals(t)
	stewardURL = server.URL
	stewardTLSInsecure = true
	stewardUpgradeVersion = "v0.5.12"

	err := runStewardUpgrade(stewardUpgradeCmd, []string{"bad-selector"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid selector")
}

func TestRunStewardUpgrade_WaitExitsNonZeroOnFailedSteward(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			writeUpgradeDispatchResponse(w, "upgrade-fail-id", 2)
		default:
			stewards := []APIUpgradeStewardStatus{
				{Device: "device-1", Status: "committed"},
				{Device: "device-2", Status: "failed"},
			}
			writeUpgradeStatusResponse(w, "upgrade-fail-id", stewards)
		}
	}))
	defer server.Close()

	saveStewardUpgradeGlobals(t)
	stewardURL = server.URL
	stewardTLSInsecure = true
	stewardUpgradeVersion = "v0.5.12"
	stewardUpgradeWait = true
	stewardUpgradeWaitTimeout = 30 * time.Second
	upgradeWaitPollInterval = time.Millisecond

	output := captureStdout(t, func() {
		err := runStewardUpgrade(stewardUpgradeCmd, []string{"id:steward-abc"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed")
	})
	assert.Contains(t, output, "device-1")
	assert.Contains(t, output, "device-2")
	assert.Contains(t, output, "failed")
}

func TestRunStewardUpgrade_WaitTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			writeUpgradeDispatchResponse(w, "upgrade-timeout-id", 1)
		default:
			// Always return dispatched (non-terminal)
			stewards := []APIUpgradeStewardStatus{
				{Device: "device-1", Status: "dispatched"},
			}
			writeUpgradeStatusResponse(w, "upgrade-timeout-id", stewards)
		}
	}))
	defer server.Close()

	saveStewardUpgradeGlobals(t)
	stewardURL = server.URL
	stewardTLSInsecure = true
	stewardUpgradeVersion = "v0.5.12"
	stewardUpgradeWait = true
	stewardUpgradeWaitTimeout = 10 * time.Millisecond
	upgradeWaitPollInterval = time.Millisecond

	_ = captureStdout(t, func() {
		err := runStewardUpgrade(stewardUpgradeCmd, []string{"id:steward-abc"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "timed out")
	})
}

// ---------------------------------------------------------------------------
// Status tests
// ---------------------------------------------------------------------------

func TestRunStewardUpgradeStatus_ByUpgradeID(t *testing.T) {
	var requestPath string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPath = r.URL.Path
		stewards := []APIUpgradeStewardStatus{
			{Device: "device-1", Version: "v0.5.12", Status: "committed", CompletedAt: "2026-06-01T12:00:00Z"},
		}
		writeUpgradeStatusResponse(w, "upgrade-status-id", stewards)
	}))
	defer server.Close()

	saveStewardUpgradeGlobals(t)
	stewardURL = server.URL
	stewardTLSInsecure = true
	stewardUpgradeID = "upgrade-status-id"

	output := captureStdout(t, func() {
		err := runStewardUpgradeStatus(stewardUpgradeStatusCmd, []string{})
		require.NoError(t, err)
	})

	assert.Equal(t, "/api/v1/stewards/upgrade/upgrade-status-id", requestPath)
	assert.Contains(t, output, "device-1")
	assert.Contains(t, output, "v0.5.12")
	assert.Contains(t, output, "committed")
}

func TestRunStewardUpgradeStatus_BySelector(t *testing.T) {
	var requestURL string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestURL = r.URL.String()
		stewards := []APIUpgradeStewardStatus{
			{Device: "device-2", Version: "v0.5.11", Status: "committed", CompletedAt: "2026-06-01T11:00:00Z"},
		}
		writeUpgradeStatusResponse(w, "", stewards)
	}))
	defer server.Close()

	saveStewardUpgradeGlobals(t)
	stewardURL = server.URL
	stewardTLSInsecure = true
	stewardUpgradeID = "" // no --upgrade-id

	output := captureStdout(t, func() {
		err := runStewardUpgradeStatus(stewardUpgradeStatusCmd, []string{"group:production"})
		require.NoError(t, err)
	})

	assert.Contains(t, requestURL, "/api/v1/stewards/upgrade")
	assert.Contains(t, requestURL, "selector=group%3Aproduction")
	assert.Contains(t, output, "device-2")
	assert.Contains(t, output, "v0.5.11")
}

func TestRunStewardUpgradeStatus_RequiresSelectorOrUpgradeID(t *testing.T) {
	saveStewardUpgradeGlobals(t)
	stewardUpgradeID = ""

	err := runStewardUpgradeStatus(stewardUpgradeStatusCmd, []string{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "selector")
}

func TestRunStewardUpgradeStatus_EmptyResult(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeUpgradeStatusResponse(w, "upgrade-empty-id", []APIUpgradeStewardStatus{})
	}))
	defer server.Close()

	saveStewardUpgradeGlobals(t)
	stewardURL = server.URL
	stewardTLSInsecure = true
	stewardUpgradeID = "upgrade-empty-id"

	output := captureStdout(t, func() {
		err := runStewardUpgradeStatus(stewardUpgradeStatusCmd, []string{})
		require.NoError(t, err)
	})

	assert.Contains(t, output, "No upgrade records")
}

// ---------------------------------------------------------------------------
// Rollback tests
// ---------------------------------------------------------------------------

func TestRunStewardUpgradeRollback_RequiresUpgradeIDOrVersion(t *testing.T) {
	saveStewardUpgradeGlobals(t)
	stewardUpgradeID = ""
	stewardUpgradeToVersion = ""

	err := runStewardUpgradeRollback(stewardUpgradeRollbackCmd, []string{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rollback requires")
}

func TestRunStewardUpgradeRollback_ToVersionAloneRequiresUpgradeID(t *testing.T) {
	saveStewardUpgradeGlobals(t)
	stewardUpgradeID = ""
	stewardUpgradeToVersion = "v0.5.10"

	err := runStewardUpgradeRollback(stewardUpgradeRollbackCmd, []string{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--upgrade-id")
}

func TestRunStewardUpgradeRollback_Success(t *testing.T) {
	var requestPath, requestMethod string
	var requestBody []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPath = r.URL.Path
		requestMethod = r.Method
		requestBody, _ = io.ReadAll(r.Body)
		stewards := []APIUpgradeStewardStatus{
			{Device: "device-1", Status: "rolled_back"},
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(APIUpgradeStatusResponse{
			UpgradeID: "upgrade-rollback-id",
			Stewards:  stewards,
		})
	}))
	defer server.Close()

	saveStewardUpgradeGlobals(t)
	stewardURL = server.URL
	stewardTLSInsecure = true
	stewardUpgradeID = "upgrade-rollback-id"
	stewardUpgradeToVersion = ""

	output := captureStdout(t, func() {
		err := runStewardUpgradeRollback(stewardUpgradeRollbackCmd, []string{})
		require.NoError(t, err)
	})

	assert.Equal(t, http.MethodPost, requestMethod)
	assert.Equal(t, "/api/v1/stewards/upgrade/upgrade-rollback-id/rollback", requestPath)
	assert.Contains(t, output, "device-1")
	assert.Contains(t, output, "rolled_back")

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(requestBody, &body))
	// to_version should be empty/absent
	assert.Empty(t, body["to_version"])
}

func TestRunStewardUpgradeRollback_WithToVersion(t *testing.T) {
	var requestBody []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestBody, _ = io.ReadAll(r.Body)
		stewards := []APIUpgradeStewardStatus{
			{Device: "device-1", Status: "rolled_back"},
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(APIUpgradeStatusResponse{
			UpgradeID: "upgrade-tv-id",
			Stewards:  stewards,
		})
	}))
	defer server.Close()

	saveStewardUpgradeGlobals(t)
	stewardURL = server.URL
	stewardTLSInsecure = true
	stewardUpgradeID = "upgrade-tv-id"
	stewardUpgradeToVersion = "v0.5.10"

	_ = captureStdout(t, func() {
		require.NoError(t, runStewardUpgradeRollback(stewardUpgradeRollbackCmd, []string{}))
	})

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(requestBody, &body))
	assert.Equal(t, "v0.5.10", body["to_version"])
}

func TestRunStewardUpgradeRollback_EmptyResult(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(APIUpgradeStatusResponse{
			UpgradeID: "upgrade-empty-rollback-id",
			Stewards:  []APIUpgradeStewardStatus{},
		})
	}))
	defer server.Close()

	saveStewardUpgradeGlobals(t)
	stewardURL = server.URL
	stewardTLSInsecure = true
	stewardUpgradeID = "upgrade-empty-rollback-id"

	output := captureStdout(t, func() {
		err := runStewardUpgradeRollback(stewardUpgradeRollbackCmd, []string{})
		require.NoError(t, err)
	})

	assert.Contains(t, output, "No stewards")
}

func TestRunStewardUpgradeRollback_HTTPErrorReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "upgrade record not found"})
	}))
	defer server.Close()

	saveStewardUpgradeGlobals(t)
	stewardURL = server.URL
	stewardTLSInsecure = true
	stewardUpgradeID = "nonexistent-upgrade-id"

	err := runStewardUpgradeRollback(stewardUpgradeRollbackCmd, []string{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "upgrade record not found")
}

// ---------------------------------------------------------------------------
// Flag registration tests — no --tls-insecure on upgrade commands
// ---------------------------------------------------------------------------

func TestStewardUpgradeCommandsRegistered(t *testing.T) {
	names := map[string]bool{}
	for _, cmd := range stewardCmd.Commands() {
		names[cmd.Name()] = true
	}
	assert.True(t, names["upgrade"], "stewardCmd must have 'upgrade' subcommand")

	upgradeNames := map[string]bool{}
	for _, cmd := range stewardUpgradeCmd.Commands() {
		upgradeNames[cmd.Name()] = true
	}
	assert.True(t, upgradeNames["status"], "upgrade cmd must have 'status' subcommand")
	assert.True(t, upgradeNames["rollback"], "upgrade cmd must have 'rollback' subcommand")
}

func TestStewardUpgradeFlagsRegistered(t *testing.T) {
	for _, flag := range []string{"url", "api-key", "tls-ca-cert", "version", "platform", "arch", "wait", "wait-timeout"} {
		assert.NotNil(t, stewardUpgradeCmd.Flags().Lookup(flag), "upgrade must have --%s flag", flag)
	}
	// --tls-insecure must NOT be registered on the upgrade command
	assert.Nil(t, stewardUpgradeCmd.Flags().Lookup("tls-insecure"), "upgrade must NOT have --tls-insecure flag")
}

func TestStewardUpgradeStatusFlagsRegistered(t *testing.T) {
	for _, flag := range []string{"url", "api-key", "tls-ca-cert", "upgrade-id"} {
		assert.NotNil(t, stewardUpgradeStatusCmd.Flags().Lookup(flag), "upgrade status must have --%s flag", flag)
	}
	assert.Nil(t, stewardUpgradeStatusCmd.Flags().Lookup("tls-insecure"), "upgrade status must NOT have --tls-insecure flag")
}

func TestStewardUpgradeRollbackFlagsRegistered(t *testing.T) {
	for _, flag := range []string{"url", "api-key", "tls-ca-cert", "upgrade-id", "to-version"} {
		assert.NotNil(t, stewardUpgradeRollbackCmd.Flags().Lookup(flag), "upgrade rollback must have --%s flag", flag)
	}
	assert.Nil(t, stewardUpgradeRollbackCmd.Flags().Lookup("tls-insecure"), "upgrade rollback must NOT have --tls-insecure flag")
}
