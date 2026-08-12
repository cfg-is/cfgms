// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setRebootWindowFlags wires module-level flags for reboot-window test runs.
func setRebootWindowFlags(url, apiKey string) func() {
	origURL := rebootWindowURL
	origKey := rebootWindowAPIKey
	origInsecure := rebootWindowTLSInsecure
	rebootWindowURL = url
	rebootWindowAPIKey = apiKey
	rebootWindowTLSInsecure = true
	return func() {
		rebootWindowURL = origURL
		rebootWindowAPIKey = origKey
		rebootWindowTLSInsecure = origInsecure
	}
}

// resetRebootWindowTargets resets the --tenant/--steward module-level flags.
func resetRebootWindowTargets() {
	rebootWindowTenantID = ""
	rebootWindowStewardID = ""
	rebootWindowTimezone = ""
}

// minimalScheduleYAML is a minimal valid schedule for reboot-window CLI tests.
const minimalScheduleYAML = `schedules:
  - freq: weekly
    days: [sunday]
    start: "02:00"
    end: "04:00"
`

// TestRebootWindowSetCmd_TenantHappyPath verifies that runRebootWindowSet sends
// a PUT to /api/v1/tenants/{id}/reboot-window with the schedule_yaml body.
func TestRebootWindowSetCmd_TenantHappyPath(t *testing.T) {
	var capturedBody rebootWindowPutRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPut, r.Method)
		assert.Equal(t, "/api/v1/tenants/acme-corp/reboot-window", r.URL.Path)
		require.NoError(t, json.NewDecoder(r.Body).Decode(&capturedBody))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"tenant_id":               "acme-corp",
				"status":                  "scheduled",
				"next_occurrence":         "2026-08-17T02:00:00Z",
				"next_occurrence_display": "Sun 17 Aug 2026, 02:00",
			},
		})
	}))
	defer srv.Close()

	cleanup := setRebootWindowFlags(srv.URL, "test-key")
	defer cleanup()
	defer resetRebootWindowTargets()
	rebootWindowTenantID = "acme-corp"

	tmpDir := t.TempDir()
	scheduleFile := filepath.Join(tmpDir, "window.yaml")
	require.NoError(t, os.WriteFile(scheduleFile, []byte(minimalScheduleYAML), 0600))
	rebootWindowScheduleFile = scheduleFile

	var out bytes.Buffer
	rebootWindowSetCmd.SetOut(&out)
	err := runRebootWindowSet(rebootWindowSetCmd, nil)
	require.NoError(t, err)

	assert.Equal(t, minimalScheduleYAML, capturedBody.ScheduleYAML)
	output := out.String()
	assert.Contains(t, output, "Reboot window updated")
	assert.Contains(t, output, "scheduled")
}

// TestRebootWindowSetCmd_StewardHappyPath verifies a device-level PUT.
func TestRebootWindowSetCmd_StewardHappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPut, r.Method)
		assert.Equal(t, "/api/v1/stewards/sw-1234/reboot-window", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"steward_id": "sw-1234",
				"status":     "scheduled",
			},
		})
	}))
	defer srv.Close()

	cleanup := setRebootWindowFlags(srv.URL, "test-key")
	defer cleanup()
	defer resetRebootWindowTargets()
	rebootWindowStewardID = "sw-1234"

	tmpDir := t.TempDir()
	scheduleFile := filepath.Join(tmpDir, "window.yaml")
	require.NoError(t, os.WriteFile(scheduleFile, []byte(minimalScheduleYAML), 0600))
	rebootWindowScheduleFile = scheduleFile

	err := runRebootWindowSet(rebootWindowSetCmd, nil)
	require.NoError(t, err)
}

// TestRebootWindowSetCmd_MutuallyExclusiveTargets verifies that --tenant and --steward
// together produce an error before contacting the server.
func TestRebootWindowSetCmd_MutuallyExclusiveTargets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("should not reach server when both flags are set")
	}))
	defer srv.Close()

	cleanup := setRebootWindowFlags(srv.URL, "test-key")
	defer cleanup()
	defer resetRebootWindowTargets()
	rebootWindowTenantID = "acme-corp"
	rebootWindowStewardID = "sw-1234"

	tmpDir := t.TempDir()
	scheduleFile := filepath.Join(tmpDir, "window.yaml")
	require.NoError(t, os.WriteFile(scheduleFile, []byte(minimalScheduleYAML), 0600))
	rebootWindowScheduleFile = scheduleFile

	err := runRebootWindowSet(rebootWindowSetCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mutually exclusive")
}

// TestRebootWindowSetCmd_NoTarget verifies that missing --tenant and --steward produces
// an error.
func TestRebootWindowSetCmd_NoTarget(t *testing.T) {
	defer resetRebootWindowTargets()
	err := runRebootWindowSet(rebootWindowSetCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exactly one of --tenant or --steward")
}

// TestRebootWindowSetCmd_MissingFile verifies that a missing schedule file is reported.
func TestRebootWindowSetCmd_MissingFile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("should not reach server when file is missing")
	}))
	defer srv.Close()

	cleanup := setRebootWindowFlags(srv.URL, "test-key")
	defer cleanup()
	defer resetRebootWindowTargets()
	rebootWindowTenantID = "acme-corp"
	rebootWindowScheduleFile = "/nonexistent/missing.yaml"

	err := runRebootWindowSet(rebootWindowSetCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read schedule file")
}

// TestRebootWindowShowCmd_TenantHappyPath verifies runRebootWindowShow for a tenant.
func TestRebootWindowShowCmd_TenantHappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/tenants/acme-corp/reboot-window", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"tenant_id":               "acme-corp",
				"status":                  "scheduled",
				"next_occurrence":         "2026-08-17T02:00:00Z",
				"next_occurrence_display": "Sun 17 Aug 2026, 02:00 (America/New_York)",
				"tenant_default_timezone": "America/New_York",
			},
		})
	}))
	defer srv.Close()

	cleanup := setRebootWindowFlags(srv.URL, "test-key")
	defer cleanup()
	defer resetRebootWindowTargets()
	rebootWindowTenantID = "acme-corp"

	var out bytes.Buffer
	rebootWindowShowCmd.SetOut(&out)
	err := runRebootWindowShow(rebootWindowShowCmd, nil)
	require.NoError(t, err)

	output := out.String()
	assert.Contains(t, output, "scheduled")
	assert.Contains(t, output, "Sun 17 Aug 2026, 02:00")
	assert.Contains(t, output, "America/New_York")
}

// TestRebootWindowShowCmd_Unrestricted verifies that the show command prints the
// canonical unrestricted message when no window is in effect.
func TestRebootWindowShowCmd_Unrestricted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"tenant_id":               "acme-corp",
				"status":                  "unrestricted",
				"next_occurrence_display": "no reboot_window in effect — unrestricted",
			},
		})
	}))
	defer srv.Close()

	cleanup := setRebootWindowFlags(srv.URL, "test-key")
	defer cleanup()
	defer resetRebootWindowTargets()
	rebootWindowTenantID = "acme-corp"

	var out bytes.Buffer
	rebootWindowShowCmd.SetOut(&out)
	err := runRebootWindowShow(rebootWindowShowCmd, nil)
	require.NoError(t, err)

	output := out.String()
	assert.Contains(t, output, "unrestricted")
	assert.Contains(t, output, "no reboot_window in effect")
}

// TestRebootWindowShowCmd_StewardHappyPath verifies show for a steward.
func TestRebootWindowShowCmd_StewardHappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/stewards/sw-1234/reboot-window", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"steward_id":              "sw-1234",
				"status":                  "scheduled",
				"next_occurrence_display": "Sun 17 Aug 2026, 02:00",
			},
		})
	}))
	defer srv.Close()

	cleanup := setRebootWindowFlags(srv.URL, "test-key")
	defer cleanup()
	defer resetRebootWindowTargets()
	rebootWindowStewardID = "sw-1234"

	var out bytes.Buffer
	rebootWindowShowCmd.SetOut(&out)
	err := runRebootWindowShow(rebootWindowShowCmd, nil)
	require.NoError(t, err)

	assert.Contains(t, out.String(), "scheduled")
}

// TestRebootWindowSetCmd_WithTimezone verifies that --timezone is forwarded in the body.
func TestRebootWindowSetCmd_WithTimezone(t *testing.T) {
	var capturedBody rebootWindowPutRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewDecoder(r.Body).Decode(&capturedBody))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"tenant_id": "acme-corp",
				"status":    "scheduled",
			},
		})
	}))
	defer srv.Close()

	cleanup := setRebootWindowFlags(srv.URL, "test-key")
	defer cleanup()
	defer resetRebootWindowTargets()
	rebootWindowTenantID = "acme-corp"
	rebootWindowTimezone = "Europe/London"

	tmpDir := t.TempDir()
	scheduleFile := filepath.Join(tmpDir, "window.yaml")
	require.NoError(t, os.WriteFile(scheduleFile, []byte(minimalScheduleYAML), 0600))
	rebootWindowScheduleFile = scheduleFile

	err := runRebootWindowSet(rebootWindowSetCmd, nil)
	require.NoError(t, err)
	assert.Equal(t, "Europe/London", capturedBody.TenantDefaultTimezone)
}
