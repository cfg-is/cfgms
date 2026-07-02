// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package fleet

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// rollingJobResponse is the 202 Accepted body from POST /api/v1/jobs.
type rollingJobResponse struct {
	Data struct {
		JobID       string `json:"job_id"`
		Status      string `json:"status"`
		TargetCount int    `json:"target_count"`
	} `json:"data"`
}

// batchJobGetResponse is the JSON returned by GET /api/v1/jobs/{id}.
// BatchJob has no JSON tags, so the Go struct field names are used as JSON keys.
type batchJobGetResponse struct {
	Data struct {
		ID     string `json:"ID"`
		Status string `json:"Status"`
		Steps  []struct {
			Index      int      `json:"Index"`
			StewardIDs []string `json:"StewardIDs"`
			Status     string   `json:"Status"`
			FailedIDs  []string `json:"FailedIDs"`
		} `json:"Steps"`
	} `json:"data"`
}

// stewardDNAGetResponse is the JSON from GET /api/v1/stewards/{id}/dna.
type stewardDNAGetResponse struct {
	Data struct {
		ConfigHash string `json:"config_hash"`
	} `json:"data"`
}

// postBatchJob submits a rolling batch job via POST /api/v1/jobs and returns the job ID.
func postBatchJob(t *testing.T, suite *FleetTestSuite, selector string, batchSize int, previousConfigRef string) string {
	t.Helper()
	body, err := json.Marshal(map[string]interface{}{
		"selector":            selector,
		"batch_size":          batchSize,
		"previous_config_ref": previousConfigRef,
	})
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		suite.controllerURL+"/api/v1/jobs", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := suite.httpClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusAccepted, resp.StatusCode,
		"POST /api/v1/jobs must return 202: %s", string(respBody))

	var jobResp rollingJobResponse
	require.NoError(t, json.Unmarshal(respBody, &jobResp))
	require.NotEmpty(t, jobResp.Data.JobID, "job_id must be non-empty in job creation response")
	return jobResp.Data.JobID
}

// pollBatchJobStatus polls GET /api/v1/jobs/{id} until a terminal status is reached or
// the timeout expires. Terminal statuses: "completed", "failed", "rolled_back", "paused".
// Returns the terminal status, or "timeout" if none was observed within the deadline.
func pollBatchJobStatus(t *testing.T, suite *FleetTestSuite, jobID string, timeout, interval time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	last := "unknown"
	for time.Now().Before(deadline) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
			fmt.Sprintf("%s/api/v1/jobs/%s", suite.controllerURL, jobID), nil)
		if err != nil {
			time.Sleep(interval)
			continue
		}
		resp, err := suite.httpClient.Do(req)
		if err != nil {
			time.Sleep(interval)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			time.Sleep(interval)
			continue
		}
		var jobResp batchJobGetResponse
		if jsonErr := json.Unmarshal(body, &jobResp); jsonErr != nil {
			time.Sleep(interval)
			continue
		}
		last = jobResp.Data.Status
		switch last {
		case "completed", "failed", "rolled_back", "paused":
			t.Logf("Batch job %s reached terminal status: %s", jobID, last)
			return last
		}
		time.Sleep(interval)
	}
	t.Logf("pollBatchJobStatus: timeout after %v; last observed status = %q", timeout, last)
	return "timeout"
}

// fetchBatchJob calls GET /api/v1/jobs/{id} and returns the parsed response.
func fetchBatchJob(t *testing.T, suite *FleetTestSuite, jobID string) batchJobGetResponse {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		fmt.Sprintf("%s/api/v1/jobs/%s", suite.controllerURL, jobID), nil)
	require.NoError(t, err)
	resp, err := suite.httpClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var jobResp batchJobGetResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&jobResp))
	return jobResp
}

// getStewardConfigHash fetches the config_hash attribute from a steward's DNA
// via GET /api/v1/stewards/{id}/dna. Returns "" when unavailable.
func getStewardConfigHash(t *testing.T, suite *FleetTestSuite, stewardID string) string {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		fmt.Sprintf("%s/api/v1/stewards/%s/dna", suite.controllerURL, stewardID), nil)
	if err != nil {
		return ""
	}
	resp, err := suite.httpClient.Do(req)
	if err != nil {
		return ""
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var dnaResp stewardDNAGetResponse
	if decodeErr := json.NewDecoder(resp.Body).Decode(&dnaResp); decodeErr != nil {
		return ""
	}
	return dnaResp.Data.ConfigHash
}

// TestRollingUpdateWithMidBatchFailure proves the rolling-update rollback path:
//
//  1. Upload fleet-config.yaml to both stewards and capture fleet-steward-1's config_hash (v1Hash).
//  2. Stop fleet-steward-2 to inject a failure on the second batch.
//  3. Submit a batch job (batch_size=1, previous_config_ref="v1").
//     With 2 stewards and batch_size=1 the executor creates 2 steps:
//     step 0 → fleet-steward-1 (connected) → succeeds
//     step 1 → fleet-steward-2 (stopped)   → fails immediately (not in gRPC registry)
//  4. [REQUIRED TEST] Assert the job reaches "rolled_back" within 2 minutes.
//  5. [REQUIRED TEST] Assert fleet-steward-1's config_hash equals v1Hash after rollback.
//  6. Assert step 1 has status "failed" and FailedIDs contains fleet-steward-2's steward ID.
func TestRollingUpdateWithMidBatchFailure(t *testing.T) {
	if os.Getenv("CFGMS_FLEET_E2E") == "" {
		t.Skip("set CFGMS_FLEET_E2E=1 to run fleet E2E tests")
	}
	suite := setupFleetSuite(t)

	steward1ID := suite.stewardIDs["fleet-steward-1"]
	steward2ID := suite.stewardIDs["fleet-steward-2"]

	require.True(t, suite.waitForConvergence(t, steward1ID, 60*time.Second),
		"fleet-steward-1 must be connected before test")
	require.True(t, suite.waitForConvergence(t, steward2ID, 60*time.Second),
		"fleet-steward-2 must be connected before test")

	// Upload the baseline config (v1) to both stewards.
	configPath := "configs/fleet-config.yaml"
	require.NoError(t, suite.uploadConfig(t, steward1ID, configPath))
	require.NoError(t, suite.uploadConfig(t, steward2ID, configPath))

	// Wait for fleet-steward-1 to apply the config (managed-file present = convergence marker).
	require.True(t, suite.waitForManagedFile(t, "fleet-steward-1", 60*time.Second),
		"fleet-steward-1 must apply v1 config within 60s")

	// Capture the v1 config_hash from fleet-steward-1's DNA. The steward publishes
	// config_hash = sha256(configData) after each successful config apply; poll until
	// it appears.
	var v1Hash string
	hashDeadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(hashDeadline) {
		h := getStewardConfigHash(t, suite, steward1ID)
		if h != "" {
			v1Hash = h
			break
		}
		time.Sleep(3 * time.Second)
	}
	require.NotEmpty(t, v1Hash, "fleet-steward-1 config_hash must be non-empty after v1 config apply")
	t.Logf("v1 config_hash for fleet-steward-1: %s", v1Hash)

	// Register cleanup before stopping the container so fleet-steward-2 is always
	// restarted — even if the test fails mid-way or a subsequent assertion panics.
	t.Cleanup(func() {
		suite.containerStart(t, "fleet-steward-2", 90*time.Second)
	})

	// Stop fleet-steward-2 to inject a failure on the second batch.
	// docker stop closes the gRPC stream and removes the steward from the controller's
	// provider registry; SendCommand returns "steward not connected" immediately.
	suite.containerStop(t, "fleet-steward-2")

	// Wait for the controller to detect the disconnect before submitting the job.
	disconnected := false
	discDeadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(discDeadline) {
		state, err := suite.getStewardConnectionState(t, steward2ID)
		if err != nil || state != "connected" {
			disconnected = true
			t.Logf("fleet-steward-2 disconnected (state=%q)", state)
			break
		}
		time.Sleep(2 * time.Second)
	}
	require.True(t, disconnected,
		"fleet-steward-2 must be disconnected before submitting the batch job")

	// Submit a rolling batch job.
	// batch_size=1 → 2 steps (one steward per step).
	// previous_config_ref="v1" → executor triggers compensating rollback on step failure.
	jobID := postBatchJob(t, suite, "all", 1, "v1")
	t.Logf("Submitted batch job %s (selector=all, batch_size=1, previous_config_ref=v1)", jobID)

	// [REQUIRED TEST] Assert the job reaches "rolled_back" within 2 minutes.
	finalStatus := pollBatchJobStatus(t, suite, jobID, 2*time.Minute, 5*time.Second)
	require.Equal(t, "rolled_back", finalStatus,
		"batch job must reach rolled_back status after mid-batch failure with previous_config_ref set (got %q)", finalStatus)

	// [REQUIRED TEST] Assert fleet-steward-1 returns to config version "v1" after rollback.
	// The rollback re-dispatches CommandSyncConfig to fleet-steward-1, which re-applies
	// the current config and publishes a new config_hash. Since no new config was pushed,
	// the hash after rollback must match the hash captured before the rollout.
	var postRollbackHash string
	hashPollDeadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(hashPollDeadline) {
		h := getStewardConfigHash(t, suite, steward1ID)
		if h == v1Hash {
			postRollbackHash = h
			break
		}
		time.Sleep(3 * time.Second)
	}
	require.Equal(t, v1Hash, postRollbackHash,
		"fleet-steward-1 config_hash must match v1 after rollback (expected %q, got %q)",
		v1Hash, postRollbackHash)
	t.Logf("fleet-steward-1 config_hash after rollback: %s (matches v1)", postRollbackHash)

	// Verify the job step structure: step 1 must be the failed step containing steward-2.
	job := fetchBatchJob(t, suite, jobID)
	require.Greater(t, len(job.Data.Steps), 1,
		"job must have at least 2 steps (one per steward with batch_size=1)")
	failedStep := job.Data.Steps[1]
	require.Equal(t, "failed", failedStep.Status,
		"step 1 must have status 'failed' (fleet-steward-2 was stopped)")
	require.Contains(t, failedStep.FailedIDs, steward2ID,
		"step 1 FailedIDs must contain fleet-steward-2's steward ID")

	// t.Cleanup restarts fleet-steward-2.
}
