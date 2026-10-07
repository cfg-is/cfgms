// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunJobSubmit_Success(t *testing.T) {
	wantJobID := "test-job-abc123"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/jobs", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)

		var body map[string]interface{}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		assert.Equal(t, "all", body["selector"])
		assert.InDelta(t, float64(5), body["batch_size"], 0.01)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"job_id":       wantJobID,
				"status":       "pending",
				"target_count": 42,
			},
		})
	}))
	defer ts.Close()

	origURL := jobURL
	origInsecure := jobTLSInsecure
	origSelector := jobSelector
	origBatchSize := jobBatchSize
	t.Cleanup(func() {
		jobURL = origURL
		jobTLSInsecure = origInsecure
		jobSelector = origSelector
		jobBatchSize = origBatchSize
	})

	jobURL = ts.URL
	jobTLSInsecure = true
	jobSelector = "all"
	jobBatchSize = 5

	require.NoError(t, runJobSubmit(jobSubmitCmd, []string{}))
}

func TestRunJobSubmit_ServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":{"message":"service unavailable"}}`))
	}))
	defer ts.Close()

	origURL := jobURL
	origInsecure := jobTLSInsecure
	origSelector := jobSelector
	t.Cleanup(func() {
		jobURL = origURL
		jobTLSInsecure = origInsecure
		jobSelector = origSelector
	})

	jobURL = ts.URL
	jobTLSInsecure = true
	jobSelector = "all"

	err := runJobSubmit(jobSubmitCmd, []string{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "job submission failed")
}

func TestRunJobStatus_Success(t *testing.T) {
	wantJobID := "status-job-xyz"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/jobs/"+wantJobID, r.URL.Path)
		assert.Equal(t, http.MethodGet, r.Method)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"ID":       wantJobID,
				"TenantID": "tenant-a",
				"Selector": "all",
				"Status":   "completed",
				"Steps":    []interface{}{},
			},
		})
	}))
	defer ts.Close()

	origURL := jobURL
	origInsecure := jobTLSInsecure
	t.Cleanup(func() {
		jobURL = origURL
		jobTLSInsecure = origInsecure
	})

	jobURL = ts.URL
	jobTLSInsecure = true

	require.NoError(t, runJobStatus(jobStatusCmd, []string{wantJobID}))
}

func TestRunJobStatus_NotFound(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":{"message":"not found"}}`))
	}))
	defer ts.Close()

	origURL := jobURL
	origInsecure := jobTLSInsecure
	t.Cleanup(func() {
		jobURL = origURL
		jobTLSInsecure = origInsecure
	})

	jobURL = ts.URL
	jobTLSInsecure = true

	err := runJobStatus(jobStatusCmd, []string{"nonexistent-id"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestRunJobStatus_WithSteps(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"ID":       "job-with-steps",
				"TenantID": "tenant-a",
				"Selector": "os:linux",
				"Status":   "running",
				"Steps": []interface{}{
					map[string]interface{}{
						"Index":      0,
						"StewardIDs": []string{"s1", "s2"},
						"Status":     "completed",
						"FailedIDs":  []string{},
					},
					map[string]interface{}{
						"Index":      1,
						"StewardIDs": []string{"s3"},
						"Status":     "running",
						"FailedIDs":  []string{"s3"},
					},
				},
			},
		})
	}))
	defer ts.Close()

	origURL := jobURL
	origInsecure := jobTLSInsecure
	t.Cleanup(func() {
		jobURL = origURL
		jobTLSInsecure = origInsecure
	})

	jobURL = ts.URL
	jobTLSInsecure = true

	require.NoError(t, runJobStatus(jobStatusCmd, []string{"job-with-steps"}))
}
