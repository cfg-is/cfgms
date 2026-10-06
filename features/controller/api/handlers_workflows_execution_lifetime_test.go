// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/workflow"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
)

// TestWorkflowExecute_OutlivesRequest guards Issue #4658: an execution started
// through the execute endpoint runs to completion after the response is sent.
// It is driven over a real HTTP server, which — unlike httptest.NewRecorder —
// cancels the request context when the handler returns; the execution used to
// inherit that cancellation and end "cancelled" almost immediately.
func TestWorkflowExecute_OutlivesRequest(t *testing.T) {
	h, _ := newTestWorkflowHandler(t)
	router := newWorkflowRouter(h)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), ctxkeys.TenantID, "tenant-a")
		ctx = context.WithValue(ctx, ctxkeys.TenantScopeKey, ctxkeys.NewTenantScope("tenant-a"))
		router.ServeHTTP(w, r.WithContext(ctx))
	}))
	t.Cleanup(srv.Close)

	body := mustMarshal(CreateWorkflowRequest{Name: "slow", Steps: []workflow.Step{
		{Name: "pause", Type: workflow.StepTypeDelay, Delay: &workflow.DelayConfig{Duration: 300 * time.Millisecond}},
	}})
	resp, err := http.Post(srv.URL+"/workflows", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	resp, err = http.Post(srv.URL+"/workflows/slow/execute", "application/json", bytes.NewReader([]byte("{}")))
	require.NoError(t, err)
	var started map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&started))
	_ = resp.Body.Close()
	require.Equal(t, http.StatusAccepted, resp.StatusCode)
	execID, _ := started["execution_id"].(string)
	require.NotEmpty(t, execID)

	var status workflow.ExecutionStatus
	require.Eventually(t, func() bool {
		execution, err := h.engine.GetExecution(execID)
		require.NoError(t, err)
		status = execution.GetStatus()
		return status == workflow.StatusCompleted || status == workflow.StatusFailed || status == workflow.StatusCancelled
	}, 10*time.Second, 20*time.Millisecond)
	assert.Equal(t, workflow.StatusCompleted, status, "the execution must not inherit the request's cancellation")
}
