// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWorkflowRunCmd_MissingFile(t *testing.T) {
	origURL := workflowURL
	origInsecure := workflowTLSInsecure
	t.Cleanup(func() {
		workflowURL = origURL
		workflowTLSInsecure = origInsecure
	})

	workflowURL = "http://localhost:9080"
	workflowTLSInsecure = true

	// No args — cobra ExactArgs(1) check happens at command level; test RunE directly with empty args.
	err := runWorkflow(workflowRunCmd, []string{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "workflow file argument is required")
}

func TestWorkflowRunCmd_FileNotFound(t *testing.T) {
	origURL := workflowURL
	origInsecure := workflowTLSInsecure
	t.Cleanup(func() {
		workflowURL = origURL
		workflowTLSInsecure = origInsecure
	})

	workflowURL = "http://localhost:9080"
	workflowTLSInsecure = true

	err := runWorkflow(workflowRunCmd, []string{"/nonexistent/path/workflow.yaml"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read workflow file")
}

func TestWorkflowRunCmd_ParsesYAML(t *testing.T) {
	workflowYAML := `name: test-workflow
description: A test workflow
version: "1.0.0"
steps:
  - name: step-one
    action: log
    params:
      message: "hello"
`
	tmpDir := t.TempDir()
	yamlFile := filepath.Join(tmpDir, "test-workflow.yaml")
	require.NoError(t, os.WriteFile(yamlFile, []byte(workflowYAML), 0600))

	var capturedCreate map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/workflows":
			require.NoError(t, json.NewDecoder(r.Body).Decode(&capturedCreate))
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"workflow": map[string]interface{}{"name": "test-workflow"},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/workflows/test-workflow/execute":
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"execution_id":  "exec-abc123",
				"workflow_name": "test-workflow",
				"status":        "running",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	origURL := workflowURL
	origInsecure := workflowTLSInsecure
	t.Cleanup(func() {
		workflowURL = origURL
		workflowTLSInsecure = origInsecure
	})

	workflowURL = server.URL
	workflowTLSInsecure = true

	output := captureStdout(t, func() {
		err := runWorkflow(workflowRunCmd, []string{yamlFile})
		require.NoError(t, err)
	})

	assert.Equal(t, "test-workflow", capturedCreate["name"])
	assert.Contains(t, output, "exec-abc123")
}

func TestWorkflowRunCmd_MissingNameField(t *testing.T) {
	tmpDir := t.TempDir()
	yamlFile := filepath.Join(tmpDir, "noname.yaml")
	require.NoError(t, os.WriteFile(yamlFile, []byte("steps:\n  - action: log\n"), 0600))

	origURL := workflowURL
	origInsecure := workflowTLSInsecure
	t.Cleanup(func() {
		workflowURL = origURL
		workflowTLSInsecure = origInsecure
	})

	workflowURL = "http://localhost:9080"
	workflowTLSInsecure = true

	err := runWorkflow(workflowRunCmd, []string{yamlFile})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "non-empty 'name' field")
}

func TestWorkflowRunCmd_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	yamlFile := filepath.Join(tmpDir, "bad.yaml")
	require.NoError(t, os.WriteFile(yamlFile, []byte(":\tinvalid: yaml: [\n"), 0600))

	origURL := workflowURL
	origInsecure := workflowTLSInsecure
	t.Cleanup(func() {
		workflowURL = origURL
		workflowTLSInsecure = origInsecure
	})

	workflowURL = "http://localhost:9080"
	workflowTLSInsecure = true

	err := runWorkflow(workflowRunCmd, []string{yamlFile})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse workflow YAML")
}

func TestWorkflowRunCmd_APICreateError(t *testing.T) {
	workflowYAML := `name: fail-workflow
steps:
  - name: s1
    action: log
    params:
      message: hi
`
	tmpDir := t.TempDir()
	yamlFile := filepath.Join(tmpDir, "fail.yaml")
	require.NoError(t, os.WriteFile(yamlFile, []byte(workflowYAML), 0600))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "storage unavailable"})
	}))
	defer server.Close()

	origURL := workflowURL
	origInsecure := workflowTLSInsecure
	t.Cleanup(func() {
		workflowURL = origURL
		workflowTLSInsecure = origInsecure
	})

	workflowURL = server.URL
	workflowTLSInsecure = true

	err := runWorkflow(workflowRunCmd, []string{yamlFile})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create workflow")
}

func TestWorkflowRunCmd_APIExecuteError(t *testing.T) {
	workflowYAML := `name: exec-fail-workflow
steps:
  - name: s1
    action: log
    params:
      message: hi
`
	tmpDir := t.TempDir()
	yamlFile := filepath.Join(tmpDir, "execfail.yaml")
	require.NoError(t, os.WriteFile(yamlFile, []byte(workflowYAML), 0600))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/workflows":
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"workflow": map[string]interface{}{"name": "exec-fail-workflow"},
			})
		default:
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "engine error"})
		}
	}))
	defer server.Close()

	origURL := workflowURL
	origInsecure := workflowTLSInsecure
	t.Cleanup(func() {
		workflowURL = origURL
		workflowTLSInsecure = origInsecure
	})

	workflowURL = server.URL
	workflowTLSInsecure = true

	err := runWorkflow(workflowRunCmd, []string{yamlFile})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to execute workflow")
}

func TestWorkflowRunCmd_FlagsRegistered(t *testing.T) {
	assert.NotNil(t, workflowRunCmd.Flags().Lookup("url"), "--url flag must be registered")
	assert.NotNil(t, workflowRunCmd.Flags().Lookup("api-key"), "--api-key flag must be registered")
	assert.NotNil(t, workflowRunCmd.Flags().Lookup("tls-ca-cert"), "--tls-ca-cert flag must be registered")
	assert.NotNil(t, workflowRunCmd.Flags().Lookup("tls-insecure"), "--tls-insecure flag must be registered")
}

func TestWorkflowCmd_RegisteredOnRoot(t *testing.T) {
	var found bool
	for _, cmd := range rootCmd.Commands() {
		if cmd.Name() == "workflow" {
			found = true
			break
		}
	}
	assert.True(t, found, "workflow command must be registered on rootCmd")
}
