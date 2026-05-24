// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

// TestWorkflowRunCmd_InvalidName covers the workflowNameRE validation that
// closes the CWE-918 SSRF path-injection surface: workflow names containing
// path separators, traversal sequences, or non-allowed characters are rejected
// at YAML-parse time before any URL is constructed.
func TestWorkflowRunCmd_InvalidName(t *testing.T) {
	origURL := workflowURL
	origInsecure := workflowTLSInsecure
	t.Cleanup(func() {
		workflowURL = origURL
		workflowTLSInsecure = origInsecure
	})
	workflowURL = "http://localhost:9080"
	workflowTLSInsecure = true

	cases := []struct {
		name    string
		wfName  string
		wantSub string
	}{
		{"path traversal", "../admin/delete", "must match"},
		{"forward slash", "foo/bar", "must match"},
		{"backslash", "foo\\bar", "must match"},
		{"space", "foo bar", "must match"},
		{"shell metachar", "foo;rm", "must match"},
		{"empty after regex", "", "non-empty 'name' field"}, // Caught earlier by the existing check
		{"too long", strings.Repeat("a", 129), "must match"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			yamlFile := filepath.Join(tmpDir, "invalid.yaml")
			body := fmt.Sprintf("name: %q\nsteps:\n  - action: log\n", tc.wfName)
			require.NoError(t, os.WriteFile(yamlFile, []byte(body), 0600))

			err := runWorkflow(workflowRunCmd, []string{yamlFile})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantSub)
		})
	}
}

// TestWorkflowRunCmd_NameEscapedInPath asserts that a valid-but-special-character
// workflow name (e.g., containing a dot) is URL-escaped when used in the execute
// path. The regex allows dots; the dot is a path segment delimiter in some URL
// parsers, so url.PathEscape is still belt-and-suspenders defense.
func TestWorkflowRunCmd_NameEscapedInPath(t *testing.T) {
	// Workflow name containing a dot is valid per workflowNameRE.
	// We assert the request path is `/api/v1/workflows/my.workflow/execute`
	// (PathEscape leaves dots alone but escapes anything else).
	wfName := "my.workflow"
	var executePath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/workflows" {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"abc","name":"my.workflow"}`))
			return
		}
		executePath = r.URL.Path
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"execution_id":"e1","workflow_name":"my.workflow","status":"running"}`))
	}))
	defer srv.Close()

	tmpDir := t.TempDir()
	yamlFile := filepath.Join(tmpDir, "ok.yaml")
	body := fmt.Sprintf("name: %s\nsteps:\n  - action: log\n", wfName)
	require.NoError(t, os.WriteFile(yamlFile, []byte(body), 0600))

	origURL := workflowURL
	origInsecure := workflowTLSInsecure
	t.Cleanup(func() {
		workflowURL = origURL
		workflowTLSInsecure = origInsecure
	})
	workflowURL = srv.URL
	workflowTLSInsecure = true

	err := runWorkflow(workflowRunCmd, []string{yamlFile})
	require.NoError(t, err)
	assert.Equal(t, "/api/v1/workflows/my.workflow/execute", executePath)
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
