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

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	wfpkg "github.com/cfgis/cfgms/features/workflow"
	"github.com/cfgis/cfgms/pkg/security"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
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

// ---- workflow list -----------------------------------------------------------

func TestWorkflowList_CallsWorkflowsEndpoint(t *testing.T) {
	var requestPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"workflows": []map[string]interface{}{
				{"name": "my-workflow", "version": "1.0.0", "steps": []map[string]string{{"name": "s1"}, {"name": "s2"}}},
				{"name": "another-wf", "version": "2.1.0", "steps": []map[string]string{{"name": "s1"}}},
			},
			"count": 2,
		})
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
		err := runWorkflowList(workflowListCmd, nil)
		require.NoError(t, err)
	})

	assert.Equal(t, "/api/v1/workflows", requestPath)
	assert.Contains(t, output, "my-workflow")
	assert.Contains(t, output, "1.0.0")
	assert.Contains(t, output, "another-wf")
	assert.Contains(t, output, "2.1.0")
}

func TestWorkflowList_HeaderPresent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"workflows": []map[string]interface{}{
				{"name": "wf1", "version": "1.0.0", "steps": []map[string]string{{"name": "s1"}}},
			},
			"count": 1,
		})
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
		err := runWorkflowList(workflowListCmd, nil)
		require.NoError(t, err)
	})

	assert.True(t, strings.Contains(output, "NAME"), "header NAME must be present")
	assert.True(t, strings.Contains(output, "VERSION"), "header VERSION must be present")
	assert.True(t, strings.Contains(output, "STEPS"), "header STEPS must be present")
}

func TestWorkflowList_EmptyList_PrintsNoWorkflows(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"workflows": []interface{}{},
			"count":     0,
		})
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
		err := runWorkflowList(workflowListCmd, nil)
		require.NoError(t, err)
	})

	assert.Contains(t, output, "No workflows")
}

func TestWorkflowList_NonOKStatus_ReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal server error"}`))
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

	err := runWorkflowList(workflowListCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

func TestWorkflowList_FlagsRegistered(t *testing.T) {
	assert.NotNil(t, workflowListCmd.Flags().Lookup("url"), "--url flag must be registered on workflow list")
	assert.NotNil(t, workflowListCmd.Flags().Lookup("tls-ca-cert"), "--tls-ca-cert flag must be registered on workflow list")
	assert.NotNil(t, workflowListCmd.Flags().Lookup("tls-insecure"), "--tls-insecure flag must be registered on workflow list")
}

// ---- workflow status ---------------------------------------------------------

func TestWorkflowStatus_HappyPath_PrintsFields(t *testing.T) {
	var requestPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"id":            "exec_1234_1",
			"workflow_name": "my-workflow",
			"status":        "running",
			"current_step":  "step1",
			"start_time":    "2026-07-01T10:00:00Z",
			"error":         "",
		})
	}))
	defer server.Close()

	origURL := workflowURL
	origInsecure := workflowTLSInsecure
	origWF := workflowStatusWorkflow
	t.Cleanup(func() {
		workflowURL = origURL
		workflowTLSInsecure = origInsecure
		workflowStatusWorkflow = origWF
	})
	workflowURL = server.URL
	workflowTLSInsecure = true
	workflowStatusWorkflow = "my-workflow"

	output := captureStdout(t, func() {
		err := runWorkflowStatus(workflowStatusCmd, []string{"exec_1234_1"})
		require.NoError(t, err)
	})

	assert.Equal(t, "/api/v1/workflows/my-workflow/executions/exec_1234_1", requestPath)
	assert.Contains(t, output, "exec_1234_1")
	assert.Contains(t, output, "my-workflow")
	assert.Contains(t, output, "running")
	assert.Contains(t, output, "step1")
	assert.Contains(t, output, "2026-07-01")
}

func TestWorkflowStatus_NotFound_ReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"execution not found"}`))
	}))
	defer server.Close()

	origURL := workflowURL
	origInsecure := workflowTLSInsecure
	origWF := workflowStatusWorkflow
	t.Cleanup(func() {
		workflowURL = origURL
		workflowTLSInsecure = origInsecure
		workflowStatusWorkflow = origWF
	})
	workflowURL = server.URL
	workflowTLSInsecure = true
	workflowStatusWorkflow = "my-workflow"

	err := runWorkflowStatus(workflowStatusCmd, []string{"exec_9999_0"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestWorkflowStatus_InvalidExecutionID_ReturnsError(t *testing.T) {
	origWF := workflowStatusWorkflow
	t.Cleanup(func() { workflowStatusWorkflow = origWF })
	workflowStatusWorkflow = "my-workflow"

	err := runWorkflowStatus(workflowStatusCmd, []string{"../../../etc/passwd"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid")
}

func TestWorkflowStatus_FlagsRegistered(t *testing.T) {
	assert.NotNil(t, workflowStatusCmd.Flags().Lookup("url"), "--url flag must be registered on workflow status")
	assert.NotNil(t, workflowStatusCmd.Flags().Lookup("workflow"), "--workflow flag must be registered on workflow status")
	assert.NotNil(t, workflowStatusCmd.Flags().Lookup("tls-ca-cert"))
	assert.NotNil(t, workflowStatusCmd.Flags().Lookup("tls-insecure"))
}

func TestWorkflowStatus_RequiresExactlyOneArg(t *testing.T) {
	err := workflowStatusCmd.Args(workflowStatusCmd, []string{})
	require.Error(t, err, "zero args must error")

	err = workflowStatusCmd.Args(workflowStatusCmd, []string{"exec_1_1", "extra"})
	require.Error(t, err, "two args must error")
}

// ---- workflow cancel ---------------------------------------------------------

func TestWorkflowCancel_Success_PrintsCancelled(t *testing.T) {
	var requestPath string
	var requestMethod string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPath = r.URL.Path
		requestMethod = r.Method
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"cancelled": "exec_1234_1",
		})
	}))
	defer server.Close()

	origURL := workflowURL
	origInsecure := workflowTLSInsecure
	origWF := workflowCancelWorkflow
	t.Cleanup(func() {
		workflowURL = origURL
		workflowTLSInsecure = origInsecure
		workflowCancelWorkflow = origWF
	})
	workflowURL = server.URL
	workflowTLSInsecure = true
	workflowCancelWorkflow = "my-workflow"

	output := captureStdout(t, func() {
		err := runWorkflowCancel(workflowCancelCmd, []string{"exec_1234_1"})
		require.NoError(t, err)
	})

	assert.Equal(t, "/api/v1/workflows/my-workflow/executions/exec_1234_1/cancel", requestPath)
	assert.Equal(t, http.MethodPost, requestMethod)
	assert.Contains(t, output, "Cancelled execution exec_1234_1")
}

func TestWorkflowCancel_NotFound_ReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"execution not found"}`))
	}))
	defer server.Close()

	origURL := workflowURL
	origInsecure := workflowTLSInsecure
	origWF := workflowCancelWorkflow
	t.Cleanup(func() {
		workflowURL = origURL
		workflowTLSInsecure = origInsecure
		workflowCancelWorkflow = origWF
	})
	workflowURL = server.URL
	workflowTLSInsecure = true
	workflowCancelWorkflow = "my-workflow"

	err := runWorkflowCancel(workflowCancelCmd, []string{"exec_9999_0"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestWorkflowCancel_AlreadyTerminal_ReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":"execution is already in a terminal state"}`))
	}))
	defer server.Close()

	origURL := workflowURL
	origInsecure := workflowTLSInsecure
	origWF := workflowCancelWorkflow
	t.Cleanup(func() {
		workflowURL = origURL
		workflowTLSInsecure = origInsecure
		workflowCancelWorkflow = origWF
	})
	workflowURL = server.URL
	workflowTLSInsecure = true
	workflowCancelWorkflow = "my-workflow"

	err := runWorkflowCancel(workflowCancelCmd, []string{"exec_1234_1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "terminal")
}

func TestWorkflowCancel_InvalidExecutionID_ReturnsError(t *testing.T) {
	origWF := workflowCancelWorkflow
	t.Cleanup(func() { workflowCancelWorkflow = origWF })
	workflowCancelWorkflow = "my-workflow"

	err := runWorkflowCancel(workflowCancelCmd, []string{"../../../etc/passwd"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid")
}

func TestWorkflowCancel_FlagsRegistered(t *testing.T) {
	assert.NotNil(t, workflowCancelCmd.Flags().Lookup("url"), "--url flag must be registered on workflow cancel")
	assert.NotNil(t, workflowCancelCmd.Flags().Lookup("workflow"), "--workflow flag must be registered on workflow cancel")
	assert.NotNil(t, workflowCancelCmd.Flags().Lookup("tls-ca-cert"))
	assert.NotNil(t, workflowCancelCmd.Flags().Lookup("tls-insecure"))
}

func TestWorkflowCancel_RequiresExactlyOneArg(t *testing.T) {
	err := workflowCancelCmd.Args(workflowCancelCmd, []string{})
	require.Error(t, err, "zero args must error")

	err = workflowCancelCmd.Args(workflowCancelCmd, []string{"exec_1_1", "extra"})
	require.Error(t, err, "two args must error")
}

// ---- subcommand registration -------------------------------------------------

func TestWorkflowCmd_SubcommandsRegistered(t *testing.T) {
	names := make(map[string]bool)
	for _, cmd := range workflowCmd.Commands() {
		names[cmd.Name()] = true
	}
	assert.True(t, names["run"], "workflow run must be registered")
	assert.True(t, names["list"], "workflow list must be registered")
	assert.True(t, names["status"], "workflow status must be registered")
	assert.True(t, names["cancel"], "workflow cancel must be registered")
	assert.True(t, names["promote-hv-role"], "workflow promote-hv-role must be registered")
}

// ---- requireSingleSteward ---------------------------------------------------

func TestRequireSingleSteward_OneMatch_ReturnsIt(t *testing.T) {
	s := StewardInfo{ID: "steward-abc", TenantID: "acme-corp/hv", DNA: &StewardInfoDNA{Hostname: "hv01"}}
	got, err := requireSingleSteward([]StewardInfo{s})
	require.NoError(t, err)
	assert.Equal(t, s, got)
}

func TestRequireSingleSteward_MultipleMatches_HardError(t *testing.T) {
	matches := []StewardInfo{
		{ID: "steward-a", TenantID: "msp/client-1", DNA: &StewardInfoDNA{Hostname: "hv01"}},
		{ID: "steward-b", TenantID: "msp/client-2", DNA: &StewardInfoDNA{Hostname: "hv01"}},
	}
	_, err := requireSingleSteward(matches)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "2", "error must mention the match count")
	assert.Contains(t, err.Error(), "hv01#steward-a", "error must list the first candidate key")
	assert.Contains(t, err.Error(), "hv01#steward-b", "error must list the second candidate key")
	assert.Contains(t, err.Error(), "msp/client-1", "error must include tenant in listing")
	assert.Contains(t, err.Error(), "id:<steward-id>", "error must hint at narrowing with id:")
}

func TestRequireSingleSteward_MultipleMatches_NoYesEscape(t *testing.T) {
	// Confirm there is no --yes or proceed path: the function always errors for N>1.
	matches := []StewardInfo{
		{ID: "a", DNA: &StewardInfoDNA{Hostname: "h"}},
		{ID: "b", DNA: &StewardInfoDNA{Hostname: "h"}},
	}
	_, err := requireSingleSteward(matches)
	require.Error(t, err, "N>1 must always be a hard error with no escape hatch")
}

// ---- deriveHVPromoteCluster -------------------------------------------------

func TestDeriveHVPromoteCluster_NoClusterMembership_Error(t *testing.T) {
	s := StewardInfo{
		ID:  "s1",
		DNA: &StewardInfoDNA{}, // no cluster: fragments
	}
	_, err := deriveHVPromoteCluster(s, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a member of any cluster")
}

func TestDeriveHVPromoteCluster_OneCluster_ResolvedAutomatically(t *testing.T) {
	s := StewardInfo{
		ID: "s1",
		DNA: &StewardInfoDNA{
			Fragments: []*commonpb.Fragment{
				{FragmentId: "cluster:prod-fc"},
			},
		},
	}
	name, err := deriveHVPromoteCluster(s, "")
	require.NoError(t, err)
	assert.Equal(t, "prod-fc", name)
}

func TestDeriveHVPromoteCluster_OneCluster_OverrideMatch_OK(t *testing.T) {
	s := StewardInfo{
		ID: "s1",
		DNA: &StewardInfoDNA{
			Fragments: []*commonpb.Fragment{
				{FragmentId: "cluster:prod-fc"},
			},
		},
	}
	name, err := deriveHVPromoteCluster(s, "prod-fc")
	require.NoError(t, err)
	assert.Equal(t, "prod-fc", name)
}

func TestDeriveHVPromoteCluster_OneCluster_OverrideMismatch_Error(t *testing.T) {
	s := StewardInfo{
		ID: "s1",
		DNA: &StewardInfoDNA{
			Fragments: []*commonpb.Fragment{
				{FragmentId: "cluster:prod-fc"},
			},
		},
	}
	_, err := deriveHVPromoteCluster(s, "other-cluster")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "other-cluster")
	assert.Contains(t, err.Error(), "prod-fc")
}

func TestDeriveHVPromoteCluster_MultipleClusters_RequiresOverride(t *testing.T) {
	s := StewardInfo{
		ID: "s1",
		DNA: &StewardInfoDNA{
			Fragments: []*commonpb.Fragment{
				{FragmentId: "cluster:fc-east"},
				{FragmentId: "cluster:fc-west"},
			},
		},
	}
	_, err := deriveHVPromoteCluster(s, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fc-east")
	assert.Contains(t, err.Error(), "fc-west")
	assert.Contains(t, err.Error(), "--cluster")
}

func TestDeriveHVPromoteCluster_MultipleClusters_OverrideMatch_OK(t *testing.T) {
	s := StewardInfo{
		ID: "s1",
		DNA: &StewardInfoDNA{
			Fragments: []*commonpb.Fragment{
				{FragmentId: "cluster:fc-east"},
				{FragmentId: "cluster:fc-west"},
			},
		},
	}
	name, err := deriveHVPromoteCluster(s, "fc-east")
	require.NoError(t, err)
	assert.Equal(t, "fc-east", name)
}

func TestDeriveHVPromoteCluster_MultipleClusters_OverrideMismatch_Error(t *testing.T) {
	s := StewardInfo{
		ID: "s1",
		DNA: &StewardInfoDNA{
			Fragments: []*commonpb.Fragment{
				{FragmentId: "cluster:fc-east"},
				{FragmentId: "cluster:fc-west"},
			},
		},
	}
	_, err := deriveHVPromoteCluster(s, "fc-north")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fc-north")
	assert.Contains(t, err.Error(), "fc-east")
	assert.Contains(t, err.Error(), "fc-west")
}

func TestDeriveHVPromoteCluster_NilDNA_NoClusterError(t *testing.T) {
	s := StewardInfo{ID: "s1", DNA: nil}
	_, err := deriveHVPromoteCluster(s, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a member of any cluster")
}

func TestDeriveHVPromoteCluster_MalformedFragmentID_Ignored(t *testing.T) {
	// Fragments with empty names, nil pointers, or non-cluster prefixes are silently
	// skipped; only the valid cluster:good fragment determines the result.
	s := StewardInfo{
		ID: "s1",
		DNA: &StewardInfoDNA{
			Fragments: []*commonpb.Fragment{
				nil,                          // nil fragment — skipped
				{FragmentId: "cluster:"},     // empty name after prefix — skipped
				{FragmentId: "host:cpu"},     // non-cluster prefix — skipped
				{FragmentId: "cluster:good"}, // valid
			},
		},
	}
	name, err := deriveHVPromoteCluster(s, "")
	require.NoError(t, err)
	assert.Equal(t, "good", name)
}

// ---- runWorkflowPromoteHVRole ------------------------------------------------

// makePromoteServer returns a test HTTP server that captures the resolve,
// create-workflow, and execute-workflow requests.
type promoteTestCapture struct {
	resolveSelector string
	createBody      map[string]interface{}
	executeBody     map[string]interface{}
	executePath     string
}

func makePromoteServer(t *testing.T, cap *promoteTestCapture, stewards []map[string]interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/fleet/resolve":
			var req map[string]string
			_ = json.NewDecoder(r.Body).Decode(&req)
			cap.resolveSelector = req["selector"]
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": stewards,
			})

		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/workflows":
			_ = json.NewDecoder(r.Body).Decode(&cap.createBody)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{})

		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/execute"):
			cap.executePath = r.URL.Path
			_ = json.NewDecoder(r.Body).Decode(&cap.executeBody)
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"execution_id":  "exec-promote-1",
				"workflow_name": "promote-hv-role",
				"status":        "running",
			})

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestRunWorkflowPromoteHVRole_HappyPath_SingleCluster(t *testing.T) {
	var cap promoteTestCapture
	steward := map[string]interface{}{
		"id":        "steward-hv01",
		"tenant_id": "acme/prod",
		"status":    "online",
		"last_seen": "2026-07-01T00:00:00Z",
		"dna": map[string]interface{}{
			"hostname": "hv01",
			"fragments": []map[string]interface{}{
				{"fragment_id": "cluster:fc-prod"},
			},
		},
	}
	srv := makePromoteServer(t, &cap, []map[string]interface{}{steward})
	defer srv.Close()

	origURL := workflowURL
	origInsecure := workflowTLSInsecure
	origCluster := workflowPromoteHVRoleCluster
	t.Cleanup(func() {
		workflowURL = origURL
		workflowTLSInsecure = origInsecure
		workflowPromoteHVRoleCluster = origCluster
	})
	workflowURL = srv.URL
	workflowTLSInsecure = true
	workflowPromoteHVRoleCluster = ""

	output := captureStdout(t, func() {
		err := runWorkflowPromoteHVRole(workflowPromoteHVRoleCmd, []string{"MyVM", "hv01"})
		require.NoError(t, err)
	})

	assert.Contains(t, output, "exec-promote-1", "execution ID must be printed")
	assert.Equal(t, "/api/v1/workflows/promote-hv-role/execute", cap.executePath)

	vars, ok := cap.executeBody["variables"].(map[string]interface{})
	require.True(t, ok, "execute body must have variables")
	assert.Equal(t, "MyVM", vars["vm_name"])
	assert.Equal(t, "steward-hv01", vars["steward_id"])
	assert.Equal(t, "fc-prod", vars["cluster_name"])
	assert.Equal(t, "acme/prod", vars["tenant_id"])
}

func TestRunWorkflowPromoteHVRole_ZeroStewards_ErrorBeforeWorkflow(t *testing.T) {
	var cap promoteTestCapture
	srv := makePromoteServer(t, &cap, []map[string]interface{}{})
	defer srv.Close()

	origURL := workflowURL
	origInsecure := workflowTLSInsecure
	t.Cleanup(func() {
		workflowURL = origURL
		workflowTLSInsecure = origInsecure
	})
	workflowURL = srv.URL
	workflowTLSInsecure = true

	err := runWorkflowPromoteHVRole(workflowPromoteHVRoleCmd, []string{"MyVM", "hv01"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "matched no stewards")
	assert.Nil(t, cap.createBody, "no workflow must be created when selector matches zero stewards")
}

func TestRunWorkflowPromoteHVRole_MultipleStewards_HardError(t *testing.T) {
	var cap promoteTestCapture
	stewards := []map[string]interface{}{
		{"id": "s-a", "tenant_id": "msp/c1", "status": "online", "last_seen": "2026-01-01T00:00:00Z",
			"dna": map[string]interface{}{"hostname": "hv01", "attributes": map[string]interface{}{}}},
		{"id": "s-b", "tenant_id": "msp/c2", "status": "online", "last_seen": "2026-01-01T00:00:00Z",
			"dna": map[string]interface{}{"hostname": "hv01", "attributes": map[string]interface{}{}}},
	}
	srv := makePromoteServer(t, &cap, stewards)
	defer srv.Close()

	origURL := workflowURL
	origInsecure := workflowTLSInsecure
	t.Cleanup(func() {
		workflowURL = origURL
		workflowTLSInsecure = origInsecure
	})
	workflowURL = srv.URL
	workflowTLSInsecure = true

	err := runWorkflowPromoteHVRole(workflowPromoteHVRoleCmd, []string{"MyVM", "hv01"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "2", "must list the ambiguous count")
	assert.Nil(t, cap.createBody, "no workflow must be created when selector is ambiguous")
}

func TestRunWorkflowPromoteHVRole_ExecuteBodyContainsAllVariables(t *testing.T) {
	var cap promoteTestCapture
	steward := map[string]interface{}{
		"id":        "steward-xyz",
		"tenant_id": "tenant-123",
		"status":    "online",
		"last_seen": "2026-07-01T00:00:00Z",
		"dna": map[string]interface{}{
			"hostname": "hv02",
			"fragments": []map[string]interface{}{
				{"fragment_id": "cluster:cluster-a"},
			},
		},
	}
	srv := makePromoteServer(t, &cap, []map[string]interface{}{steward})
	defer srv.Close()

	origURL := workflowURL
	origInsecure := workflowTLSInsecure
	origCluster := workflowPromoteHVRoleCluster
	t.Cleanup(func() {
		workflowURL = origURL
		workflowTLSInsecure = origInsecure
		workflowPromoteHVRoleCluster = origCluster
	})
	workflowURL = srv.URL
	workflowTLSInsecure = true
	workflowPromoteHVRoleCluster = ""

	_ = captureStdout(t, func() {
		err := runWorkflowPromoteHVRole(workflowPromoteHVRoleCmd, []string{"VmAlpha", "hv02"})
		require.NoError(t, err)
	})

	vars, ok := cap.executeBody["variables"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "VmAlpha", vars["vm_name"])
	assert.Equal(t, "steward-xyz", vars["steward_id"])
	assert.Equal(t, "cluster-a", vars["cluster_name"])
	assert.Equal(t, "tenant-123", vars["tenant_id"])
}

func TestWorkflowPromoteHVRoleCmd_FlagsRegistered(t *testing.T) {
	assert.NotNil(t, workflowPromoteHVRoleCmd.Flags().Lookup("url"))
	assert.NotNil(t, workflowPromoteHVRoleCmd.Flags().Lookup("tls-ca-cert"))
	assert.NotNil(t, workflowPromoteHVRoleCmd.Flags().Lookup("tls-insecure"))
	assert.NotNil(t, workflowPromoteHVRoleCmd.Flags().Lookup("cluster"), "--cluster must be registered")
	assert.Nil(t, workflowPromoteHVRoleCmd.Flags().Lookup("yes"), "--yes must NOT be registered on promote-hv-role")
}

func TestWorkflowPromoteHVRoleCmd_RequiresExactlyTwoArgs(t *testing.T) {
	err := workflowPromoteHVRoleCmd.Args(workflowPromoteHVRoleCmd, []string{})
	require.Error(t, err)

	err = workflowPromoteHVRoleCmd.Args(workflowPromoteHVRoleCmd, []string{"vmname"})
	require.Error(t, err)

	err = workflowPromoteHVRoleCmd.Args(workflowPromoteHVRoleCmd, []string{"vmname", "selector", "extra"})
	require.Error(t, err)

	err = workflowPromoteHVRoleCmd.Args(workflowPromoteHVRoleCmd, []string{"vmname", "selector"})
	require.NoError(t, err)
}

// ---- promote-hv-role template validation -------------------------------------

// TestPromoteHVRoleTemplate_PassesProductionValidation verifies the embedded
// promote-hv-role template satisfies the exact constraints enforced by
// validateGenericRequest (validation_middleware.go): charset:safe_text and
// max_length:1024 on description, and ParseSemanticVersion on version.
// Uses the production validator — not a hand-rolled approximation — per AC.
func TestPromoteHVRoleTemplate_PassesProductionValidation(t *testing.T) {
	var wrapper workflowFileWrapper
	require.NoError(t, yaml.Unmarshal(promoteHVRoleTemplateData, &wrapper),
		"embedded template must parse as valid YAML")

	desc := wrapper.Workflow.Description

	validator := security.NewValidator()
	result := &security.ValidationResult{Valid: true}
	validator.ValidateString(result, "body.description", desc, "charset:safe_text", "max_length:1024")

	assert.True(t, result.Valid,
		"description must pass charset:safe_text + max_length:1024 (validateGenericRequest): %v", result.Errors)
	assert.LessOrEqual(t, len(desc), 1024,
		"description must be at most 1024 characters (validateGenericRequest body.description)")

	_, err := wfpkg.ParseSemanticVersion(wrapper.Workflow.Version)
	assert.NoError(t, err,
		"version %q must parse as semantic version N.N.N (ParseSemanticVersion)", wrapper.Workflow.Version)
}
