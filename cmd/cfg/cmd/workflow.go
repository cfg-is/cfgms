// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package cmd implements the CLI commands for cfg
package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// workflowNameRE bounds workflow names to a safe character set so they cannot
// inject path segments or query fragments when used to construct request URLs.
// Matches the controller's accepted name pattern: alphanumerics plus a small
// punctuation set, length 1–128. Enforced at parse time (defense in depth)
// AND the path segment is url.PathEscape'd at the sink (defense at the call).
var workflowNameRE = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,128}$`)

var (
	workflowURL         string
	workflowAPIKey      string
	workflowTLSCACert   string
	workflowTLSInsecure bool
)

// workflowCmd is the parent command for workflow subcommands.
var workflowCmd = &cobra.Command{
	Use:   "workflow",
	Short: "Manage and run workflows",
	Long:  `Commands for submitting and executing workflow definitions on the controller.`,
}

// workflowRunCmd submits a workflow YAML file to the controller and triggers execution.
var workflowRunCmd = &cobra.Command{
	Use:   "run <file.yaml>",
	Short: "Submit and execute a workflow definition",
	Long: `Read a workflow definition YAML file, submit it to the controller, and trigger execution.

The command prints the execution ID returned by the controller and exits.

Examples:
  # Run a workflow against a local controller
  cfg workflow run example-workflow.yaml --url=http://localhost:9080

  # Run with API key authentication
  cfg workflow run example-workflow.yaml --url=https://controller.example.com --api-key=mykey`,
	RunE: runWorkflow,
}

func init() {
	workflowRunCmd.Flags().StringVar(&workflowURL, "url", "", "Controller API URL (required)")
	workflowRunCmd.Flags().StringVar(&workflowAPIKey, "api-key", "", "API key for authentication")
	workflowRunCmd.Flags().StringVar(&workflowTLSCACert, "tls-ca-cert", "", "Path to CA certificate for TLS verification (env: CFGMS_TLS_CA_CERT)")
	workflowRunCmd.Flags().BoolVar(&workflowTLSInsecure, "tls-insecure", false, "Skip TLS verification (development only, env: CFGMS_TLS_INSECURE)")

	_ = workflowRunCmd.MarkFlagRequired("url")

	workflowCmd.AddCommand(workflowRunCmd)
}

// workflowDefinition is the local representation of a workflow YAML file.
// Fields mirror CreateWorkflowRequest on the server; kept local to avoid importing the server package.
type workflowDefinition struct {
	Name        string                   `yaml:"name"        json:"name"`
	Description string                   `yaml:"description" json:"description,omitempty"`
	Version     string                   `yaml:"version"     json:"version,omitempty"`
	Steps       []map[string]interface{} `yaml:"steps"       json:"steps"`
	Variables   map[string]interface{}   `yaml:"variables"   json:"variables,omitempty"`
}

// getWorkflowClient creates an API client using bundle auth (mTLS) when available,
// falling back to API key auth when no bundle is found or discovery is opted out.
func getWorkflowClient() (*APIClient, error) {
	apiURL := strings.TrimSuffix(workflowURL, "/")
	if apiURL == "" {
		apiURL = os.Getenv("CFGMS_API_URL")
	}

	client, err := resolveBundleClient(apiURL)
	if err != nil {
		return nil, fmt.Errorf("bundle lookup failed: %w", err)
	}
	if client != nil {
		return client, nil
	}

	apiKey := workflowAPIKey
	if apiKey == "" {
		apiKey = os.Getenv("CFGMS_API_KEY")
	}

	tlsInsecure := workflowTLSInsecure
	if !tlsInsecure && os.Getenv("CFGMS_TLS_INSECURE") == "true" {
		tlsInsecure = true
	}

	tlsCACertPath := workflowTLSCACert
	if tlsCACertPath == "" {
		tlsCACertPath = os.Getenv("CFGMS_TLS_CA_CERT")
	}

	return newClientFromFlags(apiURL, apiKey, tlsCACertPath, tlsInsecure)
}

func runWorkflow(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("workflow file argument is required")
	}

	filePath := args[0]
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read workflow file %q: %w", filePath, err)
	}

	var def workflowDefinition
	if err := yaml.Unmarshal(data, &def); err != nil {
		return fmt.Errorf("failed to parse workflow YAML: %w", err)
	}

	if def.Name == "" {
		return fmt.Errorf("workflow YAML must include a non-empty 'name' field")
	}
	if !workflowNameRE.MatchString(def.Name) {
		return fmt.Errorf("workflow name %q invalid: must match %s (alphanumerics, dot, underscore, hyphen; length 1–128)", def.Name, workflowNameRE.String())
	}

	client, err := getWorkflowClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	// POST /api/v1/workflows
	body, err := json.Marshal(def)
	if err != nil {
		return fmt.Errorf("failed to marshal workflow: %w", err)
	}

	createResp, err := client.doRequest(context.Background(), http.MethodPost, "/api/v1/workflows", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create workflow: %w", err)
	}
	defer func() { _ = createResp.Body.Close() }()

	if createResp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(createResp.Body)
		return fmt.Errorf("failed to create workflow: %s - %s", createResp.Status, string(respBody))
	}
	// Drain body to allow connection reuse.
	_, _ = io.Copy(io.Discard, createResp.Body)

	// POST /api/v1/workflows/{name}/execute
	// url.PathEscape on def.Name closes the SSRF path-injection sink (CWE-918);
	// defense-in-depth with the workflowNameRE validation above.
	executePath := "/api/v1/workflows/" + url.PathEscape(def.Name) + "/execute"
	executeResp, err := client.doRequest(context.Background(), http.MethodPost, executePath, bytes.NewReader([]byte("{}")))
	if err != nil {
		return fmt.Errorf("failed to execute workflow: %w", err)
	}
	defer func() { _ = executeResp.Body.Close() }()

	if executeResp.StatusCode != http.StatusAccepted {
		respBody, _ := io.ReadAll(executeResp.Body)
		return fmt.Errorf("failed to execute workflow: %s - %s", executeResp.Status, string(respBody))
	}

	var execResult struct {
		ExecutionID  string `json:"execution_id"`
		WorkflowName string `json:"workflow_name"`
		Status       string `json:"status"`
	}
	if err := json.NewDecoder(executeResp.Body).Decode(&execResult); err != nil {
		return fmt.Errorf("failed to parse execution response: %w", err)
	}

	fmt.Printf("Workflow submitted: %s\nExecution ID: %s\nStatus: %s\n",
		execResult.WorkflowName, execResult.ExecutionID, execResult.Status)

	return nil
}
