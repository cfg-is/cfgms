// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package cmd implements the CLI commands for cfg
package cmd

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/cfgis/cfgms/features/controller/clusterregistry"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

//go:embed templates/promote-hv-role.yaml
var promoteHVRoleTemplateData []byte

// workflowNameRE bounds workflow names to a safe character set so they cannot
// inject path segments or query fragments when used to construct request URLs.
// Matches the controller's accepted name pattern: alphanumerics plus a small
// punctuation set, length 1–128. Enforced at parse time (defense in depth)
// AND the path segment is url.PathEscape'd at the sink (defense at the call).
var workflowNameRE = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,128}$`)

// workflowExecutionIDRE bounds execution IDs to a safe character set to prevent
// path injection when constructing request URLs. url.PathEscape is applied at the
// sink as defense-in-depth.
var workflowExecutionIDRE = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)

var (
	workflowURL         string
	workflowAPIKey      string
	workflowTLSCACert   string
	workflowTLSInsecure bool
	workflowServerName  string

	workflowStatusWorkflow string
	workflowCancelWorkflow string

	workflowPromoteHVRoleCluster string
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

// workflowListCmd prints a table of workflow definitions registered on the controller.
var workflowListCmd = &cobra.Command{
	Use:   "list",
	Short: "List workflow definitions",
	Long: `Print a table of workflow definitions (name, version, step count) registered on the controller.

Examples:
  cfg workflow list --url=https://controller.example.com
  cfg workflow list --url=https://controller.example.com --api-key=mykey`,
	RunE: runWorkflowList,
}

// workflowStatusCmd prints the status of a single workflow execution.
var workflowStatusCmd = &cobra.Command{
	Use:   "status <execution-id>",
	Short: "Show the status of a workflow execution",
	Long: `Print execution state, current step, started_at, and error for a workflow execution.

The execution ID is returned by 'cfg workflow run'.

Examples:
  cfg workflow status exec_1234_1 --workflow my-workflow --url=https://controller.example.com`,
	Args: cobra.ExactArgs(1),
	RunE: runWorkflowStatus,
}

// workflowCancelCmd cancels a running workflow execution.
var workflowCancelCmd = &cobra.Command{
	Use:   "cancel <execution-id>",
	Short: "Cancel a running workflow execution",
	Long: `Cancel a running workflow execution. Returns an error if the execution is already in a terminal state (completed, failed, or cancelled).

The execution ID is returned by 'cfg workflow run'.

Examples:
  cfg workflow cancel exec_1234_1 --workflow my-workflow --url=https://controller.example.com`,
	Args: cobra.ExactArgs(1),
	RunE: runWorkflowCancel,
}

// workflowPromoteHVRoleCmd submits the embedded promote-hv-role workflow template
// for a specific VM on a single host identified by the steward selector.
var workflowPromoteHVRoleCmd = &cobra.Command{
	Use:   "promote-hv-role <vmname> <host-selector>",
	Short: "Promote a Hyper-V VM from standalone to Failover Cluster role",
	Long: `Submit the promote-hv-role workflow for a specific VM on the host identified by
<host-selector>. The selector uses the same grammar as 'cfg steward' commands —
see docs/administration/cli-selectors.md for the full reference.

Selector forms:
  hv01                   bare hostname (exact match)
  name:es-hv0*           hostname glob
  acme-corp/hv01         tenant-path/hostname (unambiguous cross-tenant)
  id:<steward-id>        exact steward ID

The selector MUST resolve to exactly one steward; a selector matching zero or
more than one steward is always a hard error. Use a tenant-path prefix or
id:<steward-id> to disambiguate across tenants that share a hostname.

When the resolved host belongs to exactly one cluster, --cluster is optional.
When it belongs to more than one, --cluster is required to name which cluster
to promote the VM into.

The command prints the execution ID, which can be observed with:
  cfg workflow status <execution-id> --workflow promote-hv-role

Examples:
  # Unambiguous single-tenant host with one cluster:
  cfg workflow promote-hv-role MyVM hv01 --url=https://controller.example.com

  # Multi-tenant environment — use tenant path to disambiguate:
  cfg workflow promote-hv-role MyVM acme-corp/hv01 --url=https://controller.example.com

  # Host in multiple clusters — specify which cluster:
  cfg workflow promote-hv-role MyVM hv01 --cluster fc-east --url=https://controller.example.com`,
	Args: cobra.ExactArgs(2),
	RunE: runWorkflowPromoteHVRole,
}

func init() {
	workflowRunCmd.Flags().StringVar(&workflowURL, "url", "", "Controller API URL (required)")
	workflowRunCmd.Flags().StringVar(&workflowAPIKey, "api-key", "", "API key for authentication")
	workflowRunCmd.Flags().StringVar(&workflowTLSCACert, "tls-ca-cert", "", "Path to CA certificate for TLS verification (env: CFGMS_TLS_CA_CERT)")
	workflowRunCmd.Flags().BoolVar(&workflowTLSInsecure, "tls-insecure", false, "Skip TLS verification (development only, env: CFGMS_TLS_INSECURE)")
	workflowRunCmd.Flags().StringVar(&workflowServerName, "server-name", "", "Override TLS server name for certificate verification")
	_ = workflowRunCmd.MarkFlagRequired("url")

	workflowListCmd.Flags().StringVar(&workflowURL, "url", "", "Controller API URL (required)")
	workflowListCmd.Flags().StringVar(&workflowAPIKey, "api-key", "", "API key for authentication")
	workflowListCmd.Flags().StringVar(&workflowTLSCACert, "tls-ca-cert", "", "Path to CA certificate for TLS verification (env: CFGMS_TLS_CA_CERT)")
	workflowListCmd.Flags().BoolVar(&workflowTLSInsecure, "tls-insecure", false, "Skip TLS verification (development only, env: CFGMS_TLS_INSECURE)")
	workflowListCmd.Flags().StringVar(&workflowServerName, "server-name", "", "Override TLS server name for certificate verification")
	_ = workflowListCmd.MarkFlagRequired("url")

	workflowStatusCmd.Flags().StringVar(&workflowURL, "url", "", "Controller API URL (required)")
	workflowStatusCmd.Flags().StringVar(&workflowAPIKey, "api-key", "", "API key for authentication")
	workflowStatusCmd.Flags().StringVar(&workflowTLSCACert, "tls-ca-cert", "", "Path to CA certificate for TLS verification (env: CFGMS_TLS_CA_CERT)")
	workflowStatusCmd.Flags().BoolVar(&workflowTLSInsecure, "tls-insecure", false, "Skip TLS verification (development only, env: CFGMS_TLS_INSECURE)")
	workflowStatusCmd.Flags().StringVar(&workflowServerName, "server-name", "", "Override TLS server name for certificate verification")
	workflowStatusCmd.Flags().StringVar(&workflowStatusWorkflow, "workflow", "", "Workflow name (required)")
	_ = workflowStatusCmd.MarkFlagRequired("url")
	_ = workflowStatusCmd.MarkFlagRequired("workflow")

	workflowCancelCmd.Flags().StringVar(&workflowURL, "url", "", "Controller API URL (required)")
	workflowCancelCmd.Flags().StringVar(&workflowAPIKey, "api-key", "", "API key for authentication")
	workflowCancelCmd.Flags().StringVar(&workflowTLSCACert, "tls-ca-cert", "", "Path to CA certificate for TLS verification (env: CFGMS_TLS_CA_CERT)")
	workflowCancelCmd.Flags().BoolVar(&workflowTLSInsecure, "tls-insecure", false, "Skip TLS verification (development only, env: CFGMS_TLS_INSECURE)")
	workflowCancelCmd.Flags().StringVar(&workflowServerName, "server-name", "", "Override TLS server name for certificate verification")
	workflowCancelCmd.Flags().StringVar(&workflowCancelWorkflow, "workflow", "", "Workflow name (required)")
	_ = workflowCancelCmd.MarkFlagRequired("url")
	_ = workflowCancelCmd.MarkFlagRequired("workflow")

	workflowPromoteHVRoleCmd.Flags().StringVar(&workflowURL, "url", "", "Controller API URL (required)")
	workflowPromoteHVRoleCmd.Flags().StringVar(&workflowAPIKey, "api-key", "", "API key for authentication")
	workflowPromoteHVRoleCmd.Flags().StringVar(&workflowTLSCACert, "tls-ca-cert", "", "Path to CA certificate for TLS verification (env: CFGMS_TLS_CA_CERT)")
	workflowPromoteHVRoleCmd.Flags().BoolVar(&workflowTLSInsecure, "tls-insecure", false, "Skip TLS verification (development only, env: CFGMS_TLS_INSECURE)")
	workflowPromoteHVRoleCmd.Flags().StringVar(&workflowServerName, "server-name", "", "Override TLS server name for certificate verification")
	workflowPromoteHVRoleCmd.Flags().StringVar(&workflowPromoteHVRoleCluster, "cluster", "", "Cluster name (required only to disambiguate a multi-cluster host)")
	_ = workflowPromoteHVRoleCmd.MarkFlagRequired("url")

	workflowCmd.AddCommand(workflowRunCmd, workflowListCmd, workflowStatusCmd, workflowCancelCmd, workflowPromoteHVRoleCmd)
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

// workflowListEntry is a single workflow entry returned by GET /api/v1/workflows.
type workflowListEntry struct {
	Name    string                   `json:"name"`
	Version string                   `json:"version"`
	Steps   []map[string]interface{} `json:"steps"`
}

// workflowListAPIResponse is the JSON shape of GET /api/v1/workflows.
type workflowListAPIResponse struct {
	Workflows []workflowListEntry `json:"workflows"`
	Count     int                 `json:"count"`
}

// workflowExecutionStatus is the JSON shape of GET /api/v1/workflows/{name}/executions/{exec_id}.
type workflowExecutionStatus struct {
	ID           string    `json:"id"`
	WorkflowName string    `json:"workflow_name"`
	Status       string    `json:"status"`
	CurrentStep  string    `json:"current_step,omitempty"`
	StartTime    time.Time `json:"start_time"`
	Error        string    `json:"error,omitempty"`
}

// getWorkflowClient creates an API client using bundle auth (mTLS) when available,
// falling back to API key auth when no bundle is found or discovery is opted out.
func getWorkflowClient() (*APIClient, error) {
	apiURL := strings.TrimSuffix(workflowURL, "/")
	if apiURL == "" {
		apiURL = os.Getenv("CFGMS_API_URL")
	}

	tlsInsecure := workflowTLSInsecure
	if !tlsInsecure {
		tlsInsecure = os.Getenv("CFGMS_TLS_INSECURE") == "true"
	}
	serverName := workflowServerName

	client, err := resolveSessionOrBundleClient(apiURL, tlsInsecure, serverName)
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

	tlsCACertPath := workflowTLSCACert
	if tlsCACertPath == "" {
		tlsCACertPath = os.Getenv("CFGMS_TLS_CA_CERT")
	}

	return newClientFromFlags(apiURL, apiKey, tlsCACertPath, tlsInsecure)
}

// submitWorkflow POSTs the workflow definition to the controller and executes it,
// printing the execution ID. executeBody is the raw JSON body for the execute
// endpoint — pass []byte("{}") for no variables.
//
// url.PathEscape on the workflow name closes the SSRF path-injection sink
// (CWE-918); the workflowNameRE validation at call sites is defense-in-depth.
func submitWorkflow(ctx context.Context, client *APIClient, def workflowDefinition, executeBody []byte) error {
	body, err := json.Marshal(def)
	if err != nil {
		return fmt.Errorf("failed to marshal workflow: %w", err)
	}

	createResp, err := client.doRequest(ctx, http.MethodPost, "/api/v1/workflows", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create workflow: %w", err)
	}
	defer func() { _ = createResp.Body.Close() }()

	if createResp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(createResp.Body)
		return fmt.Errorf("failed to create workflow: %s - %s", createResp.Status, string(respBody))
	}
	_, _ = io.Copy(io.Discard, createResp.Body)

	executePath := "/api/v1/workflows/" + url.PathEscape(def.Name) + "/execute"
	executeResp, err := client.doRequest(ctx, http.MethodPost, executePath, bytes.NewReader(executeBody))
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

func runWorkflow(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("workflow file argument is required")
	}

	filePath := args[0]
	// #nosec G304 -- the CLI operator explicitly selects the local workflow
	// definition to submit; this command only reads that requested file.
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

	return submitWorkflow(context.Background(), client, def, []byte("{}"))
}

// requireSingleSteward enforces the single-target constraint for promote-hv-role.
// It returns the one matching steward when len(matches) == 1, and a hard error
// listing all candidates when len(matches) > 1. len(matches) == 0 is never
// reached here because resolveOrFailFast already errors before this is called.
func requireSingleSteward(matches []StewardInfo) (StewardInfo, error) {
	if len(matches) == 1 {
		return matches[0], nil
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "selector matched %d stewards; promote-hv-role requires exactly one target.\n", len(matches))
	fmt.Fprintf(&sb, "Matched stewards:\n")
	for _, m := range matches {
		key := stewardKey(m)
		if m.TenantID != "" {
			fmt.Fprintf(&sb, "  %s (tenant: %s)\n", key, m.TenantID)
		} else {
			fmt.Fprintf(&sb, "  %s\n", key)
		}
	}
	fmt.Fprintf(&sb, "Narrow the selector with a tenant-path prefix (e.g. acme-corp/hv01) or use id:<steward-id>.")
	return StewardInfo{}, fmt.Errorf("%s", sb.String())
}

// deriveHVPromoteCluster resolves the cluster name for a promote-hv-role operation
// by calling clusterregistry.ClustersFromFragments on the steward's DNA fragments.
//
// Outcomes:
//
//	0 candidates → error: host is not a cluster member
//	1 candidate  → use it; error if clusterOverride is set but mismatched
//	2+ candidates → require clusterOverride; error listing candidates when absent or mismatched
func deriveHVPromoteCluster(steward StewardInfo, clusterOverride string) (string, error) {
	var candidates []string
	if steward.DNA != nil {
		candidates = clusterregistry.ClustersFromFragments(steward.DNA.Fragments)
	}

	switch len(candidates) {
	case 0:
		return "", fmt.Errorf("host is not a member of any cluster; nothing to promote")
	case 1:
		clusterName := candidates[0]
		if clusterOverride != "" && clusterOverride != clusterName {
			return "", fmt.Errorf("--cluster %q does not match the host's only cluster %q", clusterOverride, clusterName)
		}
		return clusterName, nil
	default:
		if clusterOverride == "" {
			return "", fmt.Errorf("host belongs to multiple clusters (%s); use --cluster to disambiguate",
				strings.Join(candidates, ", "))
		}
		for _, name := range candidates {
			if name == clusterOverride {
				return clusterOverride, nil
			}
		}
		return "", fmt.Errorf("--cluster %q does not match any of the host's clusters (%s)",
			clusterOverride, strings.Join(candidates, ", "))
	}
}

// workflowFileWrapper wraps the top-level "workflow:" key used by the
// promote-hv-role.yaml template so yaml.Unmarshal populates workflowDefinition
// correctly.
type workflowFileWrapper struct {
	Workflow workflowDefinition `yaml:"workflow"`
}

func runWorkflowPromoteHVRole(cmd *cobra.Command, args []string) error {
	vmName := args[0]
	selector := args[1]

	client, err := getWorkflowClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	matches, err := resolveOrFailFast(context.Background(), client, selector)
	if err != nil {
		return err
	}

	steward, err := requireSingleSteward(matches)
	if err != nil {
		return err
	}

	clusterName, err := deriveHVPromoteCluster(steward, workflowPromoteHVRoleCluster)
	if err != nil {
		return err
	}

	var wrapper workflowFileWrapper
	if err := yaml.Unmarshal(promoteHVRoleTemplateData, &wrapper); err != nil {
		return fmt.Errorf("failed to parse embedded promote-hv-role template: %w", err)
	}
	def := wrapper.Workflow

	variables := map[string]interface{}{
		"vm_name":      vmName,
		"steward_id":   steward.ID,
		"cluster_name": clusterName,
		"tenant_id":    steward.TenantID,
	}
	executeBody, err := json.Marshal(map[string]interface{}{"variables": variables})
	if err != nil {
		return fmt.Errorf("failed to marshal execute body: %w", err)
	}

	return submitWorkflow(context.Background(), client, def, executeBody)
}

func runWorkflowList(cmd *cobra.Command, args []string) error {
	client, err := getWorkflowClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	resp, err := client.doRequest(context.Background(), http.MethodGet, "/api/v1/workflows", nil)
	if err != nil {
		return fmt.Errorf("failed to list workflows: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("controller returned %s: %s", resp.Status, string(respBody))
	}

	var result workflowListAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if len(result.Workflows) == 0 {
		if _, err := fmt.Fprintln(os.Stdout, "No workflows registered."); err != nil {
			return fmt.Errorf("failed to write output: %w", err)
		}
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(w, "NAME\tVERSION\tSTEPS"); err != nil {
		return fmt.Errorf("failed to write output: %w", err)
	}
	for _, wf := range result.Workflows {
		if _, err := fmt.Fprintf(w, "%s\t%s\t%d\n", wf.Name, wf.Version, len(wf.Steps)); err != nil {
			return fmt.Errorf("failed to write output: %w", err)
		}
	}
	return w.Flush()
}

func runWorkflowStatus(cmd *cobra.Command, args []string) error {
	execID := args[0]
	if !workflowExecutionIDRE.MatchString(execID) {
		return fmt.Errorf("execution ID %q invalid: must match %s", execID, workflowExecutionIDRE.String())
	}

	wfName := workflowStatusWorkflow
	if !workflowNameRE.MatchString(wfName) {
		return fmt.Errorf("workflow name %q invalid: must match %s", wfName, workflowNameRE.String())
	}

	client, err := getWorkflowClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	// url.PathEscape prevents path injection at the sink.
	path := "/api/v1/workflows/" + url.PathEscape(wfName) + "/executions/" + url.PathEscape(execID)
	resp, err := client.doRequest(context.Background(), http.MethodGet, path, nil)
	if err != nil {
		return fmt.Errorf("failed to get execution status: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("execution %q not found for workflow %q", execID, wfName)
	}
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("controller returned %s: %s", resp.Status, string(respBody))
	}

	var ex workflowExecutionStatus
	if err := json.NewDecoder(resp.Body).Decode(&ex); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	errStr := ex.Error
	if errStr == "" {
		errStr = "-"
	}
	currentStep := ex.CurrentStep
	if currentStep == "" {
		currentStep = "-"
	}

	fmt.Printf("execution_id:  %s\n", ex.ID)
	fmt.Printf("workflow:      %s\n", ex.WorkflowName)
	fmt.Printf("status:        %s\n", ex.Status)
	fmt.Printf("current_step:  %s\n", currentStep)
	fmt.Printf("started_at:    %s\n", ex.StartTime.UTC().Format(time.RFC3339))
	fmt.Printf("error:         %s\n", errStr)

	return nil
}

func runWorkflowCancel(cmd *cobra.Command, args []string) error {
	execID := args[0]
	if !workflowExecutionIDRE.MatchString(execID) {
		return fmt.Errorf("execution ID %q invalid: must match %s", execID, workflowExecutionIDRE.String())
	}

	wfName := workflowCancelWorkflow
	if !workflowNameRE.MatchString(wfName) {
		return fmt.Errorf("workflow name %q invalid: must match %s", wfName, workflowNameRE.String())
	}

	client, err := getWorkflowClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	// url.PathEscape prevents path injection at the sink.
	path := "/api/v1/workflows/" + url.PathEscape(wfName) + "/executions/" + url.PathEscape(execID) + "/cancel"
	resp, err := client.doRequest(context.Background(), http.MethodPost, path, nil)
	if err != nil {
		return fmt.Errorf("failed to cancel execution: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		_, _ = io.Copy(io.Discard, resp.Body)
		fmt.Printf("Cancelled execution %s\n", execID)
		return nil
	case http.StatusNotFound:
		return fmt.Errorf("execution %q not found for workflow %q", execID, wfName)
	case http.StatusConflict:
		return fmt.Errorf("execution %q is already in a terminal state", execID)
	default:
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("controller returned %s: %s", resp.Status, string(respBody))
	}
}
