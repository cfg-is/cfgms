// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package cmd implements the CLI commands for cfg
package cmd

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/cfgis/cfgms/pkg/cert/bundle"
	"github.com/spf13/cobra"
)

var (
	stewardURL              string
	stewardAPIKey           string
	stewardTLSCACert        string
	stewardTLSInsecure      bool
	stewardStatusJSONOutput bool
)

// stewardCmd is the parent command for steward subcommands.
var stewardCmd = &cobra.Command{
	Use:   "steward",
	Short: "Manage registered stewards",
	Long:  `Commands for inspecting and managing stewards registered with the controller.`,
}

// stewardListCmd lists all stewards registered with the controller.
var stewardListCmd = &cobra.Command{
	Use:   "list",
	Short: "List registered stewards",
	Long: `Display all stewards registered with the controller.

Prints a tabular list of steward IDs, tenants, statuses, and last-seen times.

Examples:
  # List stewards using admin bundle (mTLS auto-discovery)
  cfg steward list

  # List stewards with explicit URL
  cfg steward list --url=https://controller.example.com

  # List stewards with API key authentication
  cfg steward list --url=https://controller.example.com --api-key=your-key`,
	RunE: runStewardList,
}

// ---------------------------------------------------------------------------
// Package-level variables for steward run subcommands.
// ---------------------------------------------------------------------------

var (
	stewardRunTarget       string
	stewardRunScript       string
	stewardRunVersion      string
	stewardRunParams       []string
	stewardRunWait         bool
	stewardRunSkipOffline  bool
	stewardRunWaitTimeout  time.Duration
	stewardRunShell        string
	stewardRunResultDevice string
)

// runWaitPollInterval is the delay between status polls in the --wait loop.
// Overridable in tests to avoid real sleeps.
var runWaitPollInterval = 5 * time.Second

// ---------------------------------------------------------------------------
// Run subcommand definitions
// ---------------------------------------------------------------------------

var stewardRunScriptCmd = &cobra.Command{
	Use:   "run-script",
	Short: "Run a library script against matching stewards",
	Long: `Submit a library script to matching stewards and return a run ID.

Exits immediately (async) by default. Use --wait to block until completion.

Examples:
  cfg steward run-script --target os:linux --script my-script
  cfg steward run-script --script my-script --version v2 --wait --wait-timeout 10m`,
	RunE: runRunScript,
}

var stewardRunCommandCmd = &cobra.Command{
	Use:   "run-command <inline-content-or-file>",
	Short: "Run an inline command against matching stewards",
	Long: `Sign and submit an inline command or script file to matching stewards.

The argument is treated as a file path if the path exists on disk; otherwise
it is used as the inline script body. Content is base64-encoded and signed with
the operator's mTLS bundle key before transmission.

Requires an admin bundle with a private key (--bundle or CFGMS_ADMIN_BUNDLE).

Examples:
  cfg steward run-command --shell bash "echo hello"
  cfg steward run-command --shell bash ./scripts/deploy.sh --target os:linux`,
	Args: cobra.ExactArgs(1),
	RunE: runRunCommand,
}

var stewardRunStatusCmd = &cobra.Command{
	Use:   "run-status <run-id>",
	Short: "Show status of a run",
	Long: `Display the status and job counts for a run.

Examples:
  cfg steward run-status 550e8400-e29b-41d4-a716-446655440000`,
	Args: cobra.ExactArgs(1),
	RunE: runRunStatus,
}

var stewardRunResultCmd = &cobra.Command{
	Use:   "run-result <run-id>",
	Short: "Show job output for a run",
	Long: `Display per-steward job details for a completed or in-progress run.

Use --device to filter output to a single steward.

Examples:
  cfg steward run-result 550e8400-e29b-41d4-a716-446655440000
  cfg steward run-result 550e8400-e29b-41d4-a716-446655440000 --device steward-abc`,
	Args: cobra.ExactArgs(1),
	RunE: runRunResult,
}

var stewardRunCancelCmd = &cobra.Command{
	Use:   "run-cancel <run-id>",
	Short: "Cancel a run",
	Long: `Cancel all pending and running jobs within a run.

Examples:
  cfg steward run-cancel 550e8400-e29b-41d4-a716-446655440000`,
	Args: cobra.ExactArgs(1),
	RunE: runRunCancel,
}

func init() {
	stewardListCmd.Flags().StringVar(&stewardURL, "url", "", "Controller API URL")
	stewardListCmd.Flags().StringVar(&stewardAPIKey, "api-key", "", "API key for authentication")
	stewardListCmd.Flags().StringVar(&stewardTLSCACert, "tls-ca-cert", "", "Path to CA certificate for TLS verification (env: CFGMS_TLS_CA_CERT)")
	stewardListCmd.Flags().BoolVar(&stewardTLSInsecure, "tls-insecure", false, "Skip TLS verification (development only, env: CFGMS_TLS_INSECURE)")

	stewardStatusCmd.Flags().StringVar(&stewardURL, "url", "", "Controller API URL")
	stewardStatusCmd.Flags().StringVar(&stewardAPIKey, "api-key", "", "API key for authentication")
	stewardStatusCmd.Flags().StringVar(&stewardTLSCACert, "tls-ca-cert", "", "Path to CA certificate for TLS verification (env: CFGMS_TLS_CA_CERT)")
	stewardStatusCmd.Flags().BoolVar(&stewardTLSInsecure, "tls-insecure", false, "Skip TLS verification (development only, env: CFGMS_TLS_INSECURE)")
	stewardStatusCmd.Flags().BoolVar(&stewardStatusJSONOutput, "json", false, "Emit JSON output instead of human-readable text")

	// run-script flags
	stewardRunScriptCmd.Flags().StringVar(&stewardURL, "url", "", "Controller API URL")
	stewardRunScriptCmd.Flags().StringVar(&stewardAPIKey, "api-key", "", "API key for authentication")
	stewardRunScriptCmd.Flags().StringVar(&stewardTLSCACert, "tls-ca-cert", "", "Path to CA certificate (env: CFGMS_TLS_CA_CERT)")
	stewardRunScriptCmd.Flags().BoolVar(&stewardTLSInsecure, "tls-insecure", false, "Skip TLS verification (env: CFGMS_TLS_INSECURE)")
	stewardRunScriptCmd.Flags().StringVar(&stewardRunTarget, "target", "", "Fleet selector (e.g. os:linux, group:prod)")
	stewardRunScriptCmd.Flags().StringVar(&stewardRunScript, "script", "", "Script ID from the controller library")
	stewardRunScriptCmd.Flags().StringVar(&stewardRunVersion, "version", "", "Script version (default: latest)")
	stewardRunScriptCmd.Flags().StringArrayVar(&stewardRunParams, "param", nil, "Parameter key=value (repeatable)")
	stewardRunScriptCmd.Flags().BoolVar(&stewardRunWait, "wait", false, "Block until all jobs reach terminal state")
	stewardRunScriptCmd.Flags().BoolVar(&stewardRunSkipOffline, "skip-offline", false, "Skip offline stewards instead of queuing for them")
	stewardRunScriptCmd.Flags().DurationVar(&stewardRunWaitTimeout, "wait-timeout", 5*time.Minute, "Maximum time to wait when --wait is set")

	// run-command flags
	stewardRunCommandCmd.Flags().StringVar(&stewardURL, "url", "", "Controller API URL")
	stewardRunCommandCmd.Flags().StringVar(&stewardAPIKey, "api-key", "", "API key for authentication")
	stewardRunCommandCmd.Flags().StringVar(&stewardTLSCACert, "tls-ca-cert", "", "Path to CA certificate (env: CFGMS_TLS_CA_CERT)")
	stewardRunCommandCmd.Flags().BoolVar(&stewardTLSInsecure, "tls-insecure", false, "Skip TLS verification (env: CFGMS_TLS_INSECURE)")
	stewardRunCommandCmd.Flags().StringVar(&stewardRunTarget, "target", "", "Fleet selector (e.g. os:linux, group:prod)")
	stewardRunCommandCmd.Flags().StringVar(&stewardRunShell, "shell", "", "Shell to use (e.g. bash, sh, powershell)")
	stewardRunCommandCmd.Flags().StringArrayVar(&stewardRunParams, "param", nil, "Parameter key=value (repeatable)")
	stewardRunCommandCmd.Flags().BoolVar(&stewardRunWait, "wait", false, "Block until all jobs reach terminal state")
	stewardRunCommandCmd.Flags().BoolVar(&stewardRunSkipOffline, "skip-offline", false, "Skip offline stewards instead of queuing for them")
	stewardRunCommandCmd.Flags().DurationVar(&stewardRunWaitTimeout, "wait-timeout", 5*time.Minute, "Maximum time to wait when --wait is set")

	// run-status flags
	stewardRunStatusCmd.Flags().StringVar(&stewardURL, "url", "", "Controller API URL")
	stewardRunStatusCmd.Flags().StringVar(&stewardAPIKey, "api-key", "", "API key for authentication")
	stewardRunStatusCmd.Flags().StringVar(&stewardTLSCACert, "tls-ca-cert", "", "Path to CA certificate (env: CFGMS_TLS_CA_CERT)")
	stewardRunStatusCmd.Flags().BoolVar(&stewardTLSInsecure, "tls-insecure", false, "Skip TLS verification (env: CFGMS_TLS_INSECURE)")

	// run-result flags
	stewardRunResultCmd.Flags().StringVar(&stewardURL, "url", "", "Controller API URL")
	stewardRunResultCmd.Flags().StringVar(&stewardAPIKey, "api-key", "", "API key for authentication")
	stewardRunResultCmd.Flags().StringVar(&stewardTLSCACert, "tls-ca-cert", "", "Path to CA certificate (env: CFGMS_TLS_CA_CERT)")
	stewardRunResultCmd.Flags().BoolVar(&stewardTLSInsecure, "tls-insecure", false, "Skip TLS verification (env: CFGMS_TLS_INSECURE)")
	stewardRunResultCmd.Flags().StringVar(&stewardRunResultDevice, "device", "", "Filter output to a single device ID")

	// run-cancel flags
	stewardRunCancelCmd.Flags().StringVar(&stewardURL, "url", "", "Controller API URL")
	stewardRunCancelCmd.Flags().StringVar(&stewardAPIKey, "api-key", "", "API key for authentication")
	stewardRunCancelCmd.Flags().StringVar(&stewardTLSCACert, "tls-ca-cert", "", "Path to CA certificate (env: CFGMS_TLS_CA_CERT)")
	stewardRunCancelCmd.Flags().BoolVar(&stewardTLSInsecure, "tls-insecure", false, "Skip TLS verification (env: CFGMS_TLS_INSECURE)")

	stewardCmd.AddCommand(stewardListCmd)
	stewardCmd.AddCommand(stewardStatusCmd)
	stewardCmd.AddCommand(stewardRunScriptCmd)
	stewardCmd.AddCommand(stewardRunCommandCmd)
	stewardCmd.AddCommand(stewardRunStatusCmd)
	stewardCmd.AddCommand(stewardRunResultCmd)
	stewardCmd.AddCommand(stewardRunCancelCmd)
}

// getStewardClient creates an API client using bundle auth (mTLS) when available,
// falling back to API key auth when no bundle is found or discovery is opted out.
func getStewardClient() (*APIClient, error) {
	apiURL := strings.TrimSuffix(stewardURL, "/")
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

	apiKey := stewardAPIKey
	if apiKey == "" {
		apiKey = os.Getenv("CFGMS_API_KEY")
	}

	tlsInsecure := stewardTLSInsecure
	if !tlsInsecure && os.Getenv("CFGMS_TLS_INSECURE") == "true" {
		tlsInsecure = true
	}

	tlsCACertPath := stewardTLSCACert
	if tlsCACertPath == "" {
		tlsCACertPath = os.Getenv("CFGMS_TLS_CA_CERT")
	}

	return newClientFromFlags(apiURL, apiKey, tlsCACertPath, tlsInsecure)
}

// stewardEntry is a local representation of a steward from the API response.
type stewardEntry struct {
	ID       string    `json:"id"`
	Status   string    `json:"status"`
	LastSeen time.Time `json:"last_seen"`
	Version  string    `json:"version"`
	DNA      *struct {
		Hostname string `json:"hostname"`
	} `json:"dna,omitempty"`
}

// stewardStatusCmd shows detailed status for a single steward.
var stewardStatusCmd = &cobra.Command{
	Use:   "status <id>",
	Short: "Show detailed status for a steward",
	Long: `Display full details for a single steward registered with the controller.

Prints labelled fields including id, status, last_seen, version, hostname, OS,
connection state, and other available metadata.

Examples:
  # Show status using admin bundle (mTLS auto-discovery)
  cfg steward status <steward-id>

  # Show status with explicit URL
  cfg steward status <steward-id> --url=https://controller.example.com

  # Show status as JSON
  cfg steward status <steward-id> --json`,
	Args: cobra.ExactArgs(1),
	RunE: runStewardStatus,
}

// stewardStatusInfo is a local representation of a steward detail from the API response.
type stewardStatusInfo struct {
	ID              string            `json:"id"`
	Status          string            `json:"status"`
	LastSeen        time.Time         `json:"last_seen"`
	Version         string            `json:"version"`
	ConnectionState string            `json:"connection_state"`
	ActiveSessions  int               `json:"active_sessions"`
	TenantID        string            `json:"tenant_id,omitempty"`
	Group           string            `json:"group,omitempty"`
	Metrics         map[string]string `json:"metrics,omitempty"`
	DNA             *struct {
		Hostname     string `json:"hostname"`
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
	} `json:"dna,omitempty"`
}

func runStewardStatus(cmd *cobra.Command, args []string) error {
	stewardID := args[0]

	client, err := getStewardClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	resp, err := client.Get(context.Background(), "/api/v1/stewards/"+stewardID)
	if err != nil {
		return fmt.Errorf("failed to fetch steward: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "failed to close response body: %v\n", err)
		}
	}()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("steward %s not found", stewardID)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API request failed: %s - %s", resp.Status, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if stewardStatusJSONOutput {
		_, err := os.Stdout.Write(body)
		return err
	}

	var apiResp struct {
		Data stewardStatusInfo `json:"data"`
	}
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	s := apiResp.Data
	fmt.Printf("ID:               %s\n", s.ID)
	fmt.Printf("Status:           %s\n", s.Status)
	fmt.Printf("Connection:       %s\n", s.ConnectionState)
	lastSeen := ""
	if !s.LastSeen.IsZero() {
		lastSeen = s.LastSeen.Format("2006-01-02 15:04:05")
	}
	fmt.Printf("Last Seen:        %s\n", lastSeen)
	fmt.Printf("Version:          %s\n", s.Version)
	if s.DNA != nil {
		fmt.Printf("Hostname:         %s\n", s.DNA.Hostname)
		fmt.Printf("OS:               %s\n", s.DNA.OS)
		if s.DNA.Architecture != "" {
			fmt.Printf("Architecture:     %s\n", s.DNA.Architecture)
		}
	}
	if s.TenantID != "" {
		fmt.Printf("Tenant ID:        %s\n", s.TenantID)
	}
	if s.Group != "" {
		fmt.Printf("Group:            %s\n", s.Group)
	}
	return nil
}

func runStewardList(cmd *cobra.Command, args []string) error {
	client, err := getStewardClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	resp, err := client.Get(context.Background(), "/api/v1/stewards")
	if err != nil {
		return fmt.Errorf("failed to fetch stewards: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			fmt.Printf("Failed to close response body: %v\n", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API request failed: %s - %s", resp.Status, string(body))
	}

	var apiResp struct {
		Data []stewardEntry `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if len(apiResp.Data) == 0 {
		fmt.Println("No stewards registered.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(w, "ID\tSTATUS\tVERSION\tLAST SEEN\tHOSTNAME"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "--\t------\t-------\t---------\t--------"); err != nil {
		return err
	}
	for _, s := range apiResp.Data {
		hostname := ""
		if s.DNA != nil {
			hostname = s.DNA.Hostname
		}
		lastSeen := ""
		if !s.LastSeen.IsZero() {
			lastSeen = s.LastSeen.Format("2006-01-02 15:04:05")
		}
		if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", s.ID, s.Status, s.Version, lastSeen, hostname); err != nil {
			return err
		}
	}
	return w.Flush()
}

// ---------------------------------------------------------------------------
// Run subcommand types
// ---------------------------------------------------------------------------

// commandSignature holds the cryptographic signature embedded in run-command requests.
type commandSignature struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`      // base64-encoded raw signature bytes
	PublicKey string `json:"public_key"` // cert PEM from the operator bundle
}

// runRecord mirrors the fields returned by GET /api/v1/runs/{run_id}.
type runRecord struct {
	RunID         string `json:"run_id"`
	Status        string `json:"status"`
	JobCount      int    `json:"job_count"`
	CompletedJobs int    `json:"completed_jobs"`
	FailedJobs    int    `json:"failed_jobs"`
}

// runJobRecord mirrors the fields returned by GET /api/v1/runs/{run_id}/jobs.
type runJobRecord struct {
	JobID       string `json:"job_id"`
	RunID       string `json:"run_id"`
	DeviceID    string `json:"device_id"`
	ExecutionID string `json:"execution_id,omitempty"`
	Status      string `json:"status"`
}

// ---------------------------------------------------------------------------
// run-script
// ---------------------------------------------------------------------------

func runRunScript(_ *cobra.Command, _ []string) error {
	params, err := parseRunParams(stewardRunParams)
	if err != nil {
		return err
	}

	reqBody := map[string]interface{}{
		"target":         stewardRunTarget,
		"script_id":      stewardRunScript,
		"script_version": stewardRunVersion,
		"params":         params,
		"skip_offline":   stewardRunSkipOffline,
	}

	bodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to encode request: %w", err)
	}

	client, err := getStewardClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	resp, err := client.doRequest(context.Background(), http.MethodPost, "/api/v1/runs/script", bytes.NewReader(bodyJSON))
	if err != nil {
		return fmt.Errorf("failed to submit run: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API request failed: %s - %s", resp.Status, string(body))
	}

	var apiResp struct {
		Data struct {
			RunID string `json:"run_id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	runID := apiResp.Data.RunID

	if stewardRunWait {
		fmt.Printf("Run ID: %s\n", runID)
		return waitForRun(context.Background(), client, runID, stewardRunWaitTimeout)
	}

	fmt.Println(runID)
	return nil
}

// ---------------------------------------------------------------------------
// run-command
// ---------------------------------------------------------------------------

func runRunCommand(_ *cobra.Command, args []string) error {
	content, err := readCommandContent(args[0])
	if err != nil {
		return err
	}

	sig, err := signCommandContent(content)
	if err != nil {
		return err
	}

	params, err := parseRunParams(stewardRunParams)
	if err != nil {
		return err
	}

	reqBody := map[string]interface{}{
		"target":       stewardRunTarget,
		"content":      base64.StdEncoding.EncodeToString(content),
		"shell":        stewardRunShell,
		"params":       params,
		"skip_offline": stewardRunSkipOffline,
		"signature":    sig,
	}

	bodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to encode request: %w", err)
	}

	client, err := getStewardClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	resp, err := client.doRequest(context.Background(), http.MethodPost, "/api/v1/runs/command", bytes.NewReader(bodyJSON))
	if err != nil {
		return fmt.Errorf("failed to submit run: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API request failed: %s - %s", resp.Status, string(body))
	}

	var apiResp struct {
		Data struct {
			RunID string `json:"run_id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	runID := apiResp.Data.RunID

	if stewardRunWait {
		fmt.Printf("Run ID: %s\n", runID)
		return waitForRun(context.Background(), client, runID, stewardRunWaitTimeout)
	}

	fmt.Println(runID)
	return nil
}

// ---------------------------------------------------------------------------
// run-status
// ---------------------------------------------------------------------------

func runRunStatus(_ *cobra.Command, args []string) error {
	runID := args[0]

	client, err := getStewardClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	run, err := fetchRunRecord(context.Background(), client, runID)
	if err != nil {
		return err
	}

	fmt.Printf("Run ID:    %s\n", run.RunID)
	fmt.Printf("Status:    %s\n", run.Status)
	fmt.Printf("Jobs:      %d total, %d completed, %d failed\n", run.JobCount, run.CompletedJobs, run.FailedJobs)
	return nil
}

// ---------------------------------------------------------------------------
// run-result
// ---------------------------------------------------------------------------

func runRunResult(_ *cobra.Command, args []string) error {
	runID := args[0]

	client, err := getStewardClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	resp, err := client.Get(context.Background(), "/api/v1/runs/"+runID+"/jobs")
	if err != nil {
		return fmt.Errorf("failed to fetch run jobs: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("run %s not found", runID)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API request failed: %s - %s", resp.Status, string(body))
	}

	var apiResp struct {
		Data []runJobRecord `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	jobs := apiResp.Data
	if stewardRunResultDevice != "" {
		filtered := jobs[:0]
		for _, j := range jobs {
			if j.DeviceID == stewardRunResultDevice {
				filtered = append(filtered, j)
			}
		}
		jobs = filtered
	}

	if len(jobs) == 0 {
		fmt.Println("No jobs found.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(w, "DEVICE\tSTATUS\tJOB ID\tEXECUTION ID"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "------\t------\t------\t------------"); err != nil {
		return err
	}
	for _, j := range jobs {
		if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", j.DeviceID, j.Status, j.JobID, j.ExecutionID); err != nil {
			return err
		}
	}
	return w.Flush()
}

// ---------------------------------------------------------------------------
// run-cancel
// ---------------------------------------------------------------------------

func runRunCancel(_ *cobra.Command, args []string) error {
	runID := args[0]

	client, err := getStewardClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	resp, err := client.doRequest(context.Background(), http.MethodDelete, "/api/v1/runs/"+runID, nil)
	if err != nil {
		return fmt.Errorf("failed to cancel run: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusNotFound:
		return fmt.Errorf("run %s not found", runID)
	case http.StatusConflict:
		return fmt.Errorf("run %s is already in a terminal state", runID)
	case http.StatusOK:
		fmt.Printf("Run %s cancelled\n", runID)
		return nil
	default:
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API request failed: %s - %s", resp.Status, string(body))
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// parseRunParams converts "key=value" strings to a map. Returns an error for
// any entry that does not contain exactly one "=".
func parseRunParams(params []string) (map[string]string, error) {
	result := make(map[string]string, len(params))
	for _, p := range params {
		parts := strings.SplitN(p, "=", 2)
		if len(parts) != 2 || parts[0] == "" {
			return nil, fmt.Errorf("invalid parameter %q: expected key=value format", p)
		}
		result[parts[0]] = parts[1]
	}
	return result, nil
}

// readCommandContent returns the raw bytes to sign and execute.
// If arg looks like an existing file path the file is read; otherwise arg
// itself is used as inline content.
func readCommandContent(arg string) ([]byte, error) {
	if _, err := os.Stat(arg); err == nil {
		data, err := os.ReadFile(arg) // #nosec G304 — user-provided path, intentional
		if err != nil {
			return nil, fmt.Errorf("read command file %q: %w", arg, err)
		}
		return data, nil
	}
	return []byte(arg), nil
}

// signCommandContent locates the operator's admin bundle, extracts its private
// key, and signs content. Returns an error if no bundle or no private key is found.
func signCommandContent(content []byte) (*commandSignature, error) {
	bundleEnvVal, _ := os.LookupEnv("CFGMS_ADMIN_BUNDLE")
	bundleFilePath, err := findBundlePath(bundleEnvVal)
	if err != nil {
		return nil, fmt.Errorf("bundle resolution failed: %w", err)
	}
	if bundleFilePath == "" {
		return nil, fmt.Errorf("no admin bundle found: run-command requires a bundle with a private key for signing; use --bundle or set CFGMS_ADMIN_BUNDLE")
	}

	b, err := bundle.Read(bundleFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read bundle at %s: %w", bundleFilePath, err)
	}

	if b.KeyPEM == "" {
		return nil, fmt.Errorf("bundle at %s has no private key: run-command requires signing capability", bundleFilePath)
	}

	privKey, err := parsePrivKeyFromPEM(b.KeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse bundle private key: %w", err)
	}

	var algorithm string
	switch privKey.(type) {
	case *rsa.PrivateKey:
		algorithm = "rsa-sha256"
	case *ecdsa.PrivateKey:
		algorithm = "ecdsa-sha256"
	default:
		return nil, fmt.Errorf("unsupported key type %T in bundle (expected RSA or ECDSA)", privKey)
	}

	digest, err := hashContent(content, algorithm)
	if err != nil {
		return nil, err
	}

	sigBytes, err := signDigest(digest, privKey, algorithm)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}

	return &commandSignature{
		Algorithm: algorithm,
		Value:     base64.StdEncoding.EncodeToString(sigBytes),
		PublicKey: b.CertPEM,
	}, nil
}

// parsePrivKeyFromPEM decodes a PEM block and parses a PKCS#8 private key.
func parsePrivKeyFromPEM(pemData string) (interface{}, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in key data")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	return key, nil
}

// fetchRunRecord calls GET /api/v1/runs/{runID} and returns the parsed record.
func fetchRunRecord(ctx context.Context, client *APIClient, runID string) (*runRecord, error) {
	resp, err := client.Get(ctx, "/api/v1/runs/"+runID)
	if err != nil {
		return nil, fmt.Errorf("failed to poll run: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("run %s not found", runID)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API request failed: %s - %s", resp.Status, string(body))
	}

	var apiResp struct {
		Data runRecord `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to parse run response: %w", err)
	}
	return &apiResp.Data, nil
}

// waitForRun polls GET /api/v1/runs/{runID} every runWaitPollInterval until the
// run reaches a terminal state or the timeout elapses.
func waitForRun(ctx context.Context, client *APIClient, runID string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for {
		run, err := fetchRunRecord(ctx, client, runID)
		if err != nil {
			return err
		}

		if isRunTerminal(run.Status) {
			fmt.Printf("Status: %s\n", run.Status)
			fmt.Printf("Jobs: %d total, %d completed, %d failed\n", run.JobCount, run.CompletedJobs, run.FailedJobs)
			return nil
		}

		if time.Now().After(deadline) {
			return fmt.Errorf("timed out after %s waiting for run %s (status: %s, %d/%d jobs completed)",
				timeout, runID, run.Status, run.CompletedJobs, run.JobCount)
		}

		fmt.Printf("Waiting... status: %s (%d/%d completed)\n", run.Status, run.CompletedJobs, run.JobCount)

		select {
		case <-time.After(runWaitPollInterval):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func isRunTerminal(status string) bool {
	return status == "completed" || status == "failed" || status == "cancelled"
}
