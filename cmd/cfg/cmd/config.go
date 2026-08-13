// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package cmd implements the CLI commands for cfg
package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/features/config/diff"
)

// errDifferencesFound is returned by runConfigDiff when the two configs differ.
// The cobra RunE handler converts this to os.Exit(1) without printing an error message,
// matching the conventional diff exit code 1 = "differences exist".
var errDifferencesFound = errors.New("configurations differ")

// secretKeyPatterns are case-insensitive substrings that mark a config key as sensitive.
var secretKeyPatterns = []string{"token", "secret", "password", "credential", "api_key"}

// rollbackPollInterval is the delay between status poll requests.
// Tests may override this to zero to avoid sleeping.
var rollbackPollInterval = 2 * time.Second

var (
	configUploadStewardID   string
	configUploadJSONOutput  bool
	configUploadURL         string
	configUploadAPIKey      string
	configUploadTLSCACert   string
	configUploadTLSInsecure bool
	configUploadServerName  string

	// Shared persistent connection flags for all config subcommands
	configAPIURL      string
	configAPIKey      string
	configTLSCACert   string
	configTLSInsecure bool
	configServerName  string

	// List command flags
	configListTenantID string
	configListJSON     bool

	// Show command flags
	configShowJSON bool

	// Deployments command flags
	configDeploymentsJSON bool

	// Diff command flags
	configDiffJSON           bool
	configDiffIncludeSecrets bool

	// Rollback command flags
	configRollbackTo     string
	configRollbackDryRun bool
	configRollbackJSON   bool
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage steward configurations",
	Long:  `Commands for uploading and managing steward configurations.`,
}

var configListCmd = &cobra.Command{
	Use:   "list",
	Short: "List stored steward configurations",
	Long: `List all stored steward configurations.

Use --tenant to filter by tenant ID.

Examples:
  cfg config list
  cfg config list --tenant=acme-corp`,
	RunE: runConfigList,
}

var configShowCmd = &cobra.Command{
	Use:   "show <steward-id>",
	Short: "Show the stored configuration for a steward",
	Long: `Show the stored YAML configuration for a specific steward.

Examples:
  cfg config show steward-abc123`,
	Args: cobra.ExactArgs(1),
	RunE: runConfigShow,
}

var configDeleteCmd = &cobra.Command{
	Use:   "delete <steward-id>",
	Short: "Delete the stored configuration for a steward",
	Long: `Delete the stored configuration for a specific steward.

Examples:
  cfg config delete steward-abc123`,
	Args: cobra.ExactArgs(1),
	RunE: runConfigDelete,
}

var configDeploymentsCmd = &cobra.Command{
	Use:   "deployments <config-id>",
	Short: "Show deployment status for a config",
	Long: `Show applied / pending / failed / halted aggregate counts and per-steward
deployment status for a given config ID.

The config-id is the identifier used when the configuration was pushed (the
config_id field in the push payload). Use 'cfg config list' to enumerate
stored configs and their IDs.

Examples:
  cfg config deployments my-prod-config
  cfg config deployments my-prod-config --json`,
	Args: cobra.ExactArgs(1),
	RunE: runConfigDeployments,
}

var configDiffCmd = &cobra.Command{
	Use:   "diff <steward-id> <new-cfg.yaml>",
	Short: "Diff local config against the config stored on the controller",
	Long: `Show what would change if <new-cfg.yaml> were uploaded to <steward-id>.

Fetches the config currently stored for the steward from the controller, then
diffs it against the local file using the same semantic engine as 'cfg diff'.
No mutation occurs.

Secret-bearing keys (those whose names contain token, secret, password,
credential, or api_key) are replaced with *** in the comparison by default.
Pass --include-secrets to show raw values.

Exit code is 1 when there are differences, 0 when configs are identical or
no config is stored for the steward.

Examples:
  cfg config diff steward-abc123 new-config.yaml
  cfg config diff steward-abc123 new-config.yaml --json
  cfg config diff steward-abc123 new-config.yaml --include-secrets`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		err := runConfigDiff(cmd, args)
		if errors.Is(err, errDifferencesFound) {
			os.Exit(1)
		}
		return err
	},
}

var configUploadCmd = &cobra.Command{
	Use:   "upload <file>",
	Short: "Upload a .cfg file to a steward",
	Long: `Upload a .cfg file to a registered steward.

Reads the file from disk and issues PUT /api/v1/stewards/{id}/config.
Auth uses the admin bundle (mTLS auto-discovery) by default.

Examples:
  # Upload a fleet config to a steward
  cfg config upload fleet-config.cfg --steward steward-abc123

  # Upload with JSON response output
  cfg config upload fleet-config.cfg --steward steward-abc123 --json

  # Upload using explicit controller URL
  cfg config upload fleet-config.cfg --steward steward-abc123 --url=https://ctrl.example.com:9080`,
	Args: cobra.ExactArgs(1),
	RunE: runConfigUpload,
}

var configRollbackCmd = &cobra.Command{
	Use:   "rollback <steward-id>",
	Short: "Roll back a steward's configuration to a previous version",
	Long: `Restore a previous configuration version for a steward.

When --to is specified, executes (or previews with --dry-run) the rollback.
If --to is omitted, lists available rollback points for the steward and exits.

Status codes returned by the server:
  412 - Rollback requires approval via the approval workflow
  409 - Another rollback is already in progress for this steward
  400 - Request rejected (e.g. cross-tenant version mismatch)

Examples:
  cfg config rollback steward-abc123 --to abc1234567890
  cfg config rollback steward-abc123 --to abc1234567890 --dry-run
  cfg config rollback steward-abc123`,
	Args: cobra.ExactArgs(1),
	RunE: runConfigRollback,
}

func init() {
	// Upload command flags (unchanged)
	configUploadCmd.Flags().StringVar(&configUploadStewardID, "steward", "", "Steward ID to upload the config to (required)")
	configUploadCmd.Flags().BoolVar(&configUploadJSONOutput, "json", false, "Emit raw API response JSON instead of human-readable text")
	configUploadCmd.Flags().StringVar(&configUploadURL, "url", "", "Controller API URL (env: CFGMS_API_URL)")
	configUploadCmd.Flags().StringVar(&configUploadAPIKey, "api-key", "", "API key for authentication (env: CFGMS_API_KEY)")
	configUploadCmd.Flags().StringVar(&configUploadTLSCACert, "tls-ca-cert", "", "Path to CA certificate for TLS verification (env: CFGMS_TLS_CA_CERT)")
	configUploadCmd.Flags().BoolVar(&configUploadTLSInsecure, "tls-insecure", false, "Skip TLS verification (development only)")
	configUploadCmd.Flags().StringVar(&configUploadServerName, "server-name", "", "Override TLS server name for certificate verification")
	_ = configUploadCmd.MarkFlagRequired("steward")

	// List command flags
	configListCmd.Flags().StringVar(&configListTenantID, "tenant", "", "Filter by tenant ID (optional)")
	configListCmd.Flags().BoolVar(&configListJSON, "json", false, "Emit raw JSON instead of human-readable table")
	configListCmd.Flags().StringVar(&configAPIURL, "api-url", "", "Controller REST API URL (env: CFGMS_API_URL)")
	configListCmd.Flags().StringVar(&configAPIKey, "api-key", "", "API key for authentication (env: CFGMS_API_KEY)")
	configListCmd.Flags().StringVar(&configTLSCACert, "tls-ca-cert", "", "Path to CA certificate for TLS verification (env: CFGMS_TLS_CA_CERT)")
	configListCmd.Flags().BoolVar(&configTLSInsecure, "tls-insecure", false, "Skip TLS verification (development only)")
	configListCmd.Flags().StringVar(&configServerName, "server-name", "", "Override TLS server name for certificate verification")

	// Show command flags (connection flags share vars with list/delete)
	configShowCmd.Flags().BoolVar(&configShowJSON, "json", false, "Emit raw JSON instead of human-readable output")
	configShowCmd.Flags().StringVar(&configAPIURL, "api-url", "", "Controller REST API URL (env: CFGMS_API_URL)")
	configShowCmd.Flags().StringVar(&configAPIKey, "api-key", "", "API key for authentication (env: CFGMS_API_KEY)")
	configShowCmd.Flags().StringVar(&configTLSCACert, "tls-ca-cert", "", "Path to CA certificate for TLS verification (env: CFGMS_TLS_CA_CERT)")
	configShowCmd.Flags().BoolVar(&configTLSInsecure, "tls-insecure", false, "Skip TLS verification (development only)")
	configShowCmd.Flags().StringVar(&configServerName, "server-name", "", "Override TLS server name for certificate verification")

	// Delete command flags
	configDeleteCmd.Flags().StringVar(&configAPIURL, "api-url", "", "Controller REST API URL (env: CFGMS_API_URL)")
	configDeleteCmd.Flags().StringVar(&configAPIKey, "api-key", "", "API key for authentication (env: CFGMS_API_KEY)")
	configDeleteCmd.Flags().StringVar(&configTLSCACert, "tls-ca-cert", "", "Path to CA certificate for TLS verification (env: CFGMS_TLS_CA_CERT)")
	configDeleteCmd.Flags().BoolVar(&configTLSInsecure, "tls-insecure", false, "Skip TLS verification (development only)")
	configDeleteCmd.Flags().StringVar(&configServerName, "server-name", "", "Override TLS server name for certificate verification")

	// Deployments command flags
	configDeploymentsCmd.Flags().BoolVar(&configDeploymentsJSON, "json", false, "Emit raw JSON instead of human-readable output")
	configDeploymentsCmd.Flags().StringVar(&configAPIURL, "api-url", "", "Controller REST API URL (env: CFGMS_API_URL)")
	configDeploymentsCmd.Flags().StringVar(&configAPIKey, "api-key", "", "API key for authentication (env: CFGMS_API_KEY)")
	configDeploymentsCmd.Flags().StringVar(&configTLSCACert, "tls-ca-cert", "", "Path to CA certificate for TLS verification (env: CFGMS_TLS_CA_CERT)")
	configDeploymentsCmd.Flags().BoolVar(&configTLSInsecure, "tls-insecure", false, "Skip TLS verification (development only)")
	configDeploymentsCmd.Flags().StringVar(&configServerName, "server-name", "", "Override TLS server name for certificate verification")

	// Diff command flags
	configDiffCmd.Flags().BoolVar(&configDiffJSON, "json", false, "Emit JSON diff format instead of human-readable text")
	configDiffCmd.Flags().BoolVar(&configDiffIncludeSecrets, "include-secrets", false, "Include raw secret values (skips redaction of token/secret/password/credential/api_key keys)")
	configDiffCmd.Flags().StringVar(&configAPIURL, "api-url", "", "Controller REST API URL (env: CFGMS_API_URL)")
	configDiffCmd.Flags().StringVar(&configAPIKey, "api-key", "", "API key for authentication (env: CFGMS_API_KEY)")
	configDiffCmd.Flags().StringVar(&configTLSCACert, "tls-ca-cert", "", "Path to CA certificate for TLS verification (env: CFGMS_TLS_CA_CERT)")
	configDiffCmd.Flags().BoolVar(&configTLSInsecure, "tls-insecure", false, "Skip TLS verification (development only)")
	configDiffCmd.Flags().StringVar(&configServerName, "server-name", "", "Override TLS server name for certificate verification")

	// Rollback command flags
	configRollbackCmd.Flags().StringVar(&configRollbackTo, "to", "", "Version (commit SHA) to roll back to; omit to list available rollback points")
	configRollbackCmd.Flags().BoolVar(&configRollbackDryRun, "dry-run", false, "Preview the rollback without executing (calls /rollback/preview)")
	configRollbackCmd.Flags().BoolVar(&configRollbackJSON, "json", false, "Emit raw JSON instead of human-readable output")
	configRollbackCmd.Flags().StringVar(&configAPIURL, "api-url", "", "Controller REST API URL (env: CFGMS_API_URL)")
	configRollbackCmd.Flags().StringVar(&configAPIKey, "api-key", "", "API key for authentication (env: CFGMS_API_KEY)")
	configRollbackCmd.Flags().StringVar(&configTLSCACert, "tls-ca-cert", "", "Path to CA certificate for TLS verification (env: CFGMS_TLS_CA_CERT)")
	configRollbackCmd.Flags().BoolVar(&configTLSInsecure, "tls-insecure", false, "Skip TLS verification (development only)")
	configRollbackCmd.Flags().StringVar(&configServerName, "server-name", "", "Override TLS server name for certificate verification")

	configCmd.AddCommand(configUploadCmd)
	configCmd.AddCommand(configListCmd)
	configCmd.AddCommand(configShowCmd)
	configCmd.AddCommand(configDeleteCmd)
	configCmd.AddCommand(configDeploymentsCmd)
	configCmd.AddCommand(configDiffCmd)
	configCmd.AddCommand(configRollbackCmd)
}

func getConfigClient() (*APIClient, error) {
	apiURL := configUploadURL
	if apiURL == "" {
		apiURL = os.Getenv("CFGMS_API_URL")
	}

	tlsInsecure := configUploadTLSInsecure
	if !tlsInsecure {
		tlsInsecure = os.Getenv("CFGMS_TLS_INSECURE") == "true"
	}
	serverName := configUploadServerName

	client, err := resolveSessionOrBundleClient(apiURL, tlsInsecure, serverName)
	if err != nil {
		return nil, fmt.Errorf("bundle lookup failed: %w", err)
	}
	if client != nil {
		return client, nil
	}

	apiKey := configUploadAPIKey
	if apiKey == "" {
		apiKey = os.Getenv("CFGMS_API_KEY")
	}

	tlsCACertPath := configUploadTLSCACert
	if tlsCACertPath == "" {
		tlsCACertPath = os.Getenv("CFGMS_TLS_CA_CERT")
	}

	return newClientFromFlags(apiURL, apiKey, tlsCACertPath, tlsInsecure)
}

// getConfigAPIClient creates an API client for list/show/delete config operations.
func getConfigAPIClient() (*APIClient, error) {
	apiURL := configAPIURL
	if apiURL == "" {
		apiURL = os.Getenv("CFGMS_API_URL")
	}

	tlsInsecure := configTLSInsecure
	if !tlsInsecure {
		tlsInsecure = os.Getenv("CFGMS_TLS_INSECURE") == "true"
	}
	serverName := configServerName

	client, err := resolveSessionOrBundleClient(apiURL, tlsInsecure, serverName)
	if err != nil {
		return nil, fmt.Errorf("bundle lookup failed: %w", err)
	}
	if client != nil {
		return client, nil
	}

	if apiURL == "" {
		apiURL = "http://localhost:9080"
	}

	apiKey := configAPIKey
	if apiKey == "" {
		apiKey = os.Getenv("CFGMS_API_KEY")
	}

	tlsCACertPath := configTLSCACert
	if tlsCACertPath == "" {
		tlsCACertPath = os.Getenv("CFGMS_TLS_CA_CERT")
	}

	return newClientFromFlags(apiURL, apiKey, tlsCACertPath, tlsInsecure)
}

// APIConfigSummary represents a stored configuration summary in API responses.
type APIConfigSummary struct {
	StewardID string    `json:"steward_id"`
	TenantID  string    `json:"tenant_id"`
	Version   int64     `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
	UpdatedBy string    `json:"updated_by"`
}

func runConfigList(cmd *cobra.Command, args []string) error {
	client, err := getConfigAPIClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	path := "/api/v1/configs"
	if configListTenantID != "" {
		path += "?tenant_id=" + url.QueryEscape(configListTenantID)
	}

	resp, err := client.doRequest(context.Background(), "GET", path, nil)
	if err != nil {
		return fmt.Errorf("failed to list configs: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return client.parseError(resp)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if configListJSON {
		_, err := os.Stdout.Write(bodyBytes)
		return err
	}

	var apiResp struct {
		Data []APIConfigSummary `json:"data"`
	}
	if err := json.Unmarshal(bodyBytes, &apiResp); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	if len(apiResp.Data) == 0 {
		fmt.Println("No configurations found.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(w, "STEWARD ID\tTENANT\tVERSION\tUPDATED AT"); err != nil {
		return err
	}
	for _, cfg := range apiResp.Data {
		if _, err := fmt.Fprintf(w, "%s\t%s\t%d\t%s\n",
			cfg.StewardID,
			cfg.TenantID,
			cfg.Version,
			cfg.UpdatedAt.Format(time.RFC3339),
		); err != nil {
			return err
		}
	}
	return w.Flush()
}

func runConfigShow(cmd *cobra.Command, args []string) error {
	stewardID := args[0]

	client, err := getConfigAPIClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	path := "/api/v1/stewards/" + stewardID + "/config"
	resp, err := client.doRequest(context.Background(), "GET", path, nil)
	if err != nil {
		return fmt.Errorf("failed to get config: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return client.parseError(resp)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if configShowJSON {
		_, err := os.Stdout.Write(bodyBytes)
		return err
	}

	var apiResp struct {
		Data map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(bodyBytes, &apiResp); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	fmt.Printf("Configuration for steward %s:\n\n", stewardID)
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(apiResp.Data)
}

func runConfigDelete(cmd *cobra.Command, args []string) error {
	stewardID := args[0]

	client, err := getConfigAPIClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	path := "/api/v1/stewards/" + stewardID + "/config"
	resp, err := client.doRequest(context.Background(), "DELETE", path, nil)
	if err != nil {
		return fmt.Errorf("failed to delete config: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNoContent {
		fmt.Printf("Configuration deleted for steward %s\n", stewardID)
		return nil
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return client.parseError(resp)
	}

	fmt.Printf("Configuration deleted for steward %s\n", stewardID)
	return nil
}

func runConfigUpload(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	// Defense-in-depth: cobra MarkFlagRequired also enforces this
	if configUploadStewardID == "" {
		return fmt.Errorf("--steward flag is required")
	}

	// Validate file exists and is non-empty before any HTTP call
	info, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("file not found: %s", filePath)
		}
		return fmt.Errorf("cannot access file %s: %w", filePath, err)
	}
	if info.Size() == 0 {
		return fmt.Errorf("file is empty: %s", filePath)
	}

	// #nosec G304 - file path provided by user via CLI argument
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file %s: %w", filePath, err)
	}

	client, err := getConfigClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	path := "/api/v1/stewards/" + configUploadStewardID + "/config"
	resp, err := client.doRequestWithContentType(context.Background(), "PUT", path, bytes.NewReader(data), "application/yaml")
	if err != nil {
		return fmt.Errorf("failed to upload config: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return client.parseError(resp)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if configUploadJSONOutput {
		_, err := os.Stdout.Write(bodyBytes)
		return err
	}

	var apiResp struct {
		Data struct {
			StewardID string `json:"steward_id"`
			Status    string `json:"status"`
		} `json:"data"`
	}
	if err := json.Unmarshal(bodyBytes, &apiResp); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	status := apiResp.Data.Status
	if status == "" {
		status = "stored"
	}

	fmt.Printf("Configuration stored for steward %s (status: %s)\n", configUploadStewardID, status)
	return nil
}

// apiDeploymentSummary mirrors the server-side DeploymentSummary for JSON decoding.
type apiDeploymentSummary struct {
	Applied int `json:"applied"`
	Pending int `json:"pending"`
	Failed  int `json:"failed"`
	Halted  int `json:"halted"`
	Total   int `json:"total"`
}

// apiStewardDeploymentStatus mirrors the server-side StewardDeploymentStatus.
type apiStewardDeploymentStatus struct {
	StewardID   string    `json:"steward_id"`
	Status      string    `json:"status"`
	LastUpdated time.Time `json:"last_updated"`
}

// apiPushSummary mirrors the server-side PushSummary.
type apiPushSummary struct {
	PushID      string    `json:"push_id"`
	Status      string    `json:"status"`
	Version     string    `json:"version"`
	InitiatedBy string    `json:"initiated_by"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func runConfigDeployments(cmd *cobra.Command, args []string) error {
	configID := args[0]

	client, err := getConfigAPIClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	path := "/api/v1/configs/" + url.PathEscape(configID) + "/deployments"
	resp, err := client.doRequest(context.Background(), "GET", path, nil)
	if err != nil {
		return fmt.Errorf("failed to get deployments: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return client.parseError(resp)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if configDeploymentsJSON {
		_, err := os.Stdout.Write(bodyBytes)
		return err
	}

	var apiResp struct {
		Data struct {
			ConfigID    string                       `json:"config_id"`
			Summary     apiDeploymentSummary         `json:"summary"`
			Stewards    []apiStewardDeploymentStatus `json:"stewards"`
			PushHistory []apiPushSummary             `json:"push_history"`
		} `json:"data"`
	}
	if err := json.Unmarshal(bodyBytes, &apiResp); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	d := apiResp.Data
	fmt.Printf("Deployment status for config: %s\n\n", d.ConfigID)
	fmt.Printf("Summary:\n")
	fmt.Printf("  Applied: %d\n", d.Summary.Applied)
	fmt.Printf("  Pending: %d\n", d.Summary.Pending)
	fmt.Printf("  Failed:  %d\n", d.Summary.Failed)
	fmt.Printf("  Halted:  %d\n", d.Summary.Halted)
	fmt.Printf("  Total:   %d\n\n", d.Summary.Total)

	if len(d.Stewards) > 0 {
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		if _, err := fmt.Fprintln(w, "STEWARD ID\tSTATUS\tLAST UPDATED"); err != nil {
			return err
		}
		for _, st := range d.Stewards {
			lastUpdated := "-"
			if !st.LastUpdated.IsZero() {
				lastUpdated = st.LastUpdated.Format(time.RFC3339)
			}
			if _, err := fmt.Fprintf(w, "%s\t%s\t%s\n", st.StewardID, st.Status, lastUpdated); err != nil {
				return err
			}
		}
		if err := w.Flush(); err != nil {
			return err
		}
	} else {
		fmt.Println("No stewards found.")
	}

	return nil
}

// redactSecrets replaces values for keys matching secretKeyPatterns with "***".
// Recurses into nested maps and slices so secrets inside resources[] are also redacted.
func redactSecrets(config map[string]interface{}) {
	for key, value := range config {
		keyLower := strings.ToLower(key)
		isSecret := false
		for _, pattern := range secretKeyPatterns {
			if strings.Contains(keyLower, pattern) {
				isSecret = true
				break
			}
		}
		if isSecret {
			config[key] = "***"
		} else {
			redactSecretsInValue(value)
		}
	}
}

// redactSecretsInValue recurses into maps and slices to find and redact secret keys.
func redactSecretsInValue(v interface{}) {
	switch val := v.(type) {
	case map[string]interface{}:
		redactSecrets(val)
	case []interface{}:
		for _, elem := range val {
			redactSecretsInValue(elem)
		}
	}
}

func runConfigDiff(cmd *cobra.Command, args []string) error {
	stewardID := args[0]
	newCfgPath := args[1]

	// Validate local file exists before making any network call
	if _, err := os.Stat(newCfgPath); os.IsNotExist(err) {
		return fmt.Errorf("file not found: %s", newCfgPath)
	}

	client, err := getConfigAPIClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	path := "/api/v1/stewards/" + stewardID + "/config"
	resp, err := client.doRequest(context.Background(), "GET", path, nil)
	if err != nil {
		return fmt.Errorf("failed to get config: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		fmt.Printf("No config stored for steward %s. Upload a config first.\n", stewardID)
		return nil
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return client.parseError(resp)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	var apiResp struct {
		Data struct {
			Config map[string]interface{} `json:"config"`
		} `json:"data"`
	}
	if err := json.Unmarshal(bodyBytes, &apiResp); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	configData := apiResp.Data.Config
	if !configDiffIncludeSecrets {
		redactSecrets(configData)
	}

	yamlBytes, err := yaml.Marshal(configData)
	if err != nil {
		return fmt.Errorf("failed to marshal config to YAML: %w", err)
	}

	tempDir, err := os.MkdirTemp("", "cfgms-diff-*")
	if err != nil {
		return fmt.Errorf("failed to create temp dir: %w", err)
	}
	// #nosec G302 - 0700 is correct for a traversable private temp directory; the execute bit is required
	if err := os.Chmod(tempDir, 0700); err != nil {
		_ = os.RemoveAll(tempDir)
		return fmt.Errorf("failed to set temp dir permissions: %w", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	tempFile := filepath.Join(tempDir, "server-config.yaml")
	// #nosec G306 - explicit 0600 matches security requirement for temp config files
	if err := os.WriteFile(tempFile, yamlBytes, 0600); err != nil {
		return fmt.Errorf("failed to write temp config: %w", err)
	}

	semanticAnalyzer := diff.NewDefaultSemanticAnalyzer()
	impactAnalyzer := diff.NewDefaultImpactAnalyzer()
	exporter := diff.NewDefaultExporter()
	engine := diff.NewDefaultEngine(semanticAnalyzer, impactAnalyzer, exporter)

	fromRef, err := createConfigurationReference(tempFile)
	if err != nil {
		return fmt.Errorf("failed to create from reference: %w", err)
	}

	toRef, err := createConfigurationReference(newCfgPath)
	if err != nil {
		return fmt.Errorf("failed to create to reference: %w", err)
	}

	diffOptions := diff.DiffOptions{
		IgnoreWhitespace: false,
		IgnoreComments:   false,
		IgnoreOrder:      false,
		ContextLines:     3,
		SemanticDiff:     true,
		ImpactAnalysis:   true,
	}

	result, err := engine.Compare(context.Background(), *fromRef, *toRef, diffOptions)
	if err != nil {
		return fmt.Errorf("comparison failed: %w", err)
	}

	exportFormat := diff.ExportFormatText
	if configDiffJSON {
		exportFormat = diff.ExportFormatJSON
	}

	exportOptions := diff.ExportOptions{
		Format:          exportFormat,
		IncludeSummary:  true,
		IncludeMetadata: false,
		IncludeContext:  true,
		ColorizeOutput:  true,
		LineNumbers:     false,
	}

	outputBytes, err := engine.Export(context.Background(), result, exportOptions)
	if err != nil {
		return fmt.Errorf("export failed: %w", err)
	}

	fmt.Print(string(outputBytes))

	if result.Summary.TotalChanges > 0 {
		return errDifferencesFound
	}

	return nil
}

// apiRollbackPoint mirrors the server-side RollbackPoint for JSON decoding.
type apiRollbackPoint struct {
	CommitSHA   string    `json:"commit_sha"`
	Timestamp   time.Time `json:"timestamp"`
	Author      string    `json:"author"`
	Message     string    `json:"message"`
	RiskLevel   string    `json:"risk_level"`
	CanRollback bool      `json:"can_rollback"`
}

// apiRollbackOperation mirrors the server-side RollbackOperation for JSON decoding.
type apiRollbackOperation struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

func runConfigRollback(cmd *cobra.Command, args []string) error {
	stewardID := args[0]

	client, err := getConfigAPIClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	// If --to is not provided, list available rollback points and exit 0.
	if configRollbackTo == "" {
		return runListRollbackPoints(client, stewardID)
	}

	// --dry-run: call preview endpoint and print diff.
	if configRollbackDryRun {
		return runPreviewRollback(client, stewardID, configRollbackTo)
	}

	// Execute rollback and poll for completion.
	return runExecuteRollback(client, stewardID, configRollbackTo)
}

func runListRollbackPoints(client *APIClient, stewardID string) error {
	path := "/api/v1/rollback/points?target_type=steward&target_id=" + url.QueryEscape(stewardID)
	resp, err := client.doRequest(context.Background(), "GET", path, nil)
	if err != nil {
		return fmt.Errorf("failed to list rollback points: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return client.parseError(resp)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if configRollbackJSON {
		_, err := os.Stdout.Write(bodyBytes)
		return err
	}

	var apiResp struct {
		RollbackPoints []apiRollbackPoint `json:"rollback_points"`
	}
	if err := json.Unmarshal(bodyBytes, &apiResp); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	if len(apiResp.RollbackPoints) == 0 {
		fmt.Printf("No rollback points available for steward %s\n", stewardID)
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(w, "COMMIT SHA\tTIMESTAMP\tAUTHOR\tRISK\tMESSAGE"); err != nil {
		return err
	}
	for _, p := range apiResp.RollbackPoints {
		msg := p.Message
		if len(msg) > 60 {
			msg = msg[:57] + "..."
		}
		if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			p.CommitSHA,
			p.Timestamp.Format(time.RFC3339),
			p.Author,
			p.RiskLevel,
			msg,
		); err != nil {
			return err
		}
	}
	return w.Flush()
}

func runPreviewRollback(client *APIClient, stewardID, version string) error {
	reqBody, err := json.Marshal(map[string]interface{}{
		"target_type": "steward",
		"target_id":   stewardID,
		"rollback_to": version,
		"dry_run":     true,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := client.doRequest(context.Background(), "POST", "/api/v1/rollback/preview", bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("failed to preview rollback: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return client.parseError(resp)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if configRollbackJSON {
		_, err := os.Stdout.Write(bodyBytes)
		return err
	}

	var apiResp struct {
		Preview map[string]interface{} `json:"preview"`
	}
	if err := json.Unmarshal(bodyBytes, &apiResp); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	fmt.Printf("Rollback preview for steward %s to version %s:\n\n", stewardID, version)
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(apiResp.Preview)
}

func runExecuteRollback(client *APIClient, stewardID, version string) error {
	reqBody, err := json.Marshal(map[string]interface{}{
		"target_type": "steward",
		"target_id":   stewardID,
		"rollback_to": version,
		"dry_run":     false,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := client.doRequest(context.Background(), "POST", "/api/v1/rollback/execute", bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("failed to execute rollback: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusPreconditionFailed: // 412
		fmt.Fprintln(os.Stderr, "Rollback requires approval. Use the approval workflow.")
		return fmt.Errorf("rollback requires approval (HTTP 412)")
	case http.StatusConflict: // 409
		fmt.Fprintln(os.Stderr, "Another rollback is already in progress for this steward.")
		return fmt.Errorf("rollback already in progress (HTTP 409)")
	case http.StatusBadRequest: // 400
		var errResp map[string]interface{}
		if json.Unmarshal(bodyBytes, &errResp) == nil {
			if code, ok := errResp["code"].(string); ok && code == "CROSS_TENANT_ROLLBACK" {
				return fmt.Errorf("rollback rejected: version does not belong to this steward tenant")
			}
		}
		return fmt.Errorf("API error (status 400): %s", strings.TrimSpace(string(bodyBytes)))
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("API error (status %d): %s", resp.StatusCode, strings.TrimSpace(string(bodyBytes)))
	}

	var executeResp struct {
		Rollback apiRollbackOperation `json:"rollback"`
	}
	if err := json.Unmarshal(bodyBytes, &executeResp); err != nil {
		return fmt.Errorf("failed to decode execute response: %w", err)
	}

	rollbackID := executeResp.Rollback.ID
	if rollbackID == "" {
		return fmt.Errorf("server returned rollback operation without an ID")
	}

	fmt.Printf("Rollback initiated (id: %s). Waiting for completion...\n", rollbackID)

	// Poll for completion with 60s timeout.
	deadline := time.Now().Add(60 * time.Second)
	statusPath := "/api/v1/rollback/" + url.PathEscape(rollbackID) + "/status"

	for time.Now().Before(deadline) {
		time.Sleep(rollbackPollInterval)

		statusResp, err := client.doRequest(context.Background(), "GET", statusPath, nil)
		if err != nil {
			return fmt.Errorf("failed to poll rollback status: %w", err)
		}
		statusBody, readErr := io.ReadAll(statusResp.Body)
		_ = statusResp.Body.Close()
		if readErr != nil {
			return fmt.Errorf("failed to read status response: %w", readErr)
		}

		if statusResp.StatusCode < 200 || statusResp.StatusCode >= 300 {
			return fmt.Errorf("API error polling status (status %d): %s", statusResp.StatusCode, strings.TrimSpace(string(statusBody)))
		}

		var statusResult struct {
			Rollback struct {
				ID     string `json:"id"`
				Status string `json:"status"`
			} `json:"rollback"`
		}
		if err := json.Unmarshal(statusBody, &statusResult); err != nil {
			return fmt.Errorf("failed to decode status response: %w", err)
		}

		status := statusResult.Rollback.Status
		switch status {
		case "completed":
			fmt.Printf("Rollback completed successfully (steward: %s, version: %s)\n", stewardID, version)
			return nil
		case "failed":
			return fmt.Errorf("rollback failed (id: %s)", rollbackID)
		case "cancelled":
			return fmt.Errorf("rollback was cancelled (id: %s)", rollbackID)
		}
		// Still pending/in_progress — keep polling
	}

	return fmt.Errorf("timeout waiting for rollback completion (id: %s)", rollbackID)
}
