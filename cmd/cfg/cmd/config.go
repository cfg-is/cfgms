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
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

var (
	configUploadStewardID   string
	configUploadJSONOutput  bool
	configUploadURL         string
	configUploadAPIKey      string
	configUploadTLSCACert   string
	configUploadTLSInsecure bool

	// Shared persistent connection flags for all config subcommands
	configAPIURL      string
	configAPIKey      string
	configTLSCACert   string
	configTLSInsecure bool

	// List command flags
	configListTenantID string
	configListJSON     bool

	// Show command flags
	configShowJSON bool
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

var configUploadCmd = &cobra.Command{
	Use:   "upload <file>",
	Short: "Upload a YAML config to a steward",
	Long: `Upload a YAML configuration file to a registered steward.

Reads the file from disk and issues PUT /api/v1/stewards/{id}/config
with Content-Type: application/yaml. Auth uses the admin bundle
(mTLS auto-discovery) by default.

Examples:
  # Upload a fleet config to a steward
  cfg config upload fleet-config.yaml --steward steward-abc123

  # Upload with JSON response output
  cfg config upload fleet-config.yaml --steward steward-abc123 --json

  # Upload using explicit controller URL
  cfg config upload fleet-config.yaml --steward steward-abc123 --url=https://ctrl.example.com:9080`,
	Args: cobra.ExactArgs(1),
	RunE: runConfigUpload,
}

func init() {
	// Upload command flags (unchanged)
	configUploadCmd.Flags().StringVar(&configUploadStewardID, "steward", "", "Steward ID to upload the config to (required)")
	configUploadCmd.Flags().BoolVar(&configUploadJSONOutput, "json", false, "Emit raw API response JSON instead of human-readable text")
	configUploadCmd.Flags().StringVar(&configUploadURL, "url", "", "Controller API URL (env: CFGMS_API_URL)")
	configUploadCmd.Flags().StringVar(&configUploadAPIKey, "api-key", "", "API key for authentication (env: CFGMS_API_KEY)")
	configUploadCmd.Flags().StringVar(&configUploadTLSCACert, "tls-ca-cert", "", "Path to CA certificate for TLS verification (env: CFGMS_TLS_CA_CERT)")
	configUploadCmd.Flags().BoolVar(&configUploadTLSInsecure, "tls-insecure", false, "Skip TLS verification (development only)")
	_ = configUploadCmd.MarkFlagRequired("steward")

	// List command flags
	configListCmd.Flags().StringVar(&configListTenantID, "tenant", "", "Filter by tenant ID (optional)")
	configListCmd.Flags().BoolVar(&configListJSON, "json", false, "Emit raw JSON instead of human-readable table")
	configListCmd.Flags().StringVar(&configAPIURL, "api-url", "", "Controller REST API URL (env: CFGMS_API_URL)")
	configListCmd.Flags().StringVar(&configAPIKey, "api-key", "", "API key for authentication (env: CFGMS_API_KEY)")
	configListCmd.Flags().StringVar(&configTLSCACert, "tls-ca-cert", "", "Path to CA certificate for TLS verification (env: CFGMS_TLS_CA_CERT)")
	configListCmd.Flags().BoolVar(&configTLSInsecure, "tls-insecure", false, "Skip TLS verification (development only)")

	// Show command flags (connection flags share vars with list/delete)
	configShowCmd.Flags().BoolVar(&configShowJSON, "json", false, "Emit raw JSON instead of human-readable output")
	configShowCmd.Flags().StringVar(&configAPIURL, "api-url", "", "Controller REST API URL (env: CFGMS_API_URL)")
	configShowCmd.Flags().StringVar(&configAPIKey, "api-key", "", "API key for authentication (env: CFGMS_API_KEY)")
	configShowCmd.Flags().StringVar(&configTLSCACert, "tls-ca-cert", "", "Path to CA certificate for TLS verification (env: CFGMS_TLS_CA_CERT)")
	configShowCmd.Flags().BoolVar(&configTLSInsecure, "tls-insecure", false, "Skip TLS verification (development only)")

	// Delete command flags
	configDeleteCmd.Flags().StringVar(&configAPIURL, "api-url", "", "Controller REST API URL (env: CFGMS_API_URL)")
	configDeleteCmd.Flags().StringVar(&configAPIKey, "api-key", "", "API key for authentication (env: CFGMS_API_KEY)")
	configDeleteCmd.Flags().StringVar(&configTLSCACert, "tls-ca-cert", "", "Path to CA certificate for TLS verification (env: CFGMS_TLS_CA_CERT)")
	configDeleteCmd.Flags().BoolVar(&configTLSInsecure, "tls-insecure", false, "Skip TLS verification (development only)")

	configCmd.AddCommand(configUploadCmd)
	configCmd.AddCommand(configListCmd)
	configCmd.AddCommand(configShowCmd)
	configCmd.AddCommand(configDeleteCmd)
}

func getConfigClient() (*APIClient, error) {
	apiURL := configUploadURL
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

	apiKey := configUploadAPIKey
	if apiKey == "" {
		apiKey = os.Getenv("CFGMS_API_KEY")
	}

	tlsInsecure := configUploadTLSInsecure
	if !tlsInsecure && os.Getenv("CFGMS_TLS_INSECURE") == "true" {
		tlsInsecure = true
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

	client, err := resolveBundleClient(apiURL)
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

	tlsInsecure := configTLSInsecure
	if !tlsInsecure && os.Getenv("CFGMS_TLS_INSECURE") == "true" {
		tlsInsecure = true
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
