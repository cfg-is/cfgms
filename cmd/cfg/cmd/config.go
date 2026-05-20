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
	"os"

	"github.com/spf13/cobra"
)

var (
	configUploadStewardID   string
	configUploadJSONOutput  bool
	configUploadURL         string
	configUploadAPIKey      string
	configUploadTLSCACert   string
	configUploadTLSInsecure bool
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage steward configurations",
	Long:  `Commands for uploading and managing steward configurations.`,
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
	configUploadCmd.Flags().StringVar(&configUploadStewardID, "steward", "", "Steward ID to upload the config to (required)")
	configUploadCmd.Flags().BoolVar(&configUploadJSONOutput, "json", false, "Emit raw API response JSON instead of human-readable text")
	configUploadCmd.Flags().StringVar(&configUploadURL, "url", "", "Controller API URL (env: CFGMS_API_URL)")
	configUploadCmd.Flags().StringVar(&configUploadAPIKey, "api-key", "", "API key for authentication (env: CFGMS_API_KEY)")
	configUploadCmd.Flags().StringVar(&configUploadTLSCACert, "tls-ca-cert", "", "Path to CA certificate for TLS verification (env: CFGMS_TLS_CA_CERT)")
	configUploadCmd.Flags().BoolVar(&configUploadTLSInsecure, "tls-insecure", false, "Skip TLS verification (development only)")

	_ = configUploadCmd.MarkFlagRequired("steward")

	configCmd.AddCommand(configUploadCmd)
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
