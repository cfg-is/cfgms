// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package cmd implements the CLI commands for cfg
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

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

	stewardCmd.AddCommand(stewardListCmd)
	stewardCmd.AddCommand(stewardStatusCmd)
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
