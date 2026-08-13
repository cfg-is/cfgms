// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
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
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

var (
	stewardTagURL         string
	stewardTagAPIKey      string
	stewardTagTLSCACert   string
	stewardTagTLSInsecure bool
	stewardTagServerName  string
)

// stewardTagCmd is the parent command for cfg steward tag subcommands.
var stewardTagCmd = &cobra.Command{
	Use:   "tag",
	Short: "Manage tags on a steward",
	Long: `Add, remove, and list operator-assigned tags on a steward.

Tags are controller-owned metadata used by tag: selectors to target stewards
in role configs and cfg steward commands.

Tag format: lowercase alphanumeric, optionally separated by hyphens (1-64 chars).
Examples: prod, web-server, github-runner.

Sub-commands: add, rm, ls`,
}

// stewardTagAddCmd implements cfg steward tag add <id> <tag>...
var stewardTagAddCmd = &cobra.Command{
	Use:   "add <steward-id> <tag> [tag...]",
	Short: "Add tags to a steward",
	Long: `Add one or more tags to a steward.

Adding a tag that already exists is a no-op (idempotent).

Examples:
  cfg steward tag add steward-abc123 prod web-server \
    --url https://controller.example.com --api-key mykey`,
	Args: cobra.MinimumNArgs(2),
	RunE: runStewardTagAdd,
}

// stewardTagRmCmd implements cfg steward tag rm <id> <tag>...
var stewardTagRmCmd = &cobra.Command{
	Use:   "rm <steward-id> <tag> [tag...]",
	Short: "Remove tags from a steward",
	Long: `Remove one or more tags from a steward.

Removing a tag that does not exist is a no-op (idempotent).

Examples:
  cfg steward tag rm steward-abc123 debug \
    --url https://controller.example.com --api-key mykey`,
	Args: cobra.MinimumNArgs(2),
	RunE: runStewardTagRm,
}

// stewardTagLsCmd implements cfg steward tag ls <id>
var stewardTagLsCmd = &cobra.Command{
	Use:   "ls <steward-id>",
	Short: "List tags on a steward",
	Long: `List all operator-assigned tags on a steward.

Examples:
  cfg steward tag ls steward-abc123 \
    --url https://controller.example.com --api-key mykey`,
	Args: cobra.ExactArgs(1),
	RunE: runStewardTagLs,
}

func init() {
	for _, cmd := range []*cobra.Command{stewardTagAddCmd, stewardTagRmCmd, stewardTagLsCmd} {
		cmd.Flags().StringVar(&stewardTagURL, "url", "", "Controller API URL (env: CFGMS_API_URL)")
		cmd.Flags().StringVar(&stewardTagAPIKey, "api-key", "", "API key for authentication (env: CFGMS_API_KEY)")
		cmd.Flags().StringVar(&stewardTagTLSCACert, "tls-ca-cert", "", "Path to CA certificate (env: CFGMS_TLS_CA_CERT)")
		cmd.Flags().BoolVar(&stewardTagTLSInsecure, "tls-insecure", false, "Skip TLS verification (env: CFGMS_TLS_INSECURE)")
	}

	stewardTagCmd.AddCommand(stewardTagAddCmd)
	stewardTagCmd.AddCommand(stewardTagRmCmd)
	stewardTagCmd.AddCommand(stewardTagLsCmd)
	stewardCmd.AddCommand(stewardTagCmd)
}

// getStewardTagClient returns an API client for steward tag commands.
func getStewardTagClient() (*APIClient, error) {
	apiURL := strings.TrimSuffix(stewardTagURL, "/")
	if apiURL == "" {
		apiURL = os.Getenv("CFGMS_API_URL")
	}

	tlsInsecure := stewardTagTLSInsecure
	if !tlsInsecure {
		tlsInsecure = os.Getenv("CFGMS_TLS_INSECURE") == "true"
	}
	serverName := stewardTagServerName

	client, err := resolveSessionOrBundleClient(apiURL, tlsInsecure, serverName)
	if err != nil {
		return nil, fmt.Errorf("bundle lookup failed: %w", err)
	}
	if client != nil {
		return client, nil
	}

	apiKey := stewardTagAPIKey
	if apiKey == "" {
		apiKey = os.Getenv("CFGMS_API_KEY")
	}

	tlsCACertPath := stewardTagTLSCACert
	if tlsCACertPath == "" {
		tlsCACertPath = os.Getenv("CFGMS_TLS_CA_CERT")
	}

	return newClientFromFlags(apiURL, apiKey, tlsCACertPath, tlsInsecure)
}

func runStewardTagAdd(cmd *cobra.Command, args []string) error {
	stewardID := url.PathEscape(args[0])
	tags := args[1:]

	payload, err := json.Marshal(map[string]interface{}{"tags": tags})
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	client, err := getStewardTagClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	resp, err := client.doRequest(context.Background(), http.MethodPost,
		"/api/v1/stewards/"+stewardID+"/tags", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return fmt.Errorf("steward %q not found", args[0])
	case http.StatusForbidden:
		return fmt.Errorf("insufficient permissions to tag steward %q", args[0])
	case http.StatusBadRequest:
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("invalid tag: %s", string(body))
	default:
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("add failed (%s): %s", resp.Status, string(body))
	}

	var apiResp struct {
		Data struct {
			Tags []string `json:"tags"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Tags on %s: %s\n", args[0], strings.Join(apiResp.Data.Tags, ", "))
	return nil
}

func runStewardTagRm(cmd *cobra.Command, args []string) error {
	stewardID := url.PathEscape(args[0])
	tags := args[1:]

	payload, err := json.Marshal(map[string]interface{}{"tags": tags})
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	client, err := getStewardTagClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	resp, err := client.doRequest(context.Background(), http.MethodDelete,
		"/api/v1/stewards/"+stewardID+"/tags", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return fmt.Errorf("steward %q not found", args[0])
	case http.StatusForbidden:
		return fmt.Errorf("insufficient permissions to manage tags on steward %q", args[0])
	default:
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("remove failed (%s): %s", resp.Status, string(body))
	}

	var apiResp struct {
		Data struct {
			Tags []string `json:"tags"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	remaining := apiResp.Data.Tags
	if len(remaining) == 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "No tags remain on %s.\n", args[0])
	} else {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Tags on %s: %s\n", args[0], strings.Join(remaining, ", "))
	}
	return nil
}

func runStewardTagLs(cmd *cobra.Command, args []string) error {
	stewardID := url.PathEscape(args[0])

	client, err := getStewardTagClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	resp, err := client.Get(context.Background(), "/api/v1/stewards/"+stewardID+"/tags")
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return fmt.Errorf("steward %q not found", args[0])
	case http.StatusForbidden:
		return fmt.Errorf("insufficient permissions to list tags on steward %q", args[0])
	default:
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("list failed (%s): %s", resp.Status, string(body))
	}

	var apiResp struct {
		Data struct {
			Tags []string `json:"tags"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	tags := apiResp.Data.Tags
	if len(tags) == 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No tags.")
		return nil
	}

	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "TAG")
	_, _ = fmt.Fprintln(w, "---")
	for _, tag := range tags {
		_, _ = fmt.Fprintln(w, tag)
	}
	return w.Flush()
}
