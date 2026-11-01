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
	"os"

	"github.com/spf13/cobra"
)

// rebootWindowResponse mirrors the controller's rebootWindowResponse type.
type rebootWindowResponse struct {
	TenantID              string `json:"tenant_id,omitempty"`
	StewardID             string `json:"steward_id,omitempty"`
	TenantDefaultTimezone string `json:"tenant_default_timezone,omitempty"`
	DeclaredScheduleYAML  string `json:"declared_schedule_yaml,omitempty"`
	NextOccurrence        string `json:"next_occurrence,omitempty"`
	NextOccurrenceDisplay string `json:"next_occurrence_display,omitempty"`
	Status                string `json:"status"`
}

// rebootWindowPutRequest mirrors the controller's rebootWindowPutRequest type.
type rebootWindowPutRequest struct {
	ScheduleYAML          string `json:"schedule_yaml"`
	TenantDefaultTimezone string `json:"tenant_default_timezone,omitempty"`
}

var (
	rebootWindowURL          string
	rebootWindowTLSCACert    string
	rebootWindowTLSInsecure  bool
	rebootWindowServerName   string
	rebootWindowTenantID     string
	rebootWindowStewardID    string
	rebootWindowScheduleFile string
	rebootWindowTimezone     string
)

// rebootWindowCmd is the parent command: cfg reboot-window ...
var rebootWindowCmd = &cobra.Command{
	Use:   "reboot-window",
	Short: "Author and inspect reboot window configuration",
	Long: `Create, update, and display reboot_window configuration on the controller.

A reboot_window constrains when managed endpoints may reboot during patch
cycles. It is declared at tenant level (inherited by all stewards in that
tenant) or overridden at the device level for a specific steward.

Permissions required:
  reboot_window:override — set (PUT)
  reboot_window:read     — show (GET)

Supported sub-commands: set, show`,
}

// rebootWindowSetCmd implements cfg reboot-window set.
var rebootWindowSetCmd = &cobra.Command{
	Use:   "set",
	Short: "Set the reboot_window for a tenant or steward",
	Long: `Set the reboot_window for a tenant or steward by uploading a schedule YAML file.

The schedule YAML must be a valid reboot_window block (validated by the controller).

Exactly one of --tenant or --steward must be specified.

Examples:
  cfg reboot-window set --tenant acme-corp --schedule window.yaml
  cfg reboot-window set --steward sw-1234 --schedule window.yaml
  cfg reboot-window set --tenant acme-corp --schedule window.yaml --timezone America/New_York`,
	RunE: runRebootWindowSet,
}

// rebootWindowShowCmd implements cfg reboot-window show.
var rebootWindowShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show the effective reboot_window for a tenant or steward",
	Long: `Show the effective reboot_window including the resolved next occurrence.

The GET endpoint returns the full cascaded value: MSP → client → group →
device. If no reboot_window is declared at any level, it reports
"unrestricted".

Exactly one of --tenant or --steward must be specified.

Examples:
  cfg reboot-window show --tenant acme-corp
  cfg reboot-window show --steward sw-1234`,
	RunE: runRebootWindowShow,
}

func init() {
	for _, cmd := range []*cobra.Command{rebootWindowSetCmd, rebootWindowShowCmd} {
		cmd.Flags().StringVar(&rebootWindowURL, "url", "", "Controller API URL (env: CFGMS_API_URL)")
		cmd.Flags().StringVar(&rebootWindowTLSCACert, "tls-ca-cert", "", "Path to CA certificate (env: CFGMS_TLS_CA_CERT)")
		cmd.Flags().BoolVar(&rebootWindowTLSInsecure, "tls-insecure", false, "Skip TLS verification (env: CFGMS_TLS_INSECURE)")
		cmd.Flags().StringVar(&rebootWindowServerName, "server-name", "", "Override TLS server name for certificate verification")
		cmd.Flags().StringVar(&rebootWindowTenantID, "tenant", "", "Target tenant ID")
		cmd.Flags().StringVar(&rebootWindowStewardID, "steward", "", "Target steward ID")
	}
	rebootWindowSetCmd.Flags().StringVar(&rebootWindowScheduleFile, "schedule", "", "Path to schedule YAML file (required)")
	rebootWindowSetCmd.Flags().StringVar(&rebootWindowTimezone, "timezone", "", "Default timezone for the reboot window (e.g. America/New_York)")
	_ = rebootWindowSetCmd.MarkFlagRequired("schedule")

	rebootWindowCmd.AddCommand(rebootWindowSetCmd)
	rebootWindowCmd.AddCommand(rebootWindowShowCmd)
	rootCmd.AddCommand(rebootWindowCmd)
}

func getRebootWindowClient() (*APIClient, error) {
	apiURL := rebootWindowURL
	if apiURL == "" {
		apiURL = os.Getenv("CFGMS_API_URL")
	}

	tlsInsecure := rebootWindowTLSInsecure
	if !tlsInsecure {
		tlsInsecure = os.Getenv("CFGMS_TLS_INSECURE") == "true"
	}
	serverName := rebootWindowServerName

	return requireSessionOrBundleClient(apiURL, tlsInsecure, serverName)
}

func runRebootWindowSet(cmd *cobra.Command, _ []string) error {
	if rebootWindowTenantID == "" && rebootWindowStewardID == "" {
		return fmt.Errorf("exactly one of --tenant or --steward must be specified")
	}
	if rebootWindowTenantID != "" && rebootWindowStewardID != "" {
		return fmt.Errorf("--tenant and --steward are mutually exclusive")
	}

	// #nosec G304 -- rebootWindowScheduleFile is an explicit local CLI flag;
	// reading the operator-selected schedule YAML is the set command's purpose.
	scheduleBytes, err := os.ReadFile(rebootWindowScheduleFile)
	if err != nil {
		return fmt.Errorf("failed to read schedule file %q: %w", rebootWindowScheduleFile, err)
	}

	reqBody := rebootWindowPutRequest{
		ScheduleYAML:          string(scheduleBytes),
		TenantDefaultTimezone: rebootWindowTimezone,
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to encode request: %w", err)
	}

	client, err := getRebootWindowClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	path := rebootWindowAPIPath()
	resp, err := client.doRequest(context.Background(), http.MethodPut, path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("set failed (%s): %s", resp.Status, string(respBody))
	}

	var apiResp struct {
		Data rebootWindowResponse `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	d := apiResp.Data
	printRebootWindowResult(cmd, d, "Reboot window updated")
	return nil
}

func runRebootWindowShow(cmd *cobra.Command, _ []string) error {
	if rebootWindowTenantID == "" && rebootWindowStewardID == "" {
		return fmt.Errorf("exactly one of --tenant or --steward must be specified")
	}
	if rebootWindowTenantID != "" && rebootWindowStewardID != "" {
		return fmt.Errorf("--tenant and --steward are mutually exclusive")
	}

	client, err := getRebootWindowClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	path := rebootWindowAPIPath()
	resp, err := client.Get(context.Background(), path)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("show failed (%s): %s", resp.Status, string(respBody))
	}

	var apiResp struct {
		Data rebootWindowResponse `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	printRebootWindowResult(cmd, apiResp.Data, "")
	return nil
}

// rebootWindowAPIPath builds the API path from the current --tenant / --steward flag.
func rebootWindowAPIPath() string {
	if rebootWindowTenantID != "" {
		return "/api/v1/tenants/" + rebootWindowTenantID + "/reboot-window"
	}
	return "/api/v1/stewards/" + rebootWindowStewardID + "/reboot-window"
}

// printRebootWindowResult writes the reboot window response to cmd's stdout.
func printRebootWindowResult(cmd *cobra.Command, d rebootWindowResponse, header string) {
	out := cmd.OutOrStdout()
	if header != "" {
		_, _ = fmt.Fprintln(out, header)
	}

	target := d.TenantID
	if d.StewardID != "" {
		target = d.StewardID
	}
	if target != "" {
		_, _ = fmt.Fprintf(out, "Target:  %s\n", target)
	}
	_, _ = fmt.Fprintf(out, "Status:  %s\n", d.Status)

	if d.NextOccurrenceDisplay != "" {
		_, _ = fmt.Fprintf(out, "Next:    %s\n", d.NextOccurrenceDisplay)
	}
	if d.NextOccurrence != "" {
		_, _ = fmt.Fprintf(out, "Next (ISO-8601): %s\n", d.NextOccurrence)
	}
	if d.TenantDefaultTimezone != "" {
		_, _ = fmt.Fprintf(out, "Timezone: %s\n", d.TenantDefaultTimezone)
	}
}
