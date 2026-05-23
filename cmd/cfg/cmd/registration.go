// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package cmd implements the CLI commands for cfg
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

var (
	registrationAPIURL      string
	registrationAPIKey      string
	registrationTLSCACert   string
	registrationTLSInsecure bool
	registrationJSONOutput  bool
	registrationDenyReason  string
)

// registrationCmd is the parent command for registration management.
var registrationCmd = &cobra.Command{
	Use:   "registration",
	Short: "Manage steward registrations",
	Long: `Manage steward registration approvals.

When the controller's registration workflow is set to manual-review, new stewards
are quarantined until an operator approves or denies them. Use these commands to
list pending registrations and approve or deny them.

This command communicates with the controller's REST API. The controller URL and
API key can be provided via flags or environment variables:
  - CFGMS_API_URL: Controller REST API URL (default: http://localhost:9080)
  - CFGMS_API_KEY: API key for authentication
  - CFGMS_TLS_CA_CERT: Path to CA certificate for TLS verification
  - CFGMS_TLS_INSECURE: Skip TLS verification (development only)

Examples:
  # List quarantined stewards awaiting approval
  cfg registration pending

  # Approve a steward registration
  cfg registration approve steward-1234567890

  # Deny a steward registration with a reason
  cfg registration deny steward-1234567890 --reason "Unauthorized deployment"`,
}

// registrationPendingCmd lists quarantined stewards awaiting approval.
var registrationPendingCmd = &cobra.Command{
	Use:   "pending",
	Short: "List pending (quarantined) steward registrations",
	Long: `List stewards that have registered but are quarantined pending operator approval.

Quarantined stewards have valid certificates but are restricted to baseline
configuration only until an operator approves or denies their registration.

Examples:
  cfg registration pending
  cfg registration pending --json`,
	RunE: runRegistrationPending,
}

// registrationApproveCmd approves a quarantined steward registration.
var registrationApproveCmd = &cobra.Command{
	Use:   "approve <pending-id>",
	Short: "Approve a pending steward registration",
	Long: `Approve a quarantined steward registration by its pending_id.

After approval, the steward's next poll returns the mTLS certificate bundle and
it gains full access to its configured policies, secrets, and scripts.

Examples:
  cfg registration approve pending-1234567890`,
	Args: cobra.ExactArgs(1),
	RunE: runRegistrationApprove,
}

// registrationDenyCmd denies a quarantined steward registration.
var registrationDenyCmd = &cobra.Command{
	Use:   "deny <pending-id>",
	Short: "Deny a pending steward registration",
	Long: `Deny a quarantined steward registration by its pending_id.

The entry is marked denied; the steward's next poll returns status="denied".
The steward must re-register to obtain a new pending_id.

Examples:
  cfg registration deny pending-1234567890
  cfg registration deny pending-1234567890 --reason "Unauthorized deployment"`,
	Args: cobra.ExactArgs(1),
	RunE: runRegistrationDeny,
}

func init() {
	registrationCmd.PersistentFlags().StringVar(&registrationAPIURL, "api-url", "", "Controller REST API URL (env: CFGMS_API_URL)")
	registrationCmd.PersistentFlags().StringVar(&registrationAPIKey, "api-key", "", "API key for authentication (env: CFGMS_API_KEY)")
	registrationCmd.PersistentFlags().StringVar(&registrationTLSCACert, "tls-ca-cert", "", "Path to CA certificate for TLS verification (env: CFGMS_TLS_CA_CERT)")
	registrationCmd.PersistentFlags().BoolVar(&registrationTLSInsecure, "tls-insecure", false, "Skip TLS verification (development only, env: CFGMS_TLS_INSECURE)")

	registrationPendingCmd.Flags().BoolVar(&registrationJSONOutput, "json", false, "Emit JSON output instead of human-readable text")

	registrationDenyCmd.Flags().StringVar(&registrationDenyReason, "reason", "", "Reason for denying the registration (optional)")

	registrationCmd.AddCommand(registrationPendingCmd)
	registrationCmd.AddCommand(registrationApproveCmd)
	registrationCmd.AddCommand(registrationDenyCmd)
}

// getRegistrationClient creates an API client using bundle auth (mTLS) when available,
// falling back to API key auth when no bundle is found or discovery is opted out.
func getRegistrationClient() (*APIClient, error) {
	apiURL := strings.TrimSuffix(registrationAPIURL, "/")
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

	apiKey := registrationAPIKey
	if apiKey == "" {
		apiKey = os.Getenv("CFGMS_API_KEY")
	}

	tlsInsecure := registrationTLSInsecure
	if !tlsInsecure && os.Getenv("CFGMS_TLS_INSECURE") == "true" {
		tlsInsecure = true
	}

	tlsCACertPath := registrationTLSCACert
	if tlsCACertPath == "" {
		tlsCACertPath = os.Getenv("CFGMS_TLS_CA_CERT")
	}

	return newClientFromFlags(apiURL, apiKey, tlsCACertPath, tlsInsecure)
}

func runRegistrationPending(cmd *cobra.Command, args []string) error {
	client, err := getRegistrationClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	pending, err := client.ListPendingRegistrations(context.Background())
	if err != nil {
		return fmt.Errorf("failed to list pending registrations: %w", err)
	}

	if registrationJSONOutput {
		return json.NewEncoder(os.Stdout).Encode(pending)
	}

	if len(pending) == 0 {
		fmt.Println("No pending registrations.")
		return nil
	}

	fmt.Printf("Pending registrations (%d):\n\n", len(pending))
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintf(w, "PENDING ID\tSTEWARD ID\tTENANT ID\tSOURCE IP\tREGISTERED AT\n")
	for _, pr := range pending {
		registeredAt := pr.RegisteredAt.UTC().Format(time.RFC3339)
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", pr.PendingID, pr.StewardID, pr.TenantID, pr.SourceIP, registeredAt)
	}
	_ = w.Flush()

	return nil
}

func runRegistrationApprove(cmd *cobra.Command, args []string) error {
	pendingID := args[0]
	client, err := getRegistrationClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	if err := client.ApproveRegistration(context.Background(), pendingID); err != nil {
		return fmt.Errorf("failed to approve registration %s: %w", pendingID, err)
	}

	fmt.Printf("Registration approved: %s\n", pendingID)
	return nil
}

func runRegistrationDeny(cmd *cobra.Command, args []string) error {
	pendingID := args[0]
	client, err := getRegistrationClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	if err := client.DenyRegistration(context.Background(), pendingID, registrationDenyReason); err != nil {
		return fmt.Errorf("failed to deny registration %s: %w", pendingID, err)
	}

	fmt.Printf("Registration denied: %s\n", pendingID)
	return nil
}
