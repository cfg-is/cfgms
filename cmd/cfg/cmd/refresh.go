// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package cmd implements the CLI commands for cfg
package cmd

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

var (
	refreshAPIURL      string
	refreshTLSCACert   string
	refreshTLSInsecure bool
	refreshServerName  string
	refreshTenantID    string
	refreshReason      string
	refreshPolicyMode  string
	refreshMaxDormancy int
	refreshSetDormancy bool
)

// refreshCmd is the parent command for refresh management subcommands.
var refreshCmd = &cobra.Command{
	Use:   "refresh",
	Short: "Manage steward registration-refresh requests and policy",
	Long: `Manage the registration-refresh approval queue and per-tenant refresh policy.

When a steward's mTLS certificate expires while it has been offline, it must
complete a registration-refresh challenge to regain access. Depending on the
tenant's refresh policy, the request may be queued for manual operator review.

Use these commands to list, approve, or reject pending refresh requests and to
get or set the per-tenant refresh policy.

This command communicates with the controller's REST API and requires an admin mTLS
bundle or an active session (cfg connect). The controller URL can be provided via
flags or environment variables:
  - CFGMS_API_URL: Controller REST API URL (default: http://localhost:9080)
  - CFGMS_ADMIN_BUNDLE: Path to the admin mTLS bundle
  - CFGMS_TLS_CA_CERT: Path to CA certificate for TLS verification
  - CFGMS_TLS_INSECURE: Skip TLS verification (development only)

Examples:
  # List pending refresh requests for all tenants
  cfg steward refresh list

  # List pending refresh requests for a specific tenant
  cfg steward refresh list --tenant acme-corp

  # Approve a pending refresh request
  cfg steward refresh approve refresh-1234567890

  # Reject a pending refresh request with a reason
  cfg steward refresh reject refresh-1234567890 --reason "Device decommissioned"

  # Get the refresh policy for a tenant
  cfg steward refresh policy get --tenant acme-corp

  # Set the refresh policy for a tenant
  cfg steward refresh policy set --mode auto_accept --tenant acme-corp`,
}

// refreshListCmd lists pending refresh requests.
var refreshListCmd = &cobra.Command{
	Use:   "list",
	Short: "List pending registration-refresh requests",
	Long: `List stewards with pending registration-refresh requests awaiting operator review.

Examples:
  cfg steward refresh list
  cfg steward refresh list --tenant acme-corp`,
	RunE: runRefreshList,
}

// refreshApproveCmd approves a pending refresh request.
var refreshApproveCmd = &cobra.Command{
	Use:   "approve <pending_id>",
	Short: "Approve a pending registration-refresh request",
	Long: `Approve a pending registration-refresh request by its pending_id.

A new mTLS certificate is generated and stored. The steward receives the
certificate bundle on its next poll.

Examples:
  cfg steward refresh approve refresh-1234567890`,
	Args: cobra.ExactArgs(1),
	RunE: runRefreshApprove,
}

// refreshRejectCmd rejects a pending refresh request.
var refreshRejectCmd = &cobra.Command{
	Use:   "reject <pending_id>",
	Short: "Reject a pending registration-refresh request",
	Long: `Reject a pending registration-refresh request by its pending_id.

The steward's refresh request is marked rejected. The steward must re-initiate
the challenge flow to get a new pending_id.

Examples:
  cfg steward refresh reject refresh-1234567890
  cfg steward refresh reject refresh-1234567890 --reason "Device decommissioned"`,
	Args: cobra.ExactArgs(1),
	RunE: runRefreshReject,
}

// refreshPolicyCmd is the parent command for policy subcommands.
var refreshPolicyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Manage the per-tenant registration-refresh policy",
}

// refreshPolicyGetCmd gets the refresh policy for a tenant.
var refreshPolicyGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Get the registration-refresh policy for a tenant",
	Long: `Display the registration-refresh policy for the given tenant.

When no policy has been set, the default is require_approval.

Examples:
  cfg steward refresh policy get --tenant acme-corp`,
	RunE: runRefreshPolicyGet,
}

// refreshPolicySetCmd sets the refresh policy for a tenant.
var refreshPolicySetCmd = &cobra.Command{
	Use:   "set",
	Short: "Set the registration-refresh policy for a tenant",
	Long: `Set the registration-refresh policy for the given tenant.

Modes:
  auto_accept      — approve automatically when provenance score is sufficient
  require_approval — queue for manual operator review (default)
  reject           — deny all refresh requests for this tenant

Examples:
  cfg steward refresh policy set --mode require_approval --tenant acme-corp
  cfg steward refresh policy set --mode auto_accept --tenant acme-corp
  cfg steward refresh policy set --mode auto_accept --max-dormancy-days 90 --tenant acme-corp`,
	RunE: runRefreshPolicySet,
}

func init() {
	// Persistent flags available on all refresh subcommands.
	refreshCmd.PersistentFlags().StringVar(&refreshAPIURL, "api-url", "", "Controller REST API URL (env: CFGMS_API_URL)")
	refreshCmd.PersistentFlags().StringVar(&refreshTLSCACert, "tls-ca-cert", "", "Path to CA certificate for TLS verification (env: CFGMS_TLS_CA_CERT)")
	refreshCmd.PersistentFlags().BoolVar(&refreshTLSInsecure, "tls-insecure", false, "Skip TLS verification (development only, env: CFGMS_TLS_INSECURE)")
	refreshCmd.PersistentFlags().StringVar(&refreshServerName, "server-name", "", "Override TLS server name for certificate verification")

	// refresh list
	refreshListCmd.Flags().StringVar(&refreshTenantID, "tenant", "", "Filter by tenant ID")

	// refresh reject
	refreshRejectCmd.Flags().StringVar(&refreshReason, "reason", "", "Reason for rejection (optional)")

	// refresh policy get
	refreshPolicyGetCmd.Flags().StringVar(&refreshTenantID, "tenant", "", "Tenant ID (required)")
	_ = refreshPolicyGetCmd.MarkFlagRequired("tenant")

	// refresh policy set
	refreshPolicySetCmd.Flags().StringVar(&refreshPolicyMode, "mode", "", "Refresh policy mode: auto_accept, require_approval, or reject (required)")
	refreshPolicySetCmd.Flags().IntVar(&refreshMaxDormancy, "max-dormancy-days", 0, "Maximum dormancy in days (0 = disabled)")
	refreshPolicySetCmd.Flags().BoolVar(&refreshSetDormancy, "set-dormancy", false, "Explicitly set max-dormancy-days (required to disable with 0)")
	refreshPolicySetCmd.Flags().StringVar(&refreshTenantID, "tenant", "", "Tenant ID (required)")
	_ = refreshPolicySetCmd.MarkFlagRequired("mode")
	_ = refreshPolicySetCmd.MarkFlagRequired("tenant")

	// Wire subcommands.
	refreshPolicyCmd.AddCommand(refreshPolicyGetCmd)
	refreshPolicyCmd.AddCommand(refreshPolicySetCmd)
	refreshCmd.AddCommand(refreshListCmd)
	refreshCmd.AddCommand(refreshApproveCmd)
	refreshCmd.AddCommand(refreshRejectCmd)
	refreshCmd.AddCommand(refreshPolicyCmd)
}

// getRefreshClient creates an API client for refresh management commands.
func getRefreshClient() (*APIClient, error) {
	apiURL := refreshAPIURL
	if apiURL == "" {
		apiURL = os.Getenv("CFGMS_API_URL")
	}

	tlsInsecure := refreshTLSInsecure
	if !tlsInsecure {
		tlsInsecure = os.Getenv("CFGMS_TLS_INSECURE") == "true"
	}
	serverName := refreshServerName

	return requireSessionOrBundleClient(apiURL, tlsInsecure, serverName)
}

func runRefreshList(_ *cobra.Command, _ []string) error {
	client, err := getRefreshClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	entries, err := client.ListPendingRefreshes(context.Background(), refreshTenantID)
	if err != nil {
		return fmt.Errorf("failed to list pending refreshes: %w", err)
	}

	if len(entries) == 0 {
		fmt.Println("No pending refresh requests.")
		return nil
	}

	fmt.Printf("Pending refresh requests (%d):\n\n", len(entries))
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintf(w, "PENDING ID\tDEVICE ID\tTENANT ID\tSOURCE IP\tSTATUS\tCREATED AT\n")
	for _, e := range entries {
		createdAt := e.CreatedAt.UTC().Format(time.RFC3339)
		deviceID := e.DeviceID
		if len(deviceID) > 16 {
			deviceID = deviceID[:16] + "…"
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			e.PendingID, deviceID, e.TenantID, e.SourceIP, e.Status, createdAt)
	}
	_ = w.Flush()

	return nil
}

func runRefreshApprove(_ *cobra.Command, args []string) error {
	pendingID := args[0]

	client, err := getRefreshClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	resp, err := client.ApproveRefresh(context.Background(), pendingID)
	if err != nil {
		return fmt.Errorf("failed to approve refresh %s: %w", pendingID, err)
	}

	fmt.Printf("Refresh request approved: %s (status: %s)\n", resp.PendingID, resp.Status)
	return nil
}

func runRefreshReject(_ *cobra.Command, args []string) error {
	pendingID := args[0]

	client, err := getRefreshClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	if err := client.RejectRefresh(context.Background(), pendingID, refreshReason); err != nil {
		return fmt.Errorf("failed to reject refresh %s: %w", pendingID, err)
	}

	fmt.Printf("Refresh request rejected: %s\n", pendingID)
	return nil
}

func runRefreshPolicyGet(_ *cobra.Command, _ []string) error {
	client, err := getRefreshClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	policy, err := client.GetRefreshPolicy(context.Background(), refreshTenantID)
	if err != nil {
		return fmt.Errorf("failed to get refresh policy for tenant %s: %w", refreshTenantID, err)
	}

	fmt.Printf("Tenant:           %s\n", policy.TenantID)
	fmt.Printf("Mode:             %s\n", policy.Mode)
	if policy.MaxDormancyDays != nil {
		fmt.Printf("Max Dormancy:     %d days\n", *policy.MaxDormancyDays)
	} else {
		fmt.Printf("Max Dormancy:     disabled\n")
	}
	return nil
}

func runRefreshPolicySet(_ *cobra.Command, _ []string) error {
	client, err := getRefreshClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	var maxDormancy *int
	if refreshSetDormancy || refreshMaxDormancy > 0 {
		v := refreshMaxDormancy
		maxDormancy = &v
	}

	if err := client.SetRefreshPolicy(context.Background(), refreshTenantID, refreshPolicyMode, maxDormancy); err != nil {
		return fmt.Errorf("failed to set refresh policy for tenant %s: %w", refreshTenantID, err)
	}

	fmt.Printf("Refresh policy updated for tenant %s: mode=%s\n", refreshTenantID, refreshPolicyMode)
	if maxDormancy != nil {
		fmt.Printf("Max dormancy: %d days\n", *maxDormancy)
	}
	return nil
}

// ---- CLI response types -------------------------------------------------------

// APIPendingRefreshEntry is the CLI view of a pending refresh record.
type APIPendingRefreshEntry struct {
	PendingID               string    `json:"pending_id"`
	DeviceID                string    `json:"device_id"`
	TenantID                string    `json:"tenant_id"`
	SourceIP                string    `json:"source_ip"`
	ProvenanceMatchedFields int       `json:"provenance_matched_fields"`
	ProvenanceTotalFields   int       `json:"provenance_total_fields"`
	Status                  string    `json:"status"`
	CreatedAt               time.Time `json:"created_at"`
	ExpiresAt               time.Time `json:"expires_at"`
}

// APIApproveRefreshResponse is the CLI view of the approve response. No client_key
// field exists on the wire (Issue #3781): the controller never generates or sees a
// private key for this credential.
type APIApproveRefreshResponse struct {
	Status      string `json:"status"`
	PendingID   string `json:"pending_id"`
	ClientCert  string `json:"client_cert,omitempty"`
	CACert      string `json:"ca_cert,omitempty"`
	SigningCert string `json:"signing_cert,omitempty"`
}

// APIRefreshPolicyResponse is the CLI view of a refresh policy.
type APIRefreshPolicyResponse struct {
	TenantID        string `json:"tenant_id"`
	Mode            string `json:"mode"`
	MaxDormancyDays *int   `json:"max_dormancy_days,omitempty"`
}
