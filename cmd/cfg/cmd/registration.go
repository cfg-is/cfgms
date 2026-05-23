// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package cmd implements the CLI commands for cfg
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

var (
	registrationAPIURL           string
	registrationAPIKey           string
	registrationTLSCACert        string
	registrationTLSInsecure      bool
	registrationJSONOutput       bool
	registrationDenyReason       string
	registrationIPTrustTenantID  string
	registrationIPTrustPreSeeded bool
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

// registrationApproveAllCmd approves all pending steward registrations in one operation.
var registrationApproveAllCmd = &cobra.Command{
	Use:   "approve-all",
	Short: "Approve all pending steward registrations",
	Long: `Approve all quarantined steward registrations in one operation.

Returns the count of newly approved registrations. Already-approved stewards
are not counted (idempotent).

Examples:
  cfg registration approve-all`,
	RunE: runRegistrationApproveAll,
}

// registrationApproveByCIDRCmd approves pending registrations by source IP CIDR.
var registrationApproveByCIDRCmd = &cobra.Command{
	Use:   "approve-by-cidr <cidr>",
	Short: "Approve pending steward registrations whose source IP falls in the CIDR",
	Long: `Approve pending registrations for stewards whose source IP falls within the
given CIDR. Registrations outside the CIDR remain pending.

Returns the count of newly approved registrations.

Examples:
  cfg registration approve-by-cidr 192.168.1.0/24`,
	Args: cobra.ExactArgs(1),
	RunE: runRegistrationApproveByCIDR,
}

// registrationIPTrustCmd is the parent for ip-trust subcommands.
var registrationIPTrustCmd = &cobra.Command{
	Use:   "ip-trust",
	Short: "Manage IP trust ranges for automatic registration approval",
	Long:  `Add or revoke trusted IP CIDR ranges for tenant-scoped automatic registration approval.`,
}

// registrationIPTrustAddCmd adds a trusted CIDR for a tenant.
var registrationIPTrustAddCmd = &cobra.Command{
	Use:   "add <cidr>",
	Short: "Add a trusted IP CIDR for a tenant",
	Long: `Add a trusted CIDR range for the given tenant. Stewards registering from IPs
in this range are automatically approved.

Examples:
  cfg registration ip-trust add 10.0.0.0/8 --tenant-id acme`,
	Args: cobra.ExactArgs(1),
	RunE: runRegistrationIPTrustAdd,
}

// registrationIPTrustRevokeCmd revokes a trusted CIDR for a tenant.
var registrationIPTrustRevokeCmd = &cobra.Command{
	Use:   "revoke <cidr>",
	Short: "Revoke a trusted IP CIDR for a tenant",
	Long: `Revoke a trusted CIDR range for the given tenant. Subsequent registrations
from IPs in this range will be quarantined for manual review.

Examples:
  cfg registration ip-trust revoke 10.0.0.0/8 --tenant-id acme`,
	Args: cobra.ExactArgs(1),
	RunE: runRegistrationIPTrustRevoke,
}

func init() {
	registrationCmd.PersistentFlags().StringVar(&registrationAPIURL, "api-url", "", "Controller REST API URL (env: CFGMS_API_URL)")
	registrationCmd.PersistentFlags().StringVar(&registrationAPIKey, "api-key", "", "API key for authentication (env: CFGMS_API_KEY)")
	registrationCmd.PersistentFlags().StringVar(&registrationTLSCACert, "tls-ca-cert", "", "Path to CA certificate for TLS verification (env: CFGMS_TLS_CA_CERT)")
	registrationCmd.PersistentFlags().BoolVar(&registrationTLSInsecure, "tls-insecure", false, "Skip TLS verification (development only, env: CFGMS_TLS_INSECURE)")

	registrationPendingCmd.Flags().BoolVar(&registrationJSONOutput, "json", false, "Emit JSON output instead of human-readable text")

	registrationDenyCmd.Flags().StringVar(&registrationDenyReason, "reason", "", "Reason for denying the registration (optional)")

	registrationIPTrustAddCmd.Flags().BoolVar(&registrationIPTrustPreSeeded, "pre-seeded", true, "Mark this CIDR as pre-seeded (operator intent: auto-approve)")
	registrationIPTrustAddCmd.Flags().StringVar(&registrationIPTrustTenantID, "tenant-id", "", "Tenant ID to configure (required)")
	_ = registrationIPTrustAddCmd.MarkFlagRequired("tenant-id")

	registrationIPTrustRevokeCmd.Flags().StringVar(&registrationIPTrustTenantID, "tenant-id", "", "Tenant ID to configure (required)")
	_ = registrationIPTrustRevokeCmd.MarkFlagRequired("tenant-id")

	registrationIPTrustCmd.AddCommand(registrationIPTrustAddCmd)
	registrationIPTrustCmd.AddCommand(registrationIPTrustRevokeCmd)

	registrationCmd.AddCommand(registrationPendingCmd)
	registrationCmd.AddCommand(registrationApproveCmd)
	registrationCmd.AddCommand(registrationDenyCmd)
	registrationCmd.AddCommand(registrationApproveAllCmd)
	registrationCmd.AddCommand(registrationApproveByCIDRCmd)
	registrationCmd.AddCommand(registrationIPTrustCmd)
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

// lookupRDNS performs a best-effort reverse DNS lookup for the given IP.
// Returns "-" on failure or timeout (2-second budget).
func lookupRDNS(sourceIP string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var r net.Resolver
	names, err := r.LookupAddr(ctx, sourceIP)
	if err != nil || len(names) == 0 {
		return "-"
	}
	return strings.TrimSuffix(names[0], ".")
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

	// Populate RDNS at display time — best-effort, does not affect the server record.
	for i := range pending {
		pending[i].RDNS = lookupRDNS(pending[i].SourceIP)
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
	_, _ = fmt.Fprintf(w, "PENDING ID\tSTEWARD ID\tTENANT ID\tSOURCE IP\tRDNS\tREGISTERED AT\n")
	for _, pr := range pending {
		registeredAt := pr.RegisteredAt.UTC().Format(time.RFC3339)
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			pr.PendingID, pr.StewardID, pr.TenantID, pr.SourceIP, pr.RDNS, registeredAt)
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

func runRegistrationApproveAll(cmd *cobra.Command, args []string) error {
	client, err := getRegistrationClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	count, err := client.ApproveAllRegistrations(context.Background())
	if err != nil {
		return fmt.Errorf("failed to approve all registrations: %w", err)
	}

	fmt.Printf("Approved %d registrations\n", count)
	return nil
}

func runRegistrationApproveByCIDR(cmd *cobra.Command, args []string) error {
	cidr := args[0]
	client, err := getRegistrationClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	count, err := client.ApproveByCIDR(context.Background(), cidr)
	if err != nil {
		return fmt.Errorf("failed to approve registrations by CIDR %s: %w", cidr, err)
	}

	fmt.Printf("Approved %d registrations\n", count)
	return nil
}

func runRegistrationIPTrustAdd(cmd *cobra.Command, args []string) error {
	cidr := args[0]
	client, err := getRegistrationClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	if err := client.AddIPTrust(context.Background(), registrationIPTrustTenantID, cidr); err != nil {
		return fmt.Errorf("failed to add IP trust range %s for tenant %s: %w", cidr, registrationIPTrustTenantID, err)
	}

	fmt.Printf("IP trust range added: %s (tenant: %s)\n", cidr, registrationIPTrustTenantID)
	return nil
}

func runRegistrationIPTrustRevoke(cmd *cobra.Command, args []string) error {
	cidr := args[0]
	client, err := getRegistrationClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	if err := client.RevokeIPTrust(context.Background(), registrationIPTrustTenantID, cidr); err != nil {
		return fmt.Errorf("failed to revoke IP trust range %s for tenant %s: %w", cidr, registrationIPTrustTenantID, err)
	}

	fmt.Printf("IP trust range revoked: %s (tenant: %s)\n", cidr, registrationIPTrustTenantID)
	return nil
}
