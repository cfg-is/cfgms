// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package cmd implements the CLI commands for cfg
package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

var (
	tenantCreateID     string
	tenantCreateParent string
	tenantAPIURL       string
	tenantTLSInsecure  bool
	tenantServerName   string
	tenantJSONOutput   bool
)

// tenantCmd is the parent command for tenant management operations.
var tenantCmd = &cobra.Command{
	Use:   "tenant",
	Short: "Manage tenants",
	Long: `Manage tenants on the controller.

Tenant operations require admin mTLS authentication via an admin bundle file.
The bundle path can be provided via --bundle or the CFGMS_ADMIN_BUNDLE environment variable.

Examples:
  # Create the root tenant: a deployment's single tenant with no parent
  cfg tenant create --tenant-id=root

  # Create tenants beneath it
  cfg tenant create --tenant-id=team-root --parent=root
  cfg tenant create --tenant-id=agent-test --parent=team-root`,
}

// tenantCreateCmd creates a named tenant on the controller.
var tenantCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a tenant",
	Long: `Create a tenant with an explicit Kubernetes-compatible ID.

The tenant ID must conform to Kubernetes RFC 1123 DNS label rules:
  - Lowercase alphanumeric characters and hyphens only
  - Must not start or end with a hyphen
  - Maximum 63 characters

The command is idempotent: re-running it on an existing tenant exits 0.

A deployment has exactly one tenant with no parent, its root; every other tenant
needs --parent. Creating a second tenant without one fails.

Examples:
  cfg tenant create --tenant-id=root
  cfg tenant create --tenant-id=team-root --parent=root
  cfg tenant create --tenant-id=agent-test --parent=team-root`,
	RunE: runTenantCreate,
}

// tenantListCmd lists the tenants visible to the caller.
var tenantListCmd = &cobra.Command{
	Use:   "list",
	Short: "List tenants",
	Long: `List the tenants visible to the caller, with parent, path and status.

The controller scopes the list to the caller's tenant exactly as GET /api/v1/tenants does.
With --json the response array is printed as received.

Examples:
  cfg tenant list
  cfg tenant list --json`,
	Args: cobra.NoArgs,
	RunE: runTenantList,
}

// tenantGetCmd shows one tenant.
var tenantGetCmd = &cobra.Command{
	Use:   "get <id>",
	Short: "Show a tenant",
	Long: `Show one tenant by ID.

Exits non-zero when the tenant does not exist or is outside the caller's scope.
With --json the tenant object is printed as received.

Examples:
  cfg tenant get team-root
  cfg tenant get team-root --json`,
	Args: cobra.ExactArgs(1),
	RunE: runTenantGet,
}

func init() {
	tenantCmd.PersistentFlags().StringVar(&tenantAPIURL, "api-url", "", "Controller REST API URL (env: CFGMS_API_URL)")
	tenantCmd.PersistentFlags().BoolVar(&tenantTLSInsecure, "tls-insecure", false, "Skip TLS verification (development only)")
	tenantCmd.PersistentFlags().StringVar(&tenantServerName, "server-name", "", "Override TLS server name for certificate verification")

	tenantCreateCmd.Flags().StringVar(&tenantCreateID, "tenant-id", "", "Tenant ID (Kubernetes-compatible, required)")
	tenantCreateCmd.Flags().StringVar(&tenantCreateParent, "parent", "", "Parent tenant ID (optional)")
	_ = tenantCreateCmd.MarkFlagRequired("tenant-id")

	tenantListCmd.Flags().BoolVar(&tenantJSONOutput, "json", false, "Emit JSON output instead of human-readable text")
	tenantGetCmd.Flags().BoolVar(&tenantJSONOutput, "json", false, "Emit JSON output instead of human-readable text")

	tenantCmd.AddCommand(tenantCreateCmd)
	tenantCmd.AddCommand(tenantListCmd)
	tenantCmd.AddCommand(tenantGetCmd)
}

func getTenantAPIClient() (*APIClient, error) {
	apiURL := tenantAPIURL
	if apiURL == "" {
		apiURL = os.Getenv("CFGMS_API_URL")
	}

	tlsInsecure := tenantTLSInsecure
	if !tlsInsecure {
		tlsInsecure = os.Getenv("CFGMS_TLS_INSECURE") == "true"
	}
	serverName := tenantServerName

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

	return newClientFromFlags(apiURL, "", tlsInsecure)
}

func runTenantCreate(_ *cobra.Command, _ []string) error {
	client, err := getTenantAPIClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	req := &APITenantCreateRequest{
		ID:       tenantCreateID,
		ParentID: tenantCreateParent,
	}

	td, err := client.CreateTenantViaAPI(context.Background(), req)
	if err != nil {
		if errors.Is(err, ErrTenantAlreadyExists) {
			fmt.Printf("tenant already exists: %s\n", tenantCreateID)
			return nil
		}
		return fmt.Errorf("failed to create tenant: %w", err)
	}

	fmt.Printf("tenant created: %s\n", td.ID)
	return nil
}

// tenantPath builds the slash-separated ancestry of id from the parent links in byID.
// It stops at a missing parent (outside the caller's scope) and on a cycle.
func tenantPath(id string, byID map[string]APITenantResponse) string {
	parts := []string{}
	seen := map[string]bool{}
	for cur := id; cur != "" && !seen[cur]; {
		seen[cur] = true
		parts = append([]string{cur}, parts...)
		t, ok := byID[cur]
		if !ok {
			break
		}
		cur = t.ParentID
	}
	return strings.Join(parts, "/")
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// renderTenantList writes the text rendering of the tenant list: one row per
// tenant (id, parent, path, status), or an explicit line when there are none.
// A boundary row (an MSP the caller holds no crossing for) is marked not accessible
// and shows its tech, device and client counts instead of a path.
func renderTenantList(w io.Writer, tenants []APITenantResponse) {
	if len(tenants) == 0 {
		_, _ = fmt.Fprintln(w, "no tenants")
		return
	}
	byID := make(map[string]APITenantResponse, len(tenants))
	for _, t := range tenants {
		byID[t.ID] = t
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "ID\tPARENT\tPATH\tSTATUS")
	for _, t := range tenants {
		if t.Boundary {
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", t.ID, orDash(t.ParentID), t.ID,
				fmt.Sprintf("%s [not accessible: %d techs, %d devices, %d clients]",
					orDash(t.Status), t.TechCount, t.DeviceCount, t.ClientCount))
			continue
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", t.ID, orDash(t.ParentID), tenantPath(t.ID, byID), orDash(t.Status))
	}
	_ = tw.Flush()
}

func runTenantList(_ *cobra.Command, _ []string) error {
	client, err := getTenantAPIClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	tenants, raw, err := client.ListTenantsViaAPI(context.Background())
	if err != nil {
		return fmt.Errorf("failed to list tenants: %w", err)
	}

	if tenantJSONOutput {
		fmt.Printf("%s\n", raw)
		return nil
	}
	renderTenantList(os.Stdout, tenants)
	return nil
}

func runTenantGet(_ *cobra.Command, args []string) error {
	client, err := getTenantAPIClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	ctx := context.Background()
	t, raw, err := client.GetTenantRawViaAPI(ctx, args[0])
	if err != nil {
		return err
	}

	if tenantJSONOutput {
		fmt.Printf("%s\n", raw)
		return nil
	}

	// Resolve the ancestry for the path; an ancestor outside the caller's scope ends it.
	byID := map[string]APITenantResponse{t.ID: *t}
	for cur := *t; cur.ParentID != ""; {
		if _, seen := byID[cur.ParentID]; seen {
			break
		}
		p, _, perr := client.GetTenantRawViaAPI(ctx, cur.ParentID)
		if perr != nil {
			break
		}
		byID[p.ID] = *p
		cur = *p
	}

	fmt.Printf("ID:      %s\n", t.ID)
	fmt.Printf("Name:    %s\n", t.Name)
	fmt.Printf("Parent:  %s\n", orDash(t.ParentID))
	fmt.Printf("Path:    %s\n", tenantPath(t.ID, byID))
	fmt.Printf("Status:  %s\n", orDash(t.Status))
	if t.Description != "" {
		fmt.Printf("Description: %s\n", t.Description)
	}
	if t.CreatedAt != "" {
		fmt.Printf("Created: %s\n", t.CreatedAt)
	}
	if t.UpdatedAt != "" {
		fmt.Printf("Updated: %s\n", t.UpdatedAt)
	}
	return nil
}
