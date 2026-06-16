// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package cmd implements the CLI commands for cfg
package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	tenantCreateID     string
	tenantCreateParent string
	tenantAPIURL       string
	tenantTLSInsecure  bool
)

// tenantCmd is the parent command for tenant management operations.
var tenantCmd = &cobra.Command{
	Use:   "tenant",
	Short: "Manage tenants",
	Long: `Manage tenants on the controller.

Tenant operations require admin mTLS authentication via an admin bundle file.
The bundle path can be provided via --bundle or the CFGMS_ADMIN_BUNDLE environment variable.

Examples:
  # Create a root tenant
  cfg tenant create --tenant-id=team-root

  # Create a child tenant
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

Examples:
  cfg tenant create --tenant-id=team-root
  cfg tenant create --tenant-id=agent-test --parent=team-root`,
	RunE: runTenantCreate,
}

func init() {
	tenantCmd.PersistentFlags().StringVar(&tenantAPIURL, "api-url", "", "Controller REST API URL (env: CFGMS_API_URL)")
	tenantCmd.PersistentFlags().BoolVar(&tenantTLSInsecure, "tls-insecure", false, "Skip TLS verification (development only)")

	tenantCreateCmd.Flags().StringVar(&tenantCreateID, "tenant-id", "", "Tenant ID (Kubernetes-compatible, required)")
	tenantCreateCmd.Flags().StringVar(&tenantCreateParent, "parent", "", "Parent tenant ID (optional)")
	_ = tenantCreateCmd.MarkFlagRequired("tenant-id")

	tenantCmd.AddCommand(tenantCreateCmd)
}

func getTenantAPIClient() (*APIClient, error) {
	apiURL := tenantAPIURL
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

	tlsInsecure := tenantTLSInsecure
	if !tlsInsecure && os.Getenv("CFGMS_TLS_INSECURE") == "true" {
		tlsInsecure = true
	}

	return newClientFromFlags(apiURL, "", "", tlsInsecure)
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
