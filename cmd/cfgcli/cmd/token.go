// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
// Package cmd implements the CLI commands for cfgcli
package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	// Token command flags
	tokenTenantID      string
	tokenControllerURL string
	tokenGroup         string
	tokenExpiresIn     string
	tokenSingleUse     bool

	// API connection flags
	tokenAPIURL     string
	tokenAPIKey     string
	tokenTLSCACert  string
	tokenTLSInsecure bool
)

// tokenCmd represents the token command
var tokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Manage steward registration tokens",
	Long: `Manage registration tokens for steward deployment.

Registration tokens are short API key-style strings that stewards use to
auto-register with the controller. Tokens contain tenant information and
can be time-limited, single-use, and revocable.

This command communicates with the controller's REST API to manage tokens.
The controller URL and API key can be provided via flags or environment variables:
  - CFGMS_API_URL: Controller REST API URL (default: http://localhost:9080)
  - CFGMS_API_KEY: API key for authentication
  - CFGMS_TLS_CA_CERT: Path to CA certificate for TLS verification
  - CFGMS_TLS_INSECURE: Skip TLS verification (development only)

Examples:
  # Create a token that expires in 7 days
  cfgcli token create --tenant-id=acme-corp --controller-url=mqtt://controller.acme.com:8883 --expires=7d

  # Create a single-use token for production group
  cfgcli token create --tenant-id=acme-corp --controller-url=mqtt://controller.acme.com:8883 --group=production --single-use

  # List all tokens for a tenant
  cfgcli token list --tenant-id=acme-corp

  # Revoke a token
  cfgcli token revoke cfgms_reg_abc123def456`,
}

// tokenCreateCmd represents the token create command
var tokenCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new registration token",
	Long: `Create a new registration token for steward deployment.

The token will be a short API key-style string (e.g., cfgms_reg_abc123def456)
that stewards can use to auto-register with the controller.

Expiration formats:
  - "24h" = 24 hours
  - "7d" = 7 days
  - "30d" = 30 days
  - "" (empty) = never expires

Examples:
  # 7-day expiring token
  cfgcli token create --tenant-id=acme-corp --controller-url=mqtt://controller.acme.com:8883 --expires=7d

  # Single-use token
  cfgcli token create --tenant-id=acme-corp --controller-url=mqtt://controller.acme.com:8883 --single-use

  # Token for specific group
  cfgcli token create --tenant-id=acme-corp --controller-url=mqtt://controller.acme.com:8883 --group=production`,
	RunE: runTokenCreate,
}

// tokenListCmd represents the token list command
var tokenListCmd = &cobra.Command{
	Use:   "list",
	Short: "List registration tokens",
	Long: `List registration tokens from the controller.

By default, lists all tokens. Use --tenant-id to filter by tenant.

Examples:
  # List all tokens
  cfgcli token list

  # List tokens for a specific tenant
  cfgcli token list --tenant-id=acme-corp`,
	RunE: runTokenList,
}

// tokenRevokeCmd represents the token revoke command
var tokenRevokeCmd = &cobra.Command{
	Use:   "revoke <token>",
	Short: "Revoke a registration token",
	Long: `Revoke a registration token so it can no longer be used.

The token will be marked as revoked but not deleted from storage.
This allows for audit trail of token usage.

Examples:
  cfgcli token revoke cfgms_reg_abc123def456`,
	Args: cobra.ExactArgs(1),
	RunE: runTokenRevoke,
}

// tokenDeleteCmd represents the token delete command
var tokenDeleteCmd = &cobra.Command{
	Use:   "delete <token>",
	Short: "Delete a registration token",
	Long: `Delete a registration token from storage.

This permanently removes the token. Use 'revoke' instead if you want
to maintain an audit trail.

Examples:
  cfgcli token delete cfgms_reg_abc123def456`,
	Args: cobra.ExactArgs(1),
	RunE: runTokenDelete,
}

func init() {
	// Global token command flags (for API connection)
	tokenCmd.PersistentFlags().StringVar(&tokenAPIURL, "api-url", "", "Controller REST API URL (env: CFGMS_API_URL)")
	tokenCmd.PersistentFlags().StringVar(&tokenAPIKey, "api-key", "", "API key for authentication (env: CFGMS_API_KEY)")
	tokenCmd.PersistentFlags().StringVar(&tokenTLSCACert, "tls-ca-cert", "", "Path to CA certificate for TLS verification (env: CFGMS_TLS_CA_CERT)")
	tokenCmd.PersistentFlags().BoolVar(&tokenTLSInsecure, "tls-insecure", false, "Skip TLS verification (development only, env: CFGMS_TLS_INSECURE)")

	// Create command flags
	tokenCreateCmd.Flags().StringVar(&tokenTenantID, "tenant-id", "", "Tenant ID (required)")
	tokenCreateCmd.Flags().StringVar(&tokenControllerURL, "controller-url", "", "Controller MQTT URL for steward connections (required)")
	tokenCreateCmd.Flags().StringVar(&tokenGroup, "group", "", "Optional group identifier")
	tokenCreateCmd.Flags().StringVar(&tokenExpiresIn, "expires", "", "Expiration duration (e.g., 24h, 7d, 30d)")
	tokenCreateCmd.Flags().BoolVar(&tokenSingleUse, "single-use", false, "Token can only be used once")

	_ = tokenCreateCmd.MarkFlagRequired("tenant-id")
	_ = tokenCreateCmd.MarkFlagRequired("controller-url")

	// List command flags
	tokenListCmd.Flags().StringVar(&tokenTenantID, "tenant-id", "", "Filter by tenant ID (optional)")

	// Add subcommands
	tokenCmd.AddCommand(tokenCreateCmd)
	tokenCmd.AddCommand(tokenListCmd)
	tokenCmd.AddCommand(tokenRevokeCmd)
	tokenCmd.AddCommand(tokenDeleteCmd)
}

// getAPIClient creates an API client using flags or environment variables
func getAPIClient() (*APIClient, error) {
	// Resolve API URL
	apiURL := tokenAPIURL
	if apiURL == "" {
		apiURL = os.Getenv("CFGMS_API_URL")
	}
	if apiURL == "" {
		apiURL = "http://localhost:9080"
	}

	// Resolve API key
	apiKey := tokenAPIKey
	if apiKey == "" {
		apiKey = os.Getenv("CFGMS_API_KEY")
	}

	// Resolve TLS settings
	tlsInsecure := tokenTLSInsecure
	if !tlsInsecure && os.Getenv("CFGMS_TLS_INSECURE") == "true" {
		tlsInsecure = true
	}

	tlsCACertPath := tokenTLSCACert
	if tlsCACertPath == "" {
		tlsCACertPath = os.Getenv("CFGMS_TLS_CA_CERT")
	}

	// Load CA certificate if provided
	var caCertPEM []byte
	if tlsCACertPath != "" {
		var err error
		// #nosec G304 - CA certificate path is intentionally provided by user via CLI flag or env var
		caCertPEM, err = os.ReadFile(tlsCACertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}
	}

	cfg := &APIClientConfig{
		BaseURL:     apiURL,
		APIKey:      apiKey,
		CACertPEM:   caCertPEM,
		TLSInsecure: tlsInsecure,
	}

	return NewAPIClient(cfg)
}

func runTokenCreate(cmd *cobra.Command, args []string) error {
	client, err := getAPIClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	// Create token via API
	req := &APITokenCreateRequest{
		TenantID:      tokenTenantID,
		ControllerURL: tokenControllerURL,
		Group:         tokenGroup,
		ExpiresIn:     tokenExpiresIn,
		SingleUse:     tokenSingleUse,
	}

	token, err := client.CreateToken(context.Background(), req)
	if err != nil {
		return fmt.Errorf("failed to create token: %w", err)
	}

	// Output results
	fmt.Printf("Registration Token: %s\n\n", token.Token)

	fmt.Println("Token Details:")
	fmt.Printf("  Tenant ID:      %s\n", token.TenantID)
	fmt.Printf("  Controller URL: %s\n", token.ControllerURL)
	if token.Group != "" {
		fmt.Printf("  Group:          %s\n", token.Group)
	}
	if token.ExpiresAt != nil {
		fmt.Printf("  Expires:        %s\n", *token.ExpiresAt)
	} else {
		fmt.Printf("  Expires:        Never\n")
	}
	fmt.Printf("  Single Use:     %v\n", token.SingleUse)

	fmt.Println()
	fmt.Println("Deployment Examples:")
	fmt.Println()
	fmt.Println("Windows MSI:")
	fmt.Printf("  msiexec /i cfgms-steward.msi /quiet REGTOKEN=\"%s\"\n", token.Token)
	fmt.Println()
	fmt.Println("Linux/macOS:")
	fmt.Printf("  ./cfgms-steward-install --regtoken=\"%s\"\n", token.Token)
	fmt.Println()
	fmt.Println("Direct execution:")
	fmt.Printf("  cfgms-steward --regtoken=%s\n", token.Token)

	return nil
}

func runTokenList(cmd *cobra.Command, args []string) error {
	client, err := getAPIClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	resp, err := client.ListTokens(context.Background(), tokenTenantID)
	if err != nil {
		return fmt.Errorf("failed to list tokens: %w", err)
	}

	if resp.Total == 0 {
		fmt.Println("No tokens found.")
		return nil
	}

	fmt.Printf("Found %d token(s):\n\n", resp.Total)

	for _, token := range resp.Tokens {
		fmt.Printf("Token: %s\n", token.Token)
		fmt.Printf("  Tenant ID:      %s\n", token.TenantID)
		fmt.Printf("  Controller URL: %s\n", token.ControllerURL)
		if token.Group != "" {
			fmt.Printf("  Group:          %s\n", token.Group)
		}
		fmt.Printf("  Created:        %s\n", token.CreatedAt)
		if token.ExpiresAt != nil {
			fmt.Printf("  Expires:        %s\n", *token.ExpiresAt)
		} else {
			fmt.Printf("  Expires:        Never\n")
		}
		fmt.Printf("  Single Use:     %v\n", token.SingleUse)
		if token.UsedAt != nil {
			fmt.Printf("  Used At:        %s\n", *token.UsedAt)
			fmt.Printf("  Used By:        %s\n", token.UsedBy)
		}
		if token.Revoked {
			fmt.Printf("  Status:         REVOKED")
			if token.RevokedAt != nil {
				fmt.Printf(" (at %s)", *token.RevokedAt)
			}
			fmt.Println()
		} else {
			fmt.Printf("  Status:         Active\n")
		}
		fmt.Println()
	}

	return nil
}

func runTokenRevoke(cmd *cobra.Command, args []string) error {
	tokenStr := args[0]
	client, err := getAPIClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	token, err := client.RevokeToken(context.Background(), tokenStr)
	if err != nil {
		return fmt.Errorf("failed to revoke token: %w", err)
	}

	fmt.Printf("Token revoked successfully: %s\n", token.Token)
	if token.RevokedAt != nil {
		fmt.Printf("  Revoked at: %s\n", *token.RevokedAt)
	}

	return nil
}

func runTokenDelete(cmd *cobra.Command, args []string) error {
	tokenStr := args[0]
	client, err := getAPIClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	if err := client.DeleteToken(context.Background(), tokenStr); err != nil {
		return fmt.Errorf("failed to delete token: %w", err)
	}

	fmt.Printf("Token deleted successfully: %s\n", tokenStr)

	return nil
}
