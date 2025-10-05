// Package cmd implements the CLI commands for cfgctl
package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/cfgis/cfgms/pkg/registration"
)

var (
	// Token command flags
	tokenTenantID      string
	tokenControllerURL string
	tokenGroup         string
	tokenExpiresIn     string
	tokenSingleUse     bool
)

// tokenCmd represents the token command
var tokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Manage steward registration tokens",
	Long: `Manage registration tokens for steward deployment.

Registration tokens are short API key-style strings that stewards use to
auto-register with the controller. Tokens contain tenant information and
can be time-limited, single-use, and revocable.

Examples:
  # Create a token that expires in 7 days
  cfgctl token create --tenant-id=acme-corp --controller-url=mqtt://controller.acme.com:8883 --expires=7d

  # Create a single-use token for production group
  cfgctl token create --tenant-id=acme-corp --controller-url=mqtt://controller.acme.com:8883 --group=production --single-use

  # Create a token that never expires
  cfgctl token create --tenant-id=acme-corp --controller-url=mqtt://controller.acme.com:8883`,
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
  cfgctl token create --tenant-id=acme-corp --controller-url=mqtt://controller.acme.com:8883 --expires=7d

  # Single-use token
  cfgctl token create --tenant-id=acme-corp --controller-url=mqtt://controller.acme.com:8883 --single-use

  # Token for specific group
  cfgctl token create --tenant-id=acme-corp --controller-url=mqtt://controller.acme.com:8883 --group=production`,
	RunE: runTokenCreate,
}

func init() {
	tokenCreateCmd.Flags().StringVar(&tokenTenantID, "tenant-id", "", "Tenant ID (required)")
	tokenCreateCmd.Flags().StringVar(&tokenControllerURL, "controller-url", "", "Controller MQTT URL (required)")
	tokenCreateCmd.Flags().StringVar(&tokenGroup, "group", "", "Optional group identifier")
	tokenCreateCmd.Flags().StringVar(&tokenExpiresIn, "expires", "", "Expiration duration (e.g., 24h, 7d, 30d)")
	tokenCreateCmd.Flags().BoolVar(&tokenSingleUse, "single-use", false, "Token can only be used once")

	tokenCreateCmd.MarkFlagRequired("tenant-id")
	tokenCreateCmd.MarkFlagRequired("controller-url")

	tokenCmd.AddCommand(tokenCreateCmd)
}

func runTokenCreate(cmd *cobra.Command, args []string) error {
	// Create token request
	req := &registration.TokenCreateRequest{
		TenantID:      tokenTenantID,
		ControllerURL: tokenControllerURL,
		Group:         tokenGroup,
		ExpiresIn:     tokenExpiresIn,
		SingleUse:     tokenSingleUse,
	}

	// Generate token
	token, err := registration.CreateToken(req)
	if err != nil {
		return fmt.Errorf("failed to create token: %w", err)
	}

	// Store token (in-memory for now, will be controller API in future)
	store := registration.NewMemoryStore()
	if err := store.SaveToken(context.Background(), token); err != nil {
		return fmt.Errorf("failed to save token: %w", err)
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
		fmt.Printf("  Expires:        %s\n", token.ExpiresAt.Format("2006-01-02 15:04:05 MST"))
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
