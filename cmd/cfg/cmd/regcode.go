// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
// Package cmd implements the CLI commands for cfg
package cmd

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

// RegistrationCode represents the decoded registration code structure.
type RegistrationCode struct {
	// TenantID is the unique identifier for the tenant
	TenantID string `json:"tenant_id"`

	// ControllerURL is the MQTT broker URL (e.g., "mqtt://controller.example.com:8883")
	ControllerURL string `json:"controller_url"`

	// Group is an optional group identifier for organization
	Group string `json:"group,omitempty"`

	// Version is the registration code format version
	Version int `json:"version"`
}

var (
	// Registration code flags
	tenantID      string
	controllerURL string
	group         string
	decode        bool
)

// regcodeCmd represents the registration code command
var regcodeCmd = &cobra.Command{
	Use:   "regcode",
	Short: "Generate or decode steward registration codes",
	Long: `Generate or decode registration codes for steward deployment.

Registration codes encode tenant information, controller URL, and optional group
into a base64-encoded JSON string that can be passed as a command-line parameter
to the steward installer.

Examples:
  # Generate a registration code
  cfg regcode --tenant-id=acme-corp --controller-url=mqtt://controller.acme.com:8883

  # Generate with optional group
  cfg regcode --tenant-id=acme-corp --controller-url=mqtt://controller.acme.com:8883 --group=production

  # Decode a registration code
  cfg regcode --decode eyJ0ZW5hbnRfaWQi...`,
	RunE: runRegCode,
}

func init() {
	regcodeCmd.Flags().StringVar(&tenantID, "tenant-id", "", "Tenant ID (required for generation)")
	regcodeCmd.Flags().StringVar(&controllerURL, "controller-url", "", "Controller MQTT URL (required for generation)")
	regcodeCmd.Flags().StringVar(&group, "group", "", "Optional group identifier")
	regcodeCmd.Flags().BoolVar(&decode, "decode", false, "Decode a registration code (provide code as argument)")
}

func runRegCode(cmd *cobra.Command, args []string) error {
	if decode {
		return decodeRegistrationCode(args)
	}
	return generateRegistrationCode()
}

// generateRegistrationCode generates a new registration code.
func generateRegistrationCode() error {
	// Validate required fields
	if tenantID == "" {
		return fmt.Errorf("--tenant-id is required for generation\n\nThe tenant ID is your organization's unique identifier (e.g., 'acme-corp', 'contoso')\n\nExample:\n  cfg regcode --tenant-id=acme-corp --controller-url=mqtts://controller.example.com:8883")
	}
	if controllerURL == "" {
		return fmt.Errorf("--controller-url is required for generation\n\nThe controller URL is the MQTT broker endpoint where stewards connect\n\nFormat: mqtt://HOST:PORT or mqtts://HOST:PORT (mqtts recommended for production)\n\nExample:\n  cfg regcode --tenant-id=acme-corp --controller-url=mqtts://controller.example.com:8883")
	}

	// Validate controller URL format
	if !strings.HasPrefix(controllerURL, "mqtt://") && !strings.HasPrefix(controllerURL, "mqtts://") {
		return fmt.Errorf("controller URL must start with mqtt:// or mqtts://\n\nYour URL: %s\n\nValid formats:\n  mqtts://HOST:PORT  (TLS-encrypted, recommended for production)\n  mqtt://HOST:PORT   (unencrypted, development only)\n\nExample:\n  mqtts://controller.example.com:8883", controllerURL)
	}

	// Create registration code structure
	regCode := RegistrationCode{
		TenantID:      tenantID,
		ControllerURL: controllerURL,
		Group:         group,
		Version:       1,
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(regCode)
	if err != nil {
		return fmt.Errorf("failed to marshal registration code: %w", err)
	}

	// Encode to base64
	encoded := base64.StdEncoding.EncodeToString(jsonData)

	// Output results
	fmt.Printf("Registration Code: %s\n\n", encoded)
	fmt.Println("Deployment Examples:")
	fmt.Println()
	fmt.Println("Windows MSI:")
	fmt.Printf("  msiexec /i cfgms-steward.msi /quiet REGCODE=\"%s\"\n", encoded)
	fmt.Println()
	fmt.Println("Linux/macOS:")
	fmt.Printf("  ./cfgms-steward-install --regcode=\"%s\"\n", encoded)
	fmt.Println()
	fmt.Println("Decoded JSON:")
	prettyJSON, _ := json.MarshalIndent(regCode, "  ", "  ")
	fmt.Printf("  %s\n", string(prettyJSON))

	return nil
}

// decodeRegistrationCode decodes a registration code.
func decodeRegistrationCode(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("registration code is required as argument\n\nUsage:\n  cfg regcode --decode <registration-code>\n\nExample:\n  cfg regcode --decode eyJ0ZW5hbnRfaWQi")
	}

	encoded := args[0]

	// Decode from base64
	jsonData, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return fmt.Errorf("failed to decode registration code: invalid base64 encoding\n\nThe registration code appears to be corrupted or incomplete\n\nTroubleshooting:\n  - Ensure you copied the entire code (starts with 'eyJ' typically)\n  - Check for extra spaces or newlines\n  - Verify the code wasn't truncated during copy/paste\n\nError details: %w", err)
	}

	// Unmarshal JSON
	var regCode RegistrationCode
	if err := json.Unmarshal(jsonData, &regCode); err != nil {
		return fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	// Output decoded results
	fmt.Println("Decoded Registration Code:")
	fmt.Println()
	fmt.Printf("  Tenant ID:      %s\n", regCode.TenantID)
	fmt.Printf("  Controller URL: %s\n", regCode.ControllerURL)
	if regCode.Group != "" {
		fmt.Printf("  Group:          %s\n", regCode.Group)
	}
	fmt.Printf("  Version:        %d\n", regCode.Version)
	fmt.Println()
	fmt.Println("JSON:")
	prettyJSON, _ := json.MarshalIndent(regCode, "  ", "  ")
	fmt.Printf("  %s\n", string(prettyJSON))

	return nil
}
