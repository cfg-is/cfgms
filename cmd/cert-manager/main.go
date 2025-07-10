// cert-manager is a CLI tool for CFGMS certificate management operations.
//
// This tool provides command-line access to certificate management functionality
// including CA initialization, certificate generation, validation, and renewal.
//
// Usage:
//   cert-manager init-ca --org "CFGMS" --country "US" --storage /etc/cfgms/certs
//   cert-manager generate-server --common-name "cfgms-controller" --dns "localhost,controller.local"
//   cert-manager generate-client --common-name "steward-001" --client-id "steward-001"
//   cert-manager list
//   cert-manager validate --serial 123456789
//   cert-manager renew --serial 123456789
//
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/cfgis/cfgms/pkg/cert"
)

var (
	storagePath string
	manager     *cert.Manager
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "cert-manager",
		Short: "CFGMS Certificate Management Tool",
		Long:  "A command-line tool for managing CFGMS certificates including CA operations, certificate generation, validation, and renewal.",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// Skip manager initialization for init-ca command
			if cmd.Name() == "init-ca" {
				return nil
			}
			
			var err error
			manager, err = cert.NewManager(&cert.ManagerConfig{
				StoragePath:    storagePath,
				LoadExistingCA: true,
			})
			if err != nil {
				return fmt.Errorf("failed to initialize certificate manager: %w", err)
			}
			
			return nil
		},
	}

	rootCmd.PersistentFlags().StringVar(&storagePath, "storage", "/etc/cfgms/certs", "Certificate storage path")

	rootCmd.AddCommand(
		initCACmd(),
		generateServerCmd(),
		generateClientCmd(),
		listCmd(),
		validateCmd(),
		renewCmd(),
		statsCmd(),
		exportCmd(),
	)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func initCACmd() *cobra.Command {
	var (
		organization string
		country      string
		state        string
		city         string
		validityDays int
	)

	cmd := &cobra.Command{
		Use:   "init-ca",
		Short: "Initialize a new Certificate Authority",
		RunE: func(cmd *cobra.Command, args []string) error {
			config := &cert.CAConfig{
				Organization: organization,
				Country:      country,
				State:        state,
				City:         city,
				ValidityDays: validityDays,
				StoragePath:  filepath.Join(storagePath, "ca"),
			}

			manager, err := cert.NewManager(&cert.ManagerConfig{
				StoragePath:    storagePath,
				CAConfig:       config,
				LoadExistingCA: false,
			})
			if err != nil {
				return fmt.Errorf("failed to initialize CA: %w", err)
			}

			caInfo, err := manager.GetCAInfo()
			if err != nil {
				return fmt.Errorf("failed to get CA info: %w", err)
			}

			fmt.Printf("Certificate Authority initialized successfully\n")
			fmt.Printf("  Common Name: %s\n", caInfo.CommonName)
			fmt.Printf("  Serial Number: %s\n", caInfo.SerialNumber)
			fmt.Printf("  Valid Until: %s\n", caInfo.ExpiresAt.Format("2006-01-02 15:04:05"))
			fmt.Printf("  Storage Path: %s\n", storagePath)

			return nil
		},
	}

	cmd.Flags().StringVar(&organization, "org", "CFGMS", "Organization name")
	cmd.Flags().StringVar(&country, "country", "US", "Country code")
	cmd.Flags().StringVar(&state, "state", "", "State or province")
	cmd.Flags().StringVar(&city, "city", "", "City or locality")
	cmd.Flags().IntVar(&validityDays, "validity", 3650, "Certificate validity in days")

	return cmd
}

func generateServerCmd() *cobra.Command {
	var (
		commonName   string
		dnsNames     string
		ipAddresses  string
		organization string
		validityDays int
	)

	cmd := &cobra.Command{
		Use:   "generate-server",
		Short: "Generate a server certificate",
		RunE: func(cmd *cobra.Command, args []string) error {
			config := &cert.ServerCertConfig{
				CommonName:   commonName,
				Organization: organization,
				ValidityDays: validityDays,
			}

			if dnsNames != "" {
				config.DNSNames = strings.Split(dnsNames, ",")
			}

			if ipAddresses != "" {
				config.IPAddresses = strings.Split(ipAddresses, ",")
			}

			certificate, err := manager.GenerateServerCertificate(config)
			if err != nil {
				return fmt.Errorf("failed to generate server certificate: %w", err)
			}

			fmt.Printf("Server certificate generated successfully\n")
			fmt.Printf("  Common Name: %s\n", certificate.CommonName)
			fmt.Printf("  Serial Number: %s\n", certificate.SerialNumber)
			fmt.Printf("  Valid Until: %s\n", certificate.ExpiresAt.Format("2006-01-02 15:04:05"))
			fmt.Printf("  Fingerprint: %s\n", certificate.Fingerprint)

			return nil
		},
	}

	cmd.Flags().StringVar(&commonName, "common-name", "", "Common name for the certificate (required)")
	cmd.Flags().StringVar(&dnsNames, "dns", "", "Comma-separated list of DNS names")
	cmd.Flags().StringVar(&ipAddresses, "ip", "", "Comma-separated list of IP addresses")
	cmd.Flags().StringVar(&organization, "org", "CFGMS", "Organization name")
	cmd.Flags().IntVar(&validityDays, "validity", 365, "Certificate validity in days")

	cmd.MarkFlagRequired("common-name")

	return cmd
}

func generateClientCmd() *cobra.Command {
	var (
		commonName   string
		organization string
		clientID     string
		validityDays int
	)

	cmd := &cobra.Command{
		Use:   "generate-client",
		Short: "Generate a client certificate",
		RunE: func(cmd *cobra.Command, args []string) error {
			config := &cert.ClientCertConfig{
				CommonName:   commonName,
				Organization: organization,
				ClientID:     clientID,
				ValidityDays: validityDays,
			}

			certificate, err := manager.GenerateClientCertificate(config)
			if err != nil {
				return fmt.Errorf("failed to generate client certificate: %w", err)
			}

			fmt.Printf("Client certificate generated successfully\n")
			fmt.Printf("  Common Name: %s\n", certificate.CommonName)
			fmt.Printf("  Serial Number: %s\n", certificate.SerialNumber)
			fmt.Printf("  Client ID: %s\n", certificate.ClientID)
			fmt.Printf("  Valid Until: %s\n", certificate.ExpiresAt.Format("2006-01-02 15:04:05"))
			fmt.Printf("  Fingerprint: %s\n", certificate.Fingerprint)

			return nil
		},
	}

	cmd.Flags().StringVar(&commonName, "common-name", "", "Common name for the certificate (required)")
	cmd.Flags().StringVar(&organization, "org", "CFGMS", "Organization name")
	cmd.Flags().StringVar(&clientID, "client-id", "", "Client identifier")
	cmd.Flags().IntVar(&validityDays, "validity", 365, "Certificate validity in days")

	cmd.MarkFlagRequired("common-name")

	return cmd
}

func listCmd() *cobra.Command {
	var certType string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List certificates",
		RunE: func(cmd *cobra.Command, args []string) error {
			var certificates []*cert.CertificateInfo
			var err error

			switch certType {
			case "server":
				certificates, err = manager.GetCertificatesByType(cert.CertificateTypeServer)
			case "client":
				certificates, err = manager.GetCertificatesByType(cert.CertificateTypeClient)
			case "ca":
				certificates, err = manager.GetCertificatesByType(cert.CertificateTypeCA)
			default:
				certificates, err = manager.ListCertificates()
			}

			if err != nil {
				return fmt.Errorf("failed to list certificates: %w", err)
			}

			if len(certificates) == 0 {
				fmt.Println("No certificates found")
				return nil
			}

			fmt.Printf("%-12s %-20s %-40s %-12s %-20s %-8s\n", 
				"Type", "Common Name", "Serial Number", "Status", "Expires", "Days Left")
			fmt.Println(strings.Repeat("-", 120))

			for _, c := range certificates {
				status := "Valid"
				if !c.IsValid {
					status = "Invalid"
				} else if c.DaysUntilExpiration <= 0 {
					status = "Expired"
				} else if c.NeedsRenewal {
					status = "Expiring"
				}

				fmt.Printf("%-12s %-20s %-40s %-12s %-20s %8d\n",
					c.Type.String(),
					c.CommonName,
					c.SerialNumber,
					status,
					c.ExpiresAt.Format("2006-01-02 15:04"),
					c.DaysUntilExpiration,
				)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&certType, "type", "", "Certificate type filter (server, client, ca)")

	return cmd
}

func validateCmd() *cobra.Command {
	var serialNumber string

	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate a certificate",
		RunE: func(cmd *cobra.Command, args []string) error {
			certificate, err := manager.GetCertificate(serialNumber)
			if err != nil {
				return fmt.Errorf("failed to get certificate: %w", err)
			}

			result, err := manager.ValidateCertificate(certificate.CertificatePEM)
			if err != nil {
				return fmt.Errorf("failed to validate certificate: %w", err)
			}

			fmt.Printf("Certificate Validation Results\n")
			fmt.Printf("  Serial Number: %s\n", certificate.SerialNumber)
			fmt.Printf("  Common Name: %s\n", certificate.CommonName)
			fmt.Printf("  Valid: %v\n", result.IsValid)
			fmt.Printf("  Expired: %v\n", result.IsExpired)
			fmt.Printf("  Days Until Expiration: %d\n", result.DaysUntilExpiration)

			if len(result.Errors) > 0 {
				fmt.Printf("  Errors:\n")
				for _, err := range result.Errors {
					fmt.Printf("    - %s\n", err)
				}
			}

			if len(result.Warnings) > 0 {
				fmt.Printf("  Warnings:\n")
				for _, warning := range result.Warnings {
					fmt.Printf("    - %s\n", warning)
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&serialNumber, "serial", "", "Certificate serial number (required)")
	cmd.MarkFlagRequired("serial")

	return cmd
}

func renewCmd() *cobra.Command {
	var serialNumber string

	cmd := &cobra.Command{
		Use:   "renew",
		Short: "Renew a certificate",
		RunE: func(cmd *cobra.Command, args []string) error {
			newCert, err := manager.RenewCertificate(serialNumber, nil)
			if err != nil {
				return fmt.Errorf("failed to renew certificate: %w", err)
			}

			fmt.Printf("Certificate renewed successfully\n")
			fmt.Printf("  Old Serial: %s\n", serialNumber)
			fmt.Printf("  New Serial: %s\n", newCert.SerialNumber)
			fmt.Printf("  Common Name: %s\n", newCert.CommonName)
			fmt.Printf("  Valid Until: %s\n", newCert.ExpiresAt.Format("2006-01-02 15:04:05"))

			return nil
		},
	}

	cmd.Flags().StringVar(&serialNumber, "serial", "", "Certificate serial number to renew (required)")
	cmd.MarkFlagRequired("serial")

	return cmd
}

func statsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "stats",
		Short: "Show certificate statistics",
		RunE: func(cmd *cobra.Command, args []string) error {
			stats, err := manager.GetManagerStats()
			if err != nil {
				return fmt.Errorf("failed to get statistics: %w", err)
			}

			fmt.Printf("Certificate Manager Statistics\n")
			fmt.Printf("  Total Certificates: %d\n", stats.TotalCertificates)
			fmt.Printf("  Expiring Certificates: %d\n", stats.ExpiringCertificates)
			fmt.Printf("  Renewal Candidates: %d\n", stats.RenewalCandidates)
			fmt.Printf("\n  Certificates by Type:\n")
			for certType, count := range stats.CertificatesByType {
				fmt.Printf("    %s: %d\n", certType.String(), count)
			}

			if stats.CAInfo != nil {
				fmt.Printf("\n  Certificate Authority:\n")
				fmt.Printf("    Common Name: %s\n", stats.CAInfo.CommonName)
				fmt.Printf("    Serial Number: %s\n", stats.CAInfo.SerialNumber)
				fmt.Printf("    Valid Until: %s\n", stats.CAInfo.ExpiresAt.Format("2006-01-02 15:04:05"))
				fmt.Printf("    Days Until Expiration: %d\n", stats.CAInfo.DaysUntilExpiration)
			}

			return nil
		},
	}

	return cmd
}

func exportCmd() *cobra.Command {
	var (
		serialNumber     string
		outputDir        string
		includePrivateKey bool
	)

	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export certificate files",
		RunE: func(cmd *cobra.Command, args []string) error {
			certPEM, keyPEM, err := manager.ExportCertificate(serialNumber, includePrivateKey)
			if err != nil {
				return fmt.Errorf("failed to export certificate: %w", err)
			}

			cert, err := manager.GetCertificate(serialNumber)
			if err != nil {
				return fmt.Errorf("failed to get certificate info: %w", err)
			}

			// Create output directory if it doesn't exist
			if err := os.MkdirAll(outputDir, 0755); err != nil {
				return fmt.Errorf("failed to create output directory: %w", err)
			}

			// Write certificate file
			certPath := filepath.Join(outputDir, fmt.Sprintf("%s.crt", cert.CommonName))
			if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
				return fmt.Errorf("failed to write certificate file: %w", err)
			}

			fmt.Printf("Certificate exported: %s\n", certPath)

			// Write private key file if included
			if includePrivateKey && keyPEM != nil {
				keyPath := filepath.Join(outputDir, fmt.Sprintf("%s.key", cert.CommonName))
				if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
					return fmt.Errorf("failed to write private key file: %w", err)
				}
				fmt.Printf("Private key exported: %s\n", keyPath)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&serialNumber, "serial", "", "Certificate serial number to export (required)")
	cmd.Flags().StringVar(&outputDir, "output", ".", "Output directory for certificate files")
	cmd.Flags().BoolVar(&includePrivateKey, "include-key", false, "Include private key in export")

	cmd.MarkFlagRequired("serial")

	return cmd
}