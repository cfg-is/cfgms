// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package acme

import (
	"fmt"
	"net"
	"net/mail"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/features/modules"
)

// ACMEConfig represents the desired state for an ACME-managed certificate
type ACMEConfig struct {
	State                string             `yaml:"state"`                            // "present" or "absent"
	Domains              []string           `yaml:"domains"`                          // SANs; first is primary domain
	Email                string             `yaml:"email"`                            // ACME account email
	ACMEServer           string             `yaml:"acme_server,omitempty"`            // Custom ACME server URL
	Staging              bool               `yaml:"staging,omitempty"`                // Use LE staging environment
	ChallengeType        string             `yaml:"challenge_type"`                   // "http-01" or "dns-01"
	DNSProvider          string             `yaml:"dns_provider,omitempty"`           // "cloudflare", "route53", "azure_dns"
	DNSCredentialKey     string             `yaml:"dns_credential_key,omitempty"`     // Key in CFGMS secrets store
	HTTPBindAddress      string             `yaml:"http_bind_address,omitempty"`      // Default: ":80"
	CertStorePath        string             `yaml:"cert_store_path,omitempty"`        // Override default path
	RenewalThresholdDays int                `yaml:"renewal_threshold_days,omitempty"` // Default: 30
	KeyType              string             `yaml:"key_type,omitempty"`               // "rsa2048", "rsa4096", "ec256", "ec384"
	CertificateStatus    *CertificateStatus `yaml:"certificate_status,omitempty"`     // Read-only, populated by Get()
}

// CertificateStatus contains read-only information about the current certificate
type CertificateStatus struct {
	Issuer          string    `yaml:"issuer"`
	NotAfter        time.Time `yaml:"not_after"`
	DaysUntilExpiry int       `yaml:"days_until_expiry"`
	SerialNumber    string    `yaml:"serial_number"`
	NeedsRenewal    bool      `yaml:"needs_renewal"`
}

// AsMap returns the configuration as a map for efficient field-by-field comparison.
// CertificateStatus is excluded because it is read-only and not a drift field.
func (c *ACMEConfig) AsMap() map[string]interface{} {
	result := map[string]interface{}{
		"state": c.State,
	}

	if c.State == "absent" {
		return result
	}

	result["domains"] = c.Domains
	result["email"] = c.Email
	result["challenge_type"] = c.ChallengeType
	result["key_type"] = c.KeyType
	result["renewal_threshold_days"] = c.RenewalThresholdDays

	if c.ACMEServer != "" {
		result["acme_server"] = c.ACMEServer
	}
	if c.Staging {
		result["staging"] = c.Staging
	}
	if c.DNSProvider != "" {
		result["dns_provider"] = c.DNSProvider
	}
	if c.DNSCredentialKey != "" {
		result["dns_credential_key"] = c.DNSCredentialKey
	}
	if c.HTTPBindAddress != "" {
		result["http_bind_address"] = c.HTTPBindAddress
	}
	if c.CertStorePath != "" {
		result["cert_store_path"] = c.CertStorePath
	}

	return result
}

// ToYAML serializes the configuration to YAML for export/storage
func (c *ACMEConfig) ToYAML() ([]byte, error) {
	return yaml.Marshal(c)
}

// FromYAML deserializes YAML data into the configuration
func (c *ACMEConfig) FromYAML(data []byte) error {
	return yaml.Unmarshal(data, c)
}

// Validate ensures the configuration is valid, applying defaults where needed
func (c *ACMEConfig) Validate() error {
	if c.State == "" {
		c.State = "present"
	}

	if c.State != "present" && c.State != "absent" {
		return fmt.Errorf("%w: state must be 'present' or 'absent', got %q", modules.ErrInvalidInput, c.State)
	}

	if c.State == "absent" {
		return nil
	}

	// Domains required for present state
	if len(c.Domains) == 0 {
		return fmt.Errorf("%w: at least one domain is required", ErrInvalidDomain)
	}

	for _, domain := range c.Domains {
		if err := validateDomain(domain); err != nil {
			return fmt.Errorf("%w: %s", ErrInvalidDomain, err.Error())
		}
	}

	// Email validation
	if c.Email == "" {
		return fmt.Errorf("%w: email is required", ErrInvalidEmail)
	}
	if _, err := mail.ParseAddress(c.Email); err != nil {
		return fmt.Errorf("%w: %s", ErrInvalidEmail, err.Error())
	}

	// Challenge type validation
	if c.ChallengeType == "" {
		return fmt.Errorf("%w", ErrInvalidChallengeType)
	}
	if c.ChallengeType != "http-01" && c.ChallengeType != "dns-01" {
		return fmt.Errorf("%w", ErrInvalidChallengeType)
	}

	// DNS-01 requires provider and credential key
	if c.ChallengeType == "dns-01" {
		if c.DNSProvider == "" {
			return ErrDNSProviderRequired
		}
		if !isSupportedDNSProvider(c.DNSProvider) {
			return fmt.Errorf("%w: %s", ErrUnsupportedDNSProvider, c.DNSProvider)
		}
		if c.DNSCredentialKey == "" {
			return ErrDNSCredentialKeyRequired
		}
	}

	// Apply defaults
	if c.KeyType == "" {
		c.KeyType = "ec256"
	}
	if !isValidKeyType(c.KeyType) {
		return fmt.Errorf("%w: key_type must be one of: rsa2048, rsa4096, ec256, ec384", modules.ErrInvalidInput)
	}

	if c.RenewalThresholdDays == 0 {
		c.RenewalThresholdDays = 30
	}
	if c.RenewalThresholdDays < 1 || c.RenewalThresholdDays > 90 {
		return fmt.Errorf("%w: renewal_threshold_days must be between 1 and 90", modules.ErrInvalidInput)
	}

	if c.HTTPBindAddress == "" {
		c.HTTPBindAddress = ":80"
	}

	return nil
}

// GetManagedFields returns the list of user-controllable fields
func (c *ACMEConfig) GetManagedFields() []string {
	fields := []string{"state"}

	if c.State == "absent" {
		return fields
	}

	fields = append(fields, "domains", "email", "challenge_type", "key_type", "renewal_threshold_days")

	if c.ACMEServer != "" {
		fields = append(fields, "acme_server")
	}
	if c.Staging {
		fields = append(fields, "staging")
	}
	if c.DNSProvider != "" {
		fields = append(fields, "dns_provider")
	}
	if c.DNSCredentialKey != "" {
		fields = append(fields, "dns_credential_key")
	}
	if c.HTTPBindAddress != "" && c.HTTPBindAddress != ":80" {
		fields = append(fields, "http_bind_address")
	}
	if c.CertStorePath != "" {
		fields = append(fields, "cert_store_path")
	}

	return fields
}

// validateDomain checks if a domain name is valid (including wildcards)
func validateDomain(domain string) error {
	if domain == "" {
		return fmt.Errorf("domain cannot be empty")
	}

	// Strip wildcard prefix for validation
	checkDomain := domain
	if strings.HasPrefix(domain, "*.") {
		checkDomain = domain[2:]
	}

	// Basic domain validation
	if len(checkDomain) > 253 {
		return fmt.Errorf("domain %q exceeds maximum length", domain)
	}

	labels := strings.Split(checkDomain, ".")
	if len(labels) < 2 {
		return fmt.Errorf("domain %q must have at least two labels", domain)
	}

	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return fmt.Errorf("domain label %q has invalid length", label)
		}
	}

	// Reject IP addresses - ACME only works with domain names
	if net.ParseIP(checkDomain) != nil {
		return fmt.Errorf("domain %q is an IP address; ACME requires domain names", domain)
	}

	return nil
}

func isSupportedDNSProvider(provider string) bool {
	switch provider {
	case "cloudflare", "route53", "azure_dns":
		return true
	default:
		return false
	}
}

func isValidKeyType(keyType string) bool {
	switch keyType {
	case "rsa2048", "rsa4096", "ec256", "ec384":
		return true
	default:
		return false
	}
}
