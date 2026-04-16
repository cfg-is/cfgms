// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package openbao implements an OpenBao-backed secrets provider for CFGMS.
// M-AUTH-1: Dynamic secret leasing and KV v2 storage via OpenBao (Apache 2.0 Vault fork).
package openbao

import (
	"fmt"
	"net/http"
	"os"
	"time"

	openbao "github.com/openbao/openbao/api/v2"

	"github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

// OpenBaoConfig holds the configuration for the OpenBao provider.
type OpenBaoConfig struct {
	// Address is the OpenBao server URL, e.g. "http://127.0.0.1:8200".
	Address string `json:"address"`

	// Token is the root or service token used to authenticate.
	Token string `json:"token"`

	// MountPath is the KV v2 mount path (default: "secret").
	MountPath string `json:"mount_path"`

	// TLSCert is the path to a PEM certificate file for TLS verification (optional).
	TLSCert string `json:"tls_cert,omitempty"`

	// Namespace is the OpenBao namespace (optional, enterprise/namespaces feature).
	Namespace string `json:"namespace,omitempty"`
}

// OpenBaoProvider implements interfaces.SecretProvider using OpenBao KV v2.
type OpenBaoProvider struct{}

// Name returns the provider identifier used in configuration.
func (p *OpenBaoProvider) Name() string {
	return "openbao"
}

// Description returns a human-readable summary.
func (p *OpenBaoProvider) Description() string {
	return "OpenBao KV v2 secrets provider with dynamic leasing support (dev-mode and production)"
}

// GetVersion returns the provider version.
func (p *OpenBaoProvider) GetVersion() string {
	return "1.0.0"
}

// GetCapabilities declares what this provider supports.
func (p *OpenBaoProvider) GetCapabilities() interfaces.ProviderCapabilities {
	return interfaces.ProviderCapabilities{
		SupportsVersioning:     true,          // KV v2 native versioning
		SupportsRotation:       true,          // Write new version = rotation
		SupportsEncryption:     true,          // OpenBao encrypts at rest
		SupportsAuditTrail:     true,          // OpenBao audit log
		SupportsLeasing:        true,          // Dynamic secret engines produce leases
		SupportsRenewal:        true,          // /sys/leases/renew
		SupportsRevocation:     true,          // /sys/leases/revoke
		SupportsMetadata:       true,          // KV v2 custom metadata
		SupportsTags:           true,          // Stored in KV v2 metadata
		SupportsAccessPolicies: true,          // OpenBao policy engine
		MaxSecretSize:          512 * 1024,    // 512 KB
		MaxKeyLength:           512,           // 512 character key names
		EncryptionAlgorithm:    "AES-256-GCM", // OpenBao default
	}
}

// Available performs a connectivity check against the configured OpenBao instance.
// It returns true if the health endpoint responds successfully.
func (p *OpenBaoProvider) Available() (bool, error) {
	// Use a short timeout for the liveness probe.
	httpClient := &http.Client{Timeout: 3 * time.Second}

	addr := os.Getenv("OPENBAO_ADDR")
	if addr == "" {
		addr = "http://127.0.0.1:8200"
	}

	resp, err := httpClient.Get(addr + "/v1/sys/health")
	if err != nil {
		return false, fmt.Errorf("OpenBao health check failed: %w", err)
	}
	_ = resp.Body.Close()

	// 200 = initialized and unsealed, 429 = standby (both mean available).
	// 501/503 = not initialized or sealed — not usable.
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusTooManyRequests {
		return true, nil
	}

	return false, fmt.Errorf("OpenBao health check returned HTTP %d", resp.StatusCode)
}

// CreateSecretStore builds an OpenBaoSecretStore from the supplied config map.
// The production-mode guard runs here: a dev-mode token/flag is rejected when
// CFGMS_TELEMETRY_ENVIRONMENT=production.
func (p *OpenBaoProvider) CreateSecretStore(config map[string]interface{}) (interfaces.SecretStore, error) {
	cfg, err := parseOpenBaoConfig(config)
	if err != nil {
		return nil, fmt.Errorf("invalid OpenBao config: %w", err)
	}

	if err := enforceProductionGuard(cfg); err != nil {
		return nil, err
	}

	store, err := newOpenBaoSecretStore(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create OpenBao secret store: %w", err)
	}

	return store, nil
}

// enforceProductionGuard rejects dev-mode indicators in production environments.
func enforceProductionGuard(cfg *OpenBaoConfig) error {
	isProduction := os.Getenv("CFGMS_TELEMETRY_ENVIRONMENT") == "production"
	if !isProduction {
		return nil
	}

	devMode := cfg.Token == "root" ||
		os.Getenv("VAULT_DEV_MODE") == "true" ||
		os.Getenv("BAO_DEV_MODE") == "true"

	if devMode {
		return fmt.Errorf(
			"OpenBao provider refused to start:\n" +
				"  Reason: dev-mode token or flag detected in a production environment.\n" +
				"  Token \"root\" and VAULT_DEV_MODE/BAO_DEV_MODE=true are only valid in\n" +
				"  OpenBao dev mode, which stores data in memory and is wiped on restart.\n" +
				"  Fix: use a proper OpenBao service token and ensure dev mode is not enabled.\n" +
				"  See: pkg/secrets/providers/openbao/README.md",
		)
	}

	return nil
}

// parseOpenBaoConfig converts the generic config map to a typed OpenBaoConfig.
func parseOpenBaoConfig(config map[string]interface{}) (*OpenBaoConfig, error) {
	cfg := &OpenBaoConfig{
		Address:   "http://127.0.0.1:8200",
		MountPath: "secret",
	}

	if v, ok := config["address"].(string); ok && v != "" {
		cfg.Address = v
	}

	if v, ok := config["token"].(string); ok {
		cfg.Token = v
	}

	if v, ok := config["mount_path"].(string); ok && v != "" {
		cfg.MountPath = v
	}

	if v, ok := config["tls_cert"].(string); ok {
		cfg.TLSCert = v
	}

	if v, ok := config["namespace"].(string); ok {
		cfg.Namespace = v
	}

	// Fall back to environment variables when not set in config map.
	if cfg.Token == "" {
		cfg.Token = os.Getenv("OPENBAO_TOKEN")
	}
	if cfg.Token == "" {
		cfg.Token = os.Getenv("BAO_TOKEN")
	}
	if addrEnv := os.Getenv("OPENBAO_ADDR"); addrEnv != "" && cfg.Address == "http://127.0.0.1:8200" {
		cfg.Address = addrEnv
	}

	return cfg, nil
}

// newOpenBaoClient builds a configured OpenBao API client.
func newOpenBaoClient(cfg *OpenBaoConfig) (*openbao.Client, error) {
	apiConfig := openbao.DefaultConfig()
	apiConfig.Address = cfg.Address

	if cfg.TLSCert != "" {
		tlsCfg := openbao.TLSConfig{CACert: cfg.TLSCert}
		if err := apiConfig.ConfigureTLS(&tlsCfg); err != nil {
			return nil, fmt.Errorf("TLS configuration failed: %w", err)
		}
	}

	client, err := openbao.NewClient(apiConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create OpenBao client: %w", err)
	}

	client.SetToken(cfg.Token)

	if cfg.Namespace != "" {
		client.SetNamespace(cfg.Namespace)
	}

	return client, nil
}

// Auto-register this provider (Salt-style init pattern).
func init() {
	interfaces.RegisterSecretProvider(&OpenBaoProvider{})
}
