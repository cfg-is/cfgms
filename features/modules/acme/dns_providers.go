// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package acme

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/providers/dns/azuredns"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/providers/dns/route53"

	secretsinterfaces "github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

// envMu protects environment variable operations during DNS provider creation.
// DNS providers read credentials from environment variables, so we must ensure
// no concurrent credential pollution between goroutines.
var envMu sync.Mutex

// DNSProviderFactory creates lego DNS challenge providers from CFGMS secret store credentials
type DNSProviderFactory struct {
	secretStore secretsinterfaces.SecretStore
}

// NewDNSProviderFactory creates a new DNS provider factory
func NewDNSProviderFactory(secretStore secretsinterfaces.SecretStore) *DNSProviderFactory {
	return &DNSProviderFactory{secretStore: secretStore}
}

// CreateProvider creates a lego DNS provider for the given provider name and credential key
func (f *DNSProviderFactory) CreateProvider(ctx context.Context, providerName, credentialKey string) (challenge.Provider, error) {
	// Retrieve credentials from the secret store
	secret, err := f.secretStore.GetSecret(ctx, credentialKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDNSCredentialMissing, err)
	}

	// Parse credential JSON
	var creds map[string]string
	if err := json.Unmarshal([]byte(secret.Value), &creds); err != nil {
		return nil, fmt.Errorf("failed to parse DNS credentials JSON: %w", err)
	}

	switch providerName {
	case "cloudflare":
		return f.createCloudflareProvider(creds)
	case "route53":
		return f.createRoute53Provider(creds)
	case "azure_dns":
		return f.createAzureDNSProvider(creds)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedDNSProvider, providerName)
	}
}

func (f *DNSProviderFactory) createCloudflareProvider(creds map[string]string) (challenge.Provider, error) {
	token, ok := creds["CF_DNS_API_TOKEN"]
	if !ok || token == "" {
		return nil, fmt.Errorf("%w: CF_DNS_API_TOKEN not found in credentials", ErrDNSCredentialMissing)
	}

	envMu.Lock()
	defer envMu.Unlock()

	restore, err := setEnvVars(map[string]string{"CF_DNS_API_TOKEN": token})
	if err != nil {
		return nil, fmt.Errorf("failed to set Cloudflare credentials: %w", err)
	}
	defer restore()

	provider, err := cloudflare.NewDNSProvider()
	if err != nil {
		return nil, fmt.Errorf("failed to create Cloudflare DNS provider: %w", err)
	}
	return provider, nil
}

func (f *DNSProviderFactory) createRoute53Provider(creds map[string]string) (challenge.Provider, error) {
	requiredKeys := []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_REGION"}
	for _, key := range requiredKeys {
		if v, ok := creds[key]; !ok || v == "" {
			return nil, fmt.Errorf("%w: %s not found in credentials", ErrDNSCredentialMissing, key)
		}
	}

	envMu.Lock()
	defer envMu.Unlock()

	envVars := make(map[string]string)
	for _, key := range requiredKeys {
		envVars[key] = creds[key]
	}

	restore, err := setEnvVars(envVars)
	if err != nil {
		return nil, fmt.Errorf("failed to set Route53 credentials: %w", err)
	}
	defer restore()

	provider, err := route53.NewDNSProvider()
	if err != nil {
		return nil, fmt.Errorf("failed to create Route53 DNS provider: %w", err)
	}
	return provider, nil
}

func (f *DNSProviderFactory) createAzureDNSProvider(creds map[string]string) (challenge.Provider, error) {
	requiredKeys := []string{
		"AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID",
		"AZURE_SUBSCRIPTION_ID", "AZURE_RESOURCE_GROUP",
	}
	for _, key := range requiredKeys {
		if v, ok := creds[key]; !ok || v == "" {
			return nil, fmt.Errorf("%w: %s not found in credentials", ErrDNSCredentialMissing, key)
		}
	}

	envMu.Lock()
	defer envMu.Unlock()

	envVars := make(map[string]string)
	for _, key := range requiredKeys {
		envVars[key] = creds[key]
	}

	restore, err := setEnvVars(envVars)
	if err != nil {
		return nil, fmt.Errorf("failed to set Azure DNS credentials: %w", err)
	}
	defer restore()

	provider, err := azuredns.NewDNSProvider()
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure DNS provider: %w", err)
	}
	return provider, nil
}

// setEnvVars sets environment variables and returns a restore function.
// The restore function reverts all variables to their original values.
// Caller must hold envMu.
func setEnvVars(vars map[string]string) (restore func(), err error) {
	originals := make(map[string]string)
	wasSet := make(map[string]bool)

	for key := range vars {
		if val, ok := os.LookupEnv(key); ok {
			originals[key] = val
			wasSet[key] = true
		}
	}

	for key, val := range vars {
		if err := os.Setenv(key, val); err != nil {
			// Best-effort rollback of already-set vars
			for k := range vars {
				if wasSet[k] {
					_ = os.Setenv(k, originals[k])
				} else {
					_ = os.Unsetenv(k)
				}
			}
			return nil, fmt.Errorf("failed to set env %s: %w", key, err)
		}
	}

	restore = func() {
		for key := range vars {
			if wasSet[key] {
				_ = os.Setenv(key, originals[key]) // #nosec G104 - best-effort restore
			} else {
				_ = os.Unsetenv(key) // #nosec G104 - best-effort restore
			}
		}
	}
	return restore, nil
}
