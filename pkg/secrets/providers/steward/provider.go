// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package steward

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

// StewardProvider implements interfaces.SecretProvider for steward endpoints.
// It uses OS-native encryption (DPAPI on Windows, AES-256-GCM on Linux/macOS).
type StewardProvider struct{}

// Name returns the provider name.
func (p *StewardProvider) Name() string {
	return "steward"
}

// Description returns a human-readable description.
func (p *StewardProvider) Description() string {
	return "OS-native encrypted secret storage for steward endpoints"
}

// GetVersion returns the provider version.
func (p *StewardProvider) GetVersion() string {
	return "1.0.0"
}

// Available reports whether the provider can be used on the current platform.
func (p *StewardProvider) Available() (bool, error) {
	return true, nil
}

// GetCapabilities returns the provider's capabilities.
func (p *StewardProvider) GetCapabilities() interfaces.ProviderCapabilities {
	algo := "AES-256-GCM"
	if runtime.GOOS == "windows" {
		algo = "DPAPI"
	}
	return interfaces.ProviderCapabilities{
		SupportsVersioning:  false,
		SupportsRotation:    true,
		SupportsEncryption:  true,
		SupportsAuditTrail:  false,
		SupportsMetadata:    true,
		SupportsTags:        true,
		MaxSecretSize:       1 * 1024 * 1024, // 1MB
		MaxKeyLength:        256,
		EncryptionAlgorithm: algo,
	}
}

// CreateSecretStore creates a steward secret store with OS-native encryption.
func (p *StewardProvider) CreateSecretStore(config map[string]interface{}) (interfaces.SecretStore, error) {
	secretsDir := defaultSecretsDir()
	if dir, ok := config["secrets_dir"].(string); ok && dir != "" {
		secretsDir = dir
	}

	// Ensure the secrets directory exists with restrictive permissions
	if err := os.MkdirAll(secretsDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create secrets directory %s: %w", secretsDir, err)
	}

	// Create blobs subdirectory
	blobsDir := filepath.Join(secretsDir, "blobs")
	if err := os.MkdirAll(blobsDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create blobs directory: %w", err)
	}

	// Create platform-specific encryptor
	encryptor, err := newPlatformEncryptor(secretsDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create platform encryptor: %w", err)
	}

	store := &StewardSecretStore{
		secretsDir: secretsDir,
		encryptor:  encryptor,
	}

	// Load existing index or create new one
	if err := store.loadIndex(); err != nil {
		return nil, fmt.Errorf("failed to load secret index: %w", err)
	}

	return store, nil
}

// defaultSecretsDir returns the platform-specific default secrets directory.
func defaultSecretsDir() string {
	switch runtime.GOOS {
	case "windows":
		programData := os.Getenv("ProgramData")
		if programData == "" {
			programData = `C:\ProgramData`
		}
		return filepath.Join(programData, "cfgms", "secrets")
	case "darwin":
		home, _ := os.UserHomeDir()
		if home == "" {
			home = "/tmp"
		}
		return filepath.Join(home, "Library", "Application Support", "cfgms", "secrets")
	default:
		return "/var/lib/cfgms/secrets"
	}
}

// Auto-register this provider (Salt-style)
func init() {
	interfaces.RegisterSecretProvider(&StewardProvider{})
}
