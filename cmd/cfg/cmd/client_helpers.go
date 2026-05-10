// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package cmd

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"

	"github.com/cfgis/cfgms/pkg/cert/bundle"
)

// userConfigDirFn is overridable in tests to avoid touching real user config directories.
var userConfigDirFn = os.UserConfigDir

// systemBundlePathFn is overridable in tests to avoid touching real system paths.
var systemBundlePathFn = defaultSystemBundlePath

// defaultSystemBundlePath returns the platform-appropriate system bundle path.
func defaultSystemBundlePath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("ProgramData"), "cfgms", "admin.bundle.yaml")
	}
	return "/etc/cfgms/admin.bundle.yaml"
}

// newClientFromFlags creates an APIClient from resolved flag values.
// Reads the CA cert from disk if caCertPath is non-empty, then delegates to NewAPIClient.
// Env var resolution is the responsibility of each command's get*Client() function.
func newClientFromFlags(url, apiKey, caCertPath string, insecure bool) (*APIClient, error) {
	var caCertPEM []byte
	if caCertPath != "" {
		var err error
		// #nosec G304 - CA certificate path is intentionally provided by user via CLI flag or env var
		caCertPEM, err = os.ReadFile(caCertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}
	}

	cfg := &APIClientConfig{
		BaseURL:     url,
		APIKey:      apiKey,
		CACertPEM:   caCertPEM,
		TLSInsecure: insecure,
	}

	return NewAPIClient(cfg)
}

// newClientFromBundle creates an mTLS-capable APIClient from an admin bundle file.
// apiURL overrides bundle.ControllerURL when non-empty; otherwise the bundle URL is used.
func newClientFromBundle(bundleFilePath, apiURL string) (*APIClient, error) {
	// #nosec G304 - bundle path comes from CLI flag, env var, or well-known system/user config location
	b, err := bundle.Read(bundleFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read admin bundle: %w", err)
	}

	baseURL := apiURL
	if baseURL == "" {
		baseURL = b.ControllerURL
	}

	serverName := ""
	if baseURL != "" {
		if parsed, parseErr := url.Parse(baseURL); parseErr == nil && parsed.Host != "" {
			serverName = parsed.Hostname()
		}
	}

	cfg := &APIClientConfig{
		BaseURL:       baseURL,
		ClientCertPEM: []byte(b.CertPEM),
		ClientKeyPEM:  []byte(b.KeyPEM),
		CACertPEM:     []byte(b.CAPEM),
		ServerName:    serverName,
	}

	return NewAPIClient(cfg)
}

// resolveBundleClient walks the admin bundle lookup chain and returns an mTLS-capable
// APIClient if a bundle file is found. Returns (nil, nil) when bundle discovery is skipped
// (--no-bundle flag, CFGMS_ADMIN_BUNDLE="" explicitly set) or no bundle file exists.
func resolveBundleClient(apiURL string) (*APIClient, error) {
	// --no-bundle flag explicitly opts out of bundle discovery
	if noBundle {
		return nil, nil
	}

	// CFGMS_ADMIN_BUNDLE="" (explicitly set to empty string) is also an opt-out.
	// Unset env var (not present) proceeds to lookup chain.
	bundleEnvVal, bundleEnvSet := os.LookupEnv("CFGMS_ADMIN_BUNDLE")
	if bundleEnvSet && bundleEnvVal == "" {
		return nil, nil
	}

	path, err := findBundlePath(bundleEnvVal)
	if err != nil {
		return nil, err
	}
	if path == "" {
		return nil, nil
	}

	return newClientFromBundle(path, apiURL)
}

// findBundlePath walks the bundle lookup chain and returns the first path that exists.
// Returns ("", nil) when no bundle file is found at any candidate path.
// Returns ("", err) when a non-NotExist error occurs (e.g., permission denied).
func findBundlePath(bundleEnvVal string) (string, error) {
	var candidates []string

	// 1. --bundle flag (highest priority)
	if bundlePath != "" {
		candidates = append(candidates, bundlePath)
	}

	// 2. CFGMS_ADMIN_BUNDLE env var (non-empty; empty was handled by caller)
	if bundleEnvVal != "" {
		candidates = append(candidates, bundleEnvVal)
	}

	// 3. User config dir: ~/.config/cfgms/admin.bundle.yaml (or OS equivalent)
	if configDir, err := userConfigDirFn(); err == nil {
		candidates = append(candidates, filepath.Join(configDir, "cfgms", "admin.bundle.yaml"))
	}

	// 4. System path: /etc/cfgms/admin.bundle.yaml (Linux/macOS) or %ProgramData%\cfgms\... (Windows)
	candidates = append(candidates, systemBundlePathFn())

	for _, p := range candidates {
		if _, statErr := os.Stat(p); statErr == nil {
			return p, nil
		} else if !os.IsNotExist(statErr) {
			// Surfacing non-NotExist errors (e.g., permission denied) is intentional
			return "", fmt.Errorf("cannot access bundle file: %w", statErr)
		}
	}

	return "", nil
}
