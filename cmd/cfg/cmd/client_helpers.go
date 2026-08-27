// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"time"

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

// newClientFromFlags creates an unauthenticated (or CA-pinned) APIClient from resolved
// flag values. Reads the CA cert from disk if caCertPath is non-empty, then delegates to
// NewAPIClient. Env var resolution is the responsibility of each command's get*Client()
// function. This does not attach any credential — it exists for pre-authentication
// bootstrap calls (e.g. tenant creation against a fresh controller); everything else
// must go through resolveSessionOrBundleClient / requireSessionOrBundleClient.
func newClientFromFlags(url, caCertPath string, insecure bool) (*APIClient, error) {
	var caCertPEM []byte
	if caCertPath != "" {
		var err error
		// #nosec G304 G703 -- this local administrative CLI intentionally reads
		// the CA path explicitly selected by its operator; it does not serve remote input.
		caCertPEM, err = os.ReadFile(caCertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}
	}

	cfg := &APIClientConfig{
		BaseURL:     url,
		CACertPEM:   caCertPEM,
		TLSInsecure: insecure,
	}

	return NewAPIClient(cfg)
}

// newClientFromBundle creates an mTLS-capable APIClient from an admin bundle file.
// apiURL overrides bundle.ControllerURL when non-empty; otherwise the bundle URL is used.
// tlsInsecure skips server certificate verification (development only; prints a warning banner).
// serverName overrides the TLS server name for certificate verification; when empty, the
// hostname from apiURL is used.
func newClientFromBundle(bundleFilePath, apiURL string, tlsInsecure bool, serverName string) (*APIClient, error) {
	// #nosec G304 - bundle path comes from CLI flag, env var, or well-known system/user config location
	b, err := bundle.Read(bundleFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read admin bundle: %w", err)
	}

	baseURL := apiURL
	if baseURL == "" {
		baseURL = b.ControllerURL
	}

	// Derive server name from URL when not explicitly overridden.
	resolvedServerName := serverName
	if resolvedServerName == "" && baseURL != "" {
		if parsed, parseErr := url.Parse(baseURL); parseErr == nil && parsed.Host != "" {
			resolvedServerName = parsed.Hostname()
		}
	}

	cfg := &APIClientConfig{
		BaseURL:       baseURL,
		ClientCertPEM: []byte(b.CertPEM),
		ClientKeyPEM:  []byte(b.KeyPEM),
		CACertPEM:     []byte(b.CAPEM),
		ServerName:    resolvedServerName,
		TLSInsecure:   tlsInsecure,
	}

	return NewAPIClient(cfg)
}

// resolveBundleClient walks the admin bundle lookup chain and returns an mTLS-capable
// APIClient if a bundle file is found. Returns (nil, nil) when bundle discovery is skipped
// (--no-bundle flag, CFGMS_ADMIN_BUNDLE="" explicitly set) or no bundle file exists.
// tlsInsecure and serverName are threaded through to newClientFromBundle.
func resolveBundleClient(apiURL string, tlsInsecure bool, serverName string) (*APIClient, error) {
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

	return newClientFromBundle(path, apiURL, tlsInsecure, serverName)
}

// resolveSessionOrBundleClient tries the active OS-keychain session token first,
// then falls through to resolveBundleClient.
//
// Falls through to bundle auth unconditionally when:
//   - bundlePath is set (--bundle flag)
//   - noBundle is set (--no-bundle flag)
//   - apiURL is non-empty (explicit --api-url flag or CFGMS_API_URL env var)
//   - no session token is stored
//   - the stored token has passed its absolute expiry
//   - the OS secret store is unavailable (Available()==false)
//
// When a valid session is found the returned client has OnTokenRenewed wired
// to write rolled X-Session-Token values back to the secret store, and
// OnUnauthorized wired to fall back to bundle auth on server-side 401.
//
// tlsInsecure skips server certificate verification. For the session-token path this
// requires explicit typed confirmation (or CFGMS_TLS_INSECURE_CONFIRM=yes non-interactively)
// because a session token is a replayable bearer credential.
// serverName overrides the TLS server name for certificate verification.
func resolveSessionOrBundleClient(apiURL string, tlsInsecure bool, serverName string) (*APIClient, error) {
	// Explicit one-shot overrides bypass the session entirely.
	if bundlePath != "" || noBundle || apiURL != "" {
		return resolveBundleClient(apiURL, tlsInsecure, serverName)
	}

	rec, err := loadSessionToken()
	if err != nil || rec == nil || time.Now().After(rec.AbsoluteExpiry) {
		return resolveBundleClient(apiURL, tlsInsecure, serverName)
	}

	// Session token is a replayable bearer credential: require explicit confirmation
	// before allowing the server certificate to go unverified.
	if tlsInsecure {
		if confirmErr := requireTLSInsecureForSession(); confirmErr != nil {
			return nil, confirmErr
		}
	}

	// Use the stored CA cert when non-empty; nil → system cert pool (public CA controllers).
	var caCertPEM []byte
	if rec.CACertPEM != "" {
		caCertPEM = []byte(rec.CACertPEM)
	}

	// Capture client by reference so the step-up handler can use it after creation.
	// The closure is not invoked until after NewAPIClient returns, so client is always set.
	var client *APIClient
	cfg := &APIClientConfig{
		BaseURL:     rec.ControllerURL,
		BearerToken: rec.Token,
		CACertPEM:   caCertPEM,
		TLSInsecure: tlsInsecure,
		ServerName:  serverName,
		OnTokenRenewed: func(newToken string) error {
			return updateSessionToken(newToken)
		},
		OnUnauthorized: func() (*APIClient, error) {
			// Fallback uses the mTLS banner gate (printed in NewAPIClient), not
			// another confirmation prompt — confirmation was already obtained above.
			return resolveBundleClient("", tlsInsecure, serverName)
		},
		OnStepUpRequired: func(wwwAuthenticate string) (string, error) {
			return defaultStepUpHandler(client)(wwwAuthenticate)
		},
	}
	client, err = NewAPIClient(cfg)
	return client, err
}

// errNoCredential is returned when neither an active session nor an admin mTLS bundle
// can be resolved. The cfg CLI accepts only those two credentials — API-key
// authentication was removed as a silent downgrade path (Issue #3688): a caller whose
// bundle was missing or whose session had expired used to fall through to
// CFGMS_API_KEY transparently and the command would still succeed. Automation that
// exported CFGMS_API_KEY should export CFGMS_ADMIN_BUNDLE instead.
var errNoCredential = fmt.Errorf("no credential found: provide an admin mTLS bundle (--bundle, CFGMS_ADMIN_BUNDLE, or the default bundle path) or an active session (run 'cfg connect' first)")

// requireSessionOrBundleClient resolves a client via resolveSessionOrBundleClient and
// fails explicitly with errNoCredential when neither a session nor a bundle credential
// is available, instead of silently falling back to a weaker credential.
func requireSessionOrBundleClient(apiURL string, tlsInsecure bool, serverName string) (*APIClient, error) {
	client, err := resolveSessionOrBundleClient(apiURL, tlsInsecure, serverName)
	if err != nil {
		return nil, fmt.Errorf("bundle lookup failed: %w", err)
	}
	if client == nil {
		return nil, errNoCredential
	}
	return client, nil
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
		// #nosec G703 -- candidates are explicit operator CLI/env choices or
		// platform-owned configuration paths used by this local administrative CLI.
		if _, statErr := os.Stat(p); statErr == nil {
			return p, nil
		} else if !os.IsNotExist(statErr) {
			// Surfacing non-NotExist errors (e.g., permission denied) is intentional
			return "", fmt.Errorf("cannot access bundle file: %w", statErr)
		}
	}

	return "", nil
}
