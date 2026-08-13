// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	certbundle "github.com/cfgis/cfgms/pkg/cert/bundle"
)

var (
	connectBundlePath  string
	connectURL         string
	connectName        string
	connectTLSInsecure bool
	connectServerName  string

	disconnectTLSInsecure bool
	disconnectServerName  string
)

var connectCmd = &cobra.Command{
	Use:   "connect [<name>] [--bundle <path>] [--url <url>] [--name <name>]",
	Short: "Start a zero-standing-privilege controller session",
	Long: `Unlock the stored credential once, obtain a controller session token, and
store it in the OS-native secret store.

First time (import bundle):
  cfg connect --bundle <path> --url <https://controller:9443>

Reconnect with a named connection (no bundle re-import):
  cfg connect <name>

If the connection name is omitted and exactly one connection is registered it is
selected automatically; otherwise a numbered selection is presented on stdin.

The --url value must be an HTTPS URL for any non-loopback address.`,
	RunE: runConnect,
}

var disconnectCmd = &cobra.Command{
	Use:   "disconnect [<name>]",
	Short: "End the active controller session",
	Long: `Revoke the active controller session (DELETE /api/v1/sessions/{id}) and remove
the session token from the OS-native secret store.

If no active session is found, exits 0 with a notice.`,
	RunE: runDisconnect,
}

func init() {
	connectCmd.Flags().StringVar(&connectBundlePath, "bundle", "", "Admin bundle file for first-time import (requires --url)")
	connectCmd.Flags().StringVar(&connectURL, "url", "", "Controller HTTPS URL (required with --bundle)")
	connectCmd.Flags().StringVar(&connectName, "name", "", "Connection name (default: derived from --url host)")
	connectCmd.Flags().BoolVar(&connectTLSInsecure, "tls-insecure", false, "Skip TLS certificate verification (development only, env: CFGMS_TLS_INSECURE)")
	connectCmd.Flags().StringVar(&connectServerName, "server-name", "", "Override TLS server name for certificate verification")

	disconnectCmd.Flags().BoolVar(&disconnectTLSInsecure, "tls-insecure", false, "Skip TLS certificate verification (development only, env: CFGMS_TLS_INSECURE)")
	disconnectCmd.Flags().StringVar(&disconnectServerName, "server-name", "", "Override TLS server name for certificate verification")
}

// isLoopback returns true when host is a loopback address or name.
func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// requireHTTPS returns an error when rawURL uses the http scheme for a non-loopback host.
func requireHTTPS(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if strings.EqualFold(u.Scheme, "http") && !isLoopback(u.Hostname()) {
		return fmt.Errorf("session connect requires HTTPS: use https:// for %s", u.Host)
	}
	return nil
}

// deriveConnectionName extracts a connection name from the URL hostname.
func deriveConnectionName(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return "default"
	}
	return u.Hostname()
}

// parseBundleBytes deserialises YAML-encoded bundle bytes without writing a temp file.
func parseBundleBytes(data []byte) (*certbundle.Bundle, error) {
	var b certbundle.Bundle
	if err := yaml.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("failed to parse bundle: %w", err)
	}
	return &b, nil
}

// newClientFromBundleData builds an mTLS-capable APIClient from a parsed Bundle struct.
// apiURL overrides bundle.ControllerURL when non-empty.
// tlsInsecure skips server certificate verification (development only; prints a warning banner).
// serverName overrides the TLS server name for certificate verification; when empty, the
// hostname from apiURL is used.
func newClientFromBundleData(b *certbundle.Bundle, apiURL string, tlsInsecure bool, serverName string) (*APIClient, error) {
	baseURL := apiURL
	if baseURL == "" {
		baseURL = b.ControllerURL
	}
	// Derive server name from URL when not explicitly overridden.
	resolvedServerName := serverName
	if resolvedServerName == "" && baseURL != "" {
		if parsed, err := url.Parse(baseURL); err == nil && parsed.Hostname() != "" {
			resolvedServerName = parsed.Hostname()
		}
	}
	return NewAPIClient(&APIClientConfig{
		BaseURL:       baseURL,
		ClientCertPEM: []byte(b.CertPEM),
		ClientKeyPEM:  []byte(b.KeyPEM),
		CACertPEM:     []byte(b.CAPEM),
		ServerName:    resolvedServerName,
		TLSInsecure:   tlsInsecure,
	})
}

func runConnect(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	if connectBundlePath != "" {
		return runConnectFirstTime(ctx, args)
	}
	return runConnectReconnect(ctx, args)
}

// runConnectFirstTime handles cfg connect --bundle <path> --url <url>.
func runConnectFirstTime(ctx context.Context, args []string) error {
	if connectURL == "" {
		return fmt.Errorf("--url is required when --bundle is provided")
	}
	if err := requireHTTPS(connectURL); err != nil {
		return err
	}

	tlsInsecure := connectTLSInsecure
	if !tlsInsecure {
		tlsInsecure = os.Getenv("CFGMS_TLS_INSECURE") == "true"
	}
	serverName := connectServerName

	// Determine connection name.
	name := connectName
	if name == "" && len(args) > 0 {
		name = args[0]
	}
	if name == "" {
		name = deriveConnectionName(connectURL)
	}

	// Read bundle bytes — stored encrypted; the raw file is only read here.
	// #nosec G304 - bundle path provided by the user via --bundle flag
	bundleBytes, err := os.ReadFile(connectBundlePath)
	if err != nil {
		return fmt.Errorf("read bundle: %w", err)
	}
	b, err := parseBundleBytes(bundleBytes)
	if err != nil {
		return fmt.Errorf("parse bundle: %w", err)
	}

	// Register non-secret connection metadata.
	reg, err := newConnectionRegistry()
	if err != nil {
		return fmt.Errorf("open connection registry: %w", err)
	}
	if err := reg.Register(ConnectionEntry{
		Name:          name,
		ControllerURL: connectURL,
		AdminIdentity: b.AuditSubject,
		UnlockMethod:  "machine",
	}); err != nil {
		return fmt.Errorf("register connection: %w", err)
	}

	// Store encrypted credential.
	credStore, err := newCredentialStore()
	if err != nil {
		return fmt.Errorf("open credential store: %w", err)
	}
	if err := credStore.Store(ctx, name, bundleBytes); err != nil {
		return fmt.Errorf("store credential: %w", err)
	}

	// Build mTLS client and issue session.
	client, err := newClientFromBundleData(b, connectURL, tlsInsecure, serverName)
	if err != nil {
		return fmt.Errorf("build mTLS client: %w", err)
	}
	sessResp, err := client.IssueSession(ctx, name)
	if err != nil {
		return fmt.Errorf("issue session: %w", err)
	}

	// Store session token in OS keychain (no file on disk).
	if err := storeSessionToken(&sessionRecord{
		Token:          sessResp.Token,
		SessionID:      sessResp.SessionID,
		ControllerURL:  connectURL,
		ConnectionName: name,
		AbsoluteExpiry: sessResp.AbsoluteExpiry,
		CACertPEM:      b.CAPEM,
	}); err != nil {
		return fmt.Errorf("store session token: %w", err)
	}

	fmt.Printf("Connected as %q (expires %s)\n", name, sessResp.AbsoluteExpiry.Format(time.RFC3339))
	return nil
}

// runConnectReconnect handles cfg connect [<name>] (without --bundle).
func runConnectReconnect(ctx context.Context, args []string) error {
	reg, err := newConnectionRegistry()
	if err != nil {
		return fmt.Errorf("open connection registry: %w", err)
	}

	// Resolve the connection name.
	name := connectName
	if name == "" && len(args) > 0 {
		name = args[0]
	}
	if name == "" {
		entries, err := reg.List()
		if err != nil {
			return fmt.Errorf("list connections: %w", err)
		}
		switch len(entries) {
		case 0:
			return fmt.Errorf("no connections registered; use --bundle --url for first-time connect")
		case 1:
			name = entries[0].Name
		default:
			// Present a numbered selection on stdin.
			fmt.Println("Multiple connections available:")
			for i, e := range entries {
				fmt.Printf("  %d) %s (%s)\n", i+1, e.Name, e.ControllerURL)
			}
			fmt.Print("Select number: ")
			scanner := bufio.NewScanner(os.Stdin)
			if scanner.Scan() {
				var idx int
				if _, err := fmt.Sscanf(scanner.Text(), "%d", &idx); err != nil || idx < 1 || idx > len(entries) {
					return fmt.Errorf("invalid selection")
				}
				name = entries[idx-1].Name
			}
		}
	}

	entry, err := reg.Get(name)
	if err != nil {
		return fmt.Errorf("get connection %q: %w", name, err)
	}
	if entry == nil {
		return fmt.Errorf("connection %q not found", name)
	}

	// Unlock stored credential (machine-bound decrypt — no interactive passphrase).
	credStore, err := newCredentialStore()
	if err != nil {
		return fmt.Errorf("open credential store: %w", err)
	}
	bundleBytes, err := credStore.Load(ctx, name)
	if err != nil {
		return fmt.Errorf("load credential %q: %w", name, err)
	}

	b, err := parseBundleBytes(bundleBytes)
	if err != nil {
		return fmt.Errorf("parse stored bundle: %w", err)
	}

	tlsInsecure := connectTLSInsecure
	if !tlsInsecure {
		tlsInsecure = os.Getenv("CFGMS_TLS_INSECURE") == "true"
	}
	serverName := connectServerName

	client, err := newClientFromBundleData(b, entry.ControllerURL, tlsInsecure, serverName)
	if err != nil {
		return fmt.Errorf("build mTLS client: %w", err)
	}
	sessResp, err := client.IssueSession(ctx, name)
	if err != nil {
		return fmt.Errorf("issue session: %w", err)
	}

	if err := storeSessionToken(&sessionRecord{
		Token:          sessResp.Token,
		SessionID:      sessResp.SessionID,
		ControllerURL:  entry.ControllerURL,
		ConnectionName: name,
		AbsoluteExpiry: sessResp.AbsoluteExpiry,
		CACertPEM:      b.CAPEM,
	}); err != nil {
		return fmt.Errorf("store session token: %w", err)
	}

	// Update last-used timestamp (non-fatal).
	_ = reg.UpdateLastUsed(name, time.Now())

	fmt.Printf("Reconnected as %q (expires %s)\n", name, sessResp.AbsoluteExpiry.Format(time.RFC3339))
	return nil
}

func runDisconnect(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	rec, err := loadSessionToken()
	if err != nil {
		return fmt.Errorf("load session token: %w", err)
	}
	if rec == nil {
		fmt.Println("No active session.")
		return nil
	}

	tlsInsecure := disconnectTLSInsecure
	if !tlsInsecure {
		tlsInsecure = os.Getenv("CFGMS_TLS_INSECURE") == "true"
	}
	serverName := disconnectServerName

	// Session token is a replayable bearer credential: require explicit confirmation
	// before allowing the server certificate to go unverified.
	if tlsInsecure {
		if confirmErr := requireTLSInsecureForSession(); confirmErr != nil {
			return confirmErr
		}
	}

	// Authenticate the revoke request with the stored session token (Bearer).
	// Use the stored CA cert so the TLS verification matches the original connect.
	// Nil when empty → system cert pool (public CA controllers).
	var caCertPEM []byte
	if rec.CACertPEM != "" {
		caCertPEM = []byte(rec.CACertPEM)
	}
	client, err := NewAPIClient(&APIClientConfig{
		BaseURL:     rec.ControllerURL,
		APIKey:      rec.Token,
		CACertPEM:   caCertPEM,
		TLSInsecure: tlsInsecure,
		ServerName:  serverName,
	})
	if err != nil {
		return fmt.Errorf("build client: %w", err)
	}

	// Revoke server-side (best-effort: proceed even on error).
	if err := client.RevokeSession(ctx, rec.SessionID); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: server-side revoke failed: %v\n", err)
	}

	// Remove token from OS keychain.
	if err := deleteSessionToken(); err != nil {
		return fmt.Errorf("delete session token: %w", err)
	}

	// Lock credential (no-op for machine-bound unlocker).
	if rec.ConnectionName != "" {
		if credStore, err := newCredentialStore(); err == nil {
			_ = credStore.Lock(ctx, rec.ConnectionName)
		}
	}

	// Update last-used in registry (non-fatal).
	if rec.ConnectionName != "" {
		if reg, err := newConnectionRegistry(); err == nil {
			_ = reg.UpdateLastUsed(rec.ConnectionName, time.Now())
		}
	}

	fmt.Printf("Disconnected from %q.\n", rec.ConnectionName)
	return nil
}
