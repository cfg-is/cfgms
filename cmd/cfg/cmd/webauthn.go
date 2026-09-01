// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #2783: cfg webauthn — passkey bootstrap and recovery via mTLS admin certificate.
//
// All three subcommands (register/list/revoke) use resolveBundleClient exclusively —
// never resolveSessionOrBundleClient. This enforces the ADR-021 §7 invariant: only
// the cert-authenticated path can reach credential registration. A Bearer session
// token alone cannot use these commands even though the underlying server endpoints
// accept any AssuranceStrong principal (mTLS certs are AssuranceStrong by construction).
//
// `cfg webauthn register` cannot run the WebAuthn ceremony itself: a browser refuses
// navigator.credentials.create() unless the calling origin's effective domain matches
// (or is a registrable suffix of) the relying party's rp_id, and a CLI-served loopback
// page can never satisfy a real rp_id — see ADR-021 Amendment 4
// (docs/architecture/decisions/021-identity-assurance-levels.md). The command fails
// fast with an actionable error pointing the operator at browser passkey enrollment via
// the web UI (ADR-021 Amendment 1 self-enrollment, Amendment 3 self-service passkey
// management) instead of attempting a ceremony that cannot complete.
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"github.com/spf13/cobra"
)

var (
	webAuthnAPIURL   string
	webAuthnUsername string
	webAuthnLabel    string
	webAuthnForce    bool
	webAuthnJSON     bool
)

// webAuthnCmd is the root command: cfg webauthn ...
var webAuthnCmd = &cobra.Command{
	Use:   "webauthn",
	Short: "Manage WebAuthn passkeys for browser authentication",
	Long: `Manage WebAuthn passkeys (FIDO2 credentials) for browser-based admin login.

All webauthn commands authenticate to the controller using the admin mTLS certificate
(admin bundle). A Bearer session token is not sufficient — the cert path is required by
design (ADR-021 §7: bootstrap and recovery ride the existing mTLS cert root of trust).

Subcommands:
  register  Register a new passkey for a web admin account
  list      List registered passkeys for a web admin account
  revoke    Revoke a passkey by credential ID`,
}

// webAuthnRegisterCmd implements cfg webauthn register.
var webAuthnRegisterCmd = &cobra.Command{
	Use:   "register",
	Short: "Register a new WebAuthn passkey",
	Long: `Register a new WebAuthn passkey (FIDO2 credential) for a web admin account.

This command cannot complete: a WebAuthn ceremony served from a CLI-local loopback page
can never satisfy a configured relying party (ADR-021 Amendment 4) — the browser itself
refuses navigator.credentials.create() because a 127.0.0.1 origin can never match a real
rp_id. Register a passkey from the controller web UI instead, at the /passkeys page
(ADR-021 Amendment 1 self-enrollment, Amendment 3 self-service passkey management).

Examples:
  cfg webauthn register --username alice
  cfg webauthn register --username alice --label "YubiKey 5C"
  cfg webauthn register --username alice --bundle /path/to/admin.bundle.yaml`,
	RunE: runWebAuthnRegister,
}

// webAuthnListCmd implements cfg webauthn list.
var webAuthnListCmd = &cobra.Command{
	Use:   "list",
	Short: "List registered WebAuthn credentials",
	Long: `List all registered WebAuthn passkeys for a web admin account.

Authentication: requires the admin mTLS certificate (admin bundle).

Examples:
  cfg webauthn list --username alice
  cfg webauthn list --username alice --json`,
	RunE: runWebAuthnList,
}

// webAuthnRevokeCmd implements cfg webauthn revoke.
var webAuthnRevokeCmd = &cobra.Command{
	Use:   "revoke <credential-id>",
	Short: "Revoke a WebAuthn credential",
	Long: `Revoke a WebAuthn passkey by its credential ID.

The credential ID is the base64url-encoded string shown by 'cfg webauthn list'.

Revoking the last credential on an account requires --force. This is a UX guard
against accidental self-lockout from browser-based admin login. Note: the admin
mTLS cert remains valid regardless of WebAuthn credential count (ADR-021 §7).

Authentication: requires the admin mTLS certificate (admin bundle).

Examples:
  cfg webauthn revoke <credential-id> --username alice
  cfg webauthn revoke <credential-id> --username alice --force`,
	Args: cobra.ExactArgs(1),
	RunE: runWebAuthnRevoke,
}

func init() {
	webAuthnCmd.PersistentFlags().StringVar(&webAuthnAPIURL, "api-url", "", "Controller REST API URL (env: CFGMS_API_URL)")
	webAuthnCmd.PersistentFlags().StringVar(&webAuthnUsername, "username", "", "Web account username")

	webAuthnRegisterCmd.Flags().StringVar(&webAuthnLabel, "label", "", "Human-readable label for the new credential")

	webAuthnListCmd.Flags().BoolVar(&webAuthnJSON, "json", false, "Emit JSON output")

	webAuthnRevokeCmd.Flags().BoolVar(&webAuthnForce, "force", false, "Force revocation even when revoking the last credential")

	webAuthnCmd.AddCommand(webAuthnRegisterCmd)
	webAuthnCmd.AddCommand(webAuthnListCmd)
	webAuthnCmd.AddCommand(webAuthnRevokeCmd)
}

// getWebAuthnClient returns an mTLS-cert-authenticated APIClient.
// Fails if no admin bundle is found — all webauthn commands require the cert path
// (ADR-021 §7: Bearer sessions cannot be used for passkey bootstrap/recovery).
func getWebAuthnClient() (*APIClient, error) {
	apiURL := webAuthnAPIURL
	if apiURL == "" {
		apiURL = os.Getenv("CFGMS_API_URL")
	}

	client, err := resolveBundleClient(apiURL, false, "")
	if err != nil {
		return nil, fmt.Errorf("failed to resolve admin bundle: %w", err)
	}
	if client == nil {
		return nil, fmt.Errorf("webauthn commands require mTLS certificate authentication; " +
			"no admin bundle found — set CFGMS_ADMIN_BUNDLE, use --bundle, or run 'cfg connect' first")
	}
	return client, nil
}

// errWebAuthnRegisterUnsupported is returned by runWebAuthnRegister before any
// controller contact. A WebAuthn ceremony served from a CLI-local loopback listener
// can never satisfy a configured relying party in any controller configuration — see
// ADR-021 Amendment 4 (docs/architecture/decisions/021-identity-assurance-levels.md)
// for the full case analysis. The operator must enroll a passkey from the controller
// web UI instead (ADR-021 Amendment 1 self-enrollment, Amendment 3 self-service passkey
// management).
var errWebAuthnRegisterUnsupported = fmt.Errorf(
	"cfg webauthn register cannot run the WebAuthn ceremony from the CLI: a browser " +
		"refuses navigator.credentials.create() from a page served at http://127.0.0.1, " +
		"which can never match a configured relying party (ADR-021 Amendment 4). " +
		"Register a passkey from the controller web UI instead, at the /passkeys page " +
		"(ADR-021 Amendment 1 self-enrollment, Amendment 3 self-service passkey management)")

func runWebAuthnRegister(cmd *cobra.Command, args []string) error {
	if webAuthnUsername == "" {
		return fmt.Errorf("--username is required")
	}

	// Enforce the ADR-021 §7 cert-path requirement before failing fast, so a bearer-only
	// caller still sees the mTLS error rather than the unrelated ceremony error.
	if _, err := getWebAuthnClient(); err != nil {
		return err
	}

	return errWebAuthnRegisterUnsupported
}

func runWebAuthnList(cmd *cobra.Command, args []string) error {
	if webAuthnUsername == "" {
		return fmt.Errorf("--username is required")
	}

	client, err := getWebAuthnClient()
	if err != nil {
		return err
	}

	result, err := client.WebAuthnListCredentials(context.Background(), webAuthnUsername)
	if err != nil {
		return fmt.Errorf("failed to list WebAuthn credentials: %w", err)
	}

	if webAuthnJSON {
		return json.NewEncoder(cmd.OutOrStdout()).Encode(result)
	}

	if len(result.Credentials) == 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "No WebAuthn credentials registered for %s.\n", result.Username)
		return nil
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "WebAuthn credentials for %s (%d):\n\n", result.Username, len(result.Credentials))
	for i, c := range result.Credentials {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  [%d] ID:    %s\n", i+1, c.ID)
		if c.Label != "" {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "      Label: %s\n", c.Label)
		}
		if len(c.Transport) > 0 {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "      Transport: %v\n", c.Transport)
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "      Registered: %s\n", c.RegisteredAt)
		_, _ = fmt.Fprintln(cmd.OutOrStdout())
	}
	return nil
}

func runWebAuthnRevoke(cmd *cobra.Command, args []string) error {
	credentialID := args[0]
	if webAuthnUsername == "" {
		return fmt.Errorf("--username is required")
	}

	client, err := getWebAuthnClient()
	if err != nil {
		return err
	}

	ctx := context.Background()

	// List credentials first to enforce the last-credential guard.
	list, err := client.WebAuthnListCredentials(ctx, webAuthnUsername)
	if err != nil {
		return fmt.Errorf("failed to list credentials (required for last-credential check): %w", err)
	}

	if len(list.Credentials) == 1 {
		if !webAuthnForce {
			return fmt.Errorf(
				"revoking the last credential for %q would prevent browser-based login\n"+
					"Use --force to confirm you want to remove the last passkey\n"+
					"(Note: your mTLS admin certificate remains valid for CLI access regardless)",
				webAuthnUsername)
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Warning: revoking the last WebAuthn credential for %s.\n"+
			"Browser login will require a new passkey registration via 'cfg webauthn register'.\n\n",
			webAuthnUsername)
	}

	if err := client.WebAuthnRevokeCredential(ctx, webAuthnUsername, credentialID); err != nil {
		return fmt.Errorf("failed to revoke credential: %w", err)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Credential revoked: %s\n", credentialID)
	return nil
}

// openBrowser opens url in the default browser. Errors are silently ignored —
// callers print url so the operator can open it manually if this fails.
func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		// #nosec G204 G702 -- executable and handler arguments are fixed; url is the
		// loopback WebAuthn relay URL generated by this CLI, passed as one argv.
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		// #nosec G204 G702 -- executable is fixed and the locally generated loopback
		// relay URL is passed as one argv without a shell.
		cmd = exec.Command("open", url)
	default:
		// #nosec G204 G702 -- executable is fixed and the locally generated loopback
		// relay URL is passed as one argv without a shell.
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start()
}
