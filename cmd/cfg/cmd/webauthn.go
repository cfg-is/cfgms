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
// Registration flow:
//  1. CLI authenticates to controller via mTLS cert (admin bundle).
//  2. CLI calls POST .../webauthn/register/begin → receives PublicKeyCredentialCreationOptions.
//  3. CLI starts a local relay HTTP server on 127.0.0.1 (random port).
//  4. CLI opens the default browser to the relay page.
//  5. Browser runs navigator.credentials.create() with the embedded challenge.
//  6. Browser posts the credential response back to the relay server.
//  7. CLI calls POST .../webauthn/register/finish with the response.
//
// RPID note: the WebAuthn ceremony requires the browser origin to match the controller's
// configured RPID. For the local relay to work, the controller must include
// "http://127.0.0.1" (or "http://localhost") in its RPOrigins configuration.
// In production deployments the admin typically opens the controller's web UI directly;
// the relay is the correct path for first-boot bootstrap when no web UI session exists.
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"github.com/spf13/cobra"
)

const (
	webAuthnDefaultTimeout = 5 * time.Minute
)

var (
	webAuthnAPIURL   string
	webAuthnUsername string
	webAuthnLabel    string
	webAuthnForce    bool
	webAuthnJSON     bool
	webAuthnTimeout  time.Duration
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

Authentication: requires the admin mTLS certificate (admin bundle). A Bearer session
token alone is not sufficient — this command enforces the cert path by design.

The registration ceremony runs in your default browser via a local relay server.
Your controller must include "http://127.0.0.1" in its RPOrigins configuration for
the relay to work (see controller WebAuthn configuration).

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
	webAuthnRegisterCmd.Flags().DurationVar(&webAuthnTimeout, "timeout", webAuthnDefaultTimeout, "Browser ceremony timeout")

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

	client, err := resolveBundleClient(apiURL)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve admin bundle: %w", err)
	}
	if client == nil {
		return nil, fmt.Errorf("webauthn commands require mTLS certificate authentication; " +
			"no admin bundle found — set CFGMS_ADMIN_BUNDLE, use --bundle, or run 'cfg connect' first")
	}
	return client, nil
}

func runWebAuthnRegister(cmd *cobra.Command, args []string) error {
	if webAuthnUsername == "" {
		return fmt.Errorf("--username is required")
	}

	client, err := getWebAuthnClient()
	if err != nil {
		return err
	}

	ctx := context.Background()

	// Step 1: Begin — get the PublicKeyCredentialCreationOptions from the controller.
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Requesting WebAuthn registration challenge from controller...\n")
	creationOptions, err := client.WebAuthnBeginRegistration(ctx, webAuthnUsername)
	if err != nil {
		return fmt.Errorf("failed to begin WebAuthn registration: %w", err)
	}

	// Step 2: Run browser-based ceremony via local relay.
	timeout := webAuthnTimeout
	if timeout == 0 {
		timeout = webAuthnDefaultTimeout
	}
	credResponseJSON, err := runWebAuthnBrowserFlow(cmd.OutOrStdout(), creationOptions, timeout)
	if err != nil {
		return fmt.Errorf("WebAuthn ceremony failed: %w", err)
	}

	// Step 3: Finish — send the authenticator response to the controller.
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Completing registration with controller...\n")
	result, err := client.WebAuthnFinishRegistration(ctx, webAuthnUsername, webAuthnLabel, credResponseJSON)
	if err != nil {
		return fmt.Errorf("failed to finish WebAuthn registration: %w", err)
	}

	if webAuthnJSON {
		return json.NewEncoder(cmd.OutOrStdout()).Encode(result)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Passkey registered successfully!\n")
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Username:      %s\n", webAuthnUsername)
	if result.Label != "" {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Label:         %s\n", result.Label)
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Registered at: %s\n", result.RegisteredAt)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "\nYou can now log in to the controller web UI using this passkey.\n")
	return nil
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

// runWebAuthnBrowserFlow starts a local relay HTTP server, opens the default browser
// to the relay page, and waits for the browser to complete the WebAuthn ceremony and
// POST back the credential response.
//
// The relay serves a single-page WebAuthn ceremony UI at GET /register and accepts the
// credential response at POST /done. It shuts down after the first POST /done or after
// the timeout elapses.
func runWebAuthnBrowserFlow(out io.Writer, creationOptions json.RawMessage, timeout time.Duration) ([]byte, error) {
	optionsJSON, err := json.Marshal(creationOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal creation options: %w", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("failed to start local relay server: %w", err)
	}
	// net.Listen("tcp", ...) is documented to return a *net.TCPListener whose Addr()
	// is always a *net.TCPAddr, so this type assertion is unconditionally safe.
	port := ln.Addr().(*net.TCPAddr).Port //nolint:forcetypeassert // see comment above: net "tcp" listener Addr() is always *net.TCPAddr

	var (
		resultMu sync.Mutex
		result   []byte
		resultCh = make(chan struct{}, 1)
		relayErr error
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprintf(w, webAuthnRelayHTML, string(optionsJSON))
	})
	mux.HandleFunc("/done", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			http.Error(w, "read error", http.StatusInternalServerError)
			resultMu.Lock()
			relayErr = readErr
			resultMu.Unlock()
			select {
			case resultCh <- struct{}{}:
			default:
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))

		resultMu.Lock()
		result = body
		resultMu.Unlock()
		select {
		case resultCh <- struct{}{}:
		default:
		}
	})

	srv := &http.Server{
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	relayURL := fmt.Sprintf("http://127.0.0.1:%d/register", port)
	_, _ = fmt.Fprintf(out, "\nOpen this URL in your browser to complete the passkey registration:\n  %s\n\n", relayURL)
	_, _ = fmt.Fprintf(out, "Waiting for browser ceremony (timeout: %s)...\n", timeout)

	_ = openBrowser(relayURL)

	select {
	case <-resultCh:
	case <-time.After(timeout):
		return nil, fmt.Errorf("timed out waiting for browser to complete WebAuthn registration")
	}

	resultMu.Lock()
	defer resultMu.Unlock()
	if relayErr != nil {
		return nil, fmt.Errorf("relay error: %w", relayErr)
	}
	return result, nil
}

// openBrowser opens url in the default browser. Errors are silently ignored —
// the relay URL is always printed to stdout so the user can open it manually.
func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start()
}

// webAuthnRelayHTML is the single-page relay UI served to the browser.
// %s is replaced with the JSON-encoded PublicKeyCredentialCreationOptions (the data
// field from the controller's begin response, which contains the "publicKey" key).
const webAuthnRelayHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CFGMS Passkey Registration</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 480px; margin: 60px auto; padding: 0 20px; }
    h1 { font-size: 1.4em; }
    button { padding: 10px 24px; font-size: 1em; cursor: pointer; }
    #status { margin: 16px 0; color: #555; }
    .error { color: #c00; }
    .success { color: #060; }
  </style>
</head>
<body>
  <h1>CFGMS Passkey Registration</h1>
  <p>Click the button below to register your passkey (security key or platform authenticator).</p>
  <button id="btn" onclick="registerPasskey()">Register Passkey</button>
  <p id="status">Ready.</p>
  <script>
    const creationOptions = %s;

    function b64decode(s) {
      const b = atob(s.replace(/-/g,'+').replace(/_/g,'/'));
      return Uint8Array.from(b, c => c.charCodeAt(0));
    }

    function b64encode(buf) {
      return btoa(String.fromCharCode(...new Uint8Array(buf)))
        .replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
    }

    function prepareOptions(opts) {
      const pk = opts.publicKey;
      pk.challenge = b64decode(pk.challenge);
      pk.user.id = b64decode(pk.user.id);
      if (pk.excludeCredentials) {
        pk.excludeCredentials = pk.excludeCredentials.map(c => ({...c, id: b64decode(c.id)}));
      }
      return opts;
    }

    async function registerPasskey() {
      const btn = document.getElementById('btn');
      const status = document.getElementById('status');
      btn.disabled = true;
      status.className = '';
      status.textContent = 'Activating authenticator — follow the browser prompt...';
      try {
        const opts = prepareOptions(JSON.parse(JSON.stringify(creationOptions)));
        const cred = await navigator.credentials.create(opts);
        status.textContent = 'Sending result to cfg CLI...';
        const body = JSON.stringify({
          id: cred.id,
          rawId: b64encode(cred.rawId),
          type: cred.type,
          response: {
            clientDataJSON: b64encode(cred.response.clientDataJSON),
            attestationObject: b64encode(cred.response.attestationObject),
          }
        });
        const res = await fetch('/done', {method:'POST', headers:{'Content-Type':'application/json'}, body});
        if (res.ok) {
          status.className = 'success';
          status.textContent = 'Passkey registered! You may close this tab.';
        } else {
          throw new Error('relay POST failed: ' + res.status);
        }
      } catch (e) {
        status.className = 'error';
        status.textContent = 'Error: ' + e.message;
        btn.disabled = false;
      }
    }
  </script>
</body>
</html>`
