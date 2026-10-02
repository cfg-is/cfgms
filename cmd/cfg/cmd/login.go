// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #3721 (Epic #3711 — browser-authenticated CLI enrolment): the login command.
// Lodges a login request, prints the user code and opens the browser at the
// controller's confirmation page, then polls collect over its own already-pinned TLS
// connection until the operator approves, denies, or the request expires. The token
// never travels from the browser to this command — see handlers_cli_login.go for the
// server half of this protocol and why both rejected relay transports (a loopback
// listener, the existing WebAuthn relay helpers) are absent here (planning-review
// amendment carried into the story).
package cmd

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"time"

	"github.com/spf13/cobra"

	"github.com/cfgis/cfgms/pkg/logging"
)

// ---- errors -------------------------------------------------------------------------

// Distinct, clear terminal outcomes for the login poll loop (Issue #3721 AC). Each
// leaves no session stored until collection succeeds.
var (
	errCliLoginDenied      = errors.New("login request was denied by an administrator")
	errCliLoginTimedOut    = errors.New("timed out waiting for browser approval; run 'cfg credential enrol' for headless enrolment instead")
	errCliLoginGone        = errors.New("login request was already collected")
	errCliLoginInterrupted = errors.New("login interrupted; no session was stored")
)

// ---- flags ----------------------------------------------------------------------

var (
	loginURL          string
	loginName         string
	loginTLSInsecure  bool
	loginServerName   string
	loginPollInterval time.Duration
	loginWaitTimeout  time.Duration
	loginNoBrowser    bool
)

// loginSignalContextFn creates the cancelable context the login command polls under,
// canceled on an operator interrupt (SIGINT/Ctrl-C) so the poll loop exits cleanly with
// the distinct errCliLoginInterrupted message and no session stored. Overridable in
// tests, which cannot send a real OS signal to the test process without affecting the
// whole `go test` run.
var loginSignalContextFn = func() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt)
}

// loginOpenBrowserFn opens url in the operator's default browser. Overridable in tests.
var loginOpenBrowserFn = openBrowser

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Log in via a browser passkey and store a session",
	Long: `Lodges a login request with the controller, prints a short user code and an
approval URL, and opens that URL in the default browser (or prints it, when a browser
cannot be opened automatically — the browser and the command need not be on the same
machine). The operator completes a passkey login there and confirms the matching user
code. On approval this command collects the minted session token over its own
already-pinned TLS connection and stores it in the OS keychain, so the next ordinary
cfg command succeeds.

The session inherits the approving account's own scope and permissions — including a
root-scoped account's — through the existing session-creation path. This flow never
transfers a private key or a bundle file; the certificate bundle remains the way to
bootstrap a brand-new controller or obtain a certificate carrying the root-scope
extension.

A denial, a timeout, or an operator interrupt (Ctrl-C) each exit with a distinct
message; a timeout names 'cfg credential enrol' as the headless alternative.

Example:
  cfg login --url https://controller:9443`,
	RunE: runLogin,
}

func init() {
	loginCmd.Flags().StringVar(&loginURL, "url", "", "Controller HTTPS URL (required)")
	loginCmd.Flags().StringVar(&loginName, "name", "", "Connection label (default: derived from --url host)")
	loginCmd.Flags().BoolVar(&loginTLSInsecure, "tls-insecure", false, "Skip TLS certificate verification (development only, env: CFGMS_TLS_INSECURE)")
	loginCmd.Flags().StringVar(&loginServerName, "server-name", "", "Override TLS server name for certificate verification")
	loginCmd.Flags().DurationVar(&loginPollInterval, "poll-interval", 3*time.Second, "Interval between collect polls")
	loginCmd.Flags().DurationVar(&loginWaitTimeout, "wait-timeout", 5*time.Minute, "Maximum time to wait for browser approval")
	loginCmd.Flags().BoolVar(&loginNoBrowser, "no-browser", false, "Never attempt to open a browser automatically; only print the URL")
}

// ---- verifier -------------------------------------------------------------------

// generateCliLoginVerifier returns a fresh random verifier. Raw bytes are hex-encoded
// purely for safe display/debugging; the server treats the value as an opaque secret
// and compares only its SHA-256 hash. The raw value is retained solely in this
// process's memory and sent to the controller exactly once, at collect time, as a
// bearer credential — never in a URL (Issue #3721 AC).
func generateCliLoginVerifier() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate verifier: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// hashCliLoginVerifier returns the SHA-256 hex digest of the raw verifier — the only
// form ever sent at lodge time.
func hashCliLoginVerifier(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// buildCliLoginConfirmURL builds the browser confirmation URL for requestID: the
// controller's confirmation page, identified by the login request ID only — never the
// verifier, which never appears in a URL (Issue #3721 AC). The confirmation page
// itself is a later story in this epic (out of scope here).
func buildCliLoginConfirmURL(controllerURL, requestID string) string {
	u, err := url.Parse(controllerURL)
	if err != nil {
		return controllerURL
	}
	u.Path = "/login/confirm"
	q := u.Query()
	q.Set("request_id", requestID)
	u.RawQuery = q.Encode()
	return u.String()
}

// ---- existing-session check (revoked vs expired) ---------------------------------

// describeExistingCliSession performs a lightweight authenticated call against the
// currently stored session, if any, so login can tell the operator why that session
// stopped working before starting a fresh one. A revoked session (its account was
// disabled) and an expired one both surface as the same 401 status code from the
// bearer-auth middleware — rendering them alike would send an operator whose account
// has been disabled into a fresh login that will also fail (Issue #3721 amendment).
// Best-effort only: any failure to reach the controller here is silently ignored —
// this is an informational notice, never a precondition for login to proceed.
func describeExistingCliSession(ctx context.Context, tlsInsecure bool, serverName string) string {
	rec, err := loadSessionToken()
	if err != nil || rec == nil || rec.Token == "" {
		return ""
	}

	var caCertPEM []byte
	if rec.CACertPEM != "" {
		caCertPEM = []byte(rec.CACertPEM)
	}
	client, err := NewAPIClient(&APIClientConfig{
		BaseURL:     rec.ControllerURL,
		BearerToken: rec.Token,
		CACertPEM:   caCertPEM,
		TLSInsecure: tlsInsecure,
		ServerName:  serverName,
	})
	if err != nil {
		return ""
	}

	resp, err := client.doRequest(ctx, "GET", "/api/v1/sessions", nil)
	if err != nil {
		return ""
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 401 {
		return ""
	}

	switch apiErrorCode(resp) {
	case "SESSION_REVOKED":
		return "Note: your previous session was revoked — this usually means the account was disabled. If a fresh login also fails, contact an administrator.\n"
	case "SESSION_EXPIRED":
		return "Note: your previous session expired. Logging in again...\n"
	default:
		return ""
	}
}

// ---- poll loop --------------------------------------------------------------------

// pollForCliLoginCollection polls collectClient for requestID every interval until the
// request is approved and collected, denied, already gone, or ctx is canceled (an
// operator interrupt or the wait timeout). It writes nothing to disk — only its return
// value carries the session token onward, so every exit path here leaves no session
// stored.
func pollForCliLoginCollection(ctx context.Context, collectClient *APIClient, requestID string, interval time.Duration, out io.Writer) (*CollectCliLoginResult, error) {
	for {
		result, err := collectClient.CollectCliLogin(ctx, requestID)
		if err != nil {
			// A canceled context can abort the in-flight HTTP call itself, not just
			// the sleep between polls.
			if ctx.Err() != nil {
				return nil, classifyCliLoginCtxErr(ctx)
			}
			return nil, fmt.Errorf("failed to poll for login collection: %w", err)
		}
		switch {
		case result.AlreadyGone:
			return nil, errCliLoginGone
		case result.Token != "":
			return result, nil
		case result.Status == "denied":
			return nil, errCliLoginDenied
		case result.Status == "expired":
			// The server-side request TTL is the authoritative timeout — surfaced with
			// the same distinct message as a client-side wait-timeout (Issue #3721 AC).
			return nil, errCliLoginTimedOut
		case result.Status == "pending":
			// keep polling
		default:
			return nil, fmt.Errorf("unexpected login request status %q", logging.SanitizeLogValue(result.Status))
		}

		_, _ = fmt.Fprintln(out, "Waiting for browser approval...")

		select {
		case <-ctx.Done():
			return nil, classifyCliLoginCtxErr(ctx)
		case <-time.After(interval):
		}
	}
}

// classifyCliLoginCtxErr distinguishes the wait-timeout deadline from an operator
// interrupt (Ctrl-C) so each produces its own distinct message (Issue #3721 AC).
func classifyCliLoginCtxErr(ctx context.Context) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return errCliLoginTimedOut
	}
	return errCliLoginInterrupted
}

// ---- command ----------------------------------------------------------------------

func runLogin(cmd *cobra.Command, _ []string) error {
	out := cmd.OutOrStdout()

	if loginURL == "" {
		return fmt.Errorf("--url is required")
	}
	if err := requireHTTPS(loginURL); err != nil {
		return err
	}

	name := loginName
	if name == "" {
		name = deriveConnectionName(loginURL)
	}

	tlsInsecure := loginTLSInsecure
	if !tlsInsecure {
		tlsInsecure = os.Getenv("CFGMS_TLS_INSECURE") == "true"
	}
	serverName := loginServerName

	// A session token is a replayable bearer credential (api_client.go), so every
	// session-carrying path demands the typed confirmation before the server
	// certificate is allowed to go unverified — connect.go and client_helpers.go do
	// the same. This command is the worst case of the three: with verification off it
	// presents the collect verifier as a bearer credential *and* receives a freshly
	// minted session token in the collect response body, so an interposing party
	// harvests a live, possibly root-scoped session rather than replaying an existing
	// one. Gate before any client is built, including the best-effort existing-session
	// probe below, which also carries the stored session token — CFGMS_TLS_INSECURE=true
	// in the environment must never degrade this silently.
	if tlsInsecure {
		if confirmErr := requireTLSInsecureForSession(); confirmErr != nil {
			return confirmErr
		}
	}

	if note := describeExistingCliSession(context.Background(), tlsInsecure, serverName); note != "" {
		_, _ = fmt.Fprint(out, note)
	}

	verifier, err := generateCliLoginVerifier()
	if err != nil {
		return err
	}

	lodgeClient, err := NewAPIClient(&APIClientConfig{
		BaseURL:     loginURL,
		TLSInsecure: tlsInsecure,
		ServerName:  serverName,
	})
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	lodged, err := lodgeClient.LodgeCliLogin(context.Background(), hashCliLoginVerifier(verifier))
	if err != nil {
		return fmt.Errorf("failed to lodge login request: %w", err)
	}

	_, _ = fmt.Fprintf(out, "Code: %s\n", logging.SanitizeLogValue(lodged.UserCode))
	confirmURL := buildCliLoginConfirmURL(loginURL, lodged.RequestID)
	_, _ = fmt.Fprintf(out, "Approve this login by visiting: %s\n", confirmURL)
	_, _ = fmt.Fprintf(out, "Expires: %s\n", logging.SanitizeLogValue(lodged.ExpiresAt))

	if loginNoBrowser {
		_, _ = fmt.Fprintln(out, "Open the URL above in a browser (on this machine or another) to continue.")
	} else if browserErr := loginOpenBrowserFn(confirmURL); browserErr != nil {
		_, _ = fmt.Fprintln(out, "Could not open a browser automatically — open the URL above manually.")
	}

	// The verifier is presented as a bearer credential at collect time only — never in
	// a URL, never logged (Issue #3721 AC).
	collectClient, err := NewAPIClient(&APIClientConfig{
		BaseURL:     loginURL,
		BearerToken: verifier,
		TLSInsecure: tlsInsecure,
		ServerName:  serverName,
	})
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	signalCtx, stopSignal := loginSignalContextFn()
	defer stopSignal()
	waitCtx, cancelWait := context.WithTimeout(signalCtx, loginWaitTimeout)
	defer cancelWait()

	result, err := pollForCliLoginCollection(waitCtx, collectClient, lodged.RequestID, loginPollInterval, out)
	if err != nil {
		return err
	}

	// Register non-secret connection metadata, mirroring runConnectFirstTime — this is
	// what makes the connection visible to `cfg connections list`. There is no bundle
	// behind it: a later expiry means running `cfg login` again, never `cfg connect
	// <name>`, which has nothing to unlock for this connection.
	reg, err := newConnectionRegistry()
	if err != nil {
		return fmt.Errorf("failed to open connection registry: %w", err)
	}
	if err := reg.Register(ConnectionEntry{
		Name:          name,
		ControllerURL: loginURL,
		UnlockMethod:  "browser",
	}); err != nil {
		return fmt.Errorf("failed to register connection: %w", err)
	}

	if err := storeSessionToken(&sessionRecord{
		Token:          result.Token,
		SessionID:      result.SessionID,
		ControllerURL:  loginURL,
		ConnectionName: name,
		AbsoluteExpiry: result.AbsoluteExpiry,
	}); err != nil {
		return fmt.Errorf("failed to store session token: %w", err)
	}

	_, _ = fmt.Fprintf(out, "Logged in as %q (expires %s)\n", logging.SanitizeLogValue(name), result.AbsoluteExpiry.Format(time.RFC3339))
	return nil
}
