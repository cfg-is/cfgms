// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #2785 (original): cfg step-up client for CFGMS-StepUp 401 challenge (Issue #2737).
// Issue #4287: the CLI presence relay. ADR-021 Amendment 4 named a controller-served
// presence relay as the fix for CLI-driven WebAuthn presence assertion — a ceremony
// served from a CLI-local loopback listener can never satisfy a configured relying
// party (no browser will run navigator.credentials.get() against http://127.0.0.1
// against an RP configured for the controller's own origin). Instead of running the
// ceremony itself, cfg:
//
//  1. Lodges a presence request with the controller, bound to the exact pending
//     action (method, path, SHA-256 of the request body, permission).
//  2. Opens a page served by the controller, at the controller's own rp_id origin,
//     where the admin sees the action in plain words and touches their key.
//  3. Polls and collects the resulting single-use presence token over its own
//     already-authenticated connection, then retries the original request with it.
//
// When the server returns a 401 + WWW-Authenticate: CFGMS-StepUp response,
// defaultStepUpHandler routes to one of three paths:
//
//  1. Non-interactive (stdin is not a TTY): fail immediately with an actionable
//     error naming the required assurance level. cfg never blocks on input it
//     cannot receive.
//
//  2. Interactive + presence="required": run the presence relay (runPresenceBrowserFlow).
//
//  3. Interactive + no presence="required": the assurance level cannot be raised
//     programmatically; fail with an actionable error naming the web UI path.
//
// This follows the callback-injection shape of OnUnauthorized (api_client.go) — no
// hidden global state, overridable in tests.
package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/mattn/go-isatty"

	"github.com/cfgis/cfgms/pkg/logging"
)

// isTerminalFn is overridable in tests to simulate interactive/non-interactive environments.
var isTerminalFn = func() bool { return isatty.IsTerminal(os.Stdin.Fd()) }

// presenceBrowserFlowFn is overridable in tests to bypass the real relay.
var presenceBrowserFlowFn = runPresenceBrowserFlow

// presencePollInterval and presenceWaitTimeout bound the CLI's collect poll, mirroring
// cfg login's own defaults (login.go's --poll-interval / --wait-timeout). Not exposed
// as flags here: the presence relay fires deep inside the generic step-up plumbing,
// reachable from any command, not from a single dedicated command's flag set. Vars
// (not consts) so tests can shrink them instead of taking the real wait.
var (
	presencePollInterval = 3 * time.Second
	presenceWaitTimeout  = 5 * time.Minute
)

// presenceSignalContextFn creates the cancelable context the presence relay polls
// under, canceled on an operator interrupt (SIGINT/Ctrl-C). Overridable in tests,
// mirroring loginSignalContextFn.
var presenceSignalContextFn = func() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt)
}

// presenceOpenBrowserFn opens url in the operator's default browser. Overridable in tests.
var presenceOpenBrowserFn = openBrowser

// defaultStepUpHandler returns an OnStepUpRequired callback for the given APIClient.
// The returned function parses the WWW-Authenticate header and either runs the CLI
// presence relay (interactive TTY + presence="required") or fails with an actionable
// error (non-interactive or assurance level cannot be raised programmatically).
func defaultStepUpHandler(client *APIClient) func(wwwAuthenticate, method, path string, bodyBytes []byte) (string, error) {
	return func(wwwAuthenticate, method, path string, bodyBytes []byte) (string, error) {
		required, presenceRequired, permission := parseStepUpHeader(wwwAuthenticate)

		if !isTerminalFn() {
			return "", fmt.Errorf("step-up required: %s assurance needed for this action; re-run interactively or use an mTLS-authenticated session", required)
		}

		if !presenceRequired {
			// The session assurance level cannot be raised programmatically in the CLI.
			// The operator must log in via the web UI or use an mTLS-authenticated session.
			return "", fmt.Errorf("step-up required: %s assurance needed for this action; log in via the web UI to elevate the session or use an mTLS-authenticated session", required)
		}

		if permission == "" {
			return "", fmt.Errorf("cfg cannot start the presence relay: the controller's step-up challenge did not name a permission (the controller may be running an older version)")
		}

		return presenceBrowserFlowFn(client, method, path, bodyBytes, permission)
	}
}

// parseStepUpHeader extracts the required assurance level, presence flag and gated
// permission ID from a WWW-Authenticate header value. Expected format:
//
//	CFGMS-StepUp realm="cfgms", required="strong", presence="required", permission="module:approve"
//
// Returns ("strong", false, "") when the header is malformed or required is absent.
func parseStepUpHeader(wwwAuthenticate string) (required string, presenceRequired bool, permission string) {
	required = "strong" // safe default
	// Strip the scheme name (everything up to the first space) and parse the remainder.
	rest := wwwAuthenticate
	if idx := strings.IndexByte(rest, ' '); idx >= 0 {
		rest = rest[idx+1:]
	} else {
		return // scheme only, no params
	}
	for _, token := range strings.Split(rest, ",") {
		token = strings.TrimSpace(token)
		k, v, ok := strings.Cut(token, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.Trim(strings.TrimSpace(v), `"`)
		switch k {
		case "required":
			if v != "" {
				required = v
			}
		case "presence":
			presenceRequired = v == "required"
		case "permission":
			permission = v
		}
	}
	return
}

// errPresenceDenied, errPresenceTimedOut and errPresenceGone are the CLI presence
// relay's distinct terminal poll outcomes, mirroring cli-login's own distinct errors
// (errCliLoginDenied et al.) so each fails closed with a message naming exactly what
// happened — never a generic "request failed".
var (
	errPresenceTimedOut = errors.New("timed out waiting for the presence ceremony to complete; run the command again")
	errPresenceGone     = errors.New("presence request was already collected")
)

// sha256Hex returns the hex-encoded SHA-256 digest of b (b may be nil/empty).
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// buildCliPresenceConfirmURL builds the browser confirmation URL for requestID —
// the controller's own presence relay page, at the controller's own rp_id origin
// (never a CLI-local address; ADR-021 Amendment 4).
func buildCliPresenceConfirmURL(controllerURL, requestID string) string {
	u, err := url.Parse(controllerURL)
	if err != nil {
		return controllerURL
	}
	u.Path = "/cli/presence"
	q := u.Query()
	q.Set("request_id", requestID)
	u.RawQuery = q.Encode()
	return u.String()
}

// describePresenceAction renders a generic, human-readable description of the pending
// action for the *terminal* — generic over every RequireUserPresence-gated permission
// (ADR-021), so this relay never special-cases module:approve or any other single
// permission.
//
// It is deliberately never sent to the controller. The confirmation page renders the
// action from the bound permission/method/path the controller itself persisted, so this
// local rendering is the terminal side of the same comparison the user code covers: the
// admin sees the same permission — method path line in both places, and neither side is
// free text the other trusts.
func describePresenceAction(permission, method, path string) string {
	return fmt.Sprintf("%s — %s %s", permission, method, path)
}

// pollForCliPresenceCollection polls collectClient for requestID every interval until
// the presence token is collected, the request is already gone, expires, or ctx is
// canceled (an operator interrupt or the wait timeout).
func pollForCliPresenceCollection(ctx context.Context, client *APIClient, requestID string, interval time.Duration) (string, error) {
	for {
		result, err := client.CollectCliPresence(ctx, requestID)
		if err != nil {
			if ctx.Err() != nil {
				return "", classifyPresenceCtxErr(ctx)
			}
			return "", fmt.Errorf("failed to poll for presence collection: %w", err)
		}
		switch {
		case result.AlreadyGone:
			return "", errPresenceGone
		case result.PresenceToken != "":
			return result.PresenceToken, nil
		case result.Status == "expired":
			return "", errPresenceTimedOut
		case result.Status == "pending", result.Status == "approved":
			// keep polling
		default:
			return "", fmt.Errorf("unexpected presence request status %q", logging.SanitizeLogValue(result.Status))
		}

		select {
		case <-ctx.Done():
			return "", classifyPresenceCtxErr(ctx)
		case <-time.After(interval):
		}
	}
}

// classifyPresenceCtxErr distinguishes the wait-timeout deadline from an operator
// interrupt (Ctrl-C), mirroring classifyCliLoginCtxErr.
func classifyPresenceCtxErr(ctx context.Context) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return errPresenceTimedOut
	}
	return fmt.Errorf("presence ceremony interrupted; the guarded action was not retried")
}

// runPresenceBrowserFlow is the CLI presence relay (Issue #4287, ADR-021 Amendment 4/6):
// lodges a presence request bound to (method, path, sha256(bodyBytes), permission),
// opens the controller's own relay page for the admin to run the WebAuthn ceremony,
// and polls collect until the resulting single-use presence token is available.
func runPresenceBrowserFlow(client *APIClient, method, path string, bodyBytes []byte, permission string) (string, error) {
	lodged, err := client.LodgeCliPresence(context.Background(), LodgeCliPresenceRequestBody{
		Method:     method,
		Path:       path,
		BodyHash:   sha256Hex(bodyBytes),
		Permission: permission,
	})
	if err != nil {
		return "", fmt.Errorf("failed to lodge presence request: %w", err)
	}

	confirmURL := buildCliPresenceConfirmURL(client.BaseURL(), lodged.RequestID)
	fmt.Fprintf(os.Stderr, "Presence required for: %s\n",
		logging.SanitizeLogValue(describePresenceAction(permission, method, path)))
	fmt.Fprintf(os.Stderr, "Code: %s\n", logging.SanitizeLogValue(lodged.UserCode))
	fmt.Fprintf(os.Stderr, "Approve this action by visiting: %s\n", confirmURL)
	fmt.Fprintf(os.Stderr, "Expires: %s\n", logging.SanitizeLogValue(lodged.ExpiresAt))

	if browserErr := presenceOpenBrowserFn(confirmURL); browserErr != nil {
		fmt.Fprintln(os.Stderr, "Could not open a browser automatically — open the URL above manually.")
	}

	signalCtx, stopSignal := presenceSignalContextFn()
	defer stopSignal()
	waitCtx, cancelWait := context.WithTimeout(signalCtx, presenceWaitTimeout)
	defer cancelWait()

	return pollForCliPresenceCollection(waitCtx, client, lodged.RequestID, presencePollInterval)
}
