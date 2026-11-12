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
// A session opened with --authenticator never uses the relay: authenticatorStepUpHandler
// answers a presence challenge itself with the controller's direct presence begin/finish
// calls and the software authenticator (Issue #6146).
//
// When the server returns a 401 + WWW-Authenticate: CFGMS-StepUp response,
// defaultStepUpHandler routes to one of three paths:
//
//  1. presence="required": run the presence relay (runPresenceBrowserFlow), with or
//     without a terminal. The relay only lodges a request, prints the confirmation URL
//     and polls, so it needs no input from stdin. It opens a browser only when stdin is
//     a TTY; otherwise (scripted and agent sessions) the URL is printed and a human or
//     configured authenticator confirms it out of band.
//
//  2. No presence="required", stdin is not a TTY: fail immediately with an actionable
//     error naming the required assurance level. cfg never blocks on input it
//     cannot receive.
//
//  3. No presence="required", interactive: the assurance level cannot be raised
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
	"github.com/cfgis/cfgms/pkg/softauthn"
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

// presenceNoBrowser is the root persistent --no-browser flag. It keeps the presence relay
// from launching a local browser even on a terminal, so a person can open the printed URL
// on another device. cfg login declares its own local --no-browser, which shadows this
// flag for that command (loginNoBrowser).
var presenceNoBrowser bool

func init() {
	rootCmd.PersistentFlags().BoolVar(&presenceNoBrowser, "no-browser", false,
		"Never launch a local browser for presence approval; print the URL and code only (env: CFGMS_NO_BROWSER)")
}

// presenceBrowserSuppressed reports whether the presence relay must not launch a browser:
// the --no-browser flag, or CFGMS_NO_BROWSER set to any non-empty value other than "0".
func presenceBrowserSuppressed() bool {
	if presenceNoBrowser {
		return true
	}
	v := os.Getenv("CFGMS_NO_BROWSER")
	return v != "" && v != "0"
}

// defaultStepUpHandler returns an OnStepUpRequired callback for the given APIClient.
// The returned function parses the WWW-Authenticate header and either runs the CLI
// presence relay (presence="required", with or without a TTY) or fails with an actionable
// error (non-interactive or assurance level cannot be raised programmatically).
func defaultStepUpHandler(client *APIClient) func(wwwAuthenticate, method, path string, bodyBytes []byte) (string, error) {
	return func(wwwAuthenticate, method, path string, bodyBytes []byte) (string, error) {
		permission, err := presencePermissionFromChallenge(wwwAuthenticate)
		if err != nil {
			return "", err
		}
		return presenceBrowserFlowFn(client, method, path, bodyBytes, permission)
	}
}

// presencePermissionFromChallenge returns the permission a presence-required step-up
// challenge names. It fails with the actionable error for a challenge that is not a
// presence challenge (the assurance level cannot be raised programmatically) or that
// names no permission; both step-up handlers share it so neither starts a ceremony it
// cannot bind.
func presencePermissionFromChallenge(wwwAuthenticate string) (string, error) {
	required, presenceRequired, permission := parseStepUpHeader(wwwAuthenticate)

	if !presenceRequired {
		if !isTerminalFn() {
			return "", fmt.Errorf("step-up required: %s assurance needed for this action; re-run interactively or use an mTLS-authenticated session", required)
		}
		// The session assurance level cannot be raised programmatically in the CLI.
		// The operator must log in via the web UI or use an mTLS-authenticated session.
		return "", fmt.Errorf("step-up required: %s assurance needed for this action; log in via the web UI to elevate the session or use an mTLS-authenticated session", required)
	}

	if permission == "" {
		return "", fmt.Errorf("cfg cannot start the presence relay: the controller's step-up challenge did not name a permission (the controller may be running an older version)")
	}
	return permission, nil
}

// presenceCeremonyTimeout bounds one direct presence begin/finish exchange. The
// controller's presence token lives only presenceTokenTTL (30 s), and the ceremony
// needs no human, so it either completes promptly or is not going to.
const presenceCeremonyTimeout = 30 * time.Second

// authenticatorStepUpHandler returns the OnStepUpRequired callback for a client that
// logged in with the software authenticator auth (--authenticator). A presence-required
// challenge is answered with the controller's direct presence begin/finish calls: begin
// names the exact guarded request (method, path, SHA-256 of the body, permission), auth
// signs the challenge, and finish returns the single-use token the client replays the
// request with. No browser and no human are involved, and nothing is cached: every
// guarded request runs its own full ceremony.
//
// Challenges that are not presence challenges, or that name no permission, fail exactly
// as they do for defaultStepUpHandler.
func authenticatorStepUpHandler(client *APIClient, auth *softauthn.Authenticator) func(wwwAuthenticate, method, path string, bodyBytes []byte) (string, error) {
	return func(wwwAuthenticate, method, path string, bodyBytes []byte) (string, error) {
		permission, err := presencePermissionFromChallenge(wwwAuthenticate)
		if err != nil {
			return "", err
		}

		ctx, cancel := context.WithTimeout(context.Background(), presenceCeremonyTimeout)
		defer cancel()
		options, err := client.WebAuthnPresenceBeginForAction(ctx, PresenceActionBinding{
			Method:       method,
			Path:         path,
			BodyHash:     sha256Hex(bodyBytes),
			PermissionID: permission,
		})
		if err != nil {
			return "", fmt.Errorf("presence ceremony failed at begin: %w", err)
		}
		// softauthn refuses options whose rpId is not the record's before it signs.
		assertion, err := auth.Assert(options)
		if err != nil {
			return "", fmt.Errorf("presence refused: %w", err)
		}
		token, err := client.WebAuthnPresenceFinish(ctx, assertion)
		if err != nil {
			return "", fmt.Errorf("presence ceremony failed at finish: %w", err)
		}
		return token, nil
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
// prints the controller's own relay page URL (and, on a TTY, opens it) for the admin to
// run the WebAuthn ceremony, and polls collect until the resulting single-use presence
// token is available.
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

	// Without a terminal (scripted and agent sessions), or with --no-browser, never launch
	// a browser: the URL above is the only channel, confirmed out of band (on this machine
	// or another device) while this process polls.
	if isTerminalFn() && !presenceBrowserSuppressed() {
		if browserErr := presenceOpenBrowserFn(confirmURL); browserErr != nil {
			fmt.Fprintln(os.Stderr, "Could not open a browser automatically — open the URL above manually.")
		}
	}

	signalCtx, stopSignal := presenceSignalContextFn()
	defer stopSignal()
	waitCtx, cancelWait := context.WithTimeout(signalCtx, presenceWaitTimeout)
	defer cancelWait()

	return pollForCliPresenceCollection(waitCtx, client, lodged.RequestID, presencePollInterval)
}
