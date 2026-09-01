// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #2785: cfg step-up client for CFGMS-StepUp 401 challenge (Issue #2737).
//
// When a cfg command hits a 401 + WWW-Authenticate: CFGMS-StepUp response,
// defaultStepUpHandler routes to one of two paths:
//
//  1. Non-interactive (stdin is not a TTY): fail immediately with an actionable
//     error naming the required assurance level. cfg never blocks on input it
//     cannot receive.
//
//  2. Interactive + presence="required": CLI-driven presence is not currently
//     supported (see runPresenceBrowserFlow) — fail fast with an actionable error
//     naming the web UI path.
//
//  3. Interactive + no presence="required": the assurance level cannot be raised
//     programmatically; fail with the same actionable error.
//
// This follows the callback-injection shape of OnUnauthorized (api_client.go) — no
// hidden global state, overridable in tests.
package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/mattn/go-isatty"
)

// isTerminalFn is overridable in tests to simulate interactive/non-interactive environments.
var isTerminalFn = func() bool { return isatty.IsTerminal(os.Stdin.Fd()) }

// presenceBrowserFlowFn is overridable in tests to bypass the fail-fast presence path.
var presenceBrowserFlowFn = runPresenceBrowserFlow

// defaultStepUpHandler returns an OnStepUpRequired callback for the given APIClient.
// The returned function parses the WWW-Authenticate header and either performs the
// WebAuthn presence assertion ceremony (interactive TTY) or fails with an actionable
// error (non-interactive or assurance level cannot be raised programmatically).
func defaultStepUpHandler(client *APIClient) func(wwwAuthenticate string) (string, error) {
	return func(wwwAuthenticate string) (string, error) {
		required, presenceRequired := parseStepUpHeader(wwwAuthenticate)

		if !isTerminalFn() {
			return "", fmt.Errorf("step-up required: %s assurance needed for this action; re-run interactively or use an mTLS-authenticated session", required)
		}

		if !presenceRequired {
			// The session assurance level cannot be raised programmatically in the CLI.
			// The operator must log in via the web UI or use an mTLS-authenticated session.
			return "", fmt.Errorf("step-up required: %s assurance needed for this action; log in via the web UI to elevate the session or use an mTLS-authenticated session", required)
		}

		return presenceBrowserFlowFn(client)
	}
}

// parseStepUpHeader extracts the required assurance level and presence flag from a
// WWW-Authenticate header value. Expected format:
//
//	CFGMS-StepUp realm="cfgms", required="strong", presence="required"
//
// Returns ("strong", false) when the header is malformed or required is absent.
func parseStepUpHeader(wwwAuthenticate string) (required string, presenceRequired bool) {
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
		}
	}
	return
}

// errPresenceCeremonyUnsupported is returned by runPresenceBrowserFlow before any
// controller contact. CLI-driven WebAuthn presence assertion is not currently
// supported: a ceremony served from a CLI-local loopback listener can never satisfy a
// configured relying party in any controller configuration — see ADR-021 Amendment 4
// (docs/architecture/decisions/021-identity-assurance-levels.md) for the full case
// analysis. The operator must complete the presence gesture via the controller web UI
// instead.
var errPresenceCeremonyUnsupported = fmt.Errorf(
	"cfg cannot complete the security key presence assertion from the CLI: a browser " +
		"refuses navigator.credentials.get() from a page served at http://127.0.0.1, " +
		"which can never match a configured relying party (ADR-021 Amendment 4). " +
		"Complete this step-up action from the controller web UI instead, where the " +
		"session can satisfy the presence requirement directly")

// runPresenceBrowserFlow is CLI-driven WebAuthn presence assertion. It fails fast,
// before contacting the controller's presence-begin endpoint: no configuration lets a
// CLI-served loopback ceremony satisfy a configured relying party (ADR-021 Amendment 4).
func runPresenceBrowserFlow(client *APIClient) (string, error) {
	return "", errPresenceCeremonyUnsupported
}
