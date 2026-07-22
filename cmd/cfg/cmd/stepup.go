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
//  2. Interactive + presence="required": open the default browser to a local relay
//     page, wait for the WebAuthn assertion ceremony to complete, obtain a single-use
//     presence token from the controller, and return it so the caller can retry the
//     original request with X-Presence-Token.
//
//  3. Interactive + no presence="required": the assurance level cannot be raised
//     programmatically; fail with the same actionable error.
//
// This follows the callback-injection shape of OnUnauthorized (api_client.go) — no
// hidden global state, overridable in tests.
package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/mattn/go-isatty"
)

const (
	stepUpPresenceTimeout = 5 * time.Minute
)

// isTerminalFn is overridable in tests to simulate interactive/non-interactive environments.
var isTerminalFn = func() bool { return isatty.IsTerminal(os.Stdin.Fd()) }

// presenceBrowserFlowFn is overridable in tests to avoid launching a real browser.
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

		// Interactive + presence required: run the WebAuthn assertion ceremony via browser relay.
		_, _ = fmt.Fprintln(os.Stderr, "Security key required — opening browser for presence assertion...")
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

// runPresenceBrowserFlow starts a local relay HTTP server, opens the default browser,
// waits for the WebAuthn assertion ceremony to complete, and returns the single-use
// presence token obtained from the controller.
func runPresenceBrowserFlow(client *APIClient) (string, error) {
	ctx := context.Background()

	assertionOptions, err := client.WebAuthnPresenceBegin(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to begin presence ceremony: %w", err)
	}

	assertionJSON, err := assertionOptions.MarshalJSON()
	if err != nil {
		return "", fmt.Errorf("failed to marshal assertion options: %w", err)
	}
	// HTML-escape the JSON before embedding in a <script> block.
	// json.HTMLEscape converts <, >, &, and / to \uXXXX, preventing script-context breakout
	// if a malformed or MITM'd controller embeds </script> in a string field.
	var escapedJSON bytes.Buffer
	json.HTMLEscape(&escapedJSON, assertionJSON)

	credResponseJSON, err := runPresenceRelayServer(os.Stderr, escapedJSON.Bytes(), stepUpPresenceTimeout)
	if err != nil {
		return "", fmt.Errorf("presence ceremony failed: %w", err)
	}

	token, err := client.WebAuthnPresenceFinish(ctx, credResponseJSON)
	if err != nil {
		return "", fmt.Errorf("failed to finish presence ceremony: %w", err)
	}
	return token, nil
}

// runPresenceRelayServer starts a local HTTP relay for the WebAuthn assertion ceremony.
// It listens on a random localhost port, opens the browser to the relay page, and waits
// for the browser to POST the assertion response. Returns the raw assertion JSON.
func runPresenceRelayServer(out io.Writer, assertionOptionsJSON []byte, timeout time.Duration) ([]byte, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("failed to start local relay server: %w", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port //nolint:forcetypeassert // net "tcp" listener Addr() is always *net.TCPAddr

	var (
		resultMu sync.Mutex
		result   []byte
		relayErr error
		resultCh = make(chan struct{}, 1)
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/presence", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprintf(w, stepUpPresenceRelayHTML, string(assertionOptionsJSON))
	})
	mux.HandleFunc("/done", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64*1024) // WebAuthn assertion responses are always small
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

	relayURL := fmt.Sprintf("http://127.0.0.1:%d/presence", port)
	_, _ = fmt.Fprintf(out, "\nOpen this URL in your browser to complete the security key assertion:\n  %s\n\n", relayURL)
	_, _ = fmt.Fprintf(out, "Waiting for browser ceremony (timeout: %s)...\n", timeout)

	_ = openBrowser(relayURL)

	select {
	case <-resultCh:
	case <-time.After(timeout):
		return nil, fmt.Errorf("timed out waiting for browser to complete security key assertion")
	}

	resultMu.Lock()
	defer resultMu.Unlock()
	if relayErr != nil {
		return nil, fmt.Errorf("relay error: %w", relayErr)
	}
	return result, nil
}

// stepUpPresenceRelayHTML is the single-page relay UI for the WebAuthn assertion ceremony.
// %s is replaced with the JSON-encoded PublicKeyCredentialRequestOptions.
const stepUpPresenceRelayHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CFGMS Security Key — Presence Assertion</title>
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
  <h1>CFGMS Security Key Required</h1>
  <p>Touch your security key to authorize this action.</p>
  <button id="btn" onclick="assertPresence()">Touch Security Key</button>
  <p id="status">Ready.</p>
  <script>
    const requestOptions = %s;

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
      if (pk.allowCredentials) {
        pk.allowCredentials = pk.allowCredentials.map(c => ({...c, id: b64decode(c.id)}));
      }
      return opts;
    }

    async function assertPresence() {
      const btn = document.getElementById('btn');
      const status = document.getElementById('status');
      btn.disabled = true;
      status.className = '';
      status.textContent = 'Activating authenticator — touch your security key...';
      try {
        const opts = prepareOptions(JSON.parse(JSON.stringify(requestOptions)));
        const cred = await navigator.credentials.get(opts);
        status.textContent = 'Sending result to cfg CLI...';
        const body = JSON.stringify({
          id: cred.id,
          rawId: b64encode(cred.rawId),
          type: cred.type,
          response: {
            clientDataJSON: b64encode(cred.response.clientDataJSON),
            authenticatorData: b64encode(cred.response.authenticatorData),
            signature: b64encode(cred.response.signature),
            userHandle: cred.response.userHandle ? b64encode(cred.response.userHandle) : null,
          }
        });
        const res = await fetch('/done', {method:'POST', headers:{'Content-Type':'application/json'}, body});
        if (res.ok) {
          status.className = 'success';
          status.textContent = 'Done! You may close this tab.';
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
