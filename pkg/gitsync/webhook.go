// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package gitsync

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/cfgis/cfgms/pkg/logging"
)

// WebhookHandler handles incoming push-event webhooks (GitHub or GitLab) and
// triggers git-sync for matching scope bindings.
//
// Signature validation: when a binding has a WebhookSecretRef configured, the
// handler validates the X-Hub-Signature-256 header against an HMAC-SHA256 of
// the request body. Requests with an invalid or missing signature are rejected
// with HTTP 401.
type WebhookHandler struct {
	syncer   *Syncer
	bindings *BindingStore
	logger   logging.Logger
	wg       sync.WaitGroup // tracks in-flight background sync goroutines
}

// NewWebhookHandler creates a new WebhookHandler.
func NewWebhookHandler(syncer *Syncer, bindings *BindingStore, logger logging.Logger) *WebhookHandler {
	return &WebhookHandler{
		syncer:   syncer,
		bindings: bindings,
		logger:   logger,
	}
}

// pushPayload is a minimal parse of GitHub / GitLab push-event JSON payloads.
// Both providers include ref and repository clone URLs.
type pushPayload struct {
	Ref        string `json:"ref"`
	Repository struct {
		CloneURL string `json:"clone_url"` // GitHub HTTPS clone URL
		HTTPURL  string `json:"http_url"`  // GitLab HTTPS clone URL
		SSHURL   string `json:"ssh_url"`   // GitHub/GitLab SSH URL
	} `json:"repository"`
}

// ServeHTTP implements http.Handler.
//
// Accepts POST only. Returns:
//   - 202 Accepted — one or more matching bindings found and sync triggered
//   - 204 No Content — no matching bindings
//   - 400 Bad Request — unreadable or unparseable body
//   - 401 Unauthorized — HMAC validation failed
//   - 405 Method Not Allowed — non-POST request
func (h *WebhookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read the body once for HMAC validation and payload parsing.
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1 MiB limit
	if err != nil {
		h.logger.Error("gitsync: failed to read webhook body", "error", err.Error())
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}

	var payload pushPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, "invalid JSON payload", http.StatusBadRequest)
		return
	}

	// Determine pushed branch from the ref field (e.g. "refs/heads/main" → "main").
	branch := strings.TrimPrefix(payload.Ref, "refs/heads/")

	allBindings := h.bindings.List()
	triggered := 0

	for _, b := range allBindings {
		if !matchesOrigin(b.OriginURL,
			payload.Repository.CloneURL,
			payload.Repository.HTTPURL,
			payload.Repository.SSHURL) {
			continue
		}

		bindingBranch := b.Branch
		if bindingBranch == "" {
			bindingBranch = "main"
		}
		if bindingBranch != branch {
			continue
		}

		// Validate HMAC-SHA256 if a webhook secret is configured.
		if b.WebhookSecretRef != "" {
			secret, secretErr := resolveWebhookSecret(b.WebhookSecretRef)
			if secretErr != nil {
				h.logger.Error("gitsync: failed to resolve webhook secret",
					"tenant_path", logging.SanitizeLogValue(b.TenantPath),
					"namespace", logging.SanitizeLogValue(b.Namespace),
					"error", secretErr.Error())
				http.Error(w, "internal error resolving webhook secret", http.StatusInternalServerError)
				return
			}
			sig := r.Header.Get("X-Hub-Signature-256")
			if !validateHMAC(body, sig, secret) {
				h.logger.Warn("gitsync: webhook HMAC validation failed",
					"tenant_path", logging.SanitizeLogValue(b.TenantPath),
					"namespace", logging.SanitizeLogValue(b.Namespace))
				http.Error(w, "invalid or missing signature", http.StatusUnauthorized)
				return
			}
		}

		// Fire sync in the background so the webhook returns quickly.
		bindingCopy := b
		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
			if syncErr := h.syncer.TriggerSync(context.Background(), bindingCopy); syncErr != nil {
				h.logger.Error("gitsync: webhook-triggered sync failed",
					"tenant_path", logging.SanitizeLogValue(bindingCopy.TenantPath),
					"namespace", logging.SanitizeLogValue(bindingCopy.Namespace),
					"error", syncErr.Error())
			}
		}()
		triggered++
	}

	if triggered == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	if _, err := fmt.Fprintf(w, `{"triggered":%d}`, triggered); err != nil {
		h.logger.Error("gitsync: failed to write webhook response", "error", err.Error())
	}
}

// WaitForPendingSyncs blocks until all background sync goroutines dispatched by
// ServeHTTP have completed. This is primarily useful in tests.
func (h *WebhookHandler) WaitForPendingSyncs() {
	h.wg.Wait()
}

// validateHMAC returns true if signature is a valid X-Hub-Signature-256 value
// for the given body and secret.
func validateHMAC(body []byte, signature, secret string) bool {
	if !strings.HasPrefix(signature, "sha256=") {
		return false
	}
	got, err := hex.DecodeString(strings.TrimPrefix(signature, "sha256="))
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := mac.Sum(nil)
	return hmac.Equal(got, expected)
}

// matchesOrigin returns true if bindingURL equals any of the repository URLs
// carried in the push event payload.
func matchesOrigin(bindingURL string, payloadURLs ...string) bool {
	for _, u := range payloadURLs {
		if u != "" && bindingURL == u {
			return true
		}
	}
	return false
}

// resolveWebhookSecret resolves a WebhookSecretRef to its plaintext secret
// value using the same rules as resolveCredentials.
func resolveWebhookSecret(ref string) (string, error) {
	if ref == "" {
		return "", nil
	}
	if strings.HasPrefix(ref, "env:") {
		envVar := strings.TrimPrefix(ref, "env:")
		val := os.Getenv(envVar)
		if val == "" {
			return "", fmt.Errorf("environment variable %s is not set or is empty", envVar)
		}
		return val, nil
	}
	// Treat as file path.
	raw, err := os.ReadFile(ref) // #nosec G304 - admin-supplied secret file path
	if err != nil {
		return "", fmt.Errorf("failed to read webhook secret file %q: %w", ref, err)
	}
	return strings.TrimSpace(string(raw)), nil
}
