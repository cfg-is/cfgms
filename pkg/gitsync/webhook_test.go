// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package gitsync_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/gitsync"
	"github.com/cfgis/cfgms/pkg/logging"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
	"github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
)

// buildPushPayload returns a JSON push-event payload for the given origin URL
// and ref (e.g. "refs/heads/main").
func buildPushPayload(originURL, ref string) []byte {
	payload := map[string]interface{}{
		"ref": ref,
		"repository": map[string]string{
			"clone_url": originURL,
			"ssh_url":   "",
			"http_url":  "",
		},
	}
	data, _ := json.Marshal(payload)
	return data
}

// hmacSHA256Signature returns the X-Hub-Signature-256 header value for body
// signed with secret.
func hmacSHA256Signature(body []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// webhookTestSetup holds the components of a webhook test fixture.
type webhookTestSetup struct {
	handler  *gitsync.WebhookHandler
	syncer   *gitsync.Syncer
	bindings *gitsync.BindingStore
}

// newWebhookSetup creates a WebhookHandler backed by a real FlatFileConfigStore
// and a BindingStore pre-populated with the given bindings.
func newWebhookSetup(t *testing.T, bs []gitsync.ScopeBinding) *webhookTestSetup {
	t.Helper()
	root := t.TempDir()

	store, err := flatfile.NewFlatFileConfigStore(filepath.Join(root, "configs"))
	require.NoError(t, err)

	bindings, err := gitsync.NewBindingStore(root)
	require.NoError(t, err)

	for _, b := range bs {
		require.NoError(t, bindings.Add(b))
	}

	logger := logging.ForComponent("webhook-test")
	syncer, err := gitsync.NewSyncer(store, bindings, filepath.Join(root, "repos"), logger)
	require.NoError(t, err)

	handler := gitsync.NewWebhookHandler(syncer, bindings, logger)

	// Ensure all background goroutines finish before the test's temp dir is
	// removed, preventing "directory not empty" cleanup failures.
	t.Cleanup(func() { handler.WaitForPendingSyncs(context.Background()) })
	t.Cleanup(syncer.Stop)

	return &webhookTestSetup{handler: handler, syncer: syncer, bindings: bindings}
}

// TestWebhookNoMatchingBinding verifies that a push payload that does not match
// any binding returns HTTP 204.
func TestWebhookNoMatchingBinding(t *testing.T) {
	setup := newWebhookSetup(t, []gitsync.ScopeBinding{
		{
			TenantPath: "root/t1",
			Namespace:  "policies",
			OriginURL:  "https://github.com/org/other-repo.git",
			Branch:     "main",
		},
	})

	body := buildPushPayload("https://github.com/org/different-repo.git", "refs/heads/main")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/git-push", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	setup.handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNoContent, rec.Code)
}

// TestWebhookMatchingBinding verifies that a push payload matching a binding
// (without HMAC validation) returns HTTP 202, and that a background sync is
// dispatched successfully using a local bare repo.
func TestWebhookMatchingBinding(t *testing.T) {
	requireGit(t)

	bareDir, _, _ := newTestRepo(t, map[string]string{
		"policy1.yaml": "key: value\n",
	})

	setup := newWebhookSetup(t, []gitsync.ScopeBinding{
		{
			TenantPath: "root/t1",
			Namespace:  "policies",
			OriginURL:  bareDir,
			Branch:     "main",
		},
	})

	body := buildPushPayload(bareDir, "refs/heads/main")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/git-push", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	setup.handler.ServeHTTP(rec, req)

	// 202 Accepted means TriggerSync was dispatched.
	assert.Equal(t, http.StatusAccepted, rec.Code)

	// Wait for the background sync goroutine to finish.
	setup.handler.WaitForPendingSyncs(context.Background())
}

// TestWebhookBranchMismatch verifies that a push to a different branch than the
// configured binding returns HTTP 204 (no match).
func TestWebhookBranchMismatch(t *testing.T) {
	const originURL = "https://github.com/org/cfgms-configs.git"
	setup := newWebhookSetup(t, []gitsync.ScopeBinding{
		{
			TenantPath: "root/t1",
			Namespace:  "policies",
			OriginURL:  originURL,
			Branch:     "main",
		},
	})

	// Payload for a push to the "feature/foo" branch.
	body := buildPushPayload(originURL, "refs/heads/feature/foo")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/git-push", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	setup.handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNoContent, rec.Code)
}

// TestWebhookValidHMAC verifies that a request with a valid HMAC-SHA256
// signature is accepted (HTTP 202) when the binding has WebhookSecretRef set.
func TestWebhookValidHMAC(t *testing.T) {
	requireGit(t)

	const secret = "super-secret-webhook-token"
	bareDir, _, _ := newTestRepo(t, map[string]string{
		"policy1.yaml": "key: value\n",
	})

	// Write the secret to a temp file so WebhookSecretRef resolves it.
	secretFile := filepath.Join(t.TempDir(), "webhook-secret.txt")
	require.NoError(t, os.WriteFile(secretFile, []byte(secret), 0600))

	setup := newWebhookSetup(t, []gitsync.ScopeBinding{
		{
			TenantPath:       "root/t1",
			Namespace:        "policies",
			OriginURL:        bareDir,
			Branch:           "main",
			WebhookSecretRef: secretFile,
		},
	})

	body := buildPushPayload(bareDir, "refs/heads/main")
	sig := hmacSHA256Signature(body, secret)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/git-push", bytes.NewReader(body))
	req.Header.Set("X-Hub-Signature-256", sig)
	rec := httptest.NewRecorder()
	setup.handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusAccepted, rec.Code)

	// Wait for the background sync goroutine.
	setup.handler.WaitForPendingSyncs(context.Background())
}

// TestWebhookInvalidHMAC verifies that a request with an invalid HMAC-SHA256
// signature is rejected with HTTP 401.
func TestWebhookInvalidHMAC(t *testing.T) {
	const (
		originURL = "https://github.com/org/cfgms-configs.git"
		secret    = "super-secret-webhook-token"
	)

	secretFile := filepath.Join(t.TempDir(), "webhook-secret.txt")
	require.NoError(t, os.WriteFile(secretFile, []byte(secret), 0600))

	setup := newWebhookSetup(t, []gitsync.ScopeBinding{
		{
			TenantPath:       "root/t1",
			Namespace:        "policies",
			OriginURL:        originURL,
			Branch:           "main",
			WebhookSecretRef: secretFile,
		},
	})

	body := buildPushPayload(originURL, "refs/heads/main")

	// Use a wrong secret to generate a bad signature.
	badSig := hmacSHA256Signature(body, "wrong-secret")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/git-push", bytes.NewReader(body))
	req.Header.Set("X-Hub-Signature-256", badSig)
	rec := httptest.NewRecorder()
	setup.handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// TestWebhookMissingSignatureWhenRequired verifies that a request without a
// signature header is rejected with HTTP 401 when the binding has a webhook
// secret configured.
func TestWebhookMissingSignatureWhenRequired(t *testing.T) {
	const (
		originURL = "https://github.com/org/cfgms-configs.git"
		secret    = "super-secret-webhook-token"
	)

	secretFile := filepath.Join(t.TempDir(), "webhook-secret.txt")
	require.NoError(t, os.WriteFile(secretFile, []byte(secret), 0600))

	setup := newWebhookSetup(t, []gitsync.ScopeBinding{
		{
			TenantPath:       "root/t1",
			Namespace:        "policies",
			OriginURL:        originURL,
			Branch:           "main",
			WebhookSecretRef: secretFile,
		},
	})

	body := buildPushPayload(originURL, "refs/heads/main")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/git-push", bytes.NewReader(body))
	// No X-Hub-Signature-256 header.
	rec := httptest.NewRecorder()
	setup.handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// TestWebhookMethodNotAllowed verifies that non-POST requests return HTTP 405.
func TestWebhookMethodNotAllowed(t *testing.T) {
	setup := newWebhookSetup(t, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/webhooks/git-push", nil)
	rec := httptest.NewRecorder()
	setup.handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// TestWebhookInvalidJSON verifies that a request with a non-JSON body returns
// HTTP 400.
func TestWebhookInvalidJSON(t *testing.T) {
	setup := newWebhookSetup(t, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/git-push",
		bytes.NewReader([]byte("not json")))
	rec := httptest.NewRecorder()
	setup.handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestWebhookHMACFailureRejectsEntireRequest verifies that when multiple
// bindings match a push event but any one of them fails HMAC validation, the
// handler returns HTTP 401 — not HTTP 202. This guards against a future
// contributor changing the early return to a continue, which would cause the
// handler to return 202 Accepted even when some bindings' HMAC checks fail.
func TestWebhookHMACFailureRejectsEntireRequest(t *testing.T) {
	const (
		originURL = "https://github.com/org/cfgms-configs.git"
		secretA   = "secret-for-binding-a"
		secretB   = "secret-for-binding-b"
	)

	tmpDir := t.TempDir()
	secretFileA := filepath.Join(tmpDir, "secret-a.txt")
	secretFileB := filepath.Join(tmpDir, "secret-b.txt")
	require.NoError(t, os.WriteFile(secretFileA, []byte(secretA), 0600))
	require.NoError(t, os.WriteFile(secretFileB, []byte(secretB), 0600))

	setup := newWebhookSetup(t, []gitsync.ScopeBinding{
		{
			TenantPath:       "root/t1",
			Namespace:        "ns1",
			OriginURL:        originURL,
			Branch:           "main",
			WebhookSecretRef: secretFileA,
		},
		{
			TenantPath:       "root/t2",
			Namespace:        "ns2",
			OriginURL:        originURL,
			Branch:           "main",
			WebhookSecretRef: secretFileB,
		},
	})

	body := buildPushPayload(originURL, "refs/heads/main")
	// Sign only with secretA — binding B's check will fail.
	sig := hmacSHA256Signature(body, secretA)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/git-push", bytes.NewReader(body))
	req.Header.Set("X-Hub-Signature-256", sig)
	rec := httptest.NewRecorder()
	setup.handler.ServeHTTP(rec, req)

	// HTTP 401 is the expected response when any binding fails HMAC,
	// regardless of which other bindings may have passed validation.
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// TestWebhookEnvVarHMAC verifies that WebhookSecretRef with "env:" prefix
// resolves the secret from an environment variable.
func TestWebhookEnvVarHMAC(t *testing.T) {
	requireGit(t)

	const (
		envVar = "CFGMS_TEST_WEBHOOK_SECRET_XYZ"
		secret = "env-var-secret"
	)
	t.Setenv(envVar, secret)

	bareDir, _, _ := newTestRepo(t, map[string]string{
		"policy1.yaml": "key: value\n",
	})

	setup := newWebhookSetup(t, []gitsync.ScopeBinding{
		{
			TenantPath:       "root/t1",
			Namespace:        "policies",
			OriginURL:        bareDir,
			Branch:           "main",
			WebhookSecretRef: "env:" + envVar,
		},
	})

	body := buildPushPayload(bareDir, "refs/heads/main")
	sig := hmacSHA256Signature(body, secret)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/git-push", bytes.NewReader(body))
	req.Header.Set("X-Hub-Signature-256", sig)
	rec := httptest.NewRecorder()
	setup.handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusAccepted, rec.Code)

	// Wait for the background sync goroutine.
	setup.handler.WaitForPendingSyncs(context.Background())
}

// TestWebhookWaitForPendingSyncsDrainsBeforeDeadline verifies that
// WaitForPendingSyncs returns before its context deadline when a
// webhook-triggered background sync completes in time, and that the sync
// result is visible in the config store after the drain. This mirrors the
// shutdown drain that Stop() performs before closing storage (Issue #681).
func TestWebhookWaitForPendingSyncsDrainsBeforeDeadline(t *testing.T) {
	requireGit(t)

	bareDir, _, _ := newTestRepo(t, map[string]string{
		"policy1.yaml": "key: value\n",
	})

	// Build components directly so the store is accessible for result verification.
	root := t.TempDir()
	store, err := flatfile.NewFlatFileConfigStore(filepath.Join(root, "configs"))
	require.NoError(t, err)

	bindings, err := gitsync.NewBindingStore(root)
	require.NoError(t, err)

	binding := gitsync.ScopeBinding{
		TenantPath: "root/t1",
		Namespace:  "policies",
		OriginURL:  bareDir,
		Branch:     "main",
	}
	require.NoError(t, bindings.Add(binding))

	logger := logging.ForComponent("webhook-test")
	syncer, err := gitsync.NewSyncer(store, bindings, filepath.Join(root, "repos"), logger)
	require.NoError(t, err)
	t.Cleanup(syncer.Stop)

	handler := gitsync.NewWebhookHandler(syncer, bindings, logger)
	t.Cleanup(func() { handler.WaitForPendingSyncs(context.Background()) })

	body := buildPushPayload(bareDir, "refs/heads/main")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/git-push", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusAccepted, rec.Code, "expected 202 Accepted when a binding matches")

	// Drain with a 5-second deadline — a local bare-repo clone + import finishes
	// well within this window even on a loaded CI runner. Context expiry here
	// means the drain did NOT complete, which is exactly the race this fix
	// prevents (writes to closed storage on shutdown).
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	handler.WaitForPendingSyncs(ctx)

	assert.NoError(t, ctx.Err(), "WaitForPendingSyncs timed out: in-flight sync did not complete before deadline")

	// Confirm the sync result is visible in the store — proves the drain
	// completed with data written, not merely that the goroutine exited.
	entry, storeErr := store.GetConfig(context.Background(), &cfgconfig.ConfigKey{
		TenantID:  "root/t1",
		Namespace: "policies",
		Name:      "policy1",
	})
	require.NoError(t, storeErr, "config store must contain the synced entry after drain")
	assert.Equal(t, "key: value\n", string(entry.Data))
}
