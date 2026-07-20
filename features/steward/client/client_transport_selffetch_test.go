// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
// Tests for the desired_version self-fetch path (Issue #2833): the steward pulls,
// verifies, stages, and swaps to a desired_version binary with no controller push.
package client

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/modules/trust"
)

// selfFetchServerConfig configures the fake controller public binary endpoint.
type selfFetchServerConfig struct {
	content        []byte
	signature      []byte // X-CFGMS-Signature (raw bytes; served base64url)
	sha256Override string // X-CFGMS-SHA256 override; empty = real digest of content
	publisher      string // X-CFGMS-Publisher; empty = "cfgms"
	okTenants      map[string]bool
}

// newSelfFetchServer returns an HTTPS test server serving the steward-binary public GET
// with the signature/publisher/sha headers, honoring per-tenant 200/404 for fallback tests.
func newSelfFetchServer(t *testing.T, cfg selfFetchServerConfig) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenant := r.URL.Query().Get("tenant")
		if cfg.okTenants != nil && !cfg.okTenants[tenant] {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		sha := cfg.sha256Override
		if sha == "" {
			sha = computeSHA256(cfg.content)
		}
		pub := cfg.publisher
		if pub == "" {
			pub = "cfgms"
		}
		w.Header().Set("X-CFGMS-SHA256", sha)
		w.Header().Set("X-CFGMS-Signature", base64.RawURLEncoding.EncodeToString(cfg.signature))
		w.Header().Set("X-CFGMS-Publisher", pub)
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(cfg.content)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(cfg.content)
	}))
}

// selfFetchClient wires a TransportClient for self-fetch tests: injectable HTTPS client,
// trust store, a real (existing) launcher file, and a captured shutdown so no process exits.
func selfFetchClient(t *testing.T, srv *httptest.Server, ts trust.TrustStore) (*TransportClient, *bool) {
	t.Helper()
	host := mustHost(t, srv.URL)
	certStoreDir := t.TempDir()
	fakeLauncher := filepath.Join(certStoreDir, "fake-launcher")
	require.NoError(t, os.WriteFile(fakeLauncher, []byte("fake"), 0o755))

	swapped := new(bool)
	c := minimalClientForUpgradeTest(t, certStoreDir, host, ts, func(_ context.Context, _, _, _ string) error {
		*swapped = true
		return nil
	})
	c.mu.Lock()
	c.transportAddress = host + ":4433"
	c.controllerHTTPSBaseURL = srv.URL
	c.upgradeHTTPClient = srv.Client()
	c.upgradeAllowDowngrade = true
	c.launcherPathOverride = fakeLauncher
	c.shutdownFunc = func() {}
	c.shutdownScheduleFunc = func(_ time.Duration, _ func()) {} // never fire a real exit
	c.mu.Unlock()
	return c, swapped
}

func mustHost(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	require.NoError(t, err)
	return u.Hostname()
}

// TestSelfFetch_HappyPath_PullsVerifiesStagesSwaps is AC5: with a desired_version binary
// published (not pre-staged) the steward fetches, verifies against the baked-in publisher
// over the version-bound composite, stages, and swaps — no controller push.
func TestSelfFetch_HappyPath_PullsVerifiesStagesSwaps(t *testing.T) {
	content := []byte("self-fetched steward binary v99.0.0")
	sha := computeSHA256(content)
	ts, sign := testPublisher(t, "cfgms")
	sig := sign(sha, "v99.0.0") // composite over host platform/arch

	srv := newSelfFetchServer(t, selfFetchServerConfig{
		content: content, signature: sig,
		okTenants: map[string]bool{"test-tenant": true},
	})
	defer srv.Close()

	c, swapped := selfFetchClient(t, srv, ts)

	require.NoError(t, c.selfFetchDesiredVersion(context.Background(), "v99.0.0"))
	assert.True(t, *swapped, "launcher swap must fire on a successful self-fetch")

	c.mu.RLock()
	stagedVer, stagedPath := c.lastStagedVersion, c.lastStagedBinaryPath
	c.mu.RUnlock()
	assert.Equal(t, "v99.0.0", stagedVer)
	require.NotEmpty(t, stagedPath)
	assert.FileExists(t, stagedPath)
}

// TestSelfFetch_TenantFallback covers AC5's own-tenant-404 → default fallback: the binary
// is published only under "default", and the steward (registered to "test-tenant") still
// converges by retrying under default.
func TestSelfFetch_TenantFallback(t *testing.T) {
	content := []byte("fleet-wide default-tenant binary")
	sha := computeSHA256(content)
	ts, sign := testPublisher(t, "cfgms")
	sig := sign(sha, "v99.0.0")

	srv := newSelfFetchServer(t, selfFetchServerConfig{
		content: content, signature: sig,
		okTenants: map[string]bool{"default": true}, // NOT test-tenant
	})
	defer srv.Close()

	c, swapped := selfFetchClient(t, srv, ts)
	require.NoError(t, c.selfFetchDesiredVersion(context.Background(), "v99.0.0"))
	assert.True(t, *swapped, "self-fetch must succeed via the default-tenant fallback")
}

// TestSelfFetch_FailClosedMatrix is AC6: every case must reject, never swap, and leave the
// staged version unchanged. Includes the compromised-controller rollback scenario.
func TestSelfFetch_FailClosedMatrix(t *testing.T) {
	const desired = "v99.0.0"
	hostPlatform, hostArch := runtime.GOOS, runtime.GOARCH

	// Build cases lazily since several need the per-case content/signature.
	type tc struct {
		name  string
		build func(t *testing.T) (*TransportClient, func())
	}
	cases := []tc{
		{
			name: "tampered binary (signature over different bytes)",
			build: func(t *testing.T) (*TransportClient, func()) {
				content := []byte("the real bytes")
				ts, sign := testPublisher(t, "cfgms")
				// Sign a DIFFERENT hash than the served content.
				sig := sign(computeSHA256([]byte("other bytes")), desired)
				srv := newSelfFetchServer(t, selfFetchServerConfig{
					content: content, signature: sig,
					okTenants: map[string]bool{"test-tenant": true},
				})
				c, _ := selfFetchClient(t, srv, ts)
				return c, srv.Close
			},
		},
		{
			name: "publisher header spoofed to attacker",
			build: func(t *testing.T) (*TransportClient, func()) {
				content := []byte("valid bytes")
				sha := computeSHA256(content)
				ts, sign := testPublisher(t, "cfgms")
				sig := sign(sha, desired)
				srv := newSelfFetchServer(t, selfFetchServerConfig{
					content: content, signature: sig, publisher: "attacker",
					okTenants: map[string]bool{"test-tenant": true},
				})
				c, _ := selfFetchClient(t, srv, ts)
				return c, srv.Close
			},
		},
		{
			name: "placeholder-key build rejects every binary",
			build: func(t *testing.T) (*TransportClient, func()) {
				content := []byte("bytes signed by the real dev key")
				sha := computeSHA256(content)
				ts, sign := testPublisher(t, "cfgms")
				sig := sign(sha, desired)
				srv := newSelfFetchServer(t, selfFetchServerConfig{
					content: content, signature: sig,
					okTenants: map[string]bool{"test-tenant": true},
				})
				c, _ := selfFetchClient(t, srv, ts)
				// Swap the trust store for one holding the all-zero placeholder identity.
				placeholder := trust.NewInMemoryTrustStore()
				require.NoError(t, placeholder.AddPublisher(trust.PublisherIdentity{
					Name: "cfgms", PublicKey: make([]byte, ed25519.PublicKeySize), Algorithm: "ed25519",
				}))
				c.mu.Lock()
				c.upgradePublisherTrustStore = placeholder
				c.mu.Unlock()
				return c, srv.Close
			},
		},
		{
			name: "off-host / non-https base URL",
			build: func(t *testing.T) (*TransportClient, func()) {
				content := []byte("valid bytes")
				sha := computeSHA256(content)
				ts, sign := testPublisher(t, "cfgms")
				sig := sign(sha, desired)
				srv := newSelfFetchServer(t, selfFetchServerConfig{
					content: content, signature: sig,
					okTenants: map[string]bool{"test-tenant": true},
				})
				c, _ := selfFetchClient(t, srv, ts)
				// Point the HTTPS base at a DIFFERENT host than the transport endpoint.
				c.mu.Lock()
				c.controllerHTTPSBaseURL = "https://evil.example.com:9080"
				c.mu.Unlock()
				return c, srv.Close
			},
		},
		{
			name: "compromised-controller rollback (old binary + authentic old-version sig at new URL)",
			build: func(t *testing.T) (*TransportClient, func()) {
				// A genuinely-signed OLD binary. The controller serves it at the NEW
				// version's URL and lies in every header it controls to claim the old
				// version. The steward must reject because it composes the verify message
				// from its OWN requested (new) version, not from anything the controller sent.
				oldContent := []byte("old vulnerable binary v1.0.0")
				oldSHA := computeSHA256(oldContent)
				ts, sign := testPublisher(t, "cfgms")
				oldSig := sign(oldSHA, "v1.0.0", hostPlatform, hostArch) // authentic for v1.0.0
				srv := newSelfFetchServer(t, selfFetchServerConfig{
					content: oldContent, signature: oldSig,
					okTenants: map[string]bool{"test-tenant": true},
				})
				c, _ := selfFetchClient(t, srv, ts)
				return c, srv.Close
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			client, cleanup := c.build(t)
			defer cleanup()

			// Track swap via the launcher func already wired in selfFetchClient.
			err := client.selfFetchDesiredVersion(context.Background(), desired)
			require.Error(t, err, "self-fetch must reject")

			client.mu.RLock()
			stagedVer, stagedPath := client.lastStagedVersion, client.lastStagedBinaryPath
			client.mu.RUnlock()
			assert.Empty(t, stagedVer, "no version may be staged on rejection")
			assert.Empty(t, stagedPath, "no binary path may be recorded on rejection")
		})
	}
}

// TestSelfFetch_NotConfigured degrades safe when no HTTPS base is set.
func TestSelfFetch_NotConfigured(t *testing.T) {
	ts, _ := testPublisher(t, "cfgms")
	certStoreDir := t.TempDir()
	c := minimalClientForUpgradeTest(t, certStoreDir, "127.0.0.1", ts, noopSwap)
	// controllerHTTPSBaseURL deliberately left empty.
	err := c.selfFetchDesiredVersion(context.Background(), "v99.0.0")
	require.ErrorIs(t, err, errSelfFetchNotConfigured)
}
