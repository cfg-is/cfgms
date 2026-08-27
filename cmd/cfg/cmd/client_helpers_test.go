// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	certbundle "github.com/cfgis/cfgms/pkg/cert/bundle"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMain wires systemBundlePathFn's default (lowest-priority) candidate to a
// generated admin mTLS bundle for the whole cmd test binary. API-key auth was
// removed from the cfg CLI (Issue #3688), so command tests that exercise a real
// get*Client() path now need SOME resolvable credential; most of them don't care
// which one, so a shared "system" bundle keeps every such test from having to wire
// its own. Tests that specifically exercise "no credential is available" override
// systemBundlePathFn (and userConfigDirFn, bundlePath, noBundle, CFGMS_ADMIN_BUNDLE)
// themselves and restore them via t.Cleanup, which shadows this default for their
// duration.
func TestMain(m *testing.M) {
	tmpDir, err := os.MkdirTemp("", "cfg-cmd-test-bundle-*")
	if err != nil {
		panic(err)
	}

	bundleFilePath := filepath.Join(tmpDir, "admin.bundle.yaml")
	b, err := buildTestAdminBundle("https://placeholder.local:9443")
	if err != nil {
		panic(err)
	}
	if err := certbundle.Write(bundleFilePath, b); err != nil {
		panic(err)
	}

	systemBundlePathFn = func() string { return bundleFilePath }

	code := m.Run()
	_ = os.RemoveAll(tmpDir)
	os.Exit(code)
}

func TestNewClientFromFlags_EmptyCACert_SystemPool(t *testing.T) {
	client, err := newClientFromFlags("https://example.com", "", false)
	require.NoError(t, err)
	require.NotNil(t, client)

	transport := client.httpClient.Transport.(*http.Transport)
	assert.Nil(t, transport.TLSClientConfig.RootCAs)
	assert.False(t, transport.TLSClientConfig.InsecureSkipVerify)
}

func TestNewClientFromFlags_Insecure(t *testing.T) {
	client, err := newClientFromFlags("https://example.com", "", true)
	require.NoError(t, err)
	require.NotNil(t, client)

	transport := client.httpClient.Transport.(*http.Transport)
	assert.True(t, transport.TLSClientConfig.InsecureSkipVerify)
}

func TestNewClientFromFlags_ValidCACert(t *testing.T) {
	certPEM := generateTestCACert(t)

	tmpFile, err := os.CreateTemp(t.TempDir(), "ca-cert-*.pem")
	require.NoError(t, err)
	_, err = tmpFile.Write(certPEM)
	require.NoError(t, err)
	require.NoError(t, tmpFile.Close())

	client, err := newClientFromFlags("https://example.com", tmpFile.Name(), false)
	require.NoError(t, err)
	require.NotNil(t, client)

	transport := client.httpClient.Transport.(*http.Transport)
	assert.NotNil(t, transport.TLSClientConfig.RootCAs)
	assert.False(t, transport.TLSClientConfig.InsecureSkipVerify)
}

func TestNewClientFromFlags_MissingCACertFile(t *testing.T) {
	client, err := newClientFromFlags("https://example.com", "/nonexistent/path/ca.pem", false)
	assert.Nil(t, client)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read CA certificate")
}

// TestRequireTLSInsecureForSession covers the session-token confirmation gate
// (AC: --tls-insecure for session token path requires typed confirmation or env var).
func TestRequireTLSInsecureForSession(t *testing.T) {
	// Helper: override test hooks and restore them after each sub-test.
	withHooks := func(t *testing.T, tty bool, input string) *strings.Builder {
		t.Helper()
		var out strings.Builder
		origWriter := tlsInsecureWriter
		origReader := tlsInsecureReader
		origTTY := isTTYFn
		tlsInsecureWriter = &out
		tlsInsecureReader = strings.NewReader(input)
		isTTYFn = func() bool { return tty }
		t.Cleanup(func() {
			tlsInsecureWriter = origWriter
			tlsInsecureReader = origReader
			isTTYFn = origTTY
		})
		return &out
	}

	t.Run("TTY correct phrase succeeds", func(t *testing.T) {
		out := withHooks(t, true, "I understand the risk\n")
		err := requireTLSInsecureForSession()
		require.NoError(t, err)
		assert.Contains(t, out.String(), tlsInsecureSessionWarning)
		assert.Contains(t, out.String(), tlsInsecureConfirmPrompt)
	})

	t.Run("TTY wrong phrase returns error", func(t *testing.T) {
		withHooks(t, true, "yes\n")
		err := requireTLSInsecureForSession()
		require.Error(t, err)
		assert.Contains(t, err.Error(), tlsInsecureConfirmPhrase)
	})

	t.Run("TTY empty input returns error", func(t *testing.T) {
		withHooks(t, true, "\n")
		err := requireTLSInsecureForSession()
		require.Error(t, err)
	})

	t.Run("non-TTY without env var returns error", func(t *testing.T) {
		withHooks(t, false, "")
		t.Setenv("CFGMS_TLS_INSECURE_CONFIRM", "")
		err := requireTLSInsecureForSession()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "CFGMS_TLS_INSECURE_CONFIRM=yes")
	})

	t.Run("non-TTY with CFGMS_TLS_INSECURE_CONFIRM=yes succeeds", func(t *testing.T) {
		out := withHooks(t, false, "")
		t.Setenv("CFGMS_TLS_INSECURE_CONFIRM", "yes")
		err := requireTLSInsecureForSession()
		require.NoError(t, err)
		assert.Contains(t, out.String(), tlsInsecureSessionWarning)
	})

	t.Run("non-TTY with wrong env value returns error", func(t *testing.T) {
		withHooks(t, false, "")
		t.Setenv("CFGMS_TLS_INSECURE_CONFIRM", "true")
		err := requireTLSInsecureForSession()
		require.Error(t, err)
	})
}
