// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInstallerDownloadURL(t *testing.T) {
	t.Run("constructs correct URL for darwin arm64", func(t *testing.T) {
		origURL := installerAPIURL
		origPlatform := installerPlatform
		origArch := installerArch
		t.Cleanup(func() {
			installerAPIURL = origURL
			installerPlatform = origPlatform
			installerArch = origArch
		})

		installerAPIURL = "https://ctrl.example.com:9080"
		installerPlatform = "darwin"
		installerArch = "arm64"

		output := captureStdout(t, func() {
			err := runInstallerDownloadURL(installerDownloadURLCmd, []string{})
			require.NoError(t, err)
		})

		assert.Equal(t, "https://ctrl.example.com:9080/api/v1/installer/download/darwin/arm64\n", output)
	})

	t.Run("constructs correct URL for windows amd64", func(t *testing.T) {
		origURL := installerAPIURL
		origPlatform := installerPlatform
		origArch := installerArch
		t.Cleanup(func() {
			installerAPIURL = origURL
			installerPlatform = origPlatform
			installerArch = origArch
		})

		installerAPIURL = "https://controller.myorg.com"
		installerPlatform = "windows"
		installerArch = "amd64"

		output := captureStdout(t, func() {
			err := runInstallerDownloadURL(installerDownloadURLCmd, []string{})
			require.NoError(t, err)
		})

		assert.Equal(t, "https://controller.myorg.com/api/v1/installer/download/windows/amd64\n", output)
	})

	t.Run("rejects unknown platform", func(t *testing.T) {
		origPlatform := installerPlatform
		origArch := installerArch
		t.Cleanup(func() {
			installerPlatform = origPlatform
			installerArch = origArch
		})

		installerPlatform = "haiku"
		installerArch = "amd64"

		err := runInstallerDownloadURL(installerDownloadURLCmd, []string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown platform")
		assert.Contains(t, err.Error(), "haiku")
	})

	t.Run("rejects unknown arch", func(t *testing.T) {
		origPlatform := installerPlatform
		origArch := installerArch
		t.Cleanup(func() {
			installerPlatform = origPlatform
			installerArch = origArch
		})

		installerPlatform = "linux"
		installerArch = "mips64"

		err := runInstallerDownloadURL(installerDownloadURLCmd, []string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown arch")
		assert.Contains(t, err.Error(), "mips64")
	})

	t.Run("uses env var for controller URL when flag not set", func(t *testing.T) {
		origURL := installerAPIURL
		origPlatform := installerPlatform
		origArch := installerArch
		t.Cleanup(func() {
			installerAPIURL = origURL
			installerPlatform = origPlatform
			installerArch = origArch
			require.NoError(t, os.Unsetenv("CFGMS_API_URL"))
		})

		installerAPIURL = ""
		installerPlatform = "linux"
		installerArch = "amd64"
		require.NoError(t, os.Setenv("CFGMS_API_URL", "https://env.controller.com"))

		output := captureStdout(t, func() {
			err := runInstallerDownloadURL(installerDownloadURLCmd, []string{})
			require.NoError(t, err)
		})

		assert.Equal(t, "https://env.controller.com/api/v1/installer/download/linux/amd64\n", output)
	})
}

// TestInstallerDownloadURLMethod tests the APIClient.InstallerDownloadURL helper directly.
func TestInstallerDownloadURLMethod(t *testing.T) {
	t.Run("returns correct URL from base URL", func(t *testing.T) {
		client := &APIClient{baseURL: "https://ctrl.example.com:9080"}
		got := client.InstallerDownloadURL("linux", "amd64")
		assert.Equal(t, "https://ctrl.example.com:9080/api/v1/installer/download/linux/amd64", got)
	})

	t.Run("strips trailing slash from base URL", func(t *testing.T) {
		client := &APIClient{baseURL: "https://ctrl.example.com/"}
		got := client.InstallerDownloadURL("darwin", "arm64")
		assert.Equal(t, "https://ctrl.example.com/api/v1/installer/download/darwin/arm64", got)
	})
}

func TestInstallerUpload(t *testing.T) {
	t.Run("rejects unknown platform before HTTP call", func(t *testing.T) {
		origPlatform := installerPlatform
		origArch := installerArch
		t.Cleanup(func() {
			installerPlatform = origPlatform
			installerArch = origArch
		})

		installerPlatform = "freebsd"
		installerArch = "amd64"

		f, err := os.CreateTemp(t.TempDir(), "installer-*.exe")
		require.NoError(t, err)
		_, _ = f.WriteString("fake installer content")
		require.NoError(t, f.Close())

		callCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callCount++
		}))
		defer server.Close()

		origURL := installerAPIURL
		t.Cleanup(func() { installerAPIURL = origURL })
		installerAPIURL = server.URL

		err = runInstallerUpload(installerUploadCmd, []string{f.Name()})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown platform")
		assert.Equal(t, 0, callCount, "HTTP call must not be made for invalid platform")
	})

	t.Run("rejects unknown arch before HTTP call", func(t *testing.T) {
		origPlatform := installerPlatform
		origArch := installerArch
		t.Cleanup(func() {
			installerPlatform = origPlatform
			installerArch = origArch
		})

		installerPlatform = "windows"
		installerArch = "riscv64"

		f, err := os.CreateTemp(t.TempDir(), "installer-*.exe")
		require.NoError(t, err)
		_, _ = f.WriteString("fake installer content")
		require.NoError(t, f.Close())

		callCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callCount++
		}))
		defer server.Close()

		origURL := installerAPIURL
		t.Cleanup(func() { installerAPIURL = origURL })
		installerAPIURL = server.URL

		err = runInstallerUpload(installerUploadCmd, []string{f.Name()})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown arch")
		assert.Equal(t, 0, callCount, "HTTP call must not be made for invalid arch")
	})

	t.Run("rejects missing file", func(t *testing.T) {
		origPlatform := installerPlatform
		origArch := installerArch
		t.Cleanup(func() {
			installerPlatform = origPlatform
			installerArch = origArch
		})

		installerPlatform = "linux"
		installerArch = "amd64"

		err := runInstallerUpload(installerUploadCmd, []string{"/nonexistent/path/installer.bin"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("rejects empty file", func(t *testing.T) {
		origPlatform := installerPlatform
		origArch := installerArch
		t.Cleanup(func() {
			installerPlatform = origPlatform
			installerArch = origArch
		})

		installerPlatform = "linux"
		installerArch = "amd64"

		emptyFile := filepath.Join(t.TempDir(), "empty.bin")
		require.NoError(t, os.WriteFile(emptyFile, []byte{}, 0600))

		err := runInstallerUpload(installerUploadCmd, []string{emptyFile})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty")
	})

	t.Run("streams file and prints confirmation on success", func(t *testing.T) {
		origPlatform := installerPlatform
		origArch := installerArch
		origURL := installerAPIURL
		origNoBundle := noBundle
		t.Cleanup(func() {
			installerPlatform = origPlatform
			installerArch = origArch
			installerAPIURL = origURL
			noBundle = origNoBundle
		})

		installerPlatform = "windows"
		installerArch = "amd64"

		fileContent := strings.Repeat("x", 1024)
		f, err := os.CreateTemp(t.TempDir(), "installer-*.exe")
		require.NoError(t, err)
		_, _ = f.WriteString(fileContent)
		require.NoError(t, f.Close())

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "PUT", r.Method)
			assert.Equal(t, "/api/v1/installer/artifacts/windows/amd64", r.URL.Path)
			assert.Equal(t, "application/octet-stream", r.Header.Get("Content-Type"))

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"platform": "windows",
					"arch":     "amd64",
					"size":     int64(len(fileContent)),
					"checksum": "sha256:abc123def456",
				},
				"timestamp": "2026-05-28T00:00:00Z",
			})
		}))
		defer server.Close()

		installerAPIURL = server.URL

		output := captureStdout(t, func() {
			err := runInstallerUpload(installerUploadCmd, []string{f.Name()})
			require.NoError(t, err)
		})

		assert.Contains(t, output, "windows/amd64")
		assert.Contains(t, output, "1024")
		assert.Contains(t, output, "abc123def456")
	})

	t.Run("returns error on server failure", func(t *testing.T) {
		origPlatform := installerPlatform
		origArch := installerArch
		origURL := installerAPIURL
		origNoBundle := noBundle
		t.Cleanup(func() {
			installerPlatform = origPlatform
			installerArch = origArch
			installerAPIURL = origURL
			noBundle = origNoBundle
		})

		installerPlatform = "linux"
		installerArch = "amd64"

		f, err := os.CreateTemp(t.TempDir(), "installer-*.bin")
		require.NoError(t, err)
		_, _ = f.WriteString("content")
		require.NoError(t, f.Close())

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"error": "storage backend unavailable",
			})
		}))
		defer server.Close()

		installerAPIURL = server.URL

		err = runInstallerUpload(installerUploadCmd, []string{f.Name()})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "storage backend unavailable")
	})

	t.Run("verifies correct request path for darwin arm64", func(t *testing.T) {
		origPlatform := installerPlatform
		origArch := installerArch
		origURL := installerAPIURL
		origNoBundle := noBundle
		t.Cleanup(func() {
			installerPlatform = origPlatform
			installerArch = origArch
			installerAPIURL = origURL
			noBundle = origNoBundle
		})

		installerPlatform = "darwin"
		installerArch = "arm64"

		dir := t.TempDir()
		installerPath := filepath.Join(dir, "cfgms-steward-darwin-arm64.pkg")
		require.NoError(t, os.WriteFile(installerPath, []byte("pkg content"), 0600))

		var receivedPath string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedPath = r.URL.Path
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"platform": "darwin",
					"arch":     "arm64",
					"size":     int64(11),
					"checksum": "sha256:deadbeef",
				},
				"timestamp": "2026-05-28T00:00:00Z",
			})
		}))
		defer server.Close()

		installerAPIURL = server.URL

		output := captureStdout(t, func() {
			err := runInstallerUpload(installerUploadCmd, []string{installerPath})
			require.NoError(t, err)
		})

		assert.Equal(t, "/api/v1/installer/artifacts/darwin/arm64", receivedPath)
		assert.Contains(t, output, "darwin/arm64")
	})
}

// ---- Publish subcommand tests ----

// TestPublishCLI_RequiresPlatformAndArch verifies that cfg installer publish returns a usage
// error before making any HTTP call when --platform or --arch is absent.
func TestPublishCLI_RequiresPlatformAndArch(t *testing.T) {
	// resetPublishFlags restores package-level flag vars after each sub-test.
	resetPublishFlags := func(t *testing.T) {
		t.Helper()
		t.Cleanup(func() {
			publishKind = ""
			publishVersion = ""
			installerPlatform = ""
			installerArch = ""
			publishBinary = ""
			publishSignature = ""
			publishForce = false
			installerAPIURL = ""
			noBundle = false
		})
	}

	t.Run("rejects missing platform", func(t *testing.T) {
		resetPublishFlags(t)
		noBundle = true
		publishKind = "steward"
		publishVersion = "v1.0.0"
		installerPlatform = "" // omitted
		installerArch = "amd64"
		publishBinary = "somefile"
		publishSignature = "somefile.sig"

		err := runInstallerPublish(installerPublishCmd, []string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown platform")
	})

	t.Run("rejects missing arch", func(t *testing.T) {
		resetPublishFlags(t)
		noBundle = true
		publishKind = "steward"
		publishVersion = "v1.0.0"
		installerPlatform = "linux"
		installerArch = "" // omitted
		publishBinary = "somefile"
		publishSignature = "somefile.sig"

		err := runInstallerPublish(installerPublishCmd, []string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown arch")
	})

	t.Run("rejects unknown kind", func(t *testing.T) {
		resetPublishFlags(t)
		noBundle = true
		publishKind = "outpost" // invalid kind
		publishVersion = "v1.0.0"
		installerPlatform = "linux"
		installerArch = "amd64"

		err := runInstallerPublish(installerPublishCmd, []string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--kind")
	})

	t.Run("rejects missing binary file", func(t *testing.T) {
		resetPublishFlags(t)
		noBundle = true
		publishKind = "steward"
		publishVersion = "v1.0.0"
		installerPlatform = "linux"
		installerArch = "amd64"
		publishBinary = "/nonexistent/path/binary"
		publishSignature = "somefile.sig"

		err := runInstallerPublish(installerPublishCmd, []string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "binary file not found")
	})
}

// TestPublishCLI_SuccessfulPublish verifies that a valid publish call sends the correct request
// and prints the expected output.
func TestPublishCLI_SuccessfulPublish(t *testing.T) {
	// Generate a real Ed25519 key pair for signing.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	_ = pub

	binaryContent := []byte("cfgms-steward-test-binary")

	// Create temporary binary and signature files.
	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "cfgms-steward")
	require.NoError(t, os.WriteFile(binaryPath, binaryContent, 0600))

	// Sign: Ed25519 over the SHA-256 hex of the binary content.
	sum := sha256.Sum256(binaryContent)
	hash := hex.EncodeToString(sum[:])
	sig := ed25519.Sign(priv, []byte(hash))
	sigPath := filepath.Join(dir, "cfgms-steward.sig")
	require.NoError(t, os.WriteFile(sigPath, sig, 0600))

	// Save and restore flag state.
	origKind := publishKind
	origVersion := publishVersion
	origPlatform := installerPlatform
	origArch := installerArch
	origBinary := publishBinary
	origSig := publishSignature
	origURL := installerAPIURL
	origNoBundle := noBundle
	t.Cleanup(func() {
		publishKind = origKind
		publishVersion = origVersion
		installerPlatform = origPlatform
		installerArch = origArch
		publishBinary = origBinary
		publishSignature = origSig
		installerAPIURL = origURL
		noBundle = origNoBundle
	})

	publishKind = "steward"
	publishVersion = "v1.2.3"
	installerPlatform = "linux"
	installerArch = "amd64"
	publishBinary = binaryPath
	publishSignature = sigPath

	var receivedPath string
	var receivedSigHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		receivedSigHeader = r.URL.Query().Get("signature")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"version":          "v1.2.3",
				"platform":         "linux",
				"arch":             "amd64",
				"size":             int64(len(binaryContent)),
				"sha256":           "sha256:abc123",
				"published_by":     "admin@example.com",
				"publisher":        "cfgms",
				"signature_digest": "deadbeef",
			},
		})
	}))
	defer server.Close()
	installerAPIURL = server.URL

	output := captureStdout(t, func() {
		err := runInstallerPublish(installerPublishCmd, []string{})
		require.NoError(t, err)
	})

	assert.Equal(t, "/api/v1/installer/steward-binaries/v1.2.3/linux/amd64", receivedPath)
	assert.NotEmpty(t, receivedSigHeader, "signature query param must be sent")
	// Verify the signature is valid URL-safe base64 (no padding).
	_, decErr := base64.RawURLEncoding.DecodeString(receivedSigHeader)
	assert.NoError(t, decErr, "signature must be valid URL-safe base64")

	assert.Contains(t, output, "v1.2.3")
	assert.Contains(t, output, "linux/amd64")
	assert.Contains(t, output, "admin@example.com")
}

// TestPublishCLI_DuplicateReturns409 verifies that a 409 response from the server
// results in an error returned to the caller (no silent swallow).
func TestPublishCLI_DuplicateReturns409(t *testing.T) {
	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "cfgms-steward")
	require.NoError(t, os.WriteFile(binaryPath, []byte("content"), 0600))
	sigPath := filepath.Join(dir, "cfgms-steward.sig")
	require.NoError(t, os.WriteFile(sigPath, bytes.Repeat([]byte{0}, 64), 0600))

	origKind := publishKind
	origVersion := publishVersion
	origPlatform := installerPlatform
	origArch := installerArch
	origBinary := publishBinary
	origSig := publishSignature
	origURL := installerAPIURL
	origNoBundle := noBundle
	t.Cleanup(func() {
		publishKind = origKind
		publishVersion = origVersion
		installerPlatform = origPlatform
		installerArch = origArch
		publishBinary = origBinary
		publishSignature = origSig
		installerAPIURL = origURL
		noBundle = origNoBundle
	})

	publishKind = "steward"
	publishVersion = "v1.0.0"
	installerPlatform = "linux"
	installerArch = "amd64"
	publishBinary = binaryPath
	publishSignature = sigPath

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error":   "DUPLICATE_BINARY",
			"message": "Steward binary already exists; use --force to overwrite",
		})
	}))
	defer server.Close()
	installerAPIURL = server.URL

	err := runInstallerPublish(installerPublishCmd, []string{})
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "409") || strings.Contains(err.Error(), "DUPLICATE") || strings.Contains(err.Error(), "Conflict"),
		"expected 409/conflict in error: %v", err)
}
