// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
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
		noBundle = true

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
		noBundle = true

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
		noBundle = true

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
