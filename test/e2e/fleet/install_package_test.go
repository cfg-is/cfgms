// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package fleet

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	fleetControllerHTTP = "https://localhost:8090"
	installerAPIKey     = "installer-test-key"
	installPrefix       = "/tmp/install-test"
	installWorkDir      = "/tmp/install-work"
)

// insecureHTTPClient returns an HTTP client that skips TLS verification.
// Used for testing against the fleet controller's self-signed certificate.
func insecureHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test-only: fleet controller uses a self-signed CA
		},
		Timeout: 30 * time.Second,
	}
}

// TestFleetInstallPackageFlow exercises the full install-package lifecycle:
// upload → download → archive verification → install.sh execution → steward registration.
//
// Requires: docker compose --profile fleet -f docker-compose.test.yml up -d
// and a healthy fleet-controller (CFGMS_API_KEY_INSTALLER=installer-test-key seeded).
func TestFleetInstallPackageFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping fleet install package test in short mode — requires Docker fleet infrastructure")
	}

	client := insecureHTTPClient()

	// Wait for fleet-controller API to be ready.
	waitForControllerAPI(t, client)

	// ── Step 1: obtain the steward binary from fleet-steward-1 ──────────────────

	binaryData := extractBinaryFromContainer(t, "fleet-steward-1", "/app/steward")

	// ── Step 2: upload the binary to the controller ──────────────────────────────

	uploadReq, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPut,
		fleetControllerHTTP+"/api/v1/installer/artifacts/linux/amd64",
		bytes.NewReader(binaryData),
	)
	require.NoError(t, err)
	uploadReq.Header.Set("X-API-Key", installerAPIKey)

	uploadResp, err := client.Do(uploadReq)
	require.NoError(t, err)
	defer func() { _ = uploadResp.Body.Close() }()
	require.Equal(t, http.StatusOK, uploadResp.StatusCode, "upload must return 200")

	// ── Step 3: download the install package ────────────────────────────────────

	dlReq, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		fleetControllerHTTP+"/api/v1/installer/download/linux/amd64",
		nil,
	)
	require.NoError(t, err)

	dlResp, err := client.Do(dlReq)
	require.NoError(t, err)
	defer func() { _ = dlResp.Body.Close() }()
	require.Equal(t, http.StatusOK, dlResp.StatusCode, "download must return 200")

	archiveData, err := io.ReadAll(dlResp.Body)
	require.NoError(t, err)
	require.NotEmpty(t, archiveData, "downloaded archive must not be empty")

	// ── Step 4: verify archive contents ─────────────────────────────────────────

	caCertPEM, caFingerprintRaw := verifyInstallArchive(t, archiveData)
	caFingerprint := strings.TrimSpace(string(caFingerprintRaw))
	require.NotEmpty(t, caFingerprint, "ca.fingerprint must not be empty")

	// ── Step 5: run install.sh via docker exec with CFGMS_INSTALL_PREFIX ────────
	//
	// CFGMS_INSTALL_PREFIX redirects CA cert writes to an isolated directory so the
	// script does not attempt to write to /etc/cfgms (root-owned inside the container).
	// A wrapper binary placed at INSTALL_PREFIX/usr/local/bin/cfgms-steward exits 0,
	// allowing the script to complete its fingerprint verification and binary-exec path
	// without invoking systemd (which is not available in the Debian test container).

	runInstallScriptInContainer(t, "fleet-steward-1", archiveData, caFingerprint, installPrefix, installWorkDir)

	// ── Step 6: place CA cert so fleet stewards can connect to the controller ────
	//
	// The stewards in docker-compose use a retry loop and will register once the CA
	// cert appears at the platform-standard path /etc/cfgms/controller-ca.crt.

	for _, container := range []string{"fleet-steward-1", "fleet-steward-2"} {
		placeCACert(t, container, caCertPEM)
	}

	// ── Step 7: confirm both stewards register ────────────────────────────────────

	waitForStewardRegistration(t, client, 2, 90*time.Second)
}

// waitForControllerAPI polls the fleet controller's health endpoint until it responds.
func waitForControllerAPI(t *testing.T, client *http.Client) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, fleetControllerHTTP+"/api/v1/health", nil)
		require.NoError(t, err)
		resp, err := client.Do(req)
		cancel()
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatal("fleet-controller API did not become ready within 60s")
}

// extractBinaryFromContainer copies a file from a running container into memory.
func extractBinaryFromContainer(t *testing.T, container, path string) []byte {
	t.Helper()
	tmpFile, err := os.CreateTemp("", "steward-binary-*")
	require.NoError(t, err)
	tmpPath := tmpFile.Name()
	_ = tmpFile.Close()
	defer func() { _ = os.Remove(tmpPath) }()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "docker", "cp",
		fmt.Sprintf("%s:%s", container, path), tmpPath).CombinedOutput()
	require.NoError(t, err, "docker cp failed: %s", string(out))

	data, err := os.ReadFile(tmpPath)
	require.NoError(t, err)
	require.NotEmpty(t, data, "extracted binary must not be empty")
	return data
}

// verifyInstallArchive extracts the tar.gz archive and asserts that ca.crt and
// ca.fingerprint are present. Returns the raw PEM bytes and fingerprint content.
func verifyInstallArchive(t *testing.T, archiveData []byte) (caCertPEM, caFingerprint []byte) {
	t.Helper()

	gzr, err := gzip.NewReader(bytes.NewReader(archiveData))
	require.NoError(t, err)
	defer func() { _ = gzr.Close() }()

	tr := tar.NewReader(gzr)
	files := make(map[string][]byte)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		if hdr.Typeflag == tar.TypeReg {
			data, readErr := io.ReadAll(tr)
			require.NoError(t, readErr)
			files[hdr.Name] = data
		}
	}

	caCertPEM, ok := files["installer/ca.crt"]
	require.True(t, ok, "install package must contain installer/ca.crt")
	require.NotEmpty(t, caCertPEM, "installer/ca.crt must not be empty")

	caFingerprint, ok = files["installer/ca.fingerprint"]
	require.True(t, ok, "install package must contain installer/ca.fingerprint")
	require.NotEmpty(t, caFingerprint, "installer/ca.fingerprint must not be empty")

	return caCertPEM, caFingerprint
}

// runInstallScriptInContainer copies install.sh, ca.crt, and ca.fingerprint into
// the container, sets up an install-prefix wrapper binary that exits 0, and executes
// install.sh with --fingerprint. Asserts the script exits 0 (fingerprint accepted).
func runInstallScriptInContainer(t *testing.T, container string, archiveData []byte, fingerprint, installPfx, workDir string) {
	t.Helper()

	// Find install.sh in the repository tree (relative to this test file's build root).
	repoRoot := findRepoRoot(t)
	installSh := filepath.Join(repoRoot, "build", "linux", "install.sh")
	_, err := os.Stat(installSh)
	require.NoError(t, err, "build/linux/install.sh must exist")

	// Extract ca.crt from the archive.
	caCert, _ := verifyInstallArchive(t, archiveData)

	// Build a temp staging dir on the host to assemble container files.
	hostStage := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(hostStage, "install.sh"), mustReadFile(t, installSh), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(hostStage, "ca.crt"), caCert, 0644))

	// docker cp the staging dir into the container's work directory.
	dockerExecRoot(t, container, "mkdir", "-p", workDir)
	copyToContainer(t, container, hostStage+"/.", workDir)

	// Create INSTALL_PREFIX directory tree and a wrapper binary that exits 0.
	// install.sh locates the binary at INSTALL_PREFIX/usr/local/bin/cfgms-steward when
	// SCRIPT_DIR/cfgms-steward is absent (the archive binary is named cfgms-steward-amd64).
	wrapperPath := installPfx + "/usr/local/bin/cfgms-steward"
	dockerExecRoot(t, container, "mkdir", "-p", installPfx+"/usr/local/bin")
	dockerExecRoot(t, container, "sh", "-c",
		fmt.Sprintf("printf '#!/bin/sh\\nexit 0\\n' > %s && chmod +x %s", wrapperPath, wrapperPath))

	// Run install.sh with CFGMS_INSTALL_PREFIX so it writes to the isolated prefix
	// instead of /etc/cfgms, and --fingerprint so no interactive prompt is required.
	// The registration token must be provided; use the token from the compose env.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "docker", "exec",
		"-e", "CFGMS_INSTALL_PREFIX="+installPfx,
		container,
		"bash", filepath.Join(workDir, "install.sh"),
		"--regtoken", "dockertest_fleet_child_a",
		"--fingerprint", fingerprint,
	).CombinedOutput()

	require.NoError(t, err, "install.sh must exit 0 (fingerprint accepted); output:\n%s", string(out))
}

// placeCACert installs the CA cert at the platform-standard path inside the container
// so the steward daemon's retry loop can find it and register with the controller.
func placeCACert(t *testing.T, container string, caCertPEM []byte) {
	t.Helper()

	// Write CA cert to a temp file on the host, then docker cp into the container.
	hostCA := filepath.Join(t.TempDir(), "controller-ca.crt")
	require.NoError(t, os.WriteFile(hostCA, caCertPEM, 0644))

	// Create /etc/cfgms/ inside the container (requires root).
	dockerExecRoot(t, container, "mkdir", "-p", "/etc/cfgms")
	dockerExecRoot(t, container, "chmod", "755", "/etc/cfgms")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "cp",
		hostCA, fmt.Sprintf("%s:/etc/cfgms/controller-ca.crt", container)).CombinedOutput()
	require.NoError(t, err, "docker cp ca cert failed: %s", string(out))

	dockerExecRoot(t, container, "chmod", "644", "/etc/cfgms/controller-ca.crt")
}

// waitForStewardRegistration polls GET /api/v1/stewards until at least wantCount
// stewards appear or the deadline is reached.
func waitForStewardRegistration(t *testing.T, client *http.Client, wantCount int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, fleetControllerHTTP+"/api/v1/stewards", nil)
		require.NoError(t, err)
		req.Header.Set("X-API-Key", installerAPIKey)
		resp, err := client.Do(req)
		cancel()
		if err == nil && resp.StatusCode == http.StatusOK {
			var result struct {
				Data []json.RawMessage `json:"data"`
			}
			if jsonErr := json.NewDecoder(resp.Body).Decode(&result); jsonErr == nil {
				if len(result.Data) >= wantCount {
					_ = resp.Body.Close()
					return
				}
			}
			_ = resp.Body.Close()
		}
		time.Sleep(3 * time.Second)
	}
	t.Errorf("expected at least %d registered steward(s) within %s, but poll timed out", wantCount, timeout)
}

// dockerExecRoot runs a command in the container as root.
func dockerExecRoot(t *testing.T, container string, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmdArgs := append([]string{"exec", "--user", "root", container}, args...)
	out, err := exec.CommandContext(ctx, "docker", cmdArgs...).CombinedOutput()
	require.NoError(t, err, "docker exec root in %s failed: %s", container, string(out))
}

// copyToContainer copies src (a path on the host) into container:dst via docker cp.
func copyToContainer(t *testing.T, container, src, dst string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "cp",
		src, fmt.Sprintf("%s:%s", container, dst)).CombinedOutput()
	require.NoError(t, err, "docker cp to %s failed: %s", container, string(out))
}

// findRepoRoot walks up from the test file's working directory to locate the
// repository root (identified by the presence of go.mod).
func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repository root (go.mod not found)")
		}
		dir = parent
	}
}

// mustReadFile reads a file and fails the test on error.
func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err, "failed to read %s", path)
	return data
}
