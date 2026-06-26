// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package fleet

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// validFleetContainers is the allowlist of permitted container names.
var validFleetContainers = map[string]bool{
	"fleet-controller": true,
	"fleet-steward-1":  true,
	"fleet-steward-2":  true,
}

// FleetTestSuite holds shared state for the fleet walkthrough test sequence.
type FleetTestSuite struct {
	controllerURL string
	httpClient    *http.Client      // mTLS client (admin bundle) for authenticated endpoints
	stewardIDs    map[string]string // container name → steward ID
	tmpDir        string            // scratch dir for the admin bundle and patched config files
	bundlePath    string            // admin bundle file on disk, passed to `cfg --bundle`
}

// cfgBinary returns the path to the cfg CLI binary. CFG_BINARY is exported by
// make test-e2e-fleet; it falls back to "cfg" on PATH for ad-hoc local runs.
func cfgBinary() string {
	if b := os.Getenv("CFG_BINARY"); b != "" {
		return b
	}
	return "cfg"
}

// adminBundle mirrors the YAML structure of /etc/cfgms/admin.bundle.yaml.
type adminBundle struct {
	CertPEM       string `yaml:"cert_pem"`
	KeyPEM        string `yaml:"key_pem"`
	CAPEM         string `yaml:"ca_pem"`
	ControllerURL string `yaml:"controller_url"`
}

// stewardAPIResponse is the data envelope from GET /api/v1/stewards/{id}.
type stewardAPIResponse struct {
	Data struct {
		ID              string `json:"id"`
		ConnectionState string `json:"connection_state"`
	} `json:"data"`
}

// setupFleetSuite initialises the fleet test suite.
// Immediately skips if CFGMS_FLEET_TEST=1 is not set.
func setupFleetSuite(t *testing.T) *FleetTestSuite {
	t.Helper()

	if os.Getenv("CFGMS_FLEET_TEST") != "1" {
		t.Skip("Fleet E2E tests require CFGMS_FLEET_TEST=1 (run via: make test-e2e-fleet)")
	}

	s := &FleetTestSuite{
		controllerURL: "https://localhost:8090",
		stewardIDs:    make(map[string]string),
		tmpDir:        t.TempDir(),
	}

	for _, name := range []string{"fleet-controller", "fleet-steward-1", "fleet-steward-2"} {
		if !s.waitForContainerHealthy(t, name, 90*time.Second) {
			t.Fatalf("container %s did not reach healthy state within 90s", name)
		}
	}

	if err := s.rebuildClients(t); err != nil {
		t.Fatalf("failed to build HTTP clients: %v", err)
	}

	// Distribute the controller's self-signed CA to each steward so the steward
	// retry loop can complete TLS verification against the controller. The
	// docker-compose fleet steward services do not mount any CA at start time —
	// without this step they retry forever with "x509: certificate signed by
	// unknown authority" and never register. In production this is the install
	// package's job (and TestFleetInstallPackageFlow exercises that full path);
	// here in suite setup we use a direct docker cp from the controller's
	// pkg/cert storage location for speed and to keep the install-package test
	// independently meaningful.
	s.distributeControllerCAToStewards(t)

	for _, name := range []string{"fleet-steward-1", "fleet-steward-2"} {
		id, err := s.getStewardIDFromLogs(t, name)
		if err != nil {
			t.Fatalf("failed to get steward ID from %s: %v", name, err)
		}
		s.stewardIDs[name] = id
		t.Logf("Fleet suite: %s → steward ID %s", name, id)
	}

	return s
}

// distributeControllerCAToStewards extracts the controller's self-signed CA
// from /app/certs/ca/ca.crt (per controller.cfg's certificate.ca_path setting
// inside fleet-controller) and writes it to /etc/cfgms/controller-ca.crt on
// each fleet steward. The stewards' 5s retry loop picks up the new cert on
// its next attempt and completes TLS verification against the controller.
func (s *FleetTestSuite) distributeControllerCAToStewards(t *testing.T) {
	t.Helper()

	hostCA := filepath.Join(s.tmpDir, "controller-ca.crt")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "cp",
		"fleet-controller:/app/certs/ca/ca.crt", hostCA).CombinedOutput()
	require.NoError(t, err, "extract controller CA: %s", string(out))

	for _, container := range []string{"fleet-steward-1", "fleet-steward-2"} {
		dockerExecRoot(t, container, "mkdir", "-p", "/etc/cfgms")
		dockerExecRoot(t, container, "chmod", "755", "/etc/cfgms")

		cpCtx, cpCancel := context.WithTimeout(context.Background(), 10*time.Second)
		cpOut, cpErr := exec.CommandContext(cpCtx, "docker", "cp",
			hostCA, fmt.Sprintf("%s:/etc/cfgms/controller-ca.crt", container)).CombinedOutput()
		cpCancel()
		require.NoError(t, cpErr, "place CA in %s: %s", container, string(cpOut))

		dockerExecRoot(t, container, "chmod", "644", "/etc/cfgms/controller-ca.crt")
		t.Logf("Distributed controller CA to %s:/etc/cfgms/controller-ca.crt", container)
	}
}

// rebuildClients re-extracts the admin bundle from fleet-controller and rebuilds both clients.
// Call this after a controller restart (the admin bundle changes on every init).
func (s *FleetTestSuite) rebuildClients(t *testing.T) error {
	t.Helper()

	bundleYAML, err := s.dockerExec(t, "fleet-controller", "cat", "/etc/cfgms/admin.bundle.yaml")
	if err != nil {
		return fmt.Errorf("read admin bundle: %w", err)
	}

	var bundle adminBundle
	if err := yaml.Unmarshal([]byte(bundleYAML), &bundle); err != nil {
		return fmt.Errorf("parse admin bundle: %w", err)
	}
	if bundle.CertPEM == "" || bundle.KeyPEM == "" || bundle.CAPEM == "" {
		return fmt.Errorf("admin bundle incomplete (cert=%v key=%v ca=%v)",
			bundle.CertPEM != "", bundle.KeyPEM != "", bundle.CAPEM != "")
	}

	// Persist the bundle to disk so the `cfg` CLI can authenticate via --bundle.
	// The controller regenerates the bundle on every init, so this is rewritten
	// after each controller restart.
	s.bundlePath = filepath.Join(s.tmpDir, "admin.bundle.yaml")
	if err := os.WriteFile(s.bundlePath, []byte(bundleYAML), 0o600); err != nil {
		return fmt.Errorf("write admin bundle file: %w", err)
	}

	clientCert, err := tls.X509KeyPair([]byte(bundle.CertPEM), []byte(bundle.KeyPEM))
	if err != nil {
		return fmt.Errorf("load admin cert/key pair: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM([]byte(bundle.CAPEM)) {
		return fmt.Errorf("parse CA cert from admin bundle")
	}

	s.httpClient = &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{clientCert},
				RootCAs:      caPool,
				MinVersion:   tls.VersionTLS13,
			},
		},
	}

	return nil
}

// validateFleetContainer returns an error if name is not in the fleet allowlist.
func validateFleetContainer(name string) error {
	if !validFleetContainers[name] {
		return fmt.Errorf("container %q not in fleet allowlist", name)
	}
	return nil
}

// dockerExec runs args in a named container and returns stdout output.
func (s *FleetTestSuite) dockerExec(t *testing.T, container string, args ...string) (string, error) {
	t.Helper()
	if err := validateFleetContainer(container); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmdArgs := append([]string{"exec", container}, args...)
	out, err := exec.CommandContext(ctx, "docker", cmdArgs...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("docker exec %s %v: %w (output: %s)", container, args, err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// getStewardIDFromLogs extracts the steward ID from /tmp/cfgms log files in the container.
// Uses the same grep pattern as test/integration/transport/module_helpers.go.
func (s *FleetTestSuite) getStewardIDFromLogs(t *testing.T, container string) (string, error) {
	t.Helper()
	if err := validateFleetContainer(container); err != nil {
		return "", err
	}

	// 90 attempts × ~1s each = ~90s window. The first registration attempt
	// after distributeControllerCAToStewards may still be in-flight (5s retry
	// loop in the steward command), so we need headroom beyond a single retry
	// cycle. Without this margin the steward ID may not appear before the
	// poll exits — see prior fleet-e2e timing failure on Issue #1709.
	for attempt := 1; attempt <= 90; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		cmd := exec.CommandContext(ctx, "docker", "exec", container, "sh", "-c",
			`ls -t /tmp/cfgms/cfgms-*.log 2>/dev/null | head -1 | xargs cat 2>/dev/null | grep -o '"steward_id":"[^"]*"' | tail -1 | cut -d'"' -f4`)
		out, err := cmd.CombinedOutput()
		cancel()
		if id := strings.TrimSpace(string(out)); err == nil && id != "" {
			return id, nil
		}
		if attempt%10 == 0 {
			t.Logf("Waiting for steward ID in %s logs (attempt %d/90)...", container, attempt)
		}
		time.Sleep(1 * time.Second)
	}
	return "", fmt.Errorf("steward ID not found in %s logs after 90 attempts", container)
}

// waitForContainerHealthy polls docker ps until the container reports healthy or timeout expires.
func (s *FleetTestSuite) waitForContainerHealthy(t *testing.T, container string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		out, err := exec.CommandContext(ctx, "docker", "ps",
			"--filter", "name="+container,
			"--filter", "health=healthy",
			"--format", "{{.Names}}").CombinedOutput()
		cancel()
		if err == nil && strings.Contains(string(out), container) {
			t.Logf("Container %s is healthy", container)
			return true
		}
		time.Sleep(2 * time.Second)
	}
	t.Logf("Container %s did not reach healthy within %v", container, timeout)
	return false
}

// waitForConvergence polls GET /api/v1/stewards/{id} until connection_state == "connected".
func (s *FleetTestSuite) waitForConvergence(t *testing.T, stewardID string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		state, err := s.getStewardConnectionState(t, stewardID)
		if err == nil && state == "connected" {
			t.Logf("Steward %s: connection_state=connected", stewardID)
			return true
		}
		time.Sleep(2 * time.Second)
	}
	t.Logf("Steward %s did not reach connected state within %v", stewardID, timeout)
	return false
}

// getStewardConnectionState returns connection_state from GET /api/v1/stewards/{id}.
func (s *FleetTestSuite) getStewardConnectionState(t *testing.T, stewardID string) (string, error) {
	t.Helper()
	url := fmt.Sprintf("%s/api/v1/stewards/%s", s.controllerURL, stewardID)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("GET %s: status %d: %s", url, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var apiResp stewardAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return "", fmt.Errorf("decode steward response: %w", err)
	}
	return apiResp.Data.ConnectionState, nil
}

// uploadConfig uploads configPath to a steward using the `cfg config upload` CLI —
// the same user-facing command an operator runs. The config's steward.id is patched
// to stewardID in a temp copy first, and the admin bundle extracted from
// fleet-controller authenticates the mTLS request.
func (s *FleetTestSuite) uploadConfig(t *testing.T, stewardID, configPath string) error {
	t.Helper()

	if s.bundlePath == "" {
		return fmt.Errorf("admin bundle path not set; call rebuildClients first")
	}

	rawYAML, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", configPath, err)
	}

	var cfg map[string]interface{}
	if err := yaml.Unmarshal(rawYAML, &cfg); err != nil {
		return fmt.Errorf("parse config YAML: %w", err)
	}
	if section, ok := cfg["steward"].(map[string]interface{}); ok {
		section["id"] = stewardID
	}
	patched, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal patched config: %w", err)
	}

	tmpConfig := filepath.Join(s.tmpDir, "upload-"+stewardID+".yaml")
	if err := os.WriteFile(tmpConfig, patched, 0o600); err != nil {
		return fmt.Errorf("write temp config: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// #nosec G204 - cfgBinary() and all args are test-controlled, not user input.
	cmd := exec.CommandContext(ctx, cfgBinary(),
		"config", "upload", tmpConfig,
		"--steward", stewardID,
		"--bundle", s.bundlePath,
		"--url", s.controllerURL)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("cfg config upload for %s: %w (output: %s)",
			stewardID, err, strings.TrimSpace(string(out)))
	}

	t.Logf("Config uploaded for steward %s via cfg config upload: %s",
		stewardID, strings.TrimSpace(string(out)))
	return nil
}

// containerRestart restarts a fleet container and waits for it to reach healthy.
func (s *FleetTestSuite) containerRestart(t *testing.T, container string, healthTimeout time.Duration) {
	t.Helper()
	if err := validateFleetContainer(container); err != nil {
		t.Fatalf("containerRestart: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "docker", "restart", container).CombinedOutput(); err != nil {
		t.Fatalf("docker restart %s: %v (output: %s)", container, err, strings.TrimSpace(string(out)))
	}
	t.Logf("Restarted %s; waiting for healthy...", container)
	if !s.waitForContainerHealthy(t, container, healthTimeout) {
		t.Fatalf("container %s did not reach healthy after restart", container)
	}
}

// containerStop stops a fleet container (its writable layer — including the
// stored steward cert — survives; only the /test-workspace tmpfs is cleared).
func (s *FleetTestSuite) containerStop(t *testing.T, container string) {
	t.Helper()
	if err := validateFleetContainer(container); err != nil {
		t.Fatalf("containerStop: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "docker", "stop", container).CombinedOutput(); err != nil {
		t.Fatalf("docker stop %s: %v (output: %s)", container, err, strings.TrimSpace(string(out)))
	}
	t.Logf("Stopped %s", container)
}

// containerStart starts a previously stopped fleet container and waits for healthy.
func (s *FleetTestSuite) containerStart(t *testing.T, container string, healthTimeout time.Duration) {
	t.Helper()
	if err := validateFleetContainer(container); err != nil {
		t.Fatalf("containerStart: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "docker", "start", container).CombinedOutput(); err != nil {
		t.Fatalf("docker start %s: %v (output: %s)", container, err, strings.TrimSpace(string(out)))
	}
	t.Logf("Started %s; waiting for healthy...", container)
	if !s.waitForContainerHealthy(t, container, healthTimeout) {
		t.Fatalf("container %s did not reach healthy after start", container)
	}
}

// readStewardLog returns the contents of the most recent steward log file.
// The steward exposes no HTTP status endpoint; its structured log is the
// authoritative local record of convergence and drift events.
func (s *FleetTestSuite) readStewardLog(t *testing.T, container string) (string, error) {
	t.Helper()
	return s.dockerExec(t, container, "sh", "-c",
		`ls -t /tmp/cfgms/cfgms-*.log 2>/dev/null | head -1 | xargs cat 2>/dev/null`)
}

const upgradeAPIKey = "cfgms-upgrade-test-key"

// upgradeStatusResponse mirrors the controller's APIResponse wrapper for upgrade records.
type upgradeStatusResponse struct {
	Data struct {
		Status string `json:"status"`
	} `json:"data"`
}

// fetchUpgradeStatus polls GET /api/v1/stewards/upgrade/{upgrade_id} until the status
// is terminal (committed, failed, rolled_back) or the timeout expires.
// Returns the last observed status string, or "timeout" if no terminal status was seen.
func fetchUpgradeStatus(t *testing.T, client *http.Client, upgradeID string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	last := "unknown"
	for time.Now().Before(deadline) {
		url := fmt.Sprintf("%s/api/v1/stewards/upgrade/%s", fleetControllerHTTP, upgradeID)
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}
		req.Header.Set("X-API-Key", upgradeAPIKey)
		resp, err := client.Do(req)
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			time.Sleep(2 * time.Second)
			continue
		}
		var result upgradeStatusResponse
		if jerr := json.Unmarshal(body, &result); jerr != nil {
			time.Sleep(2 * time.Second)
			continue
		}
		last = result.Data.Status
		if last == "committed" || last == "failed" || last == "rolled_back" {
			return last
		}
		time.Sleep(2 * time.Second)
	}
	t.Logf("fetchUpgradeStatus: timeout after %v; last status = %q", timeout, last)
	return "timeout"
}

// waitForStewardVersion polls the steward container's log until the specified version
// string appears (indicating the upgrade handler processed that version). Returns true
// if found within the timeout.
func (s *FleetTestSuite) waitForStewardVersion(t *testing.T, container, version string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		log, err := s.readStewardLog(t, container)
		if err == nil && strings.Contains(log, version) {
			return true
		}
		time.Sleep(2 * time.Second)
	}
	return false
}

// expireStewardCerts replaces the steward's stored mTLS client certificate with an
// expired one, simulating a steward that has been offline past cert expiry.
//
// It docker-copies the cert store from the container to a host temp dir, loads a
// cert.Manager from it to find existing client cert serials, writes expired cert/key/
// metadata files directly into each existing serial directory, and copies the modified
// store back. The in-place serial-directory approach sidesteps docker cp's additive
// behaviour: files inside existing directories are overwritten, but no new serial
// directories are created and no container-side deletions are needed.
//
// device_identity.enc and steward-identity.json are preserved because they live in
// the cert store root, not in per-serial subdirectories.
//
// The container must be stopped before calling this helper.
func (s *FleetTestSuite) expireStewardCerts(t *testing.T, container string) {
	t.Helper()
	if err := validateFleetContainer(container); err != nil {
		t.Fatalf("expireStewardCerts: %v", err)
	}

	const certStoreDir = "/var/lib/cfgms/steward/certs"

	// Copy cert store from container to a host temp directory.
	hostCertDir := filepath.Join(s.tmpDir, "certstore-"+container)
	if err := os.MkdirAll(hostCertDir, 0o750); err != nil {
		t.Fatalf("expireStewardCerts: create host cert dir: %v", err)
	}

	cpOutCtx, cpOutCancel := context.WithTimeout(context.Background(), 30*time.Second)
	// docker cp container:dir/. dst copies directory CONTENTS (not the dir itself).
	out, err := exec.CommandContext(cpOutCtx, "docker", "cp",
		fmt.Sprintf("%s:%s/.", container, certStoreDir), hostCertDir).CombinedOutput()
	cpOutCancel()
	require.NoError(t, err, "expireStewardCerts: docker cp cert store out: %s", string(out))

	// Load the cert.Manager from the copied store.
	mgr, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath:    hostCertDir,
		LoadExistingCA: true,
	})
	require.NoError(t, err, "expireStewardCerts: load cert manager")

	// Record serial numbers of existing client certs to replace in-place.
	certs, err := mgr.ListCertificates()
	require.NoError(t, err, "expireStewardCerts: list certificates")
	var oldSerials []string
	for _, c := range certs {
		if c.Type == cert.CertificateTypeClient {
			oldSerials = append(oldSerials, c.SerialNumber)
		}
	}
	require.NotEmpty(t, oldSerials,
		"expireStewardCerts: no client certs found in %s cert store; steward may not be registered", container)

	// Generate a self-signed cert+key pair with NotBefore/NotAfter both in the past.
	expiredCertPEM, expiredKeyPEM := generateExpiredClientCertPEM(t)

	// Replace each client cert IN-PLACE: write expired cert data into the same serial
	// directories that already exist in the container. docker cp is additive — it merges
	// files into the destination but never deletes directories. By overwriting the files
	// in the existing serial directories (rather than creating a new serial directory),
	// the docker cp below replaces the valid cert data with expired data in-place, so
	// the steward's cert store contains only expired client certs after the copy-back.
	now := time.Now().UTC()
	for _, serial := range oldSerials {
		serialDir := filepath.Join(hostCertDir, serial)
		if err := os.WriteFile(filepath.Join(serialDir, "cert.pem"), expiredCertPEM, 0o600); err != nil {
			t.Fatalf("expireStewardCerts: overwrite cert.pem for serial %s: %v", serial, err)
		}
		if err := os.WriteFile(filepath.Join(serialDir, "key.pem"), expiredKeyPEM, 0o600); err != nil {
			t.Fatalf("expireStewardCerts: overwrite key.pem for serial %s: %v", serial, err)
		}
		// Overwrite metadata.json with expired timestamps so loadCertificates recomputes
		// IsValid = false (time.Now().Before(ExpiresAt) → false when ExpiresAt is in the past).
		meta := &cert.CertificateInfo{
			Type:         cert.CertificateTypeClient,
			CommonName:   "cfgms-expired-test-client",
			SerialNumber: serial,
			CreatedAt:    now.Add(-48 * time.Hour),
			ExpiresAt:    now.Add(-24 * time.Hour),
			IsValid:      false,
		}
		metaJSON, jerr := json.MarshalIndent(meta, "", "  ")
		require.NoError(t, jerr, "expireStewardCerts: marshal metadata for serial %s", serial)
		if err := os.WriteFile(filepath.Join(serialDir, "metadata.json"), metaJSON, 0o600); err != nil {
			t.Fatalf("expireStewardCerts: overwrite metadata.json for serial %s: %v", serial, err)
		}
	}

	// Copy the modified cert store back to the container — preserving the steward's
	// ownership. The steward process runs as user cfgms (UID/GID 1001; see
	// cmd/steward/Dockerfile.debian), and /var/lib/cfgms/steward/certs is chowned to
	// cfgms at image build. A plain `docker cp src/. container:dst` re-creates the
	// copied files (and the destination dir) owned by the HOST uid running the test
	// (empirically the host UID, not the container's), so the steward can no longer
	// read steward-identity.json or write machine-id in that directory. That silently
	// disables registration-refresh ("Failed to create device identity key store;
	// registration-refresh disabled") and the steward falls back to a FULL HTTP
	// re-registration instead of the refresh handshake — making every refresh-path
	// assertion fail. To avoid that, stream a tar of the cert store with every entry
	// forced to 1001:1001 and feed it to `docker cp -`, which extracts to DEST
	// preserving the tar's uid/gid. This restores the steward's access on restart.
	const stewardUIDGID = "1001" // cfgms user/group in cmd/steward/Dockerfile.debian
	cpInCtx, cpInCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cpInCancel()
	var tarBuf bytes.Buffer
	tarCmd := exec.CommandContext(cpInCtx, "tar", "-C", hostCertDir,
		"--owner="+stewardUIDGID, "--group="+stewardUIDGID, "-cf", "-", ".")
	tarCmd.Stdout = &tarBuf
	var tarErr bytes.Buffer
	tarCmd.Stderr = &tarErr
	require.NoError(t, tarCmd.Run(), "expireStewardCerts: tar cert store with cfgms ownership: %s", tarErr.String())

	cpInCmd := exec.CommandContext(cpInCtx, "docker", "cp", "-",
		fmt.Sprintf("%s:%s", container, certStoreDir))
	cpInCmd.Stdin = &tarBuf
	out, err = cpInCmd.CombinedOutput()
	require.NoError(t, err, "expireStewardCerts: docker cp modified cert store back: %s", string(out))

	t.Logf("expireStewardCerts: replaced %d client cert(s) with expired version in %s (in-place)",
		len(oldSerials), container)
}

// generateExpiredClientCertPEM creates a self-signed RSA cert+key pair with
// NotBefore=-48h and NotAfter=-24h, simulating a cert that expired yesterday.
// The cert does not need to be CA-signed; cert.Manager.ImportCertificate only
// validates that the cert and key match, not that the cert is CA-signed.
func generateExpiredClientCertPEM(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "generateExpiredClientCertPEM: generate RSA key")

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err, "generateExpiredClientCertPEM: generate serial")

	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "cfgms-expired-test-client"},
		NotBefore:    now.Add(-48 * time.Hour),
		NotAfter:     now.Add(-24 * time.Hour), // expired 24 hours ago
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	// Self-signed: parent == template, signer == key.
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err, "generateExpiredClientCertPEM: create certificate")

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER := x509.MarshalPKCS1PrivateKey(key)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

// ---- Registration-refresh helper functions (Issue #2098) ---------------------

// getDeviceIDFromContainer reads the device_id from the steward-identity.json
// stored in the container's cert store. The container must be running.
func (s *FleetTestSuite) getDeviceIDFromContainer(t *testing.T, container string) string {
	t.Helper()
	const identityFile = "/var/lib/cfgms/steward/certs/steward-identity.json"
	raw, err := s.dockerExec(t, container, "cat", identityFile)
	require.NoError(t, err, "getDeviceIDFromContainer: read %s from %s", identityFile, container)
	var id struct {
		DeviceID string `json:"device_id"`
	}
	require.NoError(t, json.Unmarshal([]byte(raw), &id),
		"getDeviceIDFromContainer: parse steward-identity.json from %s", container)
	require.NotEmpty(t, id.DeviceID,
		"getDeviceIDFromContainer: device_id is empty in %s:%s", container, identityFile)
	return id.DeviceID
}

// setStewardStatusByID sets the lifecycle status of the steward with the given ID
// via the controller's test-mode REST endpoint (PUT /api/v1/test/stewards/{id}/status).
// The fleet-controller must have CFGMS_ENABLE_TEST_ENDPOINTS=true.
func (s *FleetTestSuite) setStewardStatusByID(t *testing.T, stewardID, status string) {
	t.Helper()
	url := fmt.Sprintf("%s/api/v1/test/stewards/%s/status", s.controllerURL, stewardID)
	body, err := json.Marshal(map[string]string{"status": status})
	require.NoError(t, err, "setStewardStatusByID: marshal request body")
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPut, url, strings.NewReader(string(body)))
	require.NoError(t, err, "setStewardStatusByID: build request")
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.httpClient.Do(req)
	require.NoError(t, err, "setStewardStatusByID: send request")
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusNoContent, resp.StatusCode,
		"setStewardStatusByID: unexpected response for steward %s → %s", stewardID, status)
}

// setRefreshPolicy sets the per-tenant refresh policy via the controller REST API.
// mode is one of: "auto_accept", "require_approval", "reject".
func (s *FleetTestSuite) setRefreshPolicy(t *testing.T, tenantID, mode string) {
	t.Helper()
	url := fmt.Sprintf("%s/api/v1/tenants/%s/refresh-policy", s.controllerURL, tenantID)
	body, err := json.Marshal(map[string]string{"mode": mode})
	require.NoError(t, err, "setRefreshPolicy: marshal request body")
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPut, url, strings.NewReader(string(body)))
	require.NoError(t, err, "setRefreshPolicy: build request")
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.httpClient.Do(req)
	require.NoError(t, err, "setRefreshPolicy: send request")
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"setRefreshPolicy: unexpected response for tenant %s mode %s: %s", tenantID, mode, resp.Status)
}

// pendingRefreshEntry is the API representation of a pending refresh queue entry.
type pendingRefreshEntry struct {
	PendingID string `json:"pending_id"`
	DeviceID  string `json:"device_id"`
	TenantID  string `json:"tenant_id"`
	Status    string `json:"status"`
}

// listPendingRefreshes fetches pending refresh entries from the controller.
// An empty tenant_id returns all entries (admin-scoped call).
func (s *FleetTestSuite) listPendingRefreshes(t *testing.T, tenantID string) []pendingRefreshEntry {
	t.Helper()
	url := fmt.Sprintf("%s/api/v1/stewards/refresh/pending", s.controllerURL)
	if tenantID != "" {
		url += "?tenant_id=" + strings.ReplaceAll(tenantID, "/", "%2F")
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	require.NoError(t, err, "listPendingRefreshes: build request")
	resp, err := s.httpClient.Do(req)
	require.NoError(t, err, "listPendingRefreshes: send request")
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"listPendingRefreshes: unexpected response: %s", resp.Status)
	var entries []pendingRefreshEntry
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&entries), "listPendingRefreshes: decode response")
	return entries
}

// approveRefreshViaAPI approves a pending refresh entry via the controller REST API.
func (s *FleetTestSuite) approveRefreshViaAPI(t *testing.T, pendingID string) {
	t.Helper()
	url := fmt.Sprintf("%s/api/v1/stewards/refresh/%s/approve", s.controllerURL, pendingID)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, nil)
	require.NoError(t, err, "approveRefreshViaAPI: build request")
	resp, err := s.httpClient.Do(req)
	require.NoError(t, err, "approveRefreshViaAPI: send request")
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"approveRefreshViaAPI: unexpected response for pending_id %s: %s", pendingID, resp.Status)
}

// queryAuditActionCount returns the number of audit entries with the given action
// attributed to the given device_id. Calls the test-mode controller endpoint which
// flushes the audit manager before querying.
func (s *FleetTestSuite) queryAuditActionCount(t *testing.T, action, deviceID string) int {
	t.Helper()
	params := url.Values{}
	params.Set("action", action)
	if deviceID != "" {
		params.Set("device_id", deviceID)
	}
	rawURL := fmt.Sprintf("%s/api/v1/test/audit/count?%s", s.controllerURL, params.Encode())
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, rawURL, nil)
	require.NoError(t, err, "queryAuditActionCount: build request")
	resp, err := s.httpClient.Do(req)
	require.NoError(t, err, "queryAuditActionCount: send request")
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"queryAuditActionCount: unexpected response: %s", resp.Status)
	var result struct {
		Count int `json:"count"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result), "queryAuditActionCount: decode response")
	return result.Count
}

// TestFleetWalkthrough is the single ordered entry point for all fleet walkthrough scenarios.
// Scenarios execute in definition order via t.Run so each is individually identified in output.
func TestFleetWalkthrough(t *testing.T) {
	suite := setupFleetSuite(t)
	cfg := "configs/fleet-config.yaml"

	t.Run("VanillaState", func(t *testing.T) { suite.testVanillaState(t) })
	t.Run("ConfigUploadAndConvergence", func(t *testing.T) { suite.testConfigUploadAndConvergence(t, cfg) })
	t.Run("IdempotentReUpload", func(t *testing.T) { suite.testIdempotentReUpload(t, cfg) })
	t.Run("PerModuleConvergence", func(t *testing.T) { suite.testPerModuleConvergence(t) })
	t.Run("ControllerRestart", func(t *testing.T) { suite.testControllerRestart(t, cfg) })
	t.Run("StewardRestart", func(t *testing.T) { suite.testStewardRestart(t, cfg) })
	t.Run("DeferredConfig", func(t *testing.T) { suite.testDeferredConfig(t, cfg) })
	t.Run("DriftAutoCorrection", func(t *testing.T) { suite.testDriftAutoCorrection(t, cfg) })
	t.Run("ConfigCascade", func(t *testing.T) { suite.testConfigCascade(t) })
}
