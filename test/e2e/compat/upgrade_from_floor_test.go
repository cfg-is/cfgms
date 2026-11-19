// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package compat

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/test/e2e/fleet/fleetkit"
)

const (
	// currentVersion is the label the steward built from this tree carries: baked
	// into the binary, published under, and dispatched as. It is a release-tag
	// form so the controller accepts it, and sorts above any floor
	// (TestCurrentVersionSortsAboveFloor).
	currentVersion = "v99.0.0-compat-current"

	// currentControllerURL is the controller URL both the floor and the current
	// steward are built with (the make test-e2e-compat floor build passes the same).
	currentControllerURL = "https://compat-controller:9080"

	// currentBinaryName is the file the current build is written to under bin/.
	currentBinaryName = "cfgms-steward-compat-current"

	// launcherRoot is the launcher's install root in the floor image
	// (test/compat/Dockerfile.steward creates it owned by cfgms).
	launcherRoot = "/opt/cfgms"

	// regTokenFile holds the registration token for the current steward, which
	// takes it from a file (the floor takes it as --regtoken; see floorAdapter).
	regTokenFile = "/tmp/regtoken"

	// launcherLogFile receives the launcher's output. It is outside /tmp/cfgms so
	// the steward-log scans of that directory never read it.
	launcherLogFile = "/tmp/launcher.log"

	// upgradeWindow bounds the push, download, stage and swap of the current build.
	upgradeWindow = 180 * time.Second

	// stagedAdapterPath and stagedShimPath are where the harness's two scripts
	// are copied before the root step moves them into place.
	stagedAdapterPath = "/tmp/compat-floor-adapter.sh"
	stagedShimPath    = "/tmp/compat-launcher-shim.sh"
)

// floorAdapter is the launcher's entry for the floor version. The launcher runs
// the child with `--regtoken-file <path>`, the form the current steward takes;
// the floor release predates that flag and takes the token as `--regtoken`. This
// adapter is the whole difference: it starts the unmodified floor binary with the
// token the floor form expects. The current build, installed by the upgrade, is
// run by the launcher directly with the file form.
const floorAdapter = `#!/bin/sh
exec "$(dirname "$0")/cfgms-steward.real" --regtoken "$(cat ` + regTokenFile + `)"
`

// launcherShim replaces /app/steward in the floor image. The compose service
// restarts ./steward whenever it exits, so the launcher runs as that process and
// no second, bare steward is ever started beside it.
const launcherShim = `#!/bin/sh
exec /usr/local/bin/cfgms-launcher run --root ` + launcherRoot + ` --child-args '--regtoken-file ` + regTokenFile + `' >>` + launcherLogFile + ` 2>&1
`

// postUpgradeConfigTemplate is the configuration TestCommandsVerifyAfterUpgrade
// syncs: one file resource on the container's /test-workspace tmpfs, distinct
// from the files the floor scenarios manage.
const postUpgradeConfigTemplate = `steward:
  id: %q
resources:
  - name: compat-after-upgrade-file
    module: file
    config:
      path: /test-workspace/compat-after-upgrade-file
      state: present
      content: "compat-after-upgrade-content\n"
      mode: "0644"
      allowed_base_path: /test-workspace
`

const (
	postUpgradeFilePath    = "/test-workspace/compat-after-upgrade-file"
	postUpgradeFileContent = "compat-after-upgrade-content\n"
)

// controllerVersionRe is the controller's accepted steward version form
// (features/controller/api handlers_steward_binary.go).
var controllerVersionRe = regexp.MustCompile(`^v\d+\.\d+\.\d+(-[a-zA-Z0-9][a-zA-Z0-9.-]*)?$`)

// publishedBinary is the data envelope of the publish response.
type publishedBinary struct {
	SHA256 string `json:"sha256"`
}

// upgradeEvidence is what a completed upgrade leaves for the scenarios to assert on.
type upgradeEvidence struct {
	stewardID string
	upgradeID string
	// sha256 is the digest of the published, approved and dispatched binary.
	sha256 string
}

// upgradeRun memoises the one upgrade of the compat stack's floor steward. The
// upgrade changes the steward for every later scenario, so it runs once; the
// scenarios that need an upgraded steward share its result.
var upgradeRun struct {
	sync.Mutex
	attempted bool
	evidence  *upgradeEvidence
}

// repoRoot is the repository root, relative to this package.
func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../../..")
	require.NoError(t, err)
	return root
}

// buildCurrentSteward builds the steward from this tree with the repository's own
// recipe (make build-steward), for the architecture of the compat containers, and
// returns the binary. The version label is baked in, so the steward reports it
// once it runs.
func buildCurrentSteward(t *testing.T, version string) []byte {
	t.Helper()
	root := repoRoot(t)
	require.NoError(t, os.MkdirAll(filepath.Join(root, "bin"), 0o750))
	out := filepath.Join(root, "bin", currentBinaryName)
	t.Cleanup(func() { _ = os.Remove(out) })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	// #nosec G204 -- make is a fixed binary; every argument is a test constant
	cmd := exec.CommandContext(ctx, "make", "-C", root, "build-steward",
		"VERSION="+version,
		"STEWARD_CONTROLLER_URL="+currentControllerURL,
		"STEWARD_BINARY="+currentBinaryName)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+runtime.GOARCH, "CGO_ENABLED=0")
	combined, err := cmd.CombinedOutput()
	require.NoError(t, err, "build the current steward (%s): %s", version, string(combined))

	bin, err := os.ReadFile(out) // #nosec G304 -- path is the build output this function just produced
	require.NoError(t, err)
	require.NotEmpty(t, bin, "the current steward build is empty")
	return bin
}

// binaryURLPath is the publish route for one coordinate.
func binaryURLPath(version, arch string) string {
	return "/api/v1/installer/steward-binaries/" + url.PathEscape(version) + "/linux/" + url.PathEscape(arch)
}

// upgradeAPI issues a request to the compat controller as the upgrade-test API
// key and returns status and body. Publishing and dispatching a steward binary
// accept a machine principal; the admin mTLS client is refused there with a
// step-up challenge (strong assurance and a fresh presence tap), and the
// requirement is not weakened here. The key is seeded into the compat controller
// by CFGMS_API_KEY_UPGRADE_TEST, scoped to the tenant the compat steward
// registers into, exactly as in the fleet stack. It carries a query string,
// which harness.api cannot.
func (h *harness) upgradeAPI(method, pathAndQuery, contentType string, body []byte, timeout time.Duration) (int, []byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, h.ControllerURL+pathAndQuery, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("X-API-Key", fleetkit.UpgradeAPIKey)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := h.HTTPClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	var buf bytes.Buffer
	_, err = buf.ReadFrom(resp.Body)
	return resp.StatusCode, buf.Bytes(), err
}

// publishBinary uploads the signed binary: the real publish step.
func (h *harness) publishBinary(t *testing.T, version, arch string, content []byte) {
	t.Helper()
	sig := fleetkit.SignUploadContent(t, content, version, "linux", arch)
	status, body, err := h.upgradeAPI(http.MethodPost,
		binaryURLPath(version, arch)+"?force=true&signature="+url.QueryEscape(sig),
		"application/octet-stream", content, 2*time.Minute)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status, "publish %s: %s", version, string(body))

	sum := sha256.Sum256(content)
	want := hex.EncodeToString(sum[:])
	got, err := decodePublishedSHA256(body)
	require.NoError(t, err)
	require.Equal(t, want, got, "the controller stored different bytes than were published")
}

// dispatchUpgrade asks the controller to upgrade the steward and returns the
// upgrade ID.
func (h *harness) dispatchUpgrade(t *testing.T, stewardID, version, arch string) string {
	t.Helper()
	payload, err := json.Marshal(map[string]string{
		"selector": "id:" + stewardID,
		"version":  version,
		"platform": "linux",
		"arch":     arch,
	})
	require.NoError(t, err)
	status, body, err := h.upgradeAPI(http.MethodPost, "/api/v1/stewards/upgrade", "application/json", payload, 30*time.Second)
	require.NoError(t, err)
	require.Equal(t, http.StatusAccepted, status, "dispatch %s: %s", version, string(body))
	id, err := decodeUpgradeID(body)
	require.NoError(t, err)
	return id
}

// waitForUpgradeStatus polls the upgrade record until it is terminal and returns
// the last status seen ("timeout" when it never settled).
func (h *harness) waitForUpgradeStatus(t *testing.T, upgradeID string, timeout time.Duration) string {
	t.Helper()
	last := "timeout"
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		status, body, err := h.upgradeAPI(http.MethodGet, "/api/v1/stewards/upgrade/"+url.PathEscape(upgradeID), "", nil, 30*time.Second)
		if err == nil && status == http.StatusOK {
			if s, derr := decodeUpgradeStatus(body); derr == nil {
				last = s
				if isTerminalUpgradeStatus(s) {
					return s
				}
			}
		}
		time.Sleep(2 * time.Second)
	}
	return last
}

// decodePublishedSHA256 reads the stored digest from the publish response.
func decodePublishedSHA256(body []byte) (string, error) {
	var env struct {
		Data publishedBinary `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return "", fmt.Errorf("decode publish response: %w", err)
	}
	if env.Data.SHA256 == "" {
		return "", errors.New("publish response carries no sha256")
	}
	return env.Data.SHA256, nil
}

// decodeUpgradeID reads upgrade_id from the dispatch response.
func decodeUpgradeID(body []byte) (string, error) {
	var env struct {
		Data struct {
			UpgradeID string `json:"upgrade_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return "", fmt.Errorf("decode dispatch response: %w", err)
	}
	if env.Data.UpgradeID == "" {
		return "", errors.New("dispatch response carries no upgrade_id")
	}
	return env.Data.UpgradeID, nil
}

// decodeUpgradeStatus reads the status from an upgrade record response.
func decodeUpgradeStatus(body []byte) (string, error) {
	var env struct {
		Data struct {
			Status string `json:"status"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return "", fmt.Errorf("decode upgrade record: %w", err)
	}
	if env.Data.Status == "" {
		return "", errors.New("upgrade record carries no status")
	}
	return env.Data.Status, nil
}

// isTerminalUpgradeStatus reports whether an upgrade record will not move on.
func isTerminalUpgradeStatus(s string) bool {
	switch s {
	case "committed", "failed", "rolled_back":
		return true
	}
	return false
}

// decodeCapabilityRecord reads the durable capability record out of a steward
// record file.
func decodeCapabilityRecord(data []byte) (*business.StewardCapabilityRecord, error) {
	var rec struct {
		Capabilities *business.StewardCapabilityRecord `json:"capabilities"`
	}
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("decode steward record: %w", err)
	}
	if rec.Capabilities == nil {
		return nil, errors.New("steward record holds no capability record")
	}
	return rec.Capabilities, nil
}

// readCapabilityRecord returns the capability record the controller holds for the
// steward. The OSS composite keeps steward records as <flatfile_root>/stewards/<id>.json
// (test/compat/controller.cfg); the file is found by name, not by a fixed root.
func readCapabilityRecord(stewardID string) (*business.StewardCapabilityRecord, error) {
	path, err := dockerExec(controllerContainer, "find", "/app/data", "-path", "*/stewards/"+stewardID+".json", "-print")
	if err != nil {
		return nil, err
	}
	path = strings.TrimSpace(strings.SplitN(path, "\n", 2)[0])
	if path == "" {
		return nil, fmt.Errorf("no steward record file for %s under /app/data", stewardID)
	}
	raw, err := dockerExec(controllerContainer, "cat", path)
	if err != nil {
		return nil, err
	}
	return decodeCapabilityRecord([]byte(raw))
}

// waitForDeclaredProfile polls the durable record until it holds a declared
// profile and returns it.
func waitForDeclaredProfile(stewardID string, timeout time.Duration) (*business.StewardCapabilityRecord, error) {
	var last *business.StewardCapabilityRecord
	lastErr := errors.New("never read")
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		rec, err := readCapabilityRecord(stewardID)
		if err == nil {
			last = rec
			if rec.State == business.StewardCapabilityDeclared {
				return rec, nil
			}
		} else {
			lastErr = err
		}
		time.Sleep(2 * time.Second)
	}
	if last != nil {
		return nil, fmt.Errorf("capability record never reached %q (last state %q)", business.StewardCapabilityDeclared, last.State)
	}
	return nil, lastErr
}

// waitForLogLines polls a container's logs until a line holds every needle and
// returns the matching lines.
func waitForLogLines(container string, timeout time.Duration, needles ...string) []string {
	deadline := time.Now().Add(timeout)
	for {
		if text, err := readContainerLogs(container); err == nil {
			if lines := linesContaining(text, needles...); len(lines) > 0 {
				return lines
			}
		}
		if !time.Now().Before(deadline) {
			return nil
		}
		time.Sleep(2 * time.Second)
	}
}

// containerRoot runs a script in a compat container as root.
func containerRoot(container, script string, timeout time.Duration) (string, error) {
	if err := validContainer(container); err != nil {
		return "", err
	}
	return fleetkit.ContainerShell(container, script, timeout)
}

// copyToFloor copies content to path in the floor container.
func copyToFloor(t *testing.T, dir, name, content, path string) {
	t.Helper()
	local := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(local, []byte(content), 0o600))
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	// #nosec G204 -- docker is a fixed binary; the container and paths are test-controlled
	out, err := exec.CommandContext(ctx, "docker", "cp", local, floorContainer+":"+path).CombinedOutput()
	require.NoError(t, err, "copy %s into %s: %s", name, floorContainer, string(out))
}

// putFloorUnderLauncher moves the floor steward from the compose service's bare
// process to the launcher the floor release shipped: the launcher layout holds the
// unmodified floor binary as the current version, the launcher replaces
// /app/steward as the process the compose restart loop runs, and the bare steward
// is killed so that loop starts it. It returns once the floor steward has opened a
// new control session under the launcher and the controller reports it connected.
func (h *harness) putFloorUnderLauncher(t *testing.T, stewardID string) {
	t.Helper()
	if fleetkit.GetLauncherCurrentVersion(t, floorContainer) != "" {
		// Already launcher-managed (a second scenario in the same stack).
		return
	}

	sessionsBefore := h.StewardLogCount(t, floorContainer, fleetkit.StewardSessionMarkers...)

	dir := t.TempDir()
	copyToFloor(t, dir, "floor-adapter.sh", floorAdapter, stagedAdapterPath)
	copyToFloor(t, dir, "launcher-shim.sh", launcherShim, stagedShimPath)

	versionDir := launcherRoot + "/versions/" + h.floor.Tag
	script := strings.Join([]string{
		"set -e",
		"mkdir -p " + versionDir,
		"cp /app/steward " + versionDir + "/cfgms-steward.real",
		"mv " + stagedAdapterPath + " " + versionDir + "/cfgms-steward",
		"chmod 755 " + versionDir + "/cfgms-steward " + versionDir + "/cfgms-steward.real",
		fmt.Sprintf("printf '{\"current\":\"%s\"}\\n' > %s/state.json", h.floor.Tag, launcherRoot),
		// The token comes from the container's own environment, never from this file.
		"(umask 077; printf %s \"$CFGMS_REGISTRATION_TOKEN\" > " + regTokenFile + ")",
		"chown -R cfgms:cfgms " + launcherRoot + " " + regTokenFile,
		"chmod 755 " + stagedShimPath,
		"cp " + stagedShimPath + " /app/steward.shim",
		"chown cfgms:cfgms /app/steward.shim",
		// Rename, not copy: /app/steward is the running binary.
		"mv /app/steward.shim /app/steward",
		"rm -f " + stagedShimPath,
		// The compose loop restarts ./steward five seconds after this; it now runs the launcher.
		"pkill -9 -x steward || true",
	}, "\n")
	out, err := containerRoot(floorContainer, script, 30*time.Second)
	require.NoError(t, err, "move the floor steward under the launcher: %s", out)

	require.True(t, h.WaitForNewStewardLogEntry(t, floorContainer, sessionsBefore, 120*time.Second, fleetkit.StewardSessionMarkers...),
		"the floor steward opened no new control session under the launcher\n%s", h.floorDiagnostics(""))
	require.True(t, h.WaitForConvergence(t, stewardID, 90*time.Second),
		"floor steward %s is not connected under the launcher\n%s", stewardID, h.floorDiagnostics(""))

	_, err = dockerExec(floorContainer, "pgrep", "-x", "cfgms-launcher")
	require.NoError(t, err, "the launcher is not running in %s\n%s", floorContainer, h.floorDiagnostics(""))
	require.Equal(t, h.floor.Tag, fleetkit.GetLauncherCurrentVersion(t, floorContainer),
		"the launcher is not supervising the floor version")
}

// floorDiagnostics returns the launcher log, the steward log tail and the upgrade
// record state, for a failed upgrade assertion.
func (h *harness) floorDiagnostics(upgradeID string) string {
	launcherLog, _ := dockerExec(floorContainer, "sh", "-c", "tail -n 60 "+launcherLogFile+" 2>&1")
	stewardLog, _ := readContainerLogs(floorContainer)
	procs, _ := dockerExec(floorContainer, "sh", "-c", "ps -eo pid,args | grep -i steward | grep -v grep; true")
	status := ""
	if upgradeID != "" {
		if code, body, err := h.upgradeAPI(http.MethodGet, "/api/v1/stewards/upgrade/"+url.PathEscape(upgradeID), "", nil, 30*time.Second); err == nil {
			status = fmt.Sprintf("upgrade record (HTTP %d): %s", code, string(body))
		}
	}
	return fmt.Sprintf("launcher log tail:\n%s\nsteward processes:\n%s\nsteward log tail:\n%s\n%s",
		launcherLog, procs, fleetkit.LastLines(stewardLog, 60), status)
}

// upgradeFloorToCurrent runs the real upgrade path against the compat stack's
// floor steward, once: it moves the steward under the launcher, builds the
// steward from this tree, publishes it (the compat controller's test mode records
// the approval bound to its SHA-256), dispatches the upgrade and waits until the steward is connected again
// reporting the new version. Every step is a require: a failure here is the
// scenario failing at that step, and later calls fail with it.
func (h *harness) upgradeFloorToCurrent(t *testing.T) *upgradeEvidence {
	t.Helper()
	upgradeRun.Lock()
	defer upgradeRun.Unlock()
	if upgradeRun.evidence != nil {
		return upgradeRun.evidence
	}
	require.False(t, upgradeRun.attempted, "the upgrade of the floor steward was attempted by an earlier scenario and did not complete")
	upgradeRun.attempted = true

	arch := runtime.GOARCH
	stewardID := h.waitForSteward(t, 120*time.Second)
	require.NotEmpty(t, stewardID)
	require.True(t, h.WaitForConvergence(t, stewardID, 90*time.Second),
		"floor steward %s did not reach connected state", stewardID)
	require.True(t, sameVersion(h.reportedVersion(t, stewardID), h.floor.Tag),
		"the upgrade starts from the floor build %s; the controller holds %q", h.floor.Tag, h.reportedVersion(t, stewardID))

	h.putFloorUnderLauncher(t, stewardID)

	bin := buildCurrentSteward(t, currentVersion)
	sum := sha256.Sum256(bin)
	sha := hex.EncodeToString(sum[:])

	// Approval: the compat controller runs in test mode (CFGMS_SEED_TEST_API_KEYS),
	// which records the approval, bound to the SHA-256 of the stored bytes, when the
	// binary is published. The explicit approve route needs a human presence tap
	// and admits no machine principal, so it is not called. Dispatch refuses a
	// binary that has no approval for the stored bytes, so a dispatch that is
	// accepted proves the approval was recorded.
	h.publishBinary(t, currentVersion, arch, bin)

	sessionsBefore := h.StewardLogCount(t, floorContainer, fleetkit.StewardSessionMarkers...)
	upgradeID := h.dispatchUpgrade(t, stewardID, currentVersion, arch)
	t.Logf("dispatched upgrade %s: steward %s, %s -> %s", upgradeID, stewardID, h.floor.Tag, currentVersion)

	status := h.waitForUpgradeStatus(t, upgradeID, upgradeWindow)
	require.Equal(t, "committed", status,
		"the floor steward did not take the push-binary command (upgrade record %q within %v)\n%s",
		status, upgradeWindow, h.floorDiagnostics(upgradeID))

	require.True(t, fleetkit.WaitForLauncherCurrentVersion(t, floorContainer, currentVersion, 60*time.Second),
		"the launcher did not switch to %s\n%s", currentVersion, h.floorDiagnostics(upgradeID))
	require.True(t, h.WaitForNewStewardLogEntry(t, floorContainer, sessionsBefore, 120*time.Second, fleetkit.StewardSessionMarkers...),
		"the launcher did not restart the steward on %s (no new control session)\n%s", currentVersion, h.floorDiagnostics(upgradeID))

	h.requireReportedVersion(t, stewardID, currentVersion, 120*time.Second, upgradeID)
	require.True(t, h.WaitForConvergence(t, stewardID, 90*time.Second),
		"steward %s is not connected after the upgrade\n%s", stewardID, h.floorDiagnostics(upgradeID))

	upgradeRun.evidence = &upgradeEvidence{stewardID: stewardID, upgradeID: upgradeID, sha256: sha}
	return upgradeRun.evidence
}

// requireReportedVersion waits until the controller holds the version the
// steward reported, and fails with the diagnostics when it never does.
func (h *harness) requireReportedVersion(t *testing.T, stewardID, want string, timeout time.Duration, upgradeID string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	got := ""
	for time.Now().Before(deadline) {
		got = h.reportedVersion(t, stewardID)
		if sameVersion(got, want) {
			return
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("steward %s reported %q to the controller, want %s within %v\n%s",
		stewardID, got, want, timeout, h.floorDiagnostics(upgradeID))
}

// TestUpgradeFromFloor proves SC3: the controller upgrades the launcher-managed
// floor steward to a binary built from this tree over the real publish and
// dispatch path. The floor steward receives the push-binary command, stages
// it, restarts under the launcher and reconnects reporting the new version.
//
// It changes the compat stack's steward, so it runs after the scenarios that
// need the floor build (test files run in name order) and shares its result with
// TestCommandsVerifyAfterUpgrade. Broken-binary rollback is covered by the fleet
// tests (test/e2e/fleet/launcher_upgrade_test.go).
func TestUpgradeFromFloor(t *testing.T) {
	h := setupHarness(t)

	ev := h.upgradeFloorToCurrent(t)

	// The steps inside upgradeFloorToCurrent each fail the test with their own
	// message; what remains is what the upgrade must have left behind.
	assert.True(t, sameVersion(h.reportedVersion(t, ev.stewardID), currentVersion),
		"the controller does not hold %s for steward %s", currentVersion, ev.stewardID)

	assert.Equal(t, "committed", h.waitForUpgradeStatus(t, ev.upgradeID, 5*time.Second),
		"the upgrade record must stay committed after the reconnect")

	// Same identity: the upgrade replaced the binary, not the steward.
	assert.Equal(t, ev.stewardID, h.waitForSteward(t, 30*time.Second),
		"the upgraded steward registered as a different steward")

	stewardLog, err := readContainerLogs(floorContainer)
	require.NoError(t, err, "read the steward's log")
	assert.Empty(t, rejectionLines(stewardLog),
		"the steward logged a command rejection across the upgrade")
}

// TestCommandsVerifyAfterUpgrade proves the connection rule picks the current
// payload version once the steward is upgraded (the connection-rule decisions of
// the compatibility contract): after the upgrade the controller's first
// on-connect command and a shared command both verify and execute on the steward,
// and the controller's record shows the steward's declared current profile.
func TestCommandsVerifyAfterUpgrade(t *testing.T) {
	h := setupHarness(t)
	ev := h.upgradeFloorToCurrent(t)

	t.Run("first on-connect command is sent, verified and executed", func(t *testing.T) {
		// The floor steward was never sent this command (the on-connect hook skips
		// a type a floor connection does not support), so a send to this steward
		// is a send on the upgraded connection.
		sent := waitForLogLines(controllerContainer, 90*time.Second,
			"Sent command to steward", ev.stewardID, string(cpTypes.CommandAdvertiseTransportAddress))
		require.NotEmpty(t, sent,
			"the controller never sent %s to the upgraded steward %s; the connection rule did not pick the declared profile",
			cpTypes.CommandAdvertiseTransportAddress, ev.stewardID)

		done := waitForLogLines(floorContainer, 90*time.Second,
			"Command completed successfully", string(cpTypes.CommandAdvertiseTransportAddress))
		require.NotEmpty(t, done,
			"the upgraded steward never completed %s; the command was not verified and executed\n%s",
			cpTypes.CommandAdvertiseTransportAddress, h.floorDiagnostics(ev.upgradeID))
	})

	t.Run("shared command executes and is delivered", func(t *testing.T) {
		body := fmt.Sprintf(postUpgradeConfigTemplate, ev.stewardID)
		status, resp, err := h.api(http.MethodPut,
			"/api/v1/stewards/"+url.PathEscape(ev.stewardID)+"/config", "application/yaml", []byte(body))
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, status, "config upload: %s", string(resp))

		commandID, err := decodeCommandID(resp)
		require.NoError(t, err)

		require.True(t, waitForFile(postUpgradeFilePath, postUpgradeFileContent, 90*time.Second),
			"%s did not appear on the upgraded steward; the sync_config was not executed (command %s)",
			postUpgradeFilePath, commandID)

		rec := h.waitForSettledDelivery(t, commandID, 60*time.Second)
		settled, ok := deliveryOutcome(rec.DeliveryStatus)
		assert.True(t, settled && ok,
			"delivery record %s ended %q (%s), want delivered", commandID, rec.DeliveryStatus, rec.DeliveryDetail)
		assert.Equal(t, "sync_config", rec.Type)
		assert.Equal(t, ev.stewardID, rec.StewardID)
	})

	t.Run("record shows the declared current profile", func(t *testing.T) {
		rec, err := waitForDeclaredProfile(ev.stewardID, 60*time.Second)
		require.NoError(t, err, "the controller's capability record for %s", ev.stewardID)
		assert.Equal(t, business.StewardCapabilityDeclared, rec.State)
		assert.Contains(t, rec.SigningPayloadVersions, cpTypes.SigningPayloadV2,
			"the declared profile lacks the current signing payload version; got %v", rec.SigningPayloadVersions)
		assert.True(t, supportsCommandType(rec, cpTypes.CommandAdvertiseTransportAddress),
			"the declared profile lacks %s; got %v", cpTypes.CommandAdvertiseTransportAddress, rec.CommandTypes)
	})

	t.Run("no command was rejected", func(t *testing.T) {
		stewardLog, err := readContainerLogs(floorContainer)
		require.NoError(t, err, "read the steward's log")
		assert.Empty(t, rejectionLines(stewardLog),
			"the upgraded steward logged a rejection; the controller sent a command it cannot verify")
	})
}

// supportsCommandType reports whether a declared record lists the command type.
func supportsCommandType(rec *business.StewardCapabilityRecord, t cpTypes.CommandType) bool {
	n, ok := cpTypes.CommandTypeNumber(t)
	if !ok {
		return false
	}
	return cpTypes.CapabilityProfile{CommandTypes: rec.CommandTypes}.SupportsCommandType(n)
}

func TestCurrentVersionSortsAboveFloor(t *testing.T) {
	assert.Regexp(t, controllerVersionRe, currentVersion, "the controller must accept the current build's label")

	m, err := LoadManifest(manifestPath)
	require.NoError(t, err)
	c, err := CompareSemver(currentVersion, m.Floor)
	require.NoError(t, err)
	assert.Equal(t, 1, c, "the current build label %s must sort above the floor %s", currentVersion, m.Floor)
}

func TestLauncherScriptsPassTheTokenOnlyInTheFormEachBuildTakes(t *testing.T) {
	// The floor takes --regtoken; the current build takes --regtoken-file, and
	// refuses --regtoken. The launcher is always given the file form.
	assert.Contains(t, floorAdapter, "--regtoken ")
	assert.NotContains(t, floorAdapter, "--regtoken-file")
	assert.Contains(t, launcherShim, "--regtoken-file "+regTokenFile)
	assert.NotContains(t, launcherShim, "--regtoken ")
	assert.True(t, strings.HasPrefix(floorAdapter, "#!/bin/sh\n"))
	assert.True(t, strings.HasPrefix(launcherShim, "#!/bin/sh\n"))
}

func TestBinaryURLPath(t *testing.T) {
	assert.Equal(t, "/api/v1/installer/steward-binaries/v99.0.0-compat-current/linux/amd64",
		binaryURLPath("v99.0.0-compat-current", "amd64"))
	assert.Equal(t, "/api/v1/installer/steward-binaries/v1%2F..%2Fx/linux/amd64",
		binaryURLPath("v1/../x", "amd64"))
}

func TestDecodePublishedSHA256(t *testing.T) {
	got, err := decodePublishedSHA256([]byte(`{"data":{"version":"v1.0.0","sha256":"ab12"}}`))
	require.NoError(t, err)
	assert.Equal(t, "ab12", got)

	_, err = decodePublishedSHA256([]byte(`{"data":{"version":"v1.0.0"}}`))
	require.Error(t, err)
	_, err = decodePublishedSHA256([]byte(`not json`))
	require.Error(t, err)
}

func TestDecodeUpgradeID(t *testing.T) {
	got, err := decodeUpgradeID([]byte(`{"data":{"upgrade_id":"up-1"}}`))
	require.NoError(t, err)
	assert.Equal(t, "up-1", got)

	_, err = decodeUpgradeID([]byte(`{"data":{}}`))
	require.Error(t, err)
	_, err = decodeUpgradeID([]byte(`{`))
	require.Error(t, err)
}

func TestDecodeUpgradeStatus(t *testing.T) {
	got, err := decodeUpgradeStatus([]byte(`{"data":{"status":"committed"}}`))
	require.NoError(t, err)
	assert.Equal(t, "committed", got)

	_, err = decodeUpgradeStatus([]byte(`{"data":{}}`))
	require.Error(t, err)
	_, err = decodeUpgradeStatus([]byte(`[`))
	require.Error(t, err)
}

func TestIsTerminalUpgradeStatus(t *testing.T) {
	for _, s := range []string{"committed", "failed", "rolled_back"} {
		assert.True(t, isTerminalUpgradeStatus(s), s)
	}
	for _, s := range []string{"dispatched", "", "unknown", "timeout"} {
		assert.False(t, isTerminalUpgradeStatus(s), s)
	}
}

func TestDecodeCapabilityRecord(t *testing.T) {
	raw := []byte(`{"id":"s1","capabilities":{"state":"declared","command_types":[1,2,15],"signing_payload_versions":[1,2]}}`)
	rec, err := decodeCapabilityRecord(raw)
	require.NoError(t, err)
	assert.Equal(t, business.StewardCapabilityDeclared, rec.State)
	assert.Equal(t, []uint32{1, 2}, rec.SigningPayloadVersions)
	assert.True(t, supportsCommandType(rec, cpTypes.CommandAdvertiseTransportAddress))
	assert.False(t, supportsCommandType(&business.StewardCapabilityRecord{CommandTypes: []int32{1, 2}},
		cpTypes.CommandAdvertiseTransportAddress), "a floor-range record must not list the command")

	_, err = decodeCapabilityRecord([]byte(`{"id":"s1"}`))
	require.Error(t, err, "a record with no capabilities is not a declared profile")
	_, err = decodeCapabilityRecord([]byte(`nope`))
	require.Error(t, err)
}

func TestContainerRootRejectsNonCompatContainer(t *testing.T) {
	_, err := containerRoot("fleet-steward-1", "true", time.Second)
	require.Error(t, err)
}
