// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package compat

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/test/e2e/fleet/fleetkit"
)

const (
	// controllerContainer and floorContainer are the compat compose services
	// (docker-compose.test.yml, `compat` profile).
	controllerContainer = "compat-controller"
	floorContainer      = "compat-steward-floor"

	// controllerURL is the compat controller's HTTPS API as reachable from the
	// test host (compose maps 8091 -> 9080).
	controllerURL = "https://localhost:8091"

	// stewardBinary is the steward's path in the compat steward image.
	stewardBinary = "/app/steward"
)

// harness is the running compat stack: the controller built from this tree and
// the floor steward built from its release tag. It embeds the fleetkit suite for
// the controller-facing helpers that take no container name
// (WaitForConvergence, GetStewardConnectionState); the container-bound fleetkit
// helpers are fleet-only (they allowlist the fleet-* container names), so the
// container-side steps below are this package's own.
type harness struct {
	*fleetkit.FleetTestSuite
	floor Entry
}

// adminBundle is the controller's persisted admin credential bundle.
//
//duplication:justified test/e2e/fleet/fleetkit/framework.go -- fleetkit.adminBundle is unexported and its RebuildClients reads fleet-controller by name; the compat controller has its own container name
type adminBundle struct {
	CertPEM string `yaml:"cert_pem"`
	KeyPEM  string `yaml:"key_pem"`
	CAPEM   string `yaml:"ca_pem"`
}

// newMTLSClient builds the HTTPS client the admin bundle authenticates.
func newMTLSClient(bundleYAML string) (*http.Client, error) {
	var b adminBundle
	if err := yaml.Unmarshal([]byte(bundleYAML), &b); err != nil {
		return nil, fmt.Errorf("parse admin bundle: %w", err)
	}
	if b.CertPEM == "" || b.KeyPEM == "" || b.CAPEM == "" {
		return nil, fmt.Errorf("admin bundle incomplete (cert=%v key=%v ca=%v)",
			b.CertPEM != "", b.KeyPEM != "", b.CAPEM != "")
	}
	pair, err := tls.X509KeyPair([]byte(b.CertPEM), []byte(b.KeyPEM))
	if err != nil {
		return nil, fmt.Errorf("load admin cert/key pair: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(b.CAPEM)) {
		return nil, errors.New("parse CA cert from admin bundle")
	}
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{pair},
			RootCAs:      pool,
			MinVersion:   tls.VersionTLS13,
		}},
	}, nil
}

// validContainer reports whether name is one of the two compat containers: the
// only names a test helper may pass to docker.
func validContainer(name string) error {
	if name != controllerContainer && name != floorContainer {
		return fmt.Errorf("container %q is not a compat container", name)
	}
	return nil
}

// dockerExec runs args in a compat container as its default user and returns
// the combined output.
func dockerExec(container string, args ...string) (string, error) {
	if err := validContainer(container); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	// #nosec G204 -- docker is a fixed binary; the container is allowlisted and the arguments are test-controlled
	out, err := exec.CommandContext(ctx, "docker", append([]string{"exec", container}, args...)...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("docker exec %s %v: %w (output: %s)", container, args, err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// waitContainerHealthy polls docker until the container reports healthy.
func waitContainerHealthy(t *testing.T, container string, timeout time.Duration) {
	t.Helper()
	require.NoError(t, validContainer(container))
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		// #nosec G204 -- docker is a fixed binary; the container is allowlisted
		out, err := exec.CommandContext(ctx, "docker", "ps",
			"--filter", "name="+container,
			"--filter", "health=healthy",
			"--format", "{{.Names}}").CombinedOutput()
		cancel()
		if err == nil && strings.Contains(string(out), container) {
			return
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("container %s did not reach healthy within %v", container, timeout)
}

// loadManifest reads the repository manifest.
func loadManifest(t *testing.T) *Manifest {
	t.Helper()
	m, err := LoadManifest(manifestPath)
	require.NoError(t, err)
	return m
}

// setupHarness attaches to the compose stack `make test-e2e-compat` started: it
// builds the admin client, hands the steward the controller CA it needs to
// verify the controller, and returns the floor entry under test.
func setupHarness(t *testing.T) *harness {
	t.Helper()
	if os.Getenv("CFGMS_COMPAT_TEST") != "1" {
		// Needs the Docker compat stack and a floor-tag steward build; the
		// merge-queue steward-compat-e2e job and `make test-e2e-compat` run it.
		t.Skip("steward compat E2E requires CFGMS_COMPAT_TEST=1 (run via: make test-e2e-compat)")
	}

	m := loadManifest(t)
	var floor *Entry
	for i := range m.Stewards {
		if m.Stewards[i].Tag == m.Floor {
			floor = &m.Stewards[i]
		}
	}
	require.NotNil(t, floor, "manifest floor %s is not listed", m.Floor)

	waitContainerHealthy(t, controllerContainer, 120*time.Second)
	waitContainerHealthy(t, floorContainer, 120*time.Second)

	suite := &fleetkit.FleetTestSuite{
		ControllerURL: controllerURL,
		StewardIDs:    map[string]string{},
		TmpDir:        t.TempDir(),
	}

	bundle, err := dockerExec(controllerContainer, "cat", "/app/data/admin.bundle.yaml")
	require.NoError(t, err, "read compat controller admin bundle")
	suite.HTTPClient, err = newMTLSClient(bundle)
	require.NoError(t, err)

	h := &harness{FleetTestSuite: suite, floor: *floor}
	h.distributeControllerCA(t)
	return h
}

// distributeControllerCA copies the controller's CA to where the steward looks
// for it. The compose steward retries registration every 5 s, so it picks the
// file up on its next attempt. In production the installer does this.
func (h *harness) distributeControllerCA(t *testing.T) {
	t.Helper()
	hostCA := filepath.Join(h.TmpDir, "controller-ca.crt")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	// #nosec G204 -- docker is a fixed binary; the container and paths are test-controlled
	out, err := exec.CommandContext(ctx, "docker", "cp", controllerContainer+":/app/certs/ca/ca.crt", hostCA).CombinedOutput()
	require.NoError(t, err, "extract controller CA: %s", string(out))

	fleetkit.DockerExecRoot(t, floorContainer, "mkdir", "-p", "/etc/cfgms")
	fleetkit.DockerExecRoot(t, floorContainer, "chmod", "755", "/etc/cfgms")

	cpCtx, cpCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cpCancel()
	// #nosec G204 -- docker is a fixed binary; the container and paths are test-controlled
	out, err = exec.CommandContext(cpCtx, "docker", "cp", hostCA, floorContainer+":/etc/cfgms/controller-ca.crt").CombinedOutput()
	require.NoError(t, err, "place CA in %s: %s", floorContainer, string(out))
	fleetkit.DockerExecRoot(t, floorContainer, "chmod", "644", "/etc/cfgms/controller-ca.crt")
}

// api issues a request to the compat controller and returns status and body.
func (h *harness) api(method, path, contentType string, body []byte) (int, []byte, error) {
	u, err := url.JoinPath(h.ControllerURL, path)
	if err != nil {
		return 0, nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := h.HTTPClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	return resp.StatusCode, data, err
}

// stewardEntry is one element of GET /api/v1/stewards.
type stewardEntry struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

// decodeStewardList decodes the data envelope of GET /api/v1/stewards.
func decodeStewardList(body []byte) ([]stewardEntry, error) {
	var env struct {
		Data []stewardEntry `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("decode steward list: %w", err)
	}
	return env.Data, nil
}

// waitForSteward polls the controller until a steward has registered and
// returns its ID. The compat controller serves only the floor steward, so more
// than one entry is a harness fault, not a choice to make.
func (h *harness) waitForSteward(t *testing.T, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		status, body, err := h.api(http.MethodGet, "/api/v1/stewards", "", nil)
		if err == nil && status == http.StatusOK {
			list, derr := decodeStewardList(body)
			require.NoError(t, derr)
			require.LessOrEqual(t, len(list), 1, "the compat controller serves one steward; got %v", list)
			if len(list) == 1 {
				return list[0].ID
			}
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("no steward registered with the compat controller within %v", timeout)
	return ""
}

// reportedVersion returns the version the controller holds for the steward, as
// the steward reported it.
func (h *harness) reportedVersion(t *testing.T, stewardID string) string {
	t.Helper()
	status, body, err := h.api(http.MethodGet, "/api/v1/stewards/"+url.PathEscape(stewardID), "", nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status, "GET steward: %s", string(body))
	var env struct {
		Data stewardEntry `json:"data"`
	}
	require.NoError(t, json.Unmarshal(body, &env))
	return env.Data.Version
}

// sameVersion reports whether a steward-reported version is the release tag.
// Release tags carry a leading "v"; a steward may report it with or without.
func sameVersion(reported, tag string) bool {
	return reported != "" && strings.TrimPrefix(reported, "v") == strings.TrimPrefix(tag, "v")
}

// commandRecord is GET /api/v1/commands/{id}.
type commandRecord struct {
	ID             string `json:"id"`
	Type           string `json:"type"`
	StewardID      string `json:"steward_id"`
	DeliveryStatus string `json:"delivery_status"`
	DeliveryDetail string `json:"delivery_detail"`
}

// decodeCommandRecord decodes the response of GET /api/v1/commands/{id}. The
// handler writes a bare CommandRecordResponse object, not a data envelope.
func decodeCommandRecord(body []byte) (*commandRecord, error) {
	var rec commandRecord
	if err := json.Unmarshal(body, &rec); err != nil {
		return nil, fmt.Errorf("decode command record: %w", err)
	}
	return &rec, nil
}

// decodeCommandID extracts command_id from the PUT /api/v1/stewards/{id}/config
// response.
func decodeCommandID(body []byte) (string, error) {
	var env struct {
		Data struct {
			CommandID string `json:"command_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return "", fmt.Errorf("decode config upload response: %w", err)
	}
	if env.Data.CommandID == "" {
		return "", errors.New("config upload response carries no command_id")
	}
	return env.Data.CommandID, nil
}

// deliveryOutcome classifies a record's delivery status: settled is true once
// the record will not move on its own, ok is true only for a status that means
// the steward took the command (delivered, acknowledged). rejected and failed
// are settled and not ok; pending and unknown statuses are not settled.
func deliveryOutcome(status string) (settled, ok bool) {
	switch status {
	case "delivered", "acknowledged":
		return true, true
	case "rejected", "failed":
		return true, false
	}
	return false, false
}

// waitForSettledDelivery polls the command record until its delivery status
// settles and returns the record.
func (h *harness) waitForSettledDelivery(t *testing.T, commandID string, timeout time.Duration) *commandRecord {
	t.Helper()
	var last *commandRecord
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		status, body, err := h.api(http.MethodGet, "/api/v1/commands/"+url.PathEscape(commandID), "", nil)
		if err == nil && status == http.StatusOK {
			rec, derr := decodeCommandRecord(body)
			require.NoError(t, derr)
			last = rec
			if settled, _ := deliveryOutcome(rec.DeliveryStatus); settled {
				return rec
			}
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("command %s did not settle within %v (last record: %+v)", commandID, timeout, last)
	return nil
}
