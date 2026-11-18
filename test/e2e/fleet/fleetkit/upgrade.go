// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package fleetkit holds the helpers shared by the fleet e2e tests: the suite
// (container control, admin-bundle HTTP client, config upload), the steward
// upgrade helpers and the launcher-supervised steward helpers. It is a regular
// package so other test packages can import it. (Issue #6308)
package fleetkit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/modules/trust"
)

// UpgradePrivKey returns the zero-seed Ed25519 private key for E2E upgrade signing.
// The corresponding public key (O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=) is
// injected into fleet containers via CFGMS_TEST_STEWARD_PUBLISHER_KEY. (Issue #1948)
func UpgradePrivKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(make([]byte, 32))
}

// SignUploadContent signs binary content using the test Ed25519 key.
// The message is the canonical (contentHash, version, platform, arch) composite from
// trust.StewardBinaryMessage, matching trust.VerifyStewardBinarySignature's derivation
// (Issue #2834). Returns a URL-safe base64 (no padding) encoded signature suitable for
// the ?signature= query parameter.
func SignUploadContent(t *testing.T, content []byte, version, platform, arch string) string {
	t.Helper()
	sum := sha256.Sum256(content)
	msg, err := trust.StewardBinaryMessage(hex.EncodeToString(sum[:]), version, platform, arch)
	require.NoError(t, err)
	sig := ed25519.Sign(UpgradePrivKey(), []byte(msg))
	return base64.RawURLEncoding.EncodeToString(sig)
}

// PublishStewardBin uploads content to the fleet controller's steward binary store
// using the upgrade-test API key (tenant: fleet-root/fleet-child-a).
// Set force=true to overwrite an existing entry without 409. Returns HTTP status code.
func PublishStewardBin(t *testing.T, client *http.Client, version string, content []byte, force bool) int {
	t.Helper()
	sig := SignUploadContent(t, content, version, "linux", "amd64")
	u := fmt.Sprintf("%s/api/v1/installer/steward-binaries/%s/linux/amd64?signature=%s",
		FleetControllerHTTP, version, sig)
	if force {
		u += "&force=true"
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, u, bytes.NewReader(content))
	require.NoError(t, err)
	req.Header.Set("X-API-Key", UpgradeAPIKey)
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

// DoDispatchUpgrade sends POST /api/v1/stewards/upgrade and returns (statusCode, upgradeID).
// upgradeID is only meaningful when statusCode == 202.
func DoDispatchUpgrade(t *testing.T, client *http.Client, stewardID, version string) (int, string) {
	t.Helper()
	payload, err := json.Marshal(map[string]string{
		"selector": "id:" + stewardID,
		"version":  version,
		"platform": "linux",
		"arch":     "amd64",
	})
	require.NoError(t, err)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		FleetControllerHTTP+"/api/v1/stewards/upgrade", bytes.NewReader(payload))
	require.NoError(t, err)
	req.Header.Set("X-API-Key", UpgradeAPIKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusAccepted {
		return resp.StatusCode, ""
	}
	var result struct {
		Data struct {
			UpgradeID string `json:"upgrade_id"`
		} `json:"data"`
	}
	_ = json.Unmarshal(body, &result)
	return http.StatusAccepted, result.Data.UpgradeID
}

// DispatchUpgrade dispatches an upgrade to a steward and asserts a 202 response.
func DispatchUpgrade(t *testing.T, client *http.Client, stewardID, version string) string {
	t.Helper()
	code, upgradeID := DoDispatchUpgrade(t, client, stewardID, version)
	require.Equal(t, http.StatusAccepted, code, "dispatch must return 202 Accepted")
	require.NotEmpty(t, upgradeID, "dispatch response must contain upgrade_id")
	return upgradeID
}

// BlobPath returns the filesystem path of a steward binary blob inside the fleet-controller
// container. The path is under the blob_storage root (/app/data/installers) scoped to the
// upgrade-test tenant (fleet-root/fleet-child-a).
func BlobPath(version string) string {
	return fmt.Sprintf("/app/data/installers/fleet-root/fleet-child-a/steward-binaries/%s-linux-amd64",
		version)
}

// BlobMetaPath returns the sidecar metadata JSON path for a steward binary blob.
func BlobMetaPath(version string) string {
	return BlobPath(version) + ".meta.json"
}
