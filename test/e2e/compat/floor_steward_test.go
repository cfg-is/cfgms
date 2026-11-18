// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package compat

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// floorConfigTemplate is the configuration the scenario syncs to the floor steward: one
// file resource on the container's /test-workspace tmpfs. The steward ID is
// filled in at upload time.
const floorConfigTemplate = `steward:
  id: %q
resources:
  - name: compat-managed-file
    module: file
    config:
      path: /test-workspace/compat-managed-file
      state: present
      content: "compat-managed-content\n"
      mode: "0644"
      allowed_base_path: /test-workspace
`

const (
	managedFilePath    = "/test-workspace/compat-managed-file"
	managedFileContent = "compat-managed-content\n"
)

// TestFloorStewardSharedCommand runs the support floor's real steward binary,
// built from its release tag, against the controller built from this tree and
// proves a shared command verifies and executes on it: the steward registers,
// reports the floor version, and a config sync dispatched by the controller is
// delivered (not rejected) and applied.
//
// If the controller signs a command in a payload version the floor steward
// cannot verify, the delivery record ends rejected and the file never appears —
// the config-sync step fails.
func TestFloorStewardSharedCommand(t *testing.T) {
	h := setupHarness(t)

	var stewardID string

	t.Run("floor steward registers and connects", func(t *testing.T) {
		stewardID = h.waitForSteward(t, 120*time.Second)
		require.NotEmpty(t, stewardID)
		require.True(t, h.WaitForConvergence(t, stewardID, 90*time.Second),
			"floor steward %s did not reach connected state", stewardID)
	})
	require.NotEmpty(t, stewardID, "later steps need the registered steward")

	// [REQUIRED TEST] The version is the one the floor tag's own build recipe
	// stamped into the real binary — not a mock, not a rebuild of this tree.
	t.Run("steward reports the floor version", func(t *testing.T) {
		reported := h.reportedVersion(t, stewardID)
		assert.True(t, sameVersion(reported, h.floor.Tag),
			"controller holds steward version %q; the floor tag is %q", reported, h.floor.Tag)

		out, err := dockerExec(floorContainer, stewardBinary, "--version")
		require.NoError(t, err)
		assert.Contains(t, out, strings.TrimPrefix(h.floor.Tag, "v"),
			"the steward binary in the image must be the floor build")
	})

	// [REQUIRED TEST] Reverting the payload-version negotiation (Issue #6311)
	// makes the controller sign v2, which the floor steward cannot verify: the
	// record ends rejected and the file below never appears.
	t.Run("config sync executes and the delivery is not rejected", func(t *testing.T) {
		body := fmt.Sprintf(floorConfigTemplate, stewardID)
		status, resp, err := h.api(http.MethodPut,
			"/api/v1/stewards/"+url.PathEscape(stewardID)+"/config", "application/yaml", []byte(body))
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, status, "config upload: %s", string(resp))

		commandID, err := decodeCommandID(resp)
		require.NoError(t, err)

		// Applied on the steward: the sync was verified and executed.
		require.True(t, waitForFile(managedFilePath, managedFileContent, 90*time.Second),
			"%s did not appear on the floor steward; the config sync was not executed (command %s)",
			managedFilePath, commandID)

		rec := h.waitForSettledDelivery(t, commandID, 60*time.Second)
		settled, ok := deliveryOutcome(rec.DeliveryStatus)
		assert.True(t, settled && ok,
			"delivery record %s ended %q (%s), want delivered", commandID, rec.DeliveryStatus, rec.DeliveryDetail)
		assert.Equal(t, "sync_config", rec.Type)
		assert.Equal(t, stewardID, rec.StewardID)
	})
}

// waitForFile polls the floor steward container until path holds exactly want.
func waitForFile(path, want string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if got, err := dockerExec(floorContainer, "cat", path); err == nil && got == want {
			return true
		}
		time.Sleep(2 * time.Second)
	}
	return false
}
