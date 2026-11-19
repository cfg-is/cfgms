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

const (
	// peerUnsupportedEvent is the controller's Info event for a command it did
	// not send because the steward's connection does not support its type
	// (service.EventCommandNotSentPeerUnsupported). Matched as text: this
	// package talks to the controller through its API and logs only.
	peerUnsupportedEvent = "command_not_sent_peer_unsupported"

	// logDirGlob is where both compat containers write their file logs
	// (CFGMS_LOG_DIR in docker-compose.test.yml).
	logDirGlob = "/tmp/cfgms/*.log"
)

// rejectionMarkers are the floor steward's log texts for a command it could not
// verify: a signature that does not match its payload (a payload version it
// cannot read) and a command without a valid operator envelope.
var rejectionMarkers = []string{
	"signature does not match data",
	"unauthenticated command",
}

// afterConnectConfigTemplate is the configuration TestSharedTypeAfterConnect
// syncs: one file resource on the container's /test-workspace tmpfs, distinct
// from the one TestFloorStewardSharedCommand manages so neither test can pass on
// the other's file. The steward ID is filled in at upload time.
const afterConnectConfigTemplate = `steward:
  id: %q
resources:
  - name: compat-after-connect-file
    module: file
    config:
      path: /test-workspace/compat-after-connect-file
      state: present
      content: "compat-after-connect-content\n"
      mode: "0644"
      allowed_base_path: /test-workspace
`

const (
	afterConnectFilePath    = "/test-workspace/compat-after-connect-file"
	afterConnectFileContent = "compat-after-connect-content\n"
)

// readContainerLogs returns the text of every file log in the container's log
// directory. A container that has not written a log yet is an error, not an
// empty result: "no rejection" must not pass on a log that was never read.
func readContainerLogs(container string) (string, error) {
	return dockerExec(container, "sh", "-c", "cat "+logDirGlob)
}

// linesContaining returns the lines of text that contain every one of needles.
func linesContaining(text string, needles ...string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		matched := true
		for _, n := range needles {
			if !strings.Contains(line, n) {
				matched = false
				break
			}
		}
		if matched {
			out = append(out, line)
		}
	}
	return out
}

// rejectionLines returns the lines of a steward log that record a rejected
// command.
func rejectionLines(stewardLog string) []string {
	var out []string
	for _, marker := range rejectionMarkers {
		out = append(out, linesContaining(stewardLog, marker)...)
	}
	return out
}

// waitForPeerUnsupportedSkip polls the controller log until the on-connect
// hooks have logged that they skipped a command for stewardID, and returns the
// matching log lines.
func waitForPeerUnsupportedSkip(stewardID string, timeout time.Duration) []string {
	deadline := time.Now().Add(timeout)
	for {
		if logText, err := readContainerLogs(controllerContainer); err == nil {
			if lines := linesContaining(logText, peerUnsupportedEvent, stewardID); len(lines) > 0 {
				return lines
			}
		}
		if !time.Now().Before(deadline) {
			return nil
		}
		time.Sleep(2 * time.Second)
	}
}

// TestNoSignatureRejectionAfterConnect proves "unsupported is not a signature
// failure" for a steward that cannot be changed. On connect the controller's
// hooks skip every command type the floor steward's connection does not
// support, so the steward is sent nothing it cannot verify. The observable form
// is the steward's own log: once the controller has logged the skip, the floor
// steward has recorded no signature rejection and no unauthenticated command.
//
// Before the skip existed the floor steward logged two rejections per connect,
// a few milliseconds after the on-connect push.
func TestNoSignatureRejectionAfterConnect(t *testing.T) {
	h := setupHarness(t)

	stewardID := h.waitForSteward(t, 120*time.Second)
	require.NotEmpty(t, stewardID)
	require.True(t, h.WaitForConvergence(t, stewardID, 90*time.Second),
		"floor steward %s did not reach connected state", stewardID)

	// The on-connect hooks have run once the controller logs the skip. Waiting
	// on it, not on a sleep, is what makes the log check below a check of the
	// moment the rejections used to appear.
	skips := waitForPeerUnsupportedSkip(stewardID, 90*time.Second)
	require.NotEmpty(t, skips,
		"the controller never logged %s for steward %s; the on-connect hooks did not skip an unsupported command",
		peerUnsupportedEvent, stewardID)

	stewardLog, err := readContainerLogs(floorContainer)
	require.NoError(t, err, "read the floor steward's log")
	require.NotEmpty(t, strings.TrimSpace(stewardLog), "the floor steward's log is empty; nothing was checked")

	assert.Empty(t, rejectionLines(stewardLog),
		"the floor steward logged a rejection after connect; the controller sent it a command it cannot verify")
}

// TestSharedTypeAfterConnect proves skipping the unsupported types left the
// shared ones working: a sync_config sent after connect is verified and
// executed by the floor steward, and the steward logs no rejection for it.
func TestSharedTypeAfterConnect(t *testing.T) {
	h := setupHarness(t)

	stewardID := h.waitForSteward(t, 120*time.Second)
	require.NotEmpty(t, stewardID)
	require.True(t, h.WaitForConvergence(t, stewardID, 90*time.Second),
		"floor steward %s did not reach connected state", stewardID)
	require.NotEmpty(t, waitForPeerUnsupportedSkip(stewardID, 90*time.Second),
		"the on-connect hooks did not run for steward %s", stewardID)

	body := fmt.Sprintf(afterConnectConfigTemplate, stewardID)
	status, resp, err := h.api(http.MethodPut,
		"/api/v1/stewards/"+url.PathEscape(stewardID)+"/config", "application/yaml", []byte(body))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status, "config upload: %s", string(resp))

	commandID, err := decodeCommandID(resp)
	require.NoError(t, err)

	require.True(t, waitForFile(afterConnectFilePath, afterConnectFileContent, 90*time.Second),
		"%s did not appear on the floor steward; the sync_config sent after connect was not executed (command %s)",
		afterConnectFilePath, commandID)

	rec := h.waitForSettledDelivery(t, commandID, 60*time.Second)
	settled, ok := deliveryOutcome(rec.DeliveryStatus)
	assert.True(t, settled && ok,
		"delivery record %s ended %q (%s), want delivered", commandID, rec.DeliveryStatus, rec.DeliveryDetail)
	assert.Equal(t, "sync_config", rec.Type)

	stewardLog, err := readContainerLogs(floorContainer)
	require.NoError(t, err, "read the floor steward's log")
	assert.Empty(t, rejectionLines(stewardLog),
		"the floor steward logged a rejection while executing the sync_config")
}

func TestLinesContaining(t *testing.T) {
	text := "a x y\nb x\nc y\n\nx y z"
	assert.Equal(t, []string{"a x y", "x y z"}, linesContaining(text, "x", "y"))
	assert.Equal(t, []string{"a x y", "b x", "x y z"}, linesContaining(text, "x"))
	assert.Empty(t, linesContaining(text, "absent"))
	assert.Empty(t, linesContaining("", "x"))
}

func TestRejectionLines(t *testing.T) {
	clean := `{"level":"info","msg":"Connected to controller via gRPC transport"}
{"level":"debug","msg":"command executed"}`
	assert.Empty(t, rejectionLines(clean))
	assert.Empty(t, rejectionLines(""))

	rejected := clean + "\n" +
		`{"level":"error","msg":"command rejected","error":"signature does not match data"}` + "\n" +
		`{"level":"error","msg":"command rejected","error":"unauthenticated command"}`
	got := rejectionLines(rejected)
	require.Len(t, got, 2)
	assert.Contains(t, got[0], "signature does not match data")
	assert.Contains(t, got[1], "unauthenticated command")
}

func TestReadContainerLogsRejectsNonCompatContainer(t *testing.T) {
	// An unreadable log is an error, never an empty string a "no rejection"
	// assertion could pass on.
	_, err := readContainerLogs("fleet-controller")
	require.Error(t, err)
}
