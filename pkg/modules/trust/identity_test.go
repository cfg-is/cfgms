// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package trust_test

import (
	"encoding/base64"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCFGMSPublisherKey_LdflagsRoundTrip verifies that the ldflags injection path
// for cfgmsPublisherPublicKey actually round-trips: build the probe binary with a
// non-placeholder key baked in via -ldflags, run it, and assert the output equals
// the injected key — proving the injection path works end to end, not just that the
// Makefile string is syntactically well-formed.
func TestCFGMSPublisherKey_LdflagsRoundTrip(t *testing.T) {
	// Use a known 32-byte test key (all 0xAB bytes — distinct from the all-zero placeholder).
	testKey := make([]byte, 32)
	for i := range testKey {
		testKey[i] = 0xAB
	}
	testKeyB64 := base64.StdEncoding.EncodeToString(testKey)

	tmpDir := t.TempDir()
	probeName := "probe"
	if runtime.GOOS == "windows" {
		probeName = "probe.exe"
	}
	probePath := filepath.Join(tmpDir, probeName)

	ldflags := "-X github.com/cfgis/cfgms/pkg/modules/trust.cfgmsPublisherPublicKey=" + testKeyB64

	// Build the probe binary with the test key baked in via ldflags.
	buildOut, err := exec.Command("go", "build",
		"-ldflags", ldflags,
		"-o", probePath,
		"github.com/cfgis/cfgms/pkg/modules/trust/testdata/probe",
	).CombinedOutput()
	require.NoError(t, err, "probe build failed: %s", buildOut)

	// Run the probe and assert it prints back the injected key exactly.
	out, err := exec.Command(probePath).Output()
	require.NoError(t, err, "probe run failed")

	assert.Equal(t, testKeyB64, string(out),
		"CFGMSPublisherIdentity().PublicKey should equal the injected ldflags key")
}
