// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package trust_test

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
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

// additionalPublisherProbeSource is a throwaway main package built through a
// go build overlay inside this module (so it can import pkg/modules/trust
// without adding a tracked probe directory). It resolves the publisher name
// given as its first argument via the production enforcer's compiled-in
// registry and prints the resolved base64 public key.
const additionalPublisherProbeSource = `package main

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/cfgis/cfgms/pkg/modules/trust"
)

func main() {
	ids, err := trust.NewStewardTrustEnforcer().ResolveAdditionalPublishers(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Print(base64.StdEncoding.EncodeToString(ids[0].PublicKey))
}
`

// additionalPublisherLdflagPath extracts the package path the Makefile's
// STEWARD_BUILD_FLAGS passes to -X for additionalPublisherKeyMaterial.
func additionalPublisherLdflagPath(t *testing.T) string {
	t.Helper()
	makefile, err := os.ReadFile(filepath.Join("..", "..", "..", "Makefile"))
	require.NoError(t, err)
	for _, line := range strings.Split(string(makefile), "\n") {
		if !strings.HasPrefix(line, "STEWARD_BUILD_FLAGS") {
			continue
		}
		m := regexp.MustCompile(`-X\s+(\S+)\.additionalPublisherKeyMaterial=`).FindStringSubmatch(line)
		require.NotNil(t, m, "STEWARD_BUILD_FLAGS must pass -X <pkg>.additionalPublisherKeyMaterial=...")
		return m[1]
	}
	require.FailNow(t, "STEWARD_BUILD_FLAGS not found in Makefile")
	return ""
}

// TestAdditionalPublisherKeyMaterial_LdflagsRoundTrip proves the Makefile's
// -X path for additionalPublisherKeyMaterial names a real symbol: the Go linker
// silently ignores a -X for a missing symbol, so a stale path would ship release
// binaries with an empty additional-publisher registry and no error. It builds a
// probe with the Makefile's path, a test publisher name and a test key, runs it,
// and asserts ResolveAdditionalPublishers resolves that name to that key.
func TestAdditionalPublisherKeyMaterial_LdflagsRoundTrip(t *testing.T) {
	testKey := make([]byte, 32)
	for i := range testKey {
		testKey[i] = 0xCD
	}
	testKeyB64 := base64.StdEncoding.EncodeToString(testKey)
	const publisher = "acme-corp"

	tmpDir := t.TempDir()
	probeSrc := filepath.Join(tmpDir, "main.go")
	require.NoError(t, os.WriteFile(probeSrc, []byte(additionalPublisherProbeSource), 0o600))

	absPkgDir, err := filepath.Abs(".")
	require.NoError(t, err)
	virtualDir := filepath.Join(absPkgDir, "testdata", "probe_additional")
	overlay, err := json.Marshal(map[string]map[string]string{
		"Replace": {filepath.Join(virtualDir, "main.go"): probeSrc},
	})
	require.NoError(t, err)
	overlayPath := filepath.Join(tmpDir, "overlay.json")
	require.NoError(t, os.WriteFile(overlayPath, overlay, 0o600))

	probeName := "probe_additional"
	if runtime.GOOS == "windows" {
		probeName += ".exe"
	}
	probePath := filepath.Join(tmpDir, probeName)

	ldflags := "-X " + additionalPublisherLdflagPath(t) + ".additionalPublisherKeyMaterial=" + publisher + "=" + testKeyB64
	buildOut, err := exec.Command("go", "build",
		"-overlay", overlayPath,
		"-ldflags", ldflags,
		"-o", probePath,
		"github.com/cfgis/cfgms/pkg/modules/trust/testdata/probe_additional",
	).CombinedOutput()
	require.NoError(t, err, "probe build failed: %s", buildOut)

	out, err := exec.Command(probePath, publisher).CombinedOutput()
	require.NoError(t, err, "the Makefile -X path did not inject the registry (resolution failed): %s", out)
	assert.Equal(t, testKeyB64, string(out),
		"ResolveAdditionalPublishers should resolve the key injected through the Makefile's -X path")
}
