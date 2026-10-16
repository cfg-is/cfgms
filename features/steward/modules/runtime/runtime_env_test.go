// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package runtime_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	proto "github.com/cfgis/cfgms/api/proto/modules"
	"github.com/cfgis/cfgms/features/config/stewardtypes"
	"github.com/cfgis/cfgms/features/steward/modules/runtime"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/modules/bundle"
	"github.com/cfgis/cfgms/pkg/modules/contract"
)

var (
	envModuleOnce sync.Once
	envModulePath string
	envModuleErr  error
	envModuleDir  string
)

// buildEnvModule compiles testdata/env_module once per test binary.
func buildEnvModule(t *testing.T) string {
	t.Helper()
	envModuleOnce.Do(func() {
		envModuleDir, envModuleErr = os.MkdirTemp("", "env-module-test-*")
		if envModuleErr != nil {
			return
		}
		envModulePath = filepath.Join(envModuleDir, "env_module"+exeSuffix())
		if out, err := exec.Command("go", "build", "-o", envModulePath, "./testdata/env_module").CombinedOutput(); err != nil {
			envModuleErr = fmt.Errorf("build env_module: %s: %w", out, err)
		}
	})
	require.NoError(t, envModuleErr)
	return envModulePath
}

// makeEnvBundle installs the module and sets the declared env names on the
// in-memory manifest (the installed manifest parser would refuse an invalid
// name, and Start must refuse one that reaches it regardless).
func makeEnvBundle(t *testing.T, binPath string, env []string) *bundle.Bundle {
	t.Helper()
	b, _ := installTestBundle(t, binPath, installOpts{name: "envmod"})
	b.Manifest.Env = env
	return b
}

func getConfig(t *testing.T, h *runtime.ModuleHandle, id string) string {
	t.Helper()
	resp, err := h.Client.Get(context.Background(), &proto.GetRequest{ResourceId: id})
	require.NoError(t, err)
	return resp.ConfigData
}

func randomCanary(t *testing.T) string {
	t.Helper()
	buf := make([]byte, 12)
	_, err := rand.Read(buf)
	require.NoError(t, err)
	return "canary-" + hex.EncodeToString(buf)
}

func TestStart_ModuleGetsOnlyDeclaredAndBaselineEnv(t *testing.T) {
	bin := buildEnvModule(t)
	t.Setenv("VENDOR_A_TEST_UNDECLARED", "undeclared-value")
	t.Setenv("VENDOR_A_TEST_DECLARED", "declared-value")

	rt := runtime.NewModuleRuntime(shortBaseDir(t))
	h, err := rt.Start(makeEnvBundle(t, bin, []string{"VENDOR_A_TEST_DECLARED"}), stewardtypes.ModuleTrustModeBypass, nil)
	require.NoError(t, err)
	defer func() { _ = rt.Stop(h) }()

	assert.Equal(t, "unset", getConfig(t, h, "env:VENDOR_A_TEST_UNDECLARED"))
	assert.Equal(t, "set:declared-value", getConfig(t, h, "env:VENDOR_A_TEST_DECLARED"))
	assert.True(t, strings.HasPrefix(getConfig(t, h, "env:PATH"), "set:"), "PATH is part of the baseline")

	allowed := append(contract.BaselineEnvNames(), "VENDOR_A_TEST_DECLARED", contract.SocketEnvVar)
	for _, name := range strings.Split(getConfig(t, h, "names"), "\n") {
		ok := false
		for _, a := range allowed {
			if strings.EqualFold(a, name) {
				ok = true
				break
			}
		}
		assert.True(t, ok, "variable %q reached the module but is not baseline, declared or contract", name)
	}
}

func TestStart_EnvValuesNeverLogged(t *testing.T) {
	bin := buildEnvModule(t)
	undeclared, declared := randomCanary(t), randomCanary(t)
	t.Setenv("VENDOR_A_TEST_UNDECLARED", undeclared)
	t.Setenv("VENDOR_A_TEST_DECLARED", declared)

	logger := logging.NewCapturingLogger()
	rt := runtime.NewModuleRuntime(shortBaseDir(t))
	rt.SetLogger(logger)

	h, err := rt.Start(makeEnvBundle(t, bin, []string{"VENDOR_A_TEST_DECLARED", "VENDOR_A_TEST_NOT_SET"}), stewardtypes.ModuleTrustModeBypass, nil)
	require.NoError(t, err)
	require.NoError(t, rt.Stop(h))

	_, badErr := rt.Start(makeEnvBundle(t, bin, []string{"VENDOR_A_TEST_DECLARED", "BAD=NAME"}), stewardtypes.ModuleTrustModeBypass, nil)
	require.Error(t, badErr)

	var seen []string
	seen = append(seen, badErr.Error())
	seen = append(seen, logger.InfoMessages...)
	seen = append(seen, logger.WarnMessages...)
	for _, e := range append(append([]logging.LogEntry{}, logger.InfoEntries...), logger.WarnEntries...) {
		for k, v := range e {
			seen = append(seen, k, fmt.Sprint(v))
		}
	}
	for _, s := range seen {
		assert.False(t, strings.Contains(s, undeclared) || strings.Contains(s, declared),
			"an environment value canary was found in a log line or error")
	}

	entry, ok := logger.FindInfo("module process started")
	require.True(t, ok, "start log line missing")
	names, ok := entry["env_names"].([]string)
	require.True(t, ok)
	assert.Contains(t, names, "VENDOR_A_TEST_DECLARED")
	assert.NotContains(t, names, "VENDOR_A_TEST_UNDECLARED")
	assert.Contains(t, names, contract.SocketEnvVar)

	warn, ok := logger.FindWarn("declared module env variable is not set in the parent")
	require.True(t, ok)
	assert.Equal(t, "VENDOR_A_TEST_NOT_SET", warn["env_name"])
}

func TestStart_InvalidEnvNameRefusedBeforeExec(t *testing.T) {
	bin := buildEnvModule(t)
	dir := shortBaseDir(t)
	rt := runtime.NewModuleRuntime(dir)

	for _, bad := range []string{"*", "A=B", "", "1ABC", contract.SocketEnvVar} {
		h, err := rt.Start(makeEnvBundle(t, bin, []string{bad}), stewardtypes.ModuleTrustModeBypass, nil)
		require.Error(t, err, "name %q", bad)
		assert.Nil(t, h)
	}

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Empty(t, entries, "a refused Start must not create a socket directory entry")
}
