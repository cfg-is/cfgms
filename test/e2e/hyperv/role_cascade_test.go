// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build e2e

// Fleet-e2e live validation of the selector-driven role-config cascade delivering
// a Hyper-V virtual switch by tag (#2548, epic #2537). This drives the REAL
// controller cascade end-to-end — it does NOT call the hyperv module's Set
// directly. It authors a role config on the controller, tags a steward, and
// observes the injected resource appear in (and disappear from) that steward's
// controller-RESOLVED effective config, exactly as an operator does from the
// runbook (docs/deployment/hyperv-host-role.md).
//
// Observation goes through the `cfg` CLI against the live controller (admin
// bundle), so the test exercises the tag REST (#2545), the role-config REST
// (#2543), and the selector-driven injection (#2546) as a black box — the same
// surface whose production wiring gaps this story fixed.
//
// The suite is excluded from CI and `make test-complete` by the e2e build tag,
// and skips cleanly unless CFGMS_E2E_ROLE_CASCADE and the required inputs are set.
//
// Inputs (env):
//
//	CFGMS_E2E_ROLE_CASCADE   set to "1" to enable this suite
//	CFGMS_E2E_CFG_BIN        path to a cfg binary built from develop (has `role`/`tag` verbs)
//	CFGMS_ADMIN_BUNDLE       admin bundle for controller auth (read by cfg itself)
//	CFGMS_E2E_STEWARD_ID     a windows-DNA steward to tag (e.g. a cfg-lab node)
//	CFGMS_E2E_ROLE_TENANT    the tenant that owns the steward (e.g. infra-hyperv)
package hyperv_e2e

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

const (
	envRoleCascade = "CFGMS_E2E_ROLE_CASCADE"
	envCfgBin      = "CFGMS_E2E_CFG_BIN"
	envStewardID   = "CFGMS_E2E_STEWARD_ID"
	envRoleTenant  = "CFGMS_E2E_ROLE_TENANT"

	roleName   = "hyperv-host-e2e"
	roleTag    = "hyperv-host-e2e"
	switchName = "cfgms-role-net-e2e"
)

// TestRoleCascade_DeliversVSwitchByTag proves the selector-driven cascade injects
// the internal vswitch resource into a steward's resolved config when it is tagged
// (matching os:windows tag:<tag>), and removes it on untag — no per-steward upload.
func TestRoleCascade_DeliversVSwitchByTag(t *testing.T) {
	if os.Getenv(envRoleCascade) != "1" {
		t.Skipf("set %s=1 to run the live role-cascade e2e", envRoleCascade)
	}
	cfgBin := mustEnv(t, envCfgBin)
	stewardID := mustEnv(t, envStewardID)
	tenant := mustEnv(t, envRoleTenant)

	// Fragment: a uniform internal vswitch, written to a temp file for `role create`.
	fragment := "resources:\n" +
		"  - name: \"" + switchName + "\"\n" +
		"    module: \"hyperv.vswitch\"\n" +
		"    config:\n" +
		"      switch_type: \"internal\"\n" +
		"      state: \"present\"\n"
	fragFile := writeTemp(t, "role-fragment-*.cfg", fragment)

	cfg := func(args ...string) string {
		t.Helper()
		out, err := exec.Command(cfgBin, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("cfg %s failed: %v\n%s", strings.Join(args, " "), err, out)
		}
		return string(out)
	}

	// Author the role and guarantee cleanup (idempotent — ignore delete errors).
	cfg("role", "create", roleName, "--tenant", tenant,
		"--selector", "os:windows tag:"+roleTag, "--config", fragFile)
	t.Cleanup(func() {
		_ = exec.Command(cfgBin, "steward", "tag", "rm", stewardID, roleTag).Run()
		_ = exec.Command(cfgBin, "role", "delete", roleName, "--tenant", tenant).Run()
	})

	// Baseline: untagged steward's resolved config must NOT carry the switch.
	if strings.Contains(cfg("config", "show", stewardID), switchName) {
		t.Fatalf("baseline: %s already present in resolved config before tagging", switchName)
	}

	// Tag → the resolved config now carries the role-injected switch (no upload).
	cfg("steward", "tag", "add", stewardID, roleTag)
	if !strings.Contains(cfg("config", "show", stewardID), switchName) {
		t.Fatalf("after tag: expected %s injected into resolved config, not found", switchName)
	}

	// Untag → the switch leaves the resolved config on the next resolve.
	cfg("steward", "tag", "rm", stewardID, roleTag)
	if strings.Contains(cfg("config", "show", stewardID), switchName) {
		t.Fatalf("after untag: %s still present in resolved config", switchName)
	}
}

func mustEnv(t *testing.T, key string) string {
	t.Helper()
	v := os.Getenv(key)
	if v == "" {
		t.Skipf("%s not set; skipping live role-cascade e2e", key)
	}
	return v
}

func writeTemp(t *testing.T, pattern, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), pattern)
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	_ = f.Close()
	return f.Name()
}
