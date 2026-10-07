// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package osquery

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cfgis/cfgms/features/config/stewardtypes"
	"github.com/cfgis/cfgms/features/modules/conformance"
)

// moduleWithFakeOsquery installs a publisher-signed osquery bundle into a temp
// root whose platform binary is an executable fake osquery, and returns a
// module wired to that installation.
//
// No mocks are involved: the bundle carries a real Ed25519 signature over a
// real content hash, and Get() runs the full production
// PreExecVerifier.VerifyBeforeExec path (trust gate + on-disk content re-check)
// before every invocation. Only the CFGMS publisher identity is injected, so
// the test controls the signing key rather than the verification logic.
func moduleWithFakeOsquery(t *testing.T, posixBody, windowsBody string) *osqueryModule {
	t.Helper()

	fake := newFakeOsquery(t, posixBody, windowsBody)
	content, err := os.ReadFile(fake) // #nosec G304 -- test fixture written by newFakeOsquery
	if err != nil {
		t.Fatalf("read fake osquery binary: %v", err)
	}

	root, b, enforcer := installOsqueryBundleAs(t, filepath.Base(fake), content, 0o700)

	return newForTesting(NewPreExecVerifierWithEnforcer(enforcer), Installation{
		Bundle:    b,
		Root:      root,
		TrustMode: stewardtypes.ModuleTrustModeStrict,
	})
}

// moduleReturning returns a module whose bundled osquery binary echoes the
// given JSON rows to stdout, ignoring its stdin and arguments.
//
// jsonRows must be a valid JSON array of objects, e.g.
//
//	`[{"hostname":"myhost","os":"Ubuntu"}]`
func moduleReturning(t *testing.T, jsonRows string) *osqueryModule {
	t.Helper()
	// On POSIX, printf avoids newline-interpretation issues with echo.
	// On Windows, cmd.exe echo adds a trailing newline automatically.
	return moduleWithFakeOsquery(t,
		`printf '%s\n' '`+jsonRows+`'`,
		"echo "+jsonRows+"\n",
	)
}

// osqueryBanned returns the set of banned ephemeral fields for the osquery
// module, extending the conformance package's default list with the
// osquery-specific exclusions documented in ephemeralOsqueryFields.
func osqueryBanned() []string {
	extra := make([]string, 0, len(ephemeralOsqueryFields))
	for k := range ephemeralOsqueryFields {
		extra = append(extra, k)
	}
	return append(conformance.DefaultBannedEphemeralFields, extra...)
}

// ── host:cpu ──────────────────────────────────────────────────────────────────

// cpuJSON is the canned osquery response for a host:cpu query. It omits
// current_clock_speed (ephemeral) and includes an empty cpu_subtype to verify
// that empty-value omission works. cpu_family is deliberately absent: it is
// not a real cpu_info column on any platform (Issue #3570) — see the queryCPU
// comment in get.go.
const cpuJSON = `[{"cpu_brand":"Intel Core i7-10700K","cpu_type":"x86_64","cpu_subtype":"","cpu_physical_cores":"8","cpu_logical_cores":"16","cpu_microcode":"0xf0","model":"Intel(R) Core(TM) i7-10700K CPU @ 3.80GHz","manufacturer":"Intel Corp.","processor_type":"Central Processor","max_clock_speed":"3800","number_of_cores":"8","logical_processors":"16","address_width":"64"}]`

func TestGetCPU_ReturnsExpectedFields(t *testing.T) {
	m := moduleReturning(t, cpuJSON)
	state, err := m.Get(context.Background(), "host:cpu")
	if err != nil {
		t.Fatalf("Get(host:cpu) error: %v", err)
	}
	got := state.AsMap()

	wantPresent := []string{
		"cpu_brand", "cpu_type", "cpu_physical_cores", "cpu_logical_cores",
		"cpu_microcode", "model", "manufacturer", "processor_type",
		"max_clock_speed", "number_of_cores", "logical_processors",
		"address_width",
	}
	for _, k := range wantPresent {
		if _, ok := got[k]; !ok {
			t.Errorf("AsMap() missing expected field %q", k)
		}
	}

	// Empty value from osquery must be omitted.
	if _, ok := got["cpu_subtype"]; ok {
		t.Errorf("AsMap() has %q with empty value — empty fields must be omitted", "cpu_subtype")
	}
}

func TestGetCPU_ExcludesEphemeralFields(t *testing.T) {
	// Include current_clock_speed in the fake response to confirm it is filtered.
	json := `[{"cpu_brand":"Intel","cpu_physical_cores":"4","current_clock_speed":"4000"}]`
	m := moduleReturning(t, json)
	state, err := m.Get(context.Background(), "host:cpu")
	if err != nil {
		t.Fatalf("Get(host:cpu) error: %v", err)
	}
	if _, ok := state.AsMap()["current_clock_speed"]; ok {
		t.Error("AsMap() contains ephemeral field current_clock_speed — must be excluded (ADR-016 clause 4)")
	}
}

func TestGetCPU_ConformanceDeterministic(t *testing.T) {
	m := moduleReturning(t, cpuJSON)
	conformance.AssertDeterministicGet(t, m, "host:cpu")
}

func TestGetCPU_ConformanceNoEphemeralFields(t *testing.T) {
	m := moduleReturning(t, cpuJSON)
	state, err := m.Get(context.Background(), "host:cpu")
	if err != nil {
		t.Fatalf("Get(host:cpu): %v", err)
	}
	conformance.AssertNoEphemeralFields(t, state, osqueryBanned())
}

// ── host:memory ───────────────────────────────────────────────────────────────

const memoryJSON = `[{"physical_memory":"17179869184"}]`

func TestGetMemory_ReturnsExpectedFields(t *testing.T) {
	m := moduleReturning(t, memoryJSON)
	state, err := m.Get(context.Background(), "host:memory")
	if err != nil {
		t.Fatalf("Get(host:memory) error: %v", err)
	}
	got := state.AsMap()
	if _, ok := got["physical_memory"]; !ok {
		t.Error("AsMap() missing expected field physical_memory")
	}
}

func TestGetMemory_ConformanceDeterministic(t *testing.T) {
	m := moduleReturning(t, memoryJSON)
	conformance.AssertDeterministicGet(t, m, "host:memory")
}

func TestGetMemory_ConformanceNoEphemeralFields(t *testing.T) {
	m := moduleReturning(t, memoryJSON)
	state, err := m.Get(context.Background(), "host:memory")
	if err != nil {
		t.Fatalf("Get(host:memory): %v", err)
	}
	conformance.AssertNoEphemeralFields(t, state, osqueryBanned())
}

// ── host:os ───────────────────────────────────────────────────────────────────

// osJSON includes the pinned "os" and "hostname" keys required by
// hostFactFragmentSpecs and every stdlib module.yaml (Issue #3319/#3358).
const osJSON = `[{"os":"Ubuntu 24.04 LTS","version":"24.04","major":"24","minor":"4","patch":"0","build":"","platform":"ubuntu","platform_like":"debian","codename":"noble","arch":"x86_64","hostname":"myhost.example.com"}]`

func TestGetOS_ReturnsHostnameAndOS(t *testing.T) {
	m := moduleReturning(t, osJSON)
	state, err := m.Get(context.Background(), "host:os")
	if err != nil {
		t.Fatalf("Get(host:os) error: %v", err)
	}
	got := state.AsMap()

	// "hostname" and "os" are pinned keys required by every stdlib module.yaml
	// (Issue #3319/#3358). Their presence is load-bearing for DNA assembly.
	hostnameVal, hasHostname := got["hostname"]
	if !hasHostname {
		t.Error("AsMap() missing required field hostname (Issue #3319/#3358)")
	} else if hostnameVal == "" || hostnameVal == nil {
		t.Errorf("AsMap() hostname is empty — must be non-empty (Issue #3319/#3358)")
	}

	osVal, hasOS := got["os"]
	if !hasOS {
		t.Error("AsMap() missing required field os (pinned key contract)")
	} else if osVal == "" || osVal == nil {
		t.Errorf("AsMap() os is empty — must be non-empty")
	}
}

func TestGetOS_OtherExpectedFields(t *testing.T) {
	m := moduleReturning(t, osJSON)
	state, err := m.Get(context.Background(), "host:os")
	if err != nil {
		t.Fatalf("Get(host:os) error: %v", err)
	}
	got := state.AsMap()

	// Other stable OS fields that should be present in the response.
	wantPresent := []string{"version", "major", "minor", "patch", "platform", "platform_like", "codename", "arch"}
	for _, k := range wantPresent {
		if _, ok := got[k]; !ok {
			t.Errorf("AsMap() missing expected field %q", k)
		}
	}

	// Empty fields must be omitted.
	if _, ok := got["build"]; ok {
		t.Errorf("AsMap() has %q with empty value — empty fields must be omitted", "build")
	}
}

func TestGetOS_ConformanceDeterministic(t *testing.T) {
	m := moduleReturning(t, osJSON)
	conformance.AssertDeterministicGet(t, m, "host:os")
}

func TestGetOS_ConformanceNoEphemeralFields(t *testing.T) {
	m := moduleReturning(t, osJSON)
	state, err := m.Get(context.Background(), "host:os")
	if err != nil {
		t.Fatalf("Get(host:os): %v", err)
	}
	conformance.AssertNoEphemeralFields(t, state, osqueryBanned())
}

// ── host:bios ─────────────────────────────────────────────────────────────────

const biosJSON = `[{"hardware_vendor":"LENOVO","hardware_model":"ThinkPad X1 Carbon Gen 9","hardware_version":"ThinkPad X1 Carbon Gen 9","hardware_serial":"PF3XXXXXX","uuid":"a1b2c3d4-e5f6-7890-abcd-ef1234567890","board_vendor":"LENOVO","board_model":"21CBXXXXXX","board_version":"None","board_serial":""}]`

func TestGetBIOS_ReturnsExpectedFields(t *testing.T) {
	m := moduleReturning(t, biosJSON)
	state, err := m.Get(context.Background(), "host:bios")
	if err != nil {
		t.Fatalf("Get(host:bios) error: %v", err)
	}
	got := state.AsMap()

	wantPresent := []string{
		"hardware_vendor", "hardware_model", "hardware_version",
		"hardware_serial", "uuid", "board_vendor", "board_model", "board_version",
	}
	for _, k := range wantPresent {
		if _, ok := got[k]; !ok {
			t.Errorf("AsMap() missing expected field %q", k)
		}
	}

	// Empty board_serial must be omitted.
	if _, ok := got["board_serial"]; ok {
		t.Errorf("AsMap() has %q with empty value — empty fields must be omitted", "board_serial")
	}
}

func TestGetBIOS_ConformanceDeterministic(t *testing.T) {
	m := moduleReturning(t, biosJSON)
	conformance.AssertDeterministicGet(t, m, "host:bios")
}

func TestGetBIOS_ConformanceNoEphemeralFields(t *testing.T) {
	m := moduleReturning(t, biosJSON)
	state, err := m.Get(context.Background(), "host:bios")
	if err != nil {
		t.Fatalf("Get(host:bios): %v", err)
	}
	conformance.AssertNoEphemeralFields(t, state, osqueryBanned())
}

// ── fail-closed: zero rows ────────────────────────────────────────────────────

// TestGet_ZeroRowsFailsClosed is a REQUIRED TEST (issue #3564 AC).
// A query returning zero rows must fail closed — no (even empty) ConfigState
// is emitted. The contract is enforced per kind so a future caller cannot
// accidentally rely on a nil-checked state.
func TestGet_ZeroRowsFailsClosed(t *testing.T) {
	// Bundled fake binary always returns an empty JSON array regardless of query.
	m := moduleWithFakeOsquery(t, `echo '[]'`, "echo []\n")
	ctx := context.Background()

	for _, kind := range []string{"host:cpu", "host:memory", "host:os", "host:bios"} {
		t.Run(kind, func(t *testing.T) {
			state, err := m.Get(ctx, kind)
			if err == nil {
				t.Errorf("Get(%q) with zero rows must return an error — fail-closed contract", kind)
			}
			if state != nil {
				t.Errorf("Get(%q) with zero rows returned non-nil state — must return nil to prevent empty fragment emission", kind)
			}
		})
	}
}

// TestGet_AllFieldsEmptyFailsClosed verifies that a row where all returned
// fields are empty strings also fails closed. This guards against an osquery
// schema change that returns the right columns with empty values.
func TestGet_AllFieldsEmptyFailsClosed(t *testing.T) {
	// Return a row with all fields set to "".
	m := moduleWithFakeOsquery(t,
		`echo '[{"physical_memory":""}]'`,
		"echo [{\"physical_memory\":\"\"}]\n",
	)
	state, err := m.Get(context.Background(), "host:memory")
	if err == nil {
		t.Error("Get(host:memory) with all-empty fields must return an error — fail-closed contract")
	}
	if state != nil {
		t.Error("Get(host:memory) with all-empty fields returned non-nil state — must return nil")
	}
}

// ── unknown kind ──────────────────────────────────────────────────────────────

func TestGet_UnknownKindReturnsError(t *testing.T) {
	m := moduleReturning(t, cpuJSON)
	unknownKinds := []string{"", "host:unknown", "arbitrary", "cpu", "os"}
	ctx := context.Background()
	for _, kind := range unknownKinds {
		t.Run(kind, func(t *testing.T) {
			state, err := m.Get(ctx, kind)
			if err == nil {
				t.Errorf("Get(%q) must return an error for unsupported kind", kind)
			}
			if state != nil {
				t.Errorf("Get(%q) returned non-nil state for unsupported kind — must return nil", kind)
			}
		})
	}
}

// TestGet_UnknownKindRejectedBeforeBinaryResolution proves the kind check runs
// ahead of binary resolution: with no installation configured at all, an
// unsupported kind still fails with the kind error rather than the
// installation error, so no verification work and no process start can be
// triggered by an unsupported kind.
func TestGet_UnknownKindRejectedBeforeBinaryResolution(t *testing.T) {
	m := newForTesting(nil, Installation{})
	_, err := m.Get(context.Background(), "host:unknown")
	if err == nil {
		t.Fatal("Get(host:unknown) must return an error")
	}
	if errors.Is(err, ErrNoVerifiedInstallation) {
		t.Errorf("Get(host:unknown) resolved the binary before validating the kind: %v", err)
	}
	if !contains(err.Error(), "unsupported fact kind") {
		t.Errorf("error = %q, want an unsupported-kind error", err)
	}
}

// ── fail-closed: binary integrity ────────────────────────────────────────────

// TestGet_NoVerifiedInstallationFailsClosed is the regression test for the
// finding that Get() executed a binary with no pre-exec integrity verification.
// A module with no installed bundle must refuse to run anything rather than
// falling back to a host-installed osquery at a well-known path.
func TestGet_NoVerifiedInstallationFailsClosed(t *testing.T) {
	m := New(Installation{})
	ctx := context.Background()

	for _, kind := range []string{"host:cpu", "host:memory", "host:os", "host:bios"} {
		t.Run(kind, func(t *testing.T) {
			state, err := m.Get(ctx, kind)
			if err == nil {
				t.Fatalf("Get(%q) with no verified installation must fail closed", kind)
			}
			if !errors.Is(err, ErrNoVerifiedInstallation) {
				t.Errorf("error = %v, want it to wrap ErrNoVerifiedInstallation", err)
			}
			if state != nil {
				t.Errorf("Get(%q) returned non-nil state without a verified binary", kind)
			}
		})
	}
}

// TestGet_TamperedBinaryRefusedOnNextCall proves Get() re-verifies before every
// invocation rather than once at construction: the first call succeeds, the
// binary is then replaced on disk, and the next call is refused.
func TestGet_TamperedBinaryRefusedOnNextCall(t *testing.T) {
	m := moduleReturning(t, cpuJSON)
	ctx := context.Background()

	if _, err := m.Get(ctx, "host:cpu"); err != nil {
		t.Fatalf("first Get(host:cpu) on an untampered bundle failed: %v", err)
	}

	binPath, err := m.verifiedBinPath()
	if err != nil {
		t.Fatalf("resolve verified binary path: %v", err)
	}
	// Replace the verified binary with one that reports different facts.
	tampered := "#!/bin/sh\nprintf '%s\\n' '[{\"cpu_brand\":\"ATTACKER\"}]'\n"
	if err := os.WriteFile(binPath, []byte(tampered), 0o700); err != nil { // #nosec G302 -- fixture must stay executable
		t.Fatalf("tamper with installed binary: %v", err)
	}

	state, err := m.Get(ctx, "host:cpu")
	if err == nil {
		t.Fatal("Get(host:cpu) executed a binary modified after installation — it must be refused")
	}
	if state != nil {
		t.Error("Get(host:cpu) returned non-nil state from a tampered binary")
	}
	if !contains(err.Error(), "refused") {
		t.Errorf("error = %q, want the content-hash refusal from VerifyBeforeExec", err)
	}
}

// TestGet_UntrustedBundleRefused proves the trust gate is on the Get() path:
// an unsigned bundle in strict mode is refused before any process starts.
func TestGet_UntrustedBundleRefused(t *testing.T) {
	m := moduleReturning(t, cpuJSON)
	m.install.Bundle.Signatures = nil

	state, err := m.Get(context.Background(), "host:cpu")
	if err == nil {
		t.Fatal("Get(host:cpu) executed a binary from an unsigned bundle in strict mode")
	}
	if state != nil {
		t.Error("Get(host:cpu) returned non-nil state for an untrusted bundle")
	}
}

// ── query-source scan tests ───────────────────────────────────────────────────

// TestQueryOS_ContainsOSAlias verifies that the queryOS constant contains the
// os_version.name AS os alias — this alias is load-bearing for the pinned "os"
// key contract (Issue #3319/#3358) and must never be silently removed.
func TestQueryOS_ContainsOSAlias(t *testing.T) {
	if queryOS == "" {
		t.Fatal("queryOS is empty")
	}
	// The alias can appear in multiple equivalent forms; check for the core token.
	hasAlias := false
	for _, form := range []string{"name AS os", "name as os"} {
		if containsIgnoreCase(queryOS, form) {
			hasAlias = true
			break
		}
	}
	if !hasAlias {
		t.Error("queryOS does not contain 'name AS os' alias — the 'os' key in host:os " +
			"is a pinned contract required by every stdlib module.yaml (Issue #3319/#3358)")
	}
}

// TestQueryOS_ContainsHostname verifies that the queryOS constant selects the
// hostname column — load-bearing for the pinned "hostname" key contract.
func TestQueryOS_ContainsHostname(t *testing.T) {
	if !containsIgnoreCase(queryOS, "hostname") {
		t.Error("queryOS does not select hostname — the 'hostname' key in host:os " +
			"is a pinned contract required by every stdlib module.yaml (Issue #3319/#3358)")
	}
}

// TestQueryCPU_ExcludesCurrentClockSpeed verifies that the queryCPU constant
// does not select current_clock_speed — the ephemeral exclusion is visible at
// the query level and must not be added back accidentally.
func TestQueryCPU_ExcludesCurrentClockSpeed(t *testing.T) {
	if containsIgnoreCase(queryCPU, "current_clock_speed") {
		t.Error("queryCPU contains current_clock_speed — this field is ephemeral " +
			"(changes with CPU throttling) and must be excluded per ADR-016 clause 4")
	}
}

// ── hostState inert method coverage ──────────────────────────────────────────

// TestHostState_InertMethods verifies the documented nil/empty return values
// of the four inert ConfigState methods on hostState. These methods are
// intentionally no-ops for a read-only osquery-derived fact snapshot — they
// satisfy the interface contract but hold no operator state.
func TestHostState_InertMethods(t *testing.T) {
	s := &hostState{data: map[string]string{"cpu_brand": "Intel"}}

	yaml, err := s.ToYAML()
	if yaml != nil || err != nil {
		t.Errorf("ToYAML() = %v, %v; want nil, nil — inert method for read-only state", yaml, err)
	}

	if err := s.FromYAML(nil); err != nil {
		t.Errorf("FromYAML(nil) = %v; want nil — inert method for read-only state", err)
	}

	if err := s.Validate(); err != nil {
		t.Errorf("Validate() = %v; want nil — snapshot was validated by the producing query", err)
	}

	if fields := s.GetManagedFields(); fields != nil {
		t.Errorf("GetManagedFields() = %v; want nil — hostState declares no field ownership", fields)
	}
}

// containsIgnoreCase reports whether s contains substr in a case-insensitive
// comparison. Used for SQL query source-scan tests where SQL keywords may be
// uppercase or lowercase depending on authoring convention.
func containsIgnoreCase(s, substr string) bool {
	sLower := toLower(s)
	substrLower := toLower(substr)
	return contains(sLower, substrLower)
}

func toLower(s string) string {
	b := make([]byte, len(s))
	for i := range s {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

func contains(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
