// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// vswitchModuleWithTransport creates a hypervModule wired with the given transport
// and tenantID for vSwitch operation tests.
func vswitchModuleWithTransport(transport winrmTransport, tenantID string) *hypervModule {
	return &hypervModule{
		executor:  &stubHypervExecutor{},
		transport: transport,
		tenantID:  tenantID,
		vms:       make(map[string]VMConfig),
		vswitches: make(map[string]VSwitchConfig),
		detector:  &fakeDetector{result: true},
	}
}

// ─── Exact host-name tests ─────────────────────────────────────────────────────

// TestVSwitchHostName_IsExactConfigName verifies that the host-side switch name is
// the exact name the admin specifies — CFGMS adds no prefix or suffix, regardless
// of tenant_id. This is the founder directive: the actual switch name on the host
// must equal what is in the cfg.
func TestVSwitchHostName_IsExactConfigName(t *testing.T) {
	transport := &testWinRMTransport{}
	m := vswitchModuleWithTransport(transport, "root/msp-a")

	cfg := &VSwitchConfig{Name: "myswitch", State: "absent"}
	require.NoError(t, m.Set(context.Background(), "vswitch:myswitch", cfg))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	// absent path: call 0 = getVSwitch (before-snapshot), call 1 = Remove-VMSwitch.
	require.Len(t, calls, 2, "getVSwitch + Remove-VMSwitch expected for absent path")
	require.NotEmpty(t, calls[1].args)
	assert.Equal(t, "myswitch", calls[1].args[0],
		"host-side switch name must be the exact config name — no cfgms- prefix or tenant namespacing")
}

// ─── VSwitchConfig.Validate tests ─────────────────────────────────────────────

// TestVSwitchConfig_Validate_RejectsNATType verifies that "nat" switch type is rejected.
func TestVSwitchConfig_Validate_RejectsNATType(t *testing.T) {
	cfg := &VSwitchConfig{Name: "myswitch", SwitchType: "nat"}
	err := cfg.Validate()
	require.Error(t, err, "nat switch type must be rejected")
	assert.ErrorIs(t, err, ErrInvalidSwitchType)
}

// TestVSwitchConfig_Validate_ExternalRequiresAdapter verifies that external type with
// empty NetAdapterName is rejected.
func TestVSwitchConfig_Validate_ExternalRequiresAdapter(t *testing.T) {
	cfg := &VSwitchConfig{Name: "myswitch", SwitchType: "external", NetAdapterName: ""}
	err := cfg.Validate()
	require.Error(t, err, "external switch without NetAdapterName must be rejected")
	assert.ErrorIs(t, err, ErrExternalRequiresAdapter)
}

// TestVSwitchConfig_Validate_AcceptsDoubleUnderscore verifies that __ in a switch
// name is now accepted — the underscore is in the allowlist charset and there is
// no longer a reserved separator (host names are exact, never namespaced).
func TestVSwitchConfig_Validate_AcceptsDoubleUnderscore(t *testing.T) {
	cfg := &VSwitchConfig{Name: "my__switch", SwitchType: "internal"}
	require.NoError(t, cfg.Validate(),
		"switch name containing __ must be accepted now that names are not namespaced")
}

// TestVSwitchConfig_Validate_RejectsInvalidSwitchType verifies that unknown types
// other than external/internal/private are rejected.
func TestVSwitchConfig_Validate_RejectsInvalidSwitchType(t *testing.T) {
	for _, typ := range []string{"nat", "bridge", "macvtap", "", "EXTERNAL"} {
		cfg := &VSwitchConfig{Name: "sw", SwitchType: typ}
		err := cfg.Validate()
		require.Error(t, err, "type %q must be rejected", typ)
		assert.ErrorIs(t, err, ErrInvalidSwitchType, "type %q should return ErrInvalidSwitchType", typ)
	}
}

// TestVSwitchConfig_Validate_RejectsInternalWithAdapter verifies that internal/private
// types with a non-empty NetAdapterName are rejected.
func TestVSwitchConfig_Validate_RejectsInternalWithAdapter(t *testing.T) {
	for _, typ := range []string{"internal", "private"} {
		cfg := &VSwitchConfig{Name: "sw", SwitchType: typ, NetAdapterName: "Ethernet"}
		err := cfg.Validate()
		require.Error(t, err, "%s switch with NetAdapterName must be rejected", typ)
		assert.ErrorIs(t, err, ErrAdapterForbiddenForNonExternal)
	}
}

// TestVSwitchConfig_Validate_AcceptsExternalWithAdapter verifies that external type
// with a non-empty NetAdapterName is accepted and AllowManagementOS is forced to true.
func TestVSwitchConfig_Validate_AcceptsExternalWithAdapter(t *testing.T) {
	cfg := &VSwitchConfig{Name: "ext-switch", SwitchType: "external", NetAdapterName: "Ethernet"}
	require.NoError(t, cfg.Validate())
	assert.True(t, cfg.AllowManagementOS, "AllowManagementOS must be forced to true for external switches")
}

// TestVSwitchConfig_Validate_AcceptsInternalAndPrivate verifies that internal and
// private types without adapters are accepted and AllowManagementOS is false.
func TestVSwitchConfig_Validate_AcceptsInternalAndPrivate(t *testing.T) {
	for _, typ := range []string{"internal", "private"} {
		cfg := &VSwitchConfig{Name: "sw", SwitchType: typ}
		require.NoError(t, cfg.Validate(), "type %s must be accepted", typ)
		assert.False(t, cfg.AllowManagementOS, "AllowManagementOS must be false for %s switches", typ)
	}
}

// TestVSwitchConfig_Validate_RejectsInjectionChars verifies that switch names containing
// PowerShell injection characters are rejected by the allowlist regex.
func TestVSwitchConfig_Validate_RejectsInjectionChars(t *testing.T) {
	payloads := []string{
		"'; Remove-VMSwitch -Force; '",
		"$(Remove-VMSwitch)",
		"`Remove-VMSwitch",
		"sw\x00name",
		"sw‐name", // U+2010 Unicode hyphen lookalike
	}
	for _, payload := range payloads {
		cfg := &VSwitchConfig{Name: payload, SwitchType: "internal"}
		err := cfg.Validate()
		require.Error(t, err, "payload %q must be rejected", payload)
		assert.ErrorIs(t, err, ErrInvalidSwitchName, "payload %q should return ErrInvalidSwitchName", payload)
	}
}

// TestVSwitchConfig_Validate_AcceptsSpacesInName verifies that switch names with spaces
// are accepted (consistent with Hyper-V naming convention).
func TestVSwitchConfig_Validate_AcceptsSpacesInName(t *testing.T) {
	cfg := &VSwitchConfig{Name: "Default Switch", SwitchType: "internal"}
	require.NoError(t, cfg.Validate())
}

// ─── VSwitchConfig interface tests ────────────────────────────────────────────

// TestVSwitchConfig_AsMap verifies that AsMap includes all configuration fields.
func TestVSwitchConfig_AsMap(t *testing.T) {
	cfg := &VSwitchConfig{
		Name:              "ext-sw",
		SwitchType:        "external",
		NetAdapterName:    "Ethernet",
		AllowManagementOS: true,
		State:             "present",
	}
	m := cfg.AsMap()
	assert.Equal(t, "ext-sw", m["name"])
	assert.Equal(t, "external", m["switch_type"])
	assert.Equal(t, "Ethernet", m["net_adapter_name"])
	assert.Equal(t, true, m["allow_management_os"])
	assert.Equal(t, "present", m["state"])
}

// TestVSwitchConfig_YAML verifies round-trip YAML serialization.
func TestVSwitchConfig_YAML(t *testing.T) {
	original := &VSwitchConfig{
		Name:              "ext-switch",
		SwitchType:        "external",
		NetAdapterName:    "Ethernet",
		AllowManagementOS: true,
		State:             "present",
	}
	data, err := original.ToYAML()
	require.NoError(t, err)

	decoded := &VSwitchConfig{}
	require.NoError(t, decoded.FromYAML(data))
	assert.Equal(t, original, decoded)
}

// ─── Injection defense tests ───────────────────────────────────────────────────

// TestVSwitchInjectionDefense verifies that the (exact) switch name is transmitted
// as a WinRM ArgumentList parameter during create/delete, never interpolated into the
// PowerShell script block text. This satisfies the AC test name alias.
func TestVSwitchInjectionDefense(t *testing.T) {
	const tenantID = "ops"
	const switchName = "corp-net"

	transport := &testWinRMTransport{}
	m := vswitchModuleWithTransport(transport, tenantID)

	cfg := &VSwitchConfig{Name: switchName, SwitchType: "internal", State: "absent"}
	err := m.Set(context.Background(), "vswitch:"+switchName, cfg)
	require.NoError(t, err)

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	// absent path: call 0 = getVSwitch, call 1 = Remove-VMSwitch.
	require.Len(t, calls, 2, "getVSwitch + Remove-VMSwitch expected for absent path")
	call := calls[1]

	// Exact name must appear in args, not scriptBlock.
	require.Len(t, call.args, 1)
	assert.Equal(t, switchName, call.args[0], "exact switch name must be in args[0]")
	assert.NotContains(t, call.scriptBlock, switchName,
		"switch name must NOT appear in scriptBlock text")
}

// ─── Get not found tests ───────────────────────────────────────────────────────

// TestGet_VSwitch_ReturnsAbsentWhenMissing verifies that Get returns a
// state:"absent" ConfigState (no error) when the remote host reports the
// switch does not exist. This matches the contract honored by the directory
// and file modules and lets the unified executor detect drift against a
// desired state:"present" configuration.
func TestGet_VSwitch_ReturnsAbsentWhenMissing(t *testing.T) {
	transport := &testWinRMTransport{output: `{"found":false}`}
	m := vswitchModuleWithTransport(transport, "t")

	state, err := m.Get(context.Background(), "vswitch:nonexistent")
	require.NoError(t, err, "missing resource must NOT be reported as an error — caller would interpret it as a Get failure")
	require.NotNil(t, state)
	assert.Equal(t, "absent", state.AsMap()["state"],
		"missing vSwitch must surface as state:absent so the executor can drive Set")
}

// TestGet_VSwitch_WrapsTransportError verifies that transport-layer failures
// are returned as wrapped errors (NOT as ErrVSwitchNotFound) so the executor
// can distinguish "absent" from "transport broken". Conflating the two was the
// root cause of F14 — every failed Get aborted the Set even though the host
// was simply offline.
func TestGet_VSwitch_WrapsTransportError(t *testing.T) {
	transport := &testWinRMTransport{execErr: errors.New("winrm: connection refused")}
	m := vswitchModuleWithTransport(transport, "t")

	_, err := m.Get(context.Background(), "vswitch:unreachable")
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrVSwitchNotFound,
		"transport errors must NOT be reported as ErrVSwitchNotFound")
	assert.Contains(t, err.Error(), "winrm: connection refused",
		"underlying transport error message must be preserved in the chain")
}

// TestGet_VSwitch_NoTransport verifies that Get returns ErrVSwitchNotFound when the
// module has no transport configured.
func TestGet_VSwitch_NoTransport(t *testing.T) {
	m := &hypervModule{
		executor:  &stubHypervExecutor{},
		vms:       make(map[string]VMConfig),
		vswitches: make(map[string]VSwitchConfig),
		detector:  &fakeDetector{result: true},
	}
	_, err := m.Get(context.Background(), "vswitch:myswitch")
	assert.ErrorIs(t, err, ErrVSwitchNotFound)
}

// TestGet_VSwitch_ReturnsConfig verifies that Get returns a properly mapped VSwitchConfig
// when the transport returns valid switch JSON.
func TestGet_VSwitch_ReturnsConfig(t *testing.T) {
	const tenantID = "prod"
	const switchName = "corp-external"

	transport := &testWinRMTransport{
		output: `{"found":true,"Name":"` + switchName + `","SwitchType":"External"}`,
	}
	m := vswitchModuleWithTransport(transport, tenantID)

	state, err := m.Get(context.Background(), "vswitch:"+switchName)
	require.NoError(t, err)
	require.NotNil(t, state)

	cfg, ok := state.(*VSwitchConfig)
	require.True(t, ok, "Get must return *VSwitchConfig")
	assert.Equal(t, switchName, cfg.Name, "Name must be the exact config name")
	assert.Equal(t, "external", cfg.SwitchType, "SwitchType 'External' must map to 'external'")
	assert.Equal(t, "present", cfg.State)
}

// ─── Create vSwitch tests ─────────────────────────────────────────────────────

// TestSet_VSwitch_CreateInternal verifies that Set creates an internal switch and
// passes the prefixed switch name via args (not embedded in scriptBlock).
func TestSet_VSwitch_CreateInternal(t *testing.T) {
	transport := &testWinRMTransport{}
	m := vswitchModuleWithTransport(transport, "dev")

	cfg := &VSwitchConfig{
		Name:       "dev-net",
		SwitchType: "internal",
		State:      "present",
	}

	err := m.Set(context.Background(), "vswitch:dev-net", cfg)
	require.NoError(t, err)

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	require.Len(t, calls, 1)
	call := calls[0]

	assert.Contains(t, call.scriptBlock, "New-VMSwitch",
		"create must invoke New-VMSwitch")
	assert.Contains(t, call.scriptBlock, "Internal",
		"internal switch creation must include SwitchType Internal")

	require.Len(t, call.args, 1, "only Name should be in psArgs for internal switch")
	assert.Equal(t, "dev-net", call.args[0],
		"exact switch name must be in args[0]")
	assert.NotContains(t, call.scriptBlock, "dev-net",
		"name must not appear in scriptBlock")
}

// TestSet_VSwitch_CreateExternal verifies that Set creates an external switch and
// passes both switch name and adapter name via args.
func TestSet_VSwitch_CreateExternal(t *testing.T) {
	transport := &testWinRMTransport{}
	m := vswitchModuleWithTransport(transport, "ops")

	cfg := &VSwitchConfig{
		Name:           "corp-net",
		SwitchType:     "external",
		NetAdapterName: "Ethernet",
		State:          "present",
	}

	err := m.Set(context.Background(), "vswitch:corp-net", cfg)
	require.NoError(t, err)

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	require.Len(t, calls, 1)
	call := calls[0]

	assert.Contains(t, call.scriptBlock, "New-VMSwitch",
		"create must invoke New-VMSwitch")
	assert.Contains(t, call.scriptBlock, "External",
		"external switch creation must include SwitchType External")
	assert.Contains(t, call.scriptBlock, "$true",
		"external switch must include AllowManagementOS $true")

	// Keys sorted: "Name" < "NetAdapter"
	require.Len(t, call.args, 2, "Name and NetAdapter should be in psArgs for external switch")
	assert.Equal(t, "corp-net", call.args[0], "exact switch name in args[0]")
	assert.Equal(t, "Ethernet", call.args[1], "adapter name in args[1]")

	// Neither value should appear in the scriptBlock
	assert.NotContains(t, call.scriptBlock, "corp-net")
	assert.NotContains(t, call.scriptBlock, "Ethernet")
}

// TestSet_VSwitch_DeleteAbsent verifies that Set with state "absent" calls Remove-VMSwitch
// and passes the prefixed switch name as a WinRM argument (not interpolated into script).
func TestSet_VSwitch_DeleteAbsent(t *testing.T) {
	transport := &testWinRMTransport{}
	m := vswitchModuleWithTransport(transport, "ops")

	cfg := &VSwitchConfig{Name: "old-switch", State: "absent"}
	err := m.Set(context.Background(), "vswitch:old-switch", cfg)
	require.NoError(t, err)

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	// absent path: call 0 = getVSwitch (before-snapshot), call 1 = Remove-VMSwitch.
	require.Len(t, calls, 2, "getVSwitch + Remove-VMSwitch expected for absent path")
	call := calls[1]

	assert.Contains(t, call.scriptBlock, "Remove-VMSwitch",
		"Set with state absent must invoke Remove-VMSwitch")

	require.Len(t, call.args, 1)
	assert.Equal(t, "old-switch", call.args[0],
		"exact switch name must be in args[0] for Remove")
	assert.NotContains(t, call.scriptBlock, "old-switch",
		"name must not be interpolated in scriptBlock")
}

// TestSet_VSwitch_ValidationRejectsNAT verifies that setVSwitch rejects nat type
// before any WinRM call is made.
func TestSet_VSwitch_ValidationRejectsNAT(t *testing.T) {
	transport := &testWinRMTransport{}
	m := vswitchModuleWithTransport(transport, "t")

	cfg := &VSwitchConfig{Name: "natswitch", SwitchType: "nat"}
	err := m.Set(context.Background(), "vswitch:natswitch", cfg)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidSwitchType)

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()
	assert.Empty(t, calls, "transport must not be called when validation rejects the input")
}

// TestSet_VSwitch_CreateTransportError verifies that transport failures in createVSwitch
// surface as wrapped errors, not silently swallowed.
func TestSet_VSwitch_CreateTransportError(t *testing.T) {
	transport := &testWinRMTransport{execErr: errors.New("winrm: access denied")}
	m := vswitchModuleWithTransport(transport, "t")

	cfg := &VSwitchConfig{Name: "sw", SwitchType: "internal", State: "present"}
	err := m.Set(context.Background(), "vswitch:sw", cfg)
	require.Error(t, err, "transport error must be surfaced from createVSwitch")
	assert.Contains(t, err.Error(), "create vswitch", "error must identify the create operation")
}

// TestSet_VSwitch_DeleteTransportError verifies that transport failures in removeVSwitch
// surface as wrapped errors, not silently swallowed.
func TestSet_VSwitch_DeleteTransportError(t *testing.T) {
	transport := &testWinRMTransport{execErr: errors.New("winrm: connection refused")}
	m := vswitchModuleWithTransport(transport, "t")

	cfg := &VSwitchConfig{Name: "sw", State: "absent"}
	err := m.Set(context.Background(), "vswitch:sw", cfg)
	require.Error(t, err, "transport error must be surfaced from removeVSwitch")
	assert.Contains(t, err.Error(), "remove vswitch", "error must identify the remove operation")
}

// ─── Exact-name-regardless-of-tenant tests ────────────────────────────────────

// TestVSwitchExactName_RegardlessOfTenant verifies that the host-side switch name
// is the exact config name regardless of tenant_id — CFGMS never namespaces.
// (Operators sharing a host across tenants must choose non-colliding names.)
func TestVSwitchExactName_RegardlessOfTenant(t *testing.T) {
	transportA := &testWinRMTransport{}
	transportB := &testWinRMTransport{}

	moduleA := vswitchModuleWithTransport(transportA, "a")
	moduleB := vswitchModuleWithTransport(transportB, "b")

	cfgA := &VSwitchConfig{Name: "net", State: "absent"}
	cfgB := &VSwitchConfig{Name: "net", State: "absent"}

	require.NoError(t, moduleA.Set(context.Background(), "vswitch:net", cfgA))
	require.NoError(t, moduleB.Set(context.Background(), "vswitch:net", cfgB))

	transportA.mu.Lock()
	callsA := transportA.calls
	transportA.mu.Unlock()

	transportB.mu.Lock()
	callsB := transportB.calls
	transportB.mu.Unlock()

	// absent path: call 0 = getVSwitch, call 1 = Remove-VMSwitch.
	require.Len(t, callsA, 2, "getVSwitch + Remove-VMSwitch expected for absent path (tenant A)")
	require.Len(t, callsB, 2, "getVSwitch + Remove-VMSwitch expected for absent path (tenant B)")

	require.Len(t, callsA[1].args, 1)
	assert.Equal(t, "net", callsA[1].args[0], "tenant A must use the exact name")

	require.Len(t, callsB[1].args, 1)
	assert.Equal(t, "net", callsB[1].args[0], "tenant B must use the exact name")

	// Injection safety: the name still travels via args, never interpolated.
	assert.NotContains(t, callsA[1].scriptBlock, "net")
	assert.NotContains(t, callsB[1].scriptBlock, "net")
}
