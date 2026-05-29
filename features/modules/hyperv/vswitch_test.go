// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/modules"
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

// ─── vswitchHostName tests ────────────────────────────────────────────────────

// TestVSwitchHostName_Format verifies the returned format matches the spec.
func TestVSwitchHostName_Format(t *testing.T) {
	got := vswitchHostName("root/msp-a", "myswitch")
	assert.Equal(t, "cfgms-root-msp-a__myswitch", got)
}

// TestVSwitchHostName_NoPrefixCollision verifies that distinct (tenantID, switchName) pairs
// always produce distinct host-side names, defeating tenant prefix forgery.
func TestVSwitchHostName_NoPrefixCollision(t *testing.T) {
	type pair struct {
		tenantID   string
		switchName string
	}
	cases := []pair{
		{"tenant_a", "switch"},
		{"tenant", "a_switch"},
		{"tenant-a", "b"},
		{"tenant", "a-b"},
		{"root/msp-a", "external"},
	}

	seen := make(map[string]pair)
	for _, c := range cases {
		host := vswitchHostName(c.tenantID, c.switchName)
		if prev, ok := seen[host]; ok {
			t.Errorf("collision: (%q, %q) and (%q, %q) both produce %q",
				prev.tenantID, prev.switchName, c.tenantID, c.switchName, host)
		}
		seen[host] = c
	}
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

// TestVSwitchConfig_Validate_RejectsDoubleUnderscore verifies that __ in switch name
// is rejected — the __ sequence is reserved for the tenant separator.
func TestVSwitchConfig_Validate_RejectsDoubleUnderscore(t *testing.T) {
	cfg := &VSwitchConfig{Name: "my__switch", SwitchType: "internal"}
	err := cfg.Validate()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidSwitchName)
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

// ─── VMAttachmentConfig.Validate tests ───────────────────────────────────────

// TestVMAttachmentConfig_Validate_AcceptsValid verifies a well-formed config passes.
func TestVMAttachmentConfig_Validate_AcceptsValid(t *testing.T) {
	cfg := &VMAttachmentConfig{VMName: "myvm", SwitchName: "ext-sw", AdapterName: "NIC1"}
	require.NoError(t, cfg.Validate())
}

// TestVMAttachmentConfig_Validate_AcceptsEmptyAdapterName verifies that an empty
// adapter name is accepted — it means Hyper-V assigns the name.
func TestVMAttachmentConfig_Validate_AcceptsEmptyAdapterName(t *testing.T) {
	cfg := &VMAttachmentConfig{VMName: "myvm", SwitchName: "ext-sw"}
	require.NoError(t, cfg.Validate())
}

// TestVMAttachmentConfig_Validate_RejectsInvalidVMName verifies that VM names with
// injection characters are rejected.
func TestVMAttachmentConfig_Validate_RejectsInvalidVMName(t *testing.T) {
	cfg := &VMAttachmentConfig{VMName: "vm__bad", SwitchName: "sw"}
	err := cfg.Validate()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidVMName)
}

// TestVMAttachmentConfig_Validate_RejectsInvalidSwitchName verifies that switch names
// with injection characters are rejected.
func TestVMAttachmentConfig_Validate_RejectsInvalidSwitchName(t *testing.T) {
	cfg := &VMAttachmentConfig{VMName: "myvm", SwitchName: "sw__bad"}
	err := cfg.Validate()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidSwitchName)
}

// ─── Injection defense tests ───────────────────────────────────────────────────

// TestAttachVM_PassesNamesAsParameters verifies that the prefixed VM name and switch
// name are transmitted as WinRM ArgumentList parameters, never interpolated into the
// PowerShell script text.
//
// Also known as TestVSwitchInjectionDefense.
func TestAttachVM_PassesNamesAsParameters(t *testing.T) {
	const tenantID = "acme"
	const vmName = "webserver"
	const switchName = "external"

	expectedVMHost := vmHostName(tenantID, vmName)
	expectedSwitchHost := vswitchHostName(tenantID, switchName)

	transport := &testWinRMTransport{}
	m := vswitchModuleWithTransport(transport, tenantID)

	err := m.attachVMToSwitch(context.Background(), vmName, switchName, "")
	require.NoError(t, err)

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	require.Len(t, calls, 1, "exactly one ExecutePS call expected")
	call := calls[0]

	// Both prefixed names must appear in args, not scriptBlock.
	// Keys sorted: "SwitchName" < "VMName", so args[0]=hostSwitchName, args[1]=hostVMName.
	require.Len(t, call.args, 2, "SwitchName and VMName must both be in psArgs")
	assert.Equal(t, expectedSwitchHost, call.args[0], "switch host name must be args[0] (key 'SwitchName')")
	assert.Equal(t, expectedVMHost, call.args[1], "VM host name must be args[1] (key 'VMName')")

	assert.NotContains(t, call.scriptBlock, expectedVMHost,
		"prefixed VM name must NOT appear in scriptBlock text")
	assert.NotContains(t, call.scriptBlock, expectedSwitchHost,
		"prefixed switch name must NOT appear in scriptBlock text")
}

// TestVSwitchInjectionDefense verifies that the prefixed switch name is transmitted
// as a WinRM ArgumentList parameter during create/delete, never interpolated into the
// PowerShell script block text. This satisfies the AC test name alias.
func TestVSwitchInjectionDefense(t *testing.T) {
	const tenantID = "ops"
	const switchName = "corp-net"
	expectedHostName := vswitchHostName(tenantID, switchName)

	transport := &testWinRMTransport{}
	m := vswitchModuleWithTransport(transport, tenantID)

	cfg := &VSwitchConfig{Name: switchName, SwitchType: "internal", State: "absent"}
	err := m.Set(context.Background(), "vswitch:"+switchName, cfg)
	require.NoError(t, err)

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	require.Len(t, calls, 1, "exactly one ExecutePS call expected for Remove")
	call := calls[0]

	// Prefixed name must appear in args, not scriptBlock.
	require.Len(t, call.args, 1)
	assert.Equal(t, expectedHostName, call.args[0], "prefixed switch name must be in args[0]")
	assert.NotContains(t, call.scriptBlock, expectedHostName,
		"prefixed switch name must NOT appear in scriptBlock text")
}

// TestEmptyAdapterName_OmitsNameParam verifies that AttachVMToSwitch with an empty
// AdapterName produces a scriptBlock without a -Name parameter and that args does
// not include an empty-string element for the adapter name.
func TestEmptyAdapterName_OmitsNameParam(t *testing.T) {
	transport := &testWinRMTransport{}
	m := vswitchModuleWithTransport(transport, "t")

	err := m.attachVMToSwitch(context.Background(), "myvm", "myswitch", "")
	require.NoError(t, err)

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	require.Len(t, calls, 1)
	call := calls[0]

	// scriptBlock must NOT contain -Name
	assert.NotContains(t, call.scriptBlock, "-Name",
		"empty AdapterName must produce scriptBlock without -Name parameter")

	// args must have exactly 2 entries (SwitchName and VMName) — no empty-string Name arg
	require.Len(t, call.args, 2,
		"empty AdapterName must produce exactly 2 args (SwitchName, VMName)")

	// None of the args should be an empty string
	for i, arg := range call.args {
		assert.NotEqual(t, "", arg, "args[%d] must not be an empty string", i)
	}
}

// TestNonEmptyAdapterName_IncludesNameParam verifies that AttachVMToSwitch with a
// non-empty AdapterName includes -Name in the scriptBlock and the adapter name in args.
func TestNonEmptyAdapterName_IncludesNameParam(t *testing.T) {
	const adapterName = "NIC-1"

	transport := &testWinRMTransport{}
	m := vswitchModuleWithTransport(transport, "t")

	err := m.attachVMToSwitch(context.Background(), "myvm", "myswitch", adapterName)
	require.NoError(t, err)

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	require.Len(t, calls, 1)
	call := calls[0]

	// scriptBlock must contain -Name
	assert.Contains(t, call.scriptBlock, "-Name",
		"non-empty AdapterName must include -Name parameter in scriptBlock")

	// args must have 3 entries: Name, SwitchName, VMName (sorted order)
	require.Len(t, call.args, 3, "3 args expected: Name, SwitchName, VMName (sorted)")
	// Keys sorted: "Name" < "SwitchName" < "VMName"
	assert.Equal(t, adapterName, call.args[0], "adapter name must be args[0] (key 'Name')")

	// Adapter name must not appear in scriptBlock text
	assert.NotContains(t, call.scriptBlock, adapterName,
		"adapter name must NOT be embedded in scriptBlock — must be in args")
}

// ─── Get not found tests ───────────────────────────────────────────────────────

// TestGet_VSwitch_ReturnsErrVSwitchNotFound_WhenMissing verifies that Get returns
// ErrVSwitchNotFound when the remote host reports the switch does not exist.
func TestGet_VSwitch_ReturnsErrVSwitchNotFound_WhenMissing(t *testing.T) {
	transport := &testWinRMTransport{output: `{"found":false}`}
	m := vswitchModuleWithTransport(transport, "t")

	_, err := m.Get(context.Background(), "vswitch:nonexistent")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrVSwitchNotFound)
}

// TestGet_VSwitch_ReturnsErrVSwitchNotFound_OnTransportError verifies that transport
// errors are surfaced as ErrVSwitchNotFound.
func TestGet_VSwitch_ReturnsErrVSwitchNotFound_OnTransportError(t *testing.T) {
	transport := &testWinRMTransport{execErr: errors.New("winrm: connection refused")}
	m := vswitchModuleWithTransport(transport, "t")

	_, err := m.Get(context.Background(), "vswitch:unreachable")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrVSwitchNotFound)
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
	hostName := vswitchHostName(tenantID, switchName)

	transport := &testWinRMTransport{
		output: `{"found":true,"Name":"` + hostName + `","SwitchType":"External"}`,
	}
	m := vswitchModuleWithTransport(transport, tenantID)

	state, err := m.Get(context.Background(), "vswitch:"+switchName)
	require.NoError(t, err)
	require.NotNil(t, state)

	cfg, ok := state.(*VSwitchConfig)
	require.True(t, ok, "Get must return *VSwitchConfig")
	assert.Equal(t, switchName, cfg.Name, "Name must be user-visible (without prefix)")
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
	assert.Equal(t, "cfgms-dev__dev-net", call.args[0],
		"prefixed switch name must be in args[0]")
	assert.NotContains(t, call.scriptBlock, "cfgms-dev__dev-net",
		"prefixed name must not appear in scriptBlock")
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
	assert.Equal(t, "cfgms-ops__corp-net", call.args[0], "prefixed switch name in args[0]")
	assert.Equal(t, "Ethernet", call.args[1], "adapter name in args[1]")

	// Neither value should appear in the scriptBlock
	assert.NotContains(t, call.scriptBlock, "cfgms-ops__corp-net")
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

	require.Len(t, calls, 1)
	call := calls[0]

	assert.Contains(t, call.scriptBlock, "Remove-VMSwitch",
		"Set with state absent must invoke Remove-VMSwitch")

	require.Len(t, call.args, 1)
	assert.Equal(t, "cfgms-ops__old-switch", call.args[0],
		"prefixed switch name must be in args[0] for Remove")
	assert.NotContains(t, call.scriptBlock, "cfgms-ops__old-switch",
		"prefixed name must not be interpolated in scriptBlock")
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

// ─── VMAttach module routing tests ────────────────────────────────────────────

// TestSet_VMAttach_NoTransport verifies that setVMAttachment returns ErrNotImplemented
// when the module has no transport configured.
func TestSet_VMAttach_NoTransport(t *testing.T) {
	m := &hypervModule{
		executor:  &stubHypervExecutor{},
		vms:       make(map[string]VMConfig),
		vswitches: make(map[string]VSwitchConfig),
		detector:  &fakeDetector{result: true},
	}
	cfg := &VMAttachmentConfig{VMName: "myvm", SwitchName: "sw", State: "present"}
	err := m.Set(context.Background(), "vmattach:myvm/sw", cfg)
	assert.ErrorIs(t, err, modules.ErrNotImplemented)
}

// TestGet_VMAttach_NoTransport verifies that getVMAttachment returns ErrVSwitchNotFound
// when the module has no transport configured.
func TestGet_VMAttach_NoTransport(t *testing.T) {
	m := &hypervModule{
		executor:  &stubHypervExecutor{},
		vms:       make(map[string]VMConfig),
		vswitches: make(map[string]VSwitchConfig),
		detector:  &fakeDetector{result: true},
	}
	_, err := m.Get(context.Background(), "vmattach:myvm/myswitch")
	assert.ErrorIs(t, err, ErrVSwitchNotFound)
}

// TestSet_VMAttach_RejectsInjectionPayloads verifies that injection payloads in
// the vmName or switchName portion of the resource ID are rejected before any WinRM call.
func TestSet_VMAttach_RejectsInjectionPayloads(t *testing.T) {
	type testCase struct {
		resourceID string
		desc       string
	}
	cases := []testCase{
		{"vmattach:'; Remove-VM -Force; '/safe", "single-quote injection in vmName"},
		{"vmattach:myvm/'; Remove-VMSwitch; '", "single-quote injection in switchName"},
		{"vmattach:$(Remove-VM)/safe", "subexpression injection in vmName"},
		{"vmattach:myvm/$(Remove-VMSwitch)", "subexpression injection in switchName"},
		{"vmattach:vm__evil/switch", "double-underscore in vmName"},
		{"vmattach:myvm/switch__evil", "double-underscore in switchName"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.desc, func(t *testing.T) {
			transport := &testWinRMTransport{}
			m := vswitchModuleWithTransport(transport, "t")

			cfg := &VMAttachmentConfig{State: "present"}
			err := m.Set(context.Background(), tc.resourceID, cfg)
			require.Error(t, err, "injection payload %q must be rejected", tc.resourceID)

			transport.mu.Lock()
			calls := transport.calls
			transport.mu.Unlock()
			assert.Empty(t, calls, "transport must not be called when validation rejects the input")
		})
	}
}

// ─── Set vmattach happy-path and error-path tests ─────────────────────────────

// TestSet_VMAttach_Present_RoutesCorrectly verifies that m.Set with vmattach resource ID
// and state "present" routes to attachVMToSwitch via the module's public Set interface.
func TestSet_VMAttach_Present_RoutesCorrectly(t *testing.T) {
	transport := &testWinRMTransport{}
	m := vswitchModuleWithTransport(transport, "prod")

	cfg := &VMAttachmentConfig{
		VMName:      "appserver",
		SwitchName:  "corp-net",
		AdapterName: "Management",
		State:       "present",
	}

	err := m.Set(context.Background(), "vmattach:appserver/corp-net", cfg)
	require.NoError(t, err)

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	require.Len(t, calls, 1, "exactly one ExecutePS call expected for attach")
	call := calls[0]

	assert.Contains(t, call.scriptBlock, "Add-VMNetworkAdapter",
		"Set with state present must invoke Add-VMNetworkAdapter")
	assert.Contains(t, call.scriptBlock, "-Name",
		"non-empty AdapterName must include -Name in the script")
}

// TestSet_VMAttach_Absent_CallsDetach verifies that Set with state "absent" routes
// to detachVMFromSwitch via the module's public Set interface.
func TestSet_VMAttach_Absent_CallsDetach(t *testing.T) {
	transport := &testWinRMTransport{}
	m := vswitchModuleWithTransport(transport, "ops")

	cfg := &VMAttachmentConfig{
		VMName:      "myvm",
		SwitchName:  "corp-net",
		AdapterName: "NIC-1",
		State:       "absent",
	}

	err := m.Set(context.Background(), "vmattach:myvm/corp-net", cfg)
	require.NoError(t, err)

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	require.Len(t, calls, 1, "exactly one ExecutePS call expected for detach")
	call := calls[0]

	assert.Contains(t, call.scriptBlock, "Remove-VMNetworkAdapter",
		"Set with state absent must invoke Remove-VMNetworkAdapter")

	// Prefixed VM name must appear in args, not scriptBlock
	require.NotEmpty(t, call.args)
	var foundVMName bool
	for _, arg := range call.args {
		if arg == "cfgms-ops__myvm" {
			foundVMName = true
		}
	}
	assert.True(t, foundVMName, "prefixed VM name must appear in args")
	assert.NotContains(t, call.scriptBlock, "cfgms-ops__myvm",
		"prefixed VM name must not be interpolated in scriptBlock")
}

// TestSet_VMAttach_Absent_TransportError verifies that transport errors from
// detachVMFromSwitch are surfaced as wrapped errors.
func TestSet_VMAttach_Absent_TransportError(t *testing.T) {
	transport := &testWinRMTransport{execErr: errors.New("winrm: connection refused")}
	m := vswitchModuleWithTransport(transport, "t")

	cfg := &VMAttachmentConfig{
		VMName:      "myvm",
		SwitchName:  "corp-net",
		AdapterName: "NIC-1",
		State:       "absent",
	}

	err := m.Set(context.Background(), "vmattach:myvm/corp-net", cfg)
	require.Error(t, err, "transport error must be surfaced")
	assert.Contains(t, err.Error(), "detach adapter", "error must identify the detach operation")
}

// TestSet_VMAttach_Present_TransportError verifies that transport failures from
// attachVMToSwitch are surfaced as wrapped errors, not silently swallowed.
func TestSet_VMAttach_Present_TransportError(t *testing.T) {
	transport := &testWinRMTransport{execErr: errors.New("winrm: connection refused")}
	m := vswitchModuleWithTransport(transport, "t")

	cfg := &VMAttachmentConfig{
		VMName:     "myvm",
		SwitchName: "myswitch",
		State:      "present",
	}

	err := m.Set(context.Background(), "vmattach:myvm/myswitch", cfg)
	require.Error(t, err, "transport error must be surfaced from attachVMToSwitch")
	assert.Contains(t, err.Error(), "attach VM", "error must identify the attach operation")
}

// TestGet_VMAttachment_TransportError verifies that transport errors from
// getVMAttachment are surfaced as ErrVSwitchNotFound.
func TestGet_VMAttachment_TransportError(t *testing.T) {
	transport := &testWinRMTransport{execErr: errors.New("winrm: connection refused")}
	m := vswitchModuleWithTransport(transport, "t")

	_, err := m.Get(context.Background(), "vmattach:myvm/myswitch")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrVSwitchNotFound)
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

// ─── VMAttachmentConfig interface tests ───────────────────────────────────────

// TestVMAttachmentConfig_AsMap verifies that AsMap includes all configuration fields.
func TestVMAttachmentConfig_AsMap(t *testing.T) {
	cfg := &VMAttachmentConfig{
		VMName:      "my-vm",
		SwitchName:  "ext-sw",
		AdapterName: "NIC-1",
		State:       "present",
	}
	m := cfg.AsMap()
	assert.Equal(t, "my-vm", m["vm_name"])
	assert.Equal(t, "ext-sw", m["switch_name"])
	assert.Equal(t, "NIC-1", m["adapter_name"])
	assert.Equal(t, "present", m["state"])
}

// TestVMAttachmentConfig_YAML verifies round-trip YAML serialization.
func TestVMAttachmentConfig_YAML(t *testing.T) {
	original := &VMAttachmentConfig{
		VMName:      "roundtrip-vm",
		SwitchName:  "corp-net",
		AdapterName: "Management",
		State:       "present",
	}
	data, err := original.ToYAML()
	require.NoError(t, err)

	decoded := &VMAttachmentConfig{}
	require.NoError(t, decoded.FromYAML(data))
	assert.Equal(t, original, decoded)
}

// TestGet_VMAttachment_ReturnsConfig verifies that getVMAttachment returns a properly
// mapped VMAttachmentConfig when the transport reports the adapter is found.
func TestGet_VMAttachment_ReturnsConfig(t *testing.T) {
	const tenantID = "prod"
	const vmName = "appserver"
	const switchName = "corp-net"

	transport := &testWinRMTransport{
		output: `{"found":true,"AdapterName":"NIC-1"}`,
	}
	m := vswitchModuleWithTransport(transport, tenantID)

	state, err := m.Get(context.Background(), "vmattach:"+vmName+"/"+switchName)
	require.NoError(t, err)
	require.NotNil(t, state)

	cfg, ok := state.(*VMAttachmentConfig)
	require.True(t, ok, "Get must return *VMAttachmentConfig")
	assert.Equal(t, vmName, cfg.VMName)
	assert.Equal(t, switchName, cfg.SwitchName)
	assert.Equal(t, "NIC-1", cfg.AdapterName)
	assert.Equal(t, "present", cfg.State)
}

// ─── Cross-tenant isolation tests ─────────────────────────────────────────────

// TestVSwitchCrossTenantIsolation verifies that two modules for different tenants
// produce distinct host-side switch names, preventing cross-tenant interference.
func TestVSwitchCrossTenantIsolation(t *testing.T) {
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

	require.Len(t, callsA, 1)
	require.Len(t, callsB, 1)

	require.Len(t, callsA[0].args, 1)
	assert.Equal(t, "cfgms-a__net", callsA[0].args[0])

	require.Len(t, callsB[0].args, 1)
	assert.Equal(t, "cfgms-b__net", callsB[0].args[0])

	assert.NotEqual(t, callsA[0].args[0], callsB[0].args[0],
		"cross-tenant isolation: host-side switch names must differ")
}
