// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/features/modules"
)

var (
	// ErrVSwitchNotFound is returned when a requested virtual switch does not exist on the host.
	ErrVSwitchNotFound = errors.New("hyperv: vswitch not found")

	// ErrInvalidSwitchName is returned when a switch name fails allowlist validation or
	// contains the reserved __ separator.
	ErrInvalidSwitchName = errors.New("hyperv: invalid switch name: must match ^[a-zA-Z0-9_\\- ]{1,64}$ and must not contain __")

	// ErrInvalidSwitchType is returned when SwitchType is not external, internal, or private.
	ErrInvalidSwitchType = errors.New("hyperv: invalid switch type: must be external, internal, or private")

	// ErrExternalRequiresAdapter is returned when an external switch has empty NetAdapterName.
	ErrExternalRequiresAdapter = errors.New("hyperv: external switch requires non-empty NetAdapterName")

	// ErrAdapterForbiddenForNonExternal is returned when a non-external switch has non-empty NetAdapterName.
	ErrAdapterForbiddenForNonExternal = errors.New("hyperv: NetAdapterName must be empty for internal and private switch types")
)

// switchNamePattern is the allowlist for user-supplied virtual switch names.
// Spaces are permitted per Hyper-V virtual switch naming convention.
// The __ check is enforced separately to produce a more specific error.
var switchNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_\- ]{1,64}$`)

// VSwitchConfig represents the desired state of a Hyper-V virtual switch.
type VSwitchConfig struct {
	Name           string `yaml:"name"`
	SwitchType     string `yaml:"switch_type"`
	NetAdapterName string `yaml:"net_adapter_name,omitempty"`
	// AllowManagementOS is forced to true for external switches in Validate().
	AllowManagementOS bool `yaml:"allow_management_os,omitempty"`
	// State is the desired lifecycle: "present" or "absent" (delete).
	State string `yaml:"state,omitempty"`
}

// Validate checks all VSwitchConfig fields against their constraints.
// Sets AllowManagementOS=true for external type (Hyper-V default for external).
func (c *VSwitchConfig) Validate() error {
	if !switchNamePattern.MatchString(c.Name) {
		return ErrInvalidSwitchName
	}
	// __ is the tenant/resource separator — forbidden in user-supplied names to prevent
	// a tenant from forging a prefix that collides with another tenant's switches.
	if strings.Contains(c.Name, "__") {
		return ErrInvalidSwitchName
	}
	switch c.SwitchType {
	case "external", "internal", "private":
		// valid
	default:
		// nat and any other value are structurally rejected
		return ErrInvalidSwitchType
	}
	if c.SwitchType == "external" {
		if c.NetAdapterName == "" {
			return ErrExternalRequiresAdapter
		}
		// External switches always enable management OS access (Hyper-V default behavior).
		c.AllowManagementOS = true
	} else {
		if c.NetAdapterName != "" {
			return ErrAdapterForbiddenForNonExternal
		}
		c.AllowManagementOS = false
	}
	return nil
}

// AsMap implements modules.ConfigState.
func (c *VSwitchConfig) AsMap() map[string]interface{} {
	return map[string]interface{}{
		"name":                c.Name,
		"switch_type":         c.SwitchType,
		"net_adapter_name":    c.NetAdapterName,
		"allow_management_os": c.AllowManagementOS,
		"state":               c.State,
	}
}

// ToYAML serializes the configuration to YAML.
func (c *VSwitchConfig) ToYAML() ([]byte, error) {
	return yaml.Marshal(c)
}

// FromYAML deserializes YAML data into the configuration.
func (c *VSwitchConfig) FromYAML(data []byte) error {
	return yaml.Unmarshal(data, c)
}

// GetManagedFields returns the list of fields this configuration manages.
func (c *VSwitchConfig) GetManagedFields() []string {
	return []string{"name", "switch_type", "net_adapter_name", "allow_management_os", "state"}
}

// VMAttachmentConfig represents the desired state of a VM network adapter attachment.
type VMAttachmentConfig struct {
	VMName     string `yaml:"vm_name"`
	SwitchName string `yaml:"switch_name"`
	// AdapterName is optional. When empty, Hyper-V assigns a default adapter name.
	AdapterName string `yaml:"adapter_name,omitempty"`
	// State is the desired lifecycle: "present" or "absent" (detach).
	State string `yaml:"state,omitempty"`
}

// Validate checks all VMAttachmentConfig fields against their constraints.
func (c *VMAttachmentConfig) Validate() error {
	if !vmNamePattern.MatchString(c.VMName) {
		return ErrInvalidVMName
	}
	if strings.Contains(c.VMName, "__") {
		return ErrInvalidVMName
	}
	if !switchNamePattern.MatchString(c.SwitchName) {
		return ErrInvalidSwitchName
	}
	if strings.Contains(c.SwitchName, "__") {
		return ErrInvalidSwitchName
	}
	return nil
}

// AsMap implements modules.ConfigState.
func (c *VMAttachmentConfig) AsMap() map[string]interface{} {
	return map[string]interface{}{
		"vm_name":      c.VMName,
		"switch_name":  c.SwitchName,
		"adapter_name": c.AdapterName,
		"state":        c.State,
	}
}

// ToYAML serializes the configuration to YAML.
func (c *VMAttachmentConfig) ToYAML() ([]byte, error) {
	return yaml.Marshal(c)
}

// FromYAML deserializes YAML data into the configuration.
func (c *VMAttachmentConfig) FromYAML(data []byte) error {
	return yaml.Unmarshal(data, c)
}

// GetManagedFields returns the list of fields this configuration manages.
func (c *VMAttachmentConfig) GetManagedFields() []string {
	return []string{"vm_name", "switch_name", "adapter_name", "state"}
}

// vswitchHostName constructs the collision-free host-side virtual switch name.
//
// The cfgms- prefix and __ separator together make it impossible for a user to
// construct a switch name that collides with another tenant's switches:
//   - __ is forbidden in user-supplied names (Validate enforces this)
//   - slashes in tenantID are replaced with hyphens to produce a flat prefix
func vswitchHostName(tenantID, name string) string {
	return "cfgms-" + strings.ReplaceAll(tenantID, "/", "-") + "__" + name
}

// psGetVSwitch checks whether a virtual switch exists; emits JSON {"found":bool,"SwitchType":"..."}.
// $Name travels via ArgumentList — never interpolated into the script text.
const psGetVSwitch = `$sw = Get-VMSwitch -Name $Name -ErrorAction SilentlyContinue; if (-not $sw) { Write-Output '{"found":false}'; return }; $result = @{ found=$true; Name=$sw.Name; SwitchType=$sw.SwitchType.ToString() }; ConvertTo-Json $result -Compress`

// psRemoveVSwitch removes a virtual switch by host-side name.
// $Name travels via ArgumentList — never interpolated into the script text.
const psRemoveVSwitch = `Remove-VMSwitch -Name $Name -Force`

// psCreateVSwitchInternal creates an internal virtual switch.
// $Name travels via ArgumentList — never interpolated into the script text.
const psCreateVSwitchInternal = `New-VMSwitch -Name $Name -SwitchType Internal | Out-Null`

// psCreateVSwitchPrivate creates a private virtual switch.
// $Name travels via ArgumentList — never interpolated into the script text.
const psCreateVSwitchPrivate = `New-VMSwitch -Name $Name -SwitchType Private | Out-Null`

// psGetVMAttachment checks whether a VM has a network adapter connected to the specified switch.
// $VMName and $SwitchName travel via ArgumentList — never interpolated into the script text.
const psGetVMAttachment = `$adapter = Get-VMNetworkAdapter -VMName $VMName -ErrorAction SilentlyContinue | Where-Object { $_.SwitchName -eq $SwitchName } | Select-Object -First 1; if (-not $adapter) { Write-Output '{"found":false}'; return }; Write-Output ('{"found":true,"AdapterName":"' + $adapter.Name + '"}')`

// psAttachVMNoAdapterName attaches a VM to a switch without specifying an adapter name.
// $VMName and $SwitchName travel via ArgumentList — never embedded in script text.
// The -Name parameter is intentionally absent: Hyper-V assigns a default adapter name.
const psAttachVMNoAdapterName = `Add-VMNetworkAdapter -VMName $VMName -SwitchName $SwitchName`

// psAttachVMWithAdapterName attaches a named adapter on a VM to a switch.
// All three values travel via ArgumentList — never embedded in script text.
const psAttachVMWithAdapterName = `Add-VMNetworkAdapter -VMName $VMName -SwitchName $SwitchName -Name $Name`

// psDetachVM removes a named network adapter from a VM.
// $VMName and $Name travel via ArgumentList — never embedded in script text.
const psDetachVM = `Remove-VMNetworkAdapter -VMName $VMName -Name $Name`

// psCreateVSwitchExternal builds the script block for creating an external virtual switch.
// $Name and $NetAdapter travel via ArgumentList. AllowManagementOS is a Go bool converted
// to a PowerShell boolean literal ($true/$false) — not user input, so embedding is safe.
func psCreateVSwitchExternal(allowManagementOS bool) string {
	val := "$false"
	if allowManagementOS {
		val = "$true"
	}
	return `New-VMSwitch -Name $Name -SwitchType External -NetAdapterName $NetAdapter -AllowManagementOS ` + val + ` | Out-Null`
}

// getVSwitch retrieves the current state of a virtual switch by user-visible name.
// Returns ErrVSwitchNotFound if the switch does not exist or the transport fails.
func (m *hypervModule) getVSwitch(ctx context.Context, switchName string) (*VSwitchConfig, error) {
	if m.transport == nil {
		return nil, ErrVSwitchNotFound
	}

	hostName := vswitchHostName(m.tenantID, switchName)
	output, err := m.transport.ExecutePS(ctx, psGetVSwitch, map[string]string{"Name": hostName})
	if err != nil {
		return nil, ErrVSwitchNotFound
	}

	var parsed map[string]interface{}
	if jsonErr := json.Unmarshal([]byte(strings.TrimSpace(output)), &parsed); jsonErr != nil {
		return nil, ErrVSwitchNotFound
	}

	found, _ := parsed["found"].(bool)
	if !found {
		return nil, ErrVSwitchNotFound
	}

	cfg := &VSwitchConfig{Name: switchName, State: "present"}
	if v, ok := parsed["SwitchType"].(string); ok {
		cfg.SwitchType = strings.ToLower(v)
	}

	// Write-through: update cache on successful read.
	m.vswitchesMu.Lock()
	m.vswitches[switchName] = *cfg
	m.vswitchesMu.Unlock()

	return cfg, nil
}

// setVSwitch applies the desired vSwitch configuration.
// Resource ID format: "vswitch:<switchName>".
// Write-through cache semantics: transport is called first; cache updated on success only.
func (m *hypervModule) setVSwitch(ctx context.Context, resourceID string, config modules.ConfigState) error {
	if m.transport == nil {
		return modules.ErrNotImplemented
	}

	parts := strings.SplitN(resourceID, ":", 2)
	if len(parts) != 2 {
		return modules.ErrNotImplemented
	}
	switchName := parts[1]

	configMap := config.AsMap()
	state, _ := configMap["state"].(string)

	if state == "absent" {
		return m.removeVSwitch(ctx, switchName)
	}

	cfg := &VSwitchConfig{Name: switchName}
	if v, ok := configMap["switch_type"].(string); ok {
		cfg.SwitchType = v
	}
	if v, ok := configMap["net_adapter_name"].(string); ok {
		cfg.NetAdapterName = v
	}
	if v, ok := configMap["allow_management_os"].(bool); ok {
		cfg.AllowManagementOS = v
	}
	cfg.State = state

	// *VSwitchConfig passed directly takes precedence over the map extraction above.
	if vc, ok := config.(*VSwitchConfig); ok {
		*cfg = *vc
		cfg.Name = switchName
	}

	if err := cfg.Validate(); err != nil {
		return err
	}

	return m.createVSwitch(ctx, switchName, cfg)
}

// createVSwitch creates a new virtual switch on the host.
// Write-through cache semantics: transport is called first; cache updated on success only.
func (m *hypervModule) createVSwitch(ctx context.Context, switchName string, cfg *VSwitchConfig) error {
	hostName := vswitchHostName(m.tenantID, switchName)

	var (
		psCmd  string
		psArgs map[string]string
	)

	switch cfg.SwitchType {
	case "external":
		psCmd = psCreateVSwitchExternal(cfg.AllowManagementOS)
		psArgs = map[string]string{
			"Name":       hostName,
			"NetAdapter": cfg.NetAdapterName,
		}
	case "internal":
		psCmd = psCreateVSwitchInternal
		psArgs = map[string]string{"Name": hostName}
	case "private":
		psCmd = psCreateVSwitchPrivate
		psArgs = map[string]string{"Name": hostName}
	default:
		return ErrInvalidSwitchType
	}

	if _, err := m.transport.ExecutePS(ctx, psCmd, psArgs); err != nil {
		return fmt.Errorf("hyperv: create vswitch %q: %w", switchName, err)
	}

	cfgCopy := *cfg
	cfgCopy.Name = switchName
	m.vswitchesMu.Lock()
	m.vswitches[switchName] = cfgCopy
	m.vswitchesMu.Unlock()

	return nil
}

// removeVSwitch deletes a virtual switch from the host.
// Write-through cache semantics: transport is called first; cache updated on success only.
func (m *hypervModule) removeVSwitch(ctx context.Context, switchName string) error {
	hostName := vswitchHostName(m.tenantID, switchName)

	if _, err := m.transport.ExecutePS(ctx, psRemoveVSwitch, map[string]string{"Name": hostName}); err != nil {
		return fmt.Errorf("hyperv: remove vswitch %q: %w", switchName, err)
	}

	m.vswitchesMu.Lock()
	delete(m.vswitches, switchName)
	m.vswitchesMu.Unlock()

	return nil
}

// getVMAttachment retrieves the current attachment state of a VM to a virtual switch.
// Resource name format: "<vmName>/<switchName>".
func (m *hypervModule) getVMAttachment(ctx context.Context, name string) (*VMAttachmentConfig, error) {
	if m.transport == nil {
		return nil, ErrVSwitchNotFound
	}

	vmName, switchName, ok := splitSnapshotName(name)
	if !ok {
		return nil, ErrVSwitchNotFound
	}

	hostVMName := vmHostName(m.tenantID, vmName)
	hostSwitchName := vswitchHostName(m.tenantID, switchName)

	output, err := m.transport.ExecutePS(ctx, psGetVMAttachment, map[string]string{
		"VMName":     hostVMName,
		"SwitchName": hostSwitchName,
	})
	if err != nil {
		return nil, ErrVSwitchNotFound
	}

	var parsed map[string]interface{}
	if jsonErr := json.Unmarshal([]byte(strings.TrimSpace(output)), &parsed); jsonErr != nil {
		return nil, ErrVSwitchNotFound
	}

	found, _ := parsed["found"].(bool)
	if !found {
		return nil, ErrVSwitchNotFound
	}

	cfg := &VMAttachmentConfig{
		VMName:     vmName,
		SwitchName: switchName,
		State:      "present",
	}
	if v, ok := parsed["AdapterName"].(string); ok {
		cfg.AdapterName = v
	}

	return cfg, nil
}

// setVMAttachment applies the desired VM attachment state.
// Resource ID format: "vmattach:<vmName>/<switchName>".
func (m *hypervModule) setVMAttachment(ctx context.Context, resourceID string, config modules.ConfigState) error {
	if m.transport == nil {
		return modules.ErrNotImplemented
	}

	parts := strings.SplitN(resourceID, ":", 2)
	if len(parts) != 2 {
		return modules.ErrNotImplemented
	}
	vmName, switchName, ok := splitSnapshotName(parts[1])
	if !ok {
		return modules.ErrNotImplemented
	}

	configMap := config.AsMap()
	state, _ := configMap["state"].(string)
	adapterName, _ := configMap["adapter_name"].(string)

	// *VMAttachmentConfig passed directly takes precedence over map extraction.
	if vc, ok := config.(*VMAttachmentConfig); ok {
		state = vc.State
		adapterName = vc.AdapterName
		vmName = vc.VMName
		switchName = vc.SwitchName
	}

	// Validate user-supplied names before any WinRM call — defense-in-depth.
	attachCfg := &VMAttachmentConfig{VMName: vmName, SwitchName: switchName}
	if err := attachCfg.Validate(); err != nil {
		return err
	}

	if state == "absent" {
		return m.detachVMFromSwitch(ctx, vmName, adapterName)
	}

	return m.attachVMToSwitch(ctx, vmName, switchName, adapterName)
}

// attachVMToSwitch attaches a VM network adapter to a virtual switch.
// If adapterName is empty, the PowerShell -Name parameter is omitted entirely —
// never passed as an empty string, which would cause Add-VMNetworkAdapter to fail.
func (m *hypervModule) attachVMToSwitch(ctx context.Context, vmName, switchName, adapterName string) error {
	hostVMName := vmHostName(m.tenantID, vmName)
	hostSwitchName := vswitchHostName(m.tenantID, switchName)

	var (
		psCmd  string
		psArgs map[string]string
	)

	if adapterName == "" {
		// Omit -Name entirely — passing -Name "" to Add-VMNetworkAdapter is an error.
		psCmd = psAttachVMNoAdapterName
		psArgs = map[string]string{
			"VMName":     hostVMName,
			"SwitchName": hostSwitchName,
		}
	} else {
		psCmd = psAttachVMWithAdapterName
		psArgs = map[string]string{
			"VMName":     hostVMName,
			"SwitchName": hostSwitchName,
			"Name":       adapterName,
		}
	}

	if _, err := m.transport.ExecutePS(ctx, psCmd, psArgs); err != nil {
		return fmt.Errorf("hyperv: attach VM %q to switch %q: %w", vmName, switchName, err)
	}
	return nil
}

// detachVMFromSwitch removes a named network adapter from a VM.
func (m *hypervModule) detachVMFromSwitch(ctx context.Context, vmName, adapterName string) error {
	hostVMName := vmHostName(m.tenantID, vmName)

	if _, err := m.transport.ExecutePS(ctx, psDetachVM, map[string]string{
		"VMName": hostVMName,
		"Name":   adapterName,
	}); err != nil {
		return fmt.Errorf("hyperv: detach adapter %q from VM %q: %w", adapterName, vmName, err)
	}
	return nil
}
