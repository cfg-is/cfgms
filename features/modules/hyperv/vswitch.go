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

	// ErrInvalidSwitchName is returned when a switch name fails allowlist validation.
	ErrInvalidSwitchName = errors.New("hyperv: invalid switch name: must match ^[a-zA-Z0-9_\\- ]{1,64}$")

	// ErrInvalidSwitchType is returned when SwitchType is not external, internal, or private.
	ErrInvalidSwitchType = errors.New("hyperv: invalid switch type: must be external, internal, or private")

	// ErrExternalRequiresAdapter is returned when an external switch has empty NetAdapterName.
	ErrExternalRequiresAdapter = errors.New("hyperv: external switch requires non-empty NetAdapterName")

	// ErrAdapterForbiddenForNonExternal is returned when a non-external switch has non-empty NetAdapterName.
	ErrAdapterForbiddenForNonExternal = errors.New("hyperv: NetAdapterName must be empty for internal and private switch types")
)

// switchNamePattern is the allowlist for user-supplied virtual switch names.
// Spaces are permitted per Hyper-V virtual switch naming convention. It is an
// injection safety guard only — the name is used verbatim as the host-side name.
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

// psGetVSwitch checks whether a virtual switch exists; emits JSON {"found":bool,"SwitchType":"..."}.
// $Name travels via ArgumentList — never interpolated into the script text.
const psGetVSwitch = `$sw = Get-VMSwitch -Name $Name -ErrorAction SilentlyContinue; if (-not $sw) { Write-Output '{"found":false}'; return }; $result = @{ found=$true; Name=$sw.Name; SwitchType=$sw.SwitchType.ToString() }; ConvertTo-Json $result -Compress`

// psEnumerateVSwitches lists all virtual switches on the host with their types.
// No parameters — enumerates the full switch inventory. Used by the domain
// observe path. The @() wrapper ensures ConvertTo-Json emits a JSON array even
// for 0 or 1 switches.
const psEnumerateVSwitches = `$sw = @(Get-VMSwitch -ErrorAction SilentlyContinue | ForEach-Object { @{Name=$_.Name; SwitchType=$_.SwitchType.ToString()} }); ConvertTo-Json @{switches=$sw} -Compress -Depth 4`

// psRemoveVSwitch removes a virtual switch by host-side name. Guarded so a
// removal of an already-absent switch is a clean no-op rather than an
// ObjectNotFound error (mirrors psRemoveVM's existence guard — keeps the
// delete path idempotent under retries/races). $Name travels via ArgumentList.
const psRemoveVSwitch = `$sw = Get-VMSwitch -Name $Name -ErrorAction SilentlyContinue; if ($sw) { Remove-VMSwitch -Name $Name -Force }`

// psCreateVSwitchInternal creates an internal virtual switch.
// $Name travels via ArgumentList — never interpolated into the script text.
const psCreateVSwitchInternal = `New-VMSwitch -Name $Name -SwitchType Internal | Out-Null`

// psCreateVSwitchPrivate creates a private virtual switch.
// $Name travels via ArgumentList — never interpolated into the script text.
const psCreateVSwitchPrivate = `New-VMSwitch -Name $Name -SwitchType Private | Out-Null`

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

// getVSwitch returns the current state of a virtual switch on the host, queried
// by its exact name.
//
// Contract (matches the directory/file modules):
//   - resource exists  → (&VSwitchConfig{State: "present", ...}, nil)
//   - resource absent  → (&VSwitchConfig{Name, State: "absent"}, nil)
//   - module not ready → (nil, ErrVSwitchNotFound)
//   - transport failed → (nil, wrapped error)
//
// Returning state:"absent" rather than an error lets the unified executor
// detect drift against a desired state:"present" config and proceed to Set,
// instead of treating "absent" as a fatal Get failure.
func (m *hypervModule) getVSwitch(ctx context.Context, switchName string) (*VSwitchConfig, error) {
	if m.transport == nil {
		return nil, ErrVSwitchNotFound
	}

	output, err := m.transport.ExecutePS(ctx, psGetVSwitch, map[string]string{"Name": switchName})
	if err != nil {
		return nil, fmt.Errorf("hyperv: get vswitch %q: %w", switchName, err)
	}

	var parsed map[string]interface{}
	if jsonErr := json.Unmarshal([]byte(strings.TrimSpace(output)), &parsed); jsonErr != nil {
		return nil, fmt.Errorf("hyperv: parse get-vswitch response for %q: %w", switchName, jsonErr)
	}

	found, _ := parsed["found"].(bool)
	if !found {
		// Absent is a valid current state — the executor compares this against
		// the desired state and calls Set to create the resource when needed.
		return &VSwitchConfig{Name: switchName, State: "absent"}, nil
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

// observeVSwitchDomain returns the full vSwitch inventory on this host without
// requiring declared hyperv.vswitch resources. Used by GetDomain. Returns nil
// when the transport is not wired. All PowerShell calls are read-only (Get-*).
func (m *hypervModule) observeVSwitchDomain(ctx context.Context) ([]*VSwitchConfig, error) {
	if m.transport == nil {
		return nil, nil
	}
	output, err := m.transport.ExecutePS(ctx, psEnumerateVSwitches, nil)
	if err != nil {
		return nil, fmt.Errorf("hyperv: enumerate vswitches: %w", err)
	}
	var parsed struct {
		Switches []struct {
			Name       string `json:"Name"`
			SwitchType string `json:"SwitchType"`
		} `json:"switches"`
	}
	if jsonErr := json.Unmarshal([]byte(strings.TrimSpace(output)), &parsed); jsonErr != nil {
		return nil, fmt.Errorf("hyperv: parse enumerate-vswitches response: %w", jsonErr)
	}
	out := make([]*VSwitchConfig, 0, len(parsed.Switches))
	for _, sw := range parsed.Switches {
		out = append(out, &VSwitchConfig{
			Name:       sw.Name,
			SwitchType: strings.ToLower(sw.SwitchType),
			State:      "present",
		})
	}
	return out, nil
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
		// Snapshot current state for audit before-capture (best-effort).
		var deleteBefore map[string]interface{}
		if cur, gErr := m.getVSwitch(ctx, switchName); gErr == nil && cur != nil && cur.State != "absent" {
			deleteBefore = map[string]interface{}{
				"switch_type": cur.SwitchType,
				"state":       cur.State,
			}
		}
		return m.removeVSwitch(ctx, switchName, deleteBefore)
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
	// The host object name is the exact switch name — no namespacing.
	hostName := switchName
	cfgResourceID := "vswitch:" + switchName
	after := map[string]interface{}{
		"switch_type": cfg.SwitchType,
		"state":       "present",
	}

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

	_, psErr := m.transport.ExecutePS(ctx, psCmd, psArgs)
	recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "New-VMSwitch", cfgResourceID, nil, after, psErr)
	if psErr != nil {
		return fmt.Errorf("hyperv: create vswitch %q: %w", switchName, psErr)
	}

	cfgCopy := *cfg
	cfgCopy.Name = switchName
	m.vswitchesMu.Lock()
	m.vswitches[switchName] = cfgCopy
	m.vswitchesMu.Unlock()

	return nil
}

// removeVSwitch deletes a virtual switch from the host.
// before captures the non-sensitive scalar state prior to deletion; pass nil
// when the current state is unknown.
// Write-through cache semantics: transport is called first; cache updated on success only.
func (m *hypervModule) removeVSwitch(ctx context.Context, switchName string, before map[string]interface{}) error {
	// The host object name is the exact switch name — no namespacing.
	hostName := switchName
	cfgResourceID := "vswitch:" + switchName

	_, psErr := m.transport.ExecutePS(ctx, psRemoveVSwitch, map[string]string{"Name": hostName})
	recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Remove-VMSwitch", cfgResourceID, before, nil, psErr)
	if psErr != nil {
		return fmt.Errorf("hyperv: remove vswitch %q: %w", switchName, psErr)
	}

	m.vswitchesMu.Lock()
	delete(m.vswitches, switchName)
	m.vswitchesMu.Unlock()

	return nil
}
