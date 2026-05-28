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
	// ErrVMNotFound is returned when a requested VM does not exist on the host.
	ErrVMNotFound = errors.New("hyperv: VM not found")

	// ErrInvalidVMName is returned when a VM name fails allowlist validation or
	// contains the reserved __ separator.
	ErrInvalidVMName = errors.New("hyperv: invalid VM name: must match ^[a-zA-Z0-9_\\-]{1,64}$ and must not contain __")

	// ErrInvalidVHDPath is returned when a VHD path is not a valid absolute Windows path.
	ErrInvalidVHDPath = errors.New("hyperv: invalid VHD path: must be an absolute Windows path (e.g. C:\\VMs\\disk.vhdx)")

	// ErrInvalidGeneration is returned when a VM generation other than 2 (or 0/unset) is specified.
	ErrInvalidGeneration = errors.New("hyperv: invalid generation: must be 2 (or 0 to accept the default)")
)

// vmNamePattern is the allowlist for user-supplied VM names.
// The __ check is enforced separately to produce a more specific error.
var vmNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_\-]{1,64}$`)

// vhdPathPattern validates Windows absolute paths.
var vhdPathPattern = regexp.MustCompile(`^[A-Za-z]:\\.*`)

// VMConfig represents the desired state of a Hyper-V virtual machine.
type VMConfig struct {
	Name       string `yaml:"name"`
	MemoryMB   int64  `yaml:"memory_mb"`
	CPUCount   int    `yaml:"cpu_count"`
	VHDPath    string `yaml:"vhd_path"`
	SwitchName string `yaml:"switch_name"`
	Generation int    `yaml:"generation"`
	// State is the desired lifecycle: "running", "stopped", or "absent" (delete).
	State string `yaml:"state,omitempty"`
}

// Validate checks all VMConfig fields against their respective constraints.
func (c *VMConfig) Validate() error {
	if !vmNamePattern.MatchString(c.Name) {
		return ErrInvalidVMName
	}
	// __ is the tenant/VM separator — forbidden in user-supplied names to prevent
	// a tenant from forging a prefix that collides with another tenant's VMs.
	if strings.Contains(c.Name, "__") {
		return ErrInvalidVMName
	}
	if c.Generation != 0 && c.Generation != 2 {
		return ErrInvalidGeneration
	}
	if c.VHDPath != "" && !vhdPathPattern.MatchString(c.VHDPath) {
		return ErrInvalidVHDPath
	}
	return nil
}

// AsMap implements modules.ConfigState.
func (c *VMConfig) AsMap() map[string]interface{} {
	return map[string]interface{}{
		"name":        c.Name,
		"memory_mb":   c.MemoryMB,
		"cpu_count":   c.CPUCount,
		"vhd_path":    c.VHDPath,
		"switch_name": c.SwitchName,
		"generation":  c.Generation,
		"state":       c.State,
	}
}

// ToYAML serializes the configuration to YAML.
func (c *VMConfig) ToYAML() ([]byte, error) {
	return yaml.Marshal(c)
}

// FromYAML deserializes YAML data into the configuration.
func (c *VMConfig) FromYAML(data []byte) error {
	return yaml.Unmarshal(data, c)
}

// GetManagedFields returns the list of fields this configuration manages.
func (c *VMConfig) GetManagedFields() []string {
	return []string{"name", "memory_mb", "cpu_count", "vhd_path", "switch_name", "generation", "state"}
}

// vmHostName constructs the collision-free host-side VM name.
//
// The cfgms- prefix and __ separator together make it impossible for a user to
// construct a VM name that collides with another tenant's VMs:
//   - __ is forbidden in user-supplied names (Validate enforces this)
//   - slashes in tenantID are replaced with hyphens to produce a flat prefix
func vmHostName(tenantID, vmName string) string {
	return "cfgms-" + strings.ReplaceAll(tenantID, "/", "-") + "__" + vmName
}

// vmUserName extracts the user-supplied VM name from a host-side prefixed name.
func vmUserName(tenantID, hostName string) string {
	prefix := "cfgms-" + strings.ReplaceAll(tenantID, "/", "-") + "__"
	return strings.TrimPrefix(hostName, prefix)
}

// psGetVM is the script block passed to ExecutePS for VM retrieval.
// $Name is the only parameter; its value is transmitted via ArgumentList.
const psGetVM = `$vm = Get-VM -Name $Name -ErrorAction SilentlyContinue; if (-not $vm) { Write-Output '{"found":false}'; return }; $adapter = Get-VMNetworkAdapter -VMName $Name -ErrorAction SilentlyContinue | Select-Object -First 1; $result = @{ found=$true; Name=$vm.Name; MemoryStartupBytes=[long]$vm.MemoryStartupBytes; ProcessorCount=[int]$vm.ProcessorCount; Generation=[int]$vm.Generation; Path=$vm.Path; SwitchName=if ($adapter) { $adapter.SwitchName } else { "" }; State=$vm.State.ToString() }; ConvertTo-Json $result -Compress`

// psCreateVM is the script block passed to ExecutePS for VM creation.
// All user-supplied values are transmitted via ArgumentList — none are
// interpolated into the script text.
const psCreateVM = `New-VM -Name $Name -MemoryStartupBytes ($MemoryMB * 1MB) -ProcessorCount $CPU -NewVHDPath $VHDPath -SwitchName $SwitchName -Generation 2 | Out-Null`

// psRemoveVM is the script block passed to ExecutePS for VM deletion.
// $Name is the only parameter; its value is transmitted via ArgumentList.
const psRemoveVM = `Remove-VM -Name $Name -Force`

// getVM retrieves the current state of a VM by user-visible name.
func (m *hypervModule) getVM(ctx context.Context, vmName string) (*VMConfig, error) {
	if m.transport == nil {
		return nil, ErrVMNotFound
	}

	hostName := vmHostName(m.tenantID, vmName)
	output, err := m.transport.ExecutePS(ctx, psGetVM, map[string]string{"Name": hostName})
	if err != nil {
		return nil, ErrVMNotFound
	}

	var parsed map[string]interface{}
	if jsonErr := json.Unmarshal([]byte(strings.TrimSpace(output)), &parsed); jsonErr != nil {
		return nil, ErrVMNotFound
	}

	found, _ := parsed["found"].(bool)
	if !found {
		return nil, ErrVMNotFound
	}

	// Strip the host-side prefix to recover the user-visible VM name.
	returnedHostName, _ := parsed["Name"].(string)
	userVisibleName := vmName
	if returnedHostName != "" {
		userVisibleName = vmUserName(m.tenantID, returnedHostName)
	}
	cfg := &VMConfig{Name: userVisibleName}

	if v, ok := parsed["MemoryStartupBytes"].(float64); ok {
		cfg.MemoryMB = int64(v) / (1024 * 1024)
	}
	if v, ok := parsed["ProcessorCount"].(float64); ok {
		cfg.CPUCount = int(v)
	}
	if v, ok := parsed["Generation"].(float64); ok {
		cfg.Generation = int(v)
	}
	if v, ok := parsed["Path"].(string); ok {
		cfg.VHDPath = v
	}
	if v, ok := parsed["SwitchName"].(string); ok {
		cfg.SwitchName = v
	}
	if v, ok := parsed["State"].(string); ok {
		switch v {
		case "Running":
			cfg.State = "running"
		case "Off":
			cfg.State = "stopped"
		default:
			cfg.State = strings.ToLower(v)
		}
	}

	// Write-through: update cache on successful read
	m.vmsMu.Lock()
	m.vms[vmName] = *cfg
	m.vmsMu.Unlock()

	return cfg, nil
}

// setVM applies the desired VM configuration.
// Write-through cache semantics: transport is called first; cache updated on success only.
func (m *hypervModule) setVM(ctx context.Context, resourceID string, config modules.ConfigState) error {
	if m.transport == nil {
		return modules.ErrNotImplemented
	}

	// Extract VM name from resource ID "vm:<name>"
	parts := strings.SplitN(resourceID, ":", 2)
	if len(parts) != 2 {
		return modules.ErrNotImplemented
	}
	vmName := parts[1]

	configMap := config.AsMap()
	state, _ := configMap["state"].(string)

	if state == "absent" {
		return m.removeVM(ctx, vmName)
	}

	cfg := &VMConfig{Name: vmName}
	if v, ok := configMap["memory_mb"].(int64); ok {
		cfg.MemoryMB = v
	} else if v, ok := configMap["memory_mb"].(int); ok {
		cfg.MemoryMB = int64(v)
	}
	if v, ok := configMap["cpu_count"].(int); ok {
		cfg.CPUCount = v
	}
	if v, ok := configMap["vhd_path"].(string); ok {
		cfg.VHDPath = v
	}
	if v, ok := configMap["switch_name"].(string); ok {
		cfg.SwitchName = v
	}
	if v, ok := configMap["generation"].(int); ok {
		cfg.Generation = v
	}
	cfg.State = state

	// Also handle *VMConfig passed directly
	if vc, ok := config.(*VMConfig); ok {
		*cfg = *vc
		cfg.Name = vmName
	}

	if err := cfg.Validate(); err != nil {
		return err
	}

	hostName := vmHostName(m.tenantID, vmName)
	psArgs := map[string]string{
		"Name":       hostName,
		"MemoryMB":   fmt.Sprintf("%d", cfg.MemoryMB),
		"CPU":        fmt.Sprintf("%d", cfg.CPUCount),
		"VHDPath":    cfg.VHDPath,
		"SwitchName": cfg.SwitchName,
	}

	if _, err := m.transport.ExecutePS(ctx, psCreateVM, psArgs); err != nil {
		return fmt.Errorf("hyperv: create VM %q: %w", vmName, err)
	}

	// Write-through: update cache on success
	cfgCopy := *cfg
	cfgCopy.Name = vmName
	m.vmsMu.Lock()
	m.vms[vmName] = cfgCopy
	m.vmsMu.Unlock()

	return nil
}

// removeVM deletes a VM from the host.
// Write-through cache semantics: transport is called first; cache updated on success only.
func (m *hypervModule) removeVM(ctx context.Context, vmName string) error {
	hostName := vmHostName(m.tenantID, vmName)

	if _, err := m.transport.ExecutePS(ctx, psRemoveVM, map[string]string{"Name": hostName}); err != nil {
		return fmt.Errorf("hyperv: remove VM %q: %w", vmName, err)
	}

	m.vmsMu.Lock()
	delete(m.vms, vmName)
	m.vmsMu.Unlock()

	return nil
}
