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
	// ErrSnapshotNotFound is returned when a requested snapshot does not exist on the host.
	ErrSnapshotNotFound = errors.New("hyperv: snapshot not found")

	// ErrInvalidSnapshotName is returned when a snapshot name fails allowlist validation or
	// contains the reserved __ separator.
	ErrInvalidSnapshotName = errors.New("hyperv: invalid snapshot name: must match ^[a-zA-Z0-9_\\- ]{1,64}$ and must not contain __")
)

// snapNamePattern is the allowlist for user-supplied snapshot names.
// Spaces are permitted per Hyper-V checkpoint naming convention.
// The __ check is enforced separately to produce a more specific error.
var snapNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_\- ]{1,64}$`)

// SnapshotConfig represents the desired state of a Hyper-V checkpoint.
type SnapshotConfig struct {
	VMName string `yaml:"vm_name"`
	Name   string `yaml:"name"`
	// State controls the lifecycle operation:
	//   "present"  — create the checkpoint if it does not exist
	//   "restored" — restore the VM to this checkpoint (write-only; Get never returns this)
	//   "absent"   — delete the checkpoint
	State string `yaml:"state,omitempty"`
}

// Validate checks all SnapshotConfig fields against their constraints.
func (c *SnapshotConfig) Validate() error {
	if !vmNamePattern.MatchString(c.VMName) {
		return ErrInvalidVMName
	}
	// __ is the tenant/resource separator — forbidden in user-supplied names.
	if strings.Contains(c.VMName, "__") {
		return ErrInvalidVMName
	}
	if !snapNamePattern.MatchString(c.Name) {
		return ErrInvalidSnapshotName
	}
	if strings.Contains(c.Name, "__") {
		return ErrInvalidSnapshotName
	}
	return nil
}

// AsMap implements modules.ConfigState.
func (c *SnapshotConfig) AsMap() map[string]interface{} {
	return map[string]interface{}{
		"vm_name": c.VMName,
		"name":    c.Name,
		"state":   c.State,
	}
}

// ToYAML serializes the configuration to YAML.
func (c *SnapshotConfig) ToYAML() ([]byte, error) {
	return yaml.Marshal(c)
}

// FromYAML deserializes YAML data into the configuration.
func (c *SnapshotConfig) FromYAML(data []byte) error {
	return yaml.Unmarshal(data, c)
}

// GetManagedFields returns the list of fields this configuration manages.
func (c *SnapshotConfig) GetManagedFields() []string {
	return []string{"vm_name", "name", "state"}
}

// snapHostName constructs the collision-free host-side snapshot name.
//
// Uses the same convention as vmHostName: cfgms-<sanitizedTenantID>__<snapName>.
// The __ separator is forbidden in user-supplied names (Validate enforces this),
// making cross-tenant name collision structurally impossible.
func snapHostName(tenantID, snapName string) string {
	return "cfgms-" + strings.ReplaceAll(tenantID, "/", "-") + "__" + snapName
}

// splitSnapshotName splits "<vmName>/<snapName>" from a resource ID name component.
// Returns ok=false if there is no "/" separator.
func splitSnapshotName(name string) (vmName, snapName string, ok bool) {
	idx := strings.IndexByte(name, '/')
	if idx < 0 {
		return "", "", false
	}
	return name[:idx], name[idx+1:], true
}

// psGetSnapshot checks whether a snapshot exists; emits JSON {"found":bool}.
// Both $VMName and $Name travel via ArgumentList — never interpolated into the script.
const psGetSnapshot = `$snap = Get-VMSnapshot -VMName $VMName -Name $Name -ErrorAction SilentlyContinue; if (-not $snap) { Write-Output '{"found":false}'; return }; Write-Output '{"found":true}'`

// psCreateSnapshot creates a new Hyper-V checkpoint.
// Both names travel via ArgumentList — never interpolated into the script text.
const psCreateSnapshot = `Checkpoint-VM -VMName $VMName -SnapshotName $Name`

// psRemoveSnapshot deletes a Hyper-V checkpoint.
// Both names travel via ArgumentList — never interpolated into the script text.
const psRemoveSnapshot = `Remove-VMSnapshot -VMName $VMName -Name $Name`

// psRestoreSnapshot restores a VM to a checkpoint.
// -Confirm:$false is a literal in the script (not user input).
// Both names travel via ArgumentList — never interpolated into the script text.
const psRestoreSnapshot = `Restore-VMSnapshot -VMName $VMName -Name $Name -Confirm:$false`

// getSnapshot retrieves the current state of a snapshot by user-visible names.
// Returns ErrSnapshotNotFound if the snapshot does not exist or the transport fails.
// State is always "present" when found — Get never returns "restored" (Hyper-V semantics).
func (m *hypervModule) getSnapshot(ctx context.Context, vmName, snapName string) (*SnapshotConfig, error) {
	if m.transport == nil {
		return nil, ErrSnapshotNotFound
	}

	// Validate before any WinRM call — defense-in-depth even though ArgumentList
	// already prevents injection at the transport layer.
	if err := (&SnapshotConfig{VMName: vmName, Name: snapName}).Validate(); err != nil {
		return nil, ErrSnapshotNotFound
	}

	hostVMName := vmHostName(m.tenantID, vmName)
	hostSnapName := snapHostName(m.tenantID, snapName)

	output, err := m.transport.ExecutePS(ctx, psGetSnapshot, map[string]string{
		"Name":   hostSnapName,
		"VMName": hostVMName,
	})
	if err != nil {
		return nil, ErrSnapshotNotFound
	}

	var parsed map[string]interface{}
	if jsonErr := json.Unmarshal([]byte(strings.TrimSpace(output)), &parsed); jsonErr != nil {
		return nil, ErrSnapshotNotFound
	}

	found, _ := parsed["found"].(bool)
	if !found {
		return nil, ErrSnapshotNotFound
	}

	// Hyper-V does not delete checkpoints on restore, so the only observable
	// state from Get is "present". "restored" is write-only.
	return &SnapshotConfig{VMName: vmName, Name: snapName, State: "present"}, nil
}

// setSnapshot applies the desired snapshot state.
// Resource ID format: "snapshot:<vmName>/<snapName>".
func (m *hypervModule) setSnapshot(ctx context.Context, resourceID string, config modules.ConfigState) error {
	if m.transport == nil {
		return modules.ErrNotImplemented
	}

	// Extract vmName and snapName from resource ID "snapshot:<vmName>/<snapName>".
	parts := strings.SplitN(resourceID, ":", 2)
	if len(parts) != 2 {
		return modules.ErrNotImplemented
	}
	vmName, snapName, ok := splitSnapshotName(parts[1])
	if !ok {
		return modules.ErrNotImplemented
	}

	// Validate user-supplied names before issuing any WinRM commands.
	snapCfg := &SnapshotConfig{VMName: vmName, Name: snapName}
	if err := snapCfg.Validate(); err != nil {
		return err
	}

	configMap := config.AsMap()
	state, _ := configMap["state"].(string)

	switch state {
	case "absent":
		return m.removeSnapshot(ctx, vmName, snapName)
	case "restored":
		return m.restoreSnapshot(ctx, vmName, snapName)
	default:
		return m.createSnapshot(ctx, vmName, snapName)
	}
}

// createSnapshot creates a new checkpoint on the host.
func (m *hypervModule) createSnapshot(ctx context.Context, vmName, snapName string) error {
	hostVMName := vmHostName(m.tenantID, vmName)
	hostSnapName := snapHostName(m.tenantID, snapName)

	if _, err := m.transport.ExecutePS(ctx, psCreateSnapshot, map[string]string{
		"Name":   hostSnapName,
		"VMName": hostVMName,
	}); err != nil {
		return fmt.Errorf("hyperv: create snapshot %q on VM %q: %w", snapName, vmName, err)
	}
	return nil
}

// removeSnapshot deletes a checkpoint from the host.
func (m *hypervModule) removeSnapshot(ctx context.Context, vmName, snapName string) error {
	hostVMName := vmHostName(m.tenantID, vmName)
	hostSnapName := snapHostName(m.tenantID, snapName)

	if _, err := m.transport.ExecutePS(ctx, psRemoveSnapshot, map[string]string{
		"Name":   hostSnapName,
		"VMName": hostVMName,
	}); err != nil {
		return fmt.Errorf("hyperv: remove snapshot %q on VM %q: %w", snapName, vmName, err)
	}
	return nil
}

// restoreSnapshot restores the VM to the named checkpoint.
// This is a write-only operation: getSnapshot always returns "present" after restore
// because Hyper-V does not delete checkpoints when restoring.
func (m *hypervModule) restoreSnapshot(ctx context.Context, vmName, snapName string) error {
	hostVMName := vmHostName(m.tenantID, vmName)
	hostSnapName := snapHostName(m.tenantID, snapName)

	if _, err := m.transport.ExecutePS(ctx, psRestoreSnapshot, map[string]string{
		"Name":   hostSnapName,
		"VMName": hostVMName,
	}); err != nil {
		return fmt.Errorf("hyperv: restore snapshot %q on VM %q: %w", snapName, vmName, err)
	}
	return nil
}
