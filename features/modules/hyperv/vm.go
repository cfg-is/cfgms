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
	"time"

	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/features/modules"
)

var (
	// ErrVMNotFound is returned when a requested VM does not exist on the host.
	ErrVMNotFound = errors.New("hyperv: VM not found")

	// ErrInvalidVMName is returned when a VM name fails allowlist validation.
	ErrInvalidVMName = errors.New("hyperv: invalid VM name: must match ^[a-zA-Z0-9_\\-]{1,64}$")

	// ErrInvalidVHDPath is returned when a VHD path is not a valid absolute Windows path.
	ErrInvalidVHDPath = errors.New("hyperv: invalid VHD path: must be an absolute Windows path (e.g. C:\\VMs\\disk.vhdx)")

	// ErrInvalidGeneration is returned when a VM generation outside {1, 2} (or 0/unset) is specified.
	ErrInvalidGeneration = errors.New("hyperv: invalid generation: must be 1 or 2 (or 0 to accept the default)")

	// ErrInvalidSourceISO is returned when the source iso field is missing or not an absolute Windows path.
	ErrInvalidSourceISO = errors.New("hyperv: invalid source iso: must be a non-empty absolute Windows path (e.g. C:\\ISO\\server.iso)")

	// ErrInvalidSourceOSFamily is returned when source os_family is not linux or windows.
	ErrInvalidSourceOSFamily = errors.New("hyperv: invalid source os_family: must be linux or windows")

	// ErrInvalidSourceUnattend is returned when source unattend does not start with profile://.
	ErrInvalidSourceUnattend = errors.New("hyperv: invalid source unattend: must start with profile://")

	// ErrInvalidSourceCompletionMode is returned when source completion.mode is not steward-registration.
	ErrInvalidSourceCompletionMode = errors.New("hyperv: invalid source completion.mode: must be steward-registration")

	// ErrInvalidSourceCompletionTimeout is returned when source completion.timeout cannot be parsed as a duration.
	ErrInvalidSourceCompletionTimeout = errors.New("hyperv: invalid source completion.timeout: must be a valid duration string (e.g. 60m)")

	// ErrInvalidSourceOnExisting is returned when source on_existing is not never or recreate.
	ErrInvalidSourceOnExisting = errors.New("hyperv: invalid source on_existing: must be never or recreate")
)

// vmNamePattern is the allowlist for user-supplied VM names. It is an injection
// safety guard only — the name is used verbatim as the host-side VM name.
var vmNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_\-]{1,64}$`)

// vhdPathPattern validates Windows absolute paths.
var vhdPathPattern = regexp.MustCompile(`^[A-Za-z]:\\.*`)

// CompletionConfig specifies how the provisioner detects that the installed OS
// is ready and has registered its steward.
type CompletionConfig struct {
	// Mode is the detection strategy; steward-registration is the only
	// supported value in v1.
	Mode string `yaml:"mode,omitempty"`
	// Timeout is a Go duration string (e.g. "60m") bounding the wait.
	Timeout string `yaml:"timeout,omitempty"`
}

// SourceConfig describes the ISO boot-provisioning parameters for a VM.
// Presence of a source block in a hyperv.vm resource triggers the provisioning
// state machine (absent → creating → installing → finalizing → ready).
type SourceConfig struct {
	// ISO is the absolute Windows path to the installation ISO.
	ISO string `yaml:"iso"`
	// OSFamily distinguishes the installer type: linux or windows.
	OSFamily string `yaml:"os_family"`
	// Unattend is an optional reference to an unattended-install profile,
	// expressed as a profile:// URI.
	Unattend string `yaml:"unattend,omitempty"`
	// Completion defines how the module knows provisioning succeeded.
	Completion CompletionConfig `yaml:"completion,omitempty"`
	// OnExisting controls behaviour when the VM already exists:
	// never (default) leaves it untouched; recreate destroys and re-provisions.
	OnExisting string `yaml:"on_existing,omitempty"`
}

// VMConfig represents the desired state of a Hyper-V virtual machine.
//
// Networking is declarative: switch_name is the FULL desired network of the
// VM and accepts either a single switch name (string — the common case,
// back-compat) or a list of switch names (multi-NIC). On convergence the
// module reconciles the VM's network adapters so that exactly one adapter is
// connected to each switch in the desired set; switches added to the set
// connect a new adapter, switches removed from the set remove the adapter.
//
// SwitchName holds the primary (first) desired switch for back-compat: the
// New-VM create path connects the first adapter to it, and getVM populates it
// from the first adapter for the single-NIC drift comparison. SwitchNames
// holds the FULL desired/observed set. Both are populated by FromYAML /
// AsMap so a single switch_name string behaves exactly as before.
type VMConfig struct {
	Name        string             `yaml:"name"`
	MemoryMB    int64              `yaml:"memory_mb"`
	CPUCount    int                `yaml:"cpu_count"`
	VHDPath     string             `yaml:"vhd_path"`
	SwitchName  string             `yaml:"-"`
	SwitchNames stringOrStringList `yaml:"switch_name"`
	Generation  int                `yaml:"generation"`
	// State is the desired lifecycle: "running", "stopped", or "absent" (delete).
	State string `yaml:"state,omitempty"`
	// Source, when non-nil, activates the ISO provisioning state machine.
	// Absent source: block leaves the VM managed by the existing lifecycle only.
	Source *SourceConfig `yaml:"source,omitempty"`
}

// stringOrStringList is a YAML scalar-or-sequence: switch_name may be a single
// string ("External") or a list (["External","Mgmt"]). It always materialises
// as a []string so the convergence code works with one shape. Marshalling
// emits a bare string when there is exactly one element (round-trips the
// common single-switch case) and a sequence otherwise.
type stringOrStringList []string

// UnmarshalYAML accepts either a scalar string or a sequence of strings.
func (s *stringOrStringList) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		var single string
		if err := value.Decode(&single); err != nil {
			return err
		}
		if single == "" {
			*s = nil
			return nil
		}
		*s = stringOrStringList{single}
		return nil
	case yaml.SequenceNode:
		var list []string
		if err := value.Decode(&list); err != nil {
			return err
		}
		*s = stringOrStringList(list)
		return nil
	default:
		return fmt.Errorf("hyperv: switch_name must be a string or a list of strings")
	}
}

// MarshalYAML emits a bare string for the single-switch case (back-compat
// round-trip) and a sequence otherwise.
func (s stringOrStringList) MarshalYAML() (interface{}, error) {
	if len(s) == 1 {
		return s[0], nil
	}
	return []string(s), nil
}

// desiredSwitches returns the full, ordered, de-duplicated desired network of
// the VM. It unions the back-compat primary SwitchName (if set) with the
// SwitchNames list, preserving first-seen order. This is the canonical desired
// set the convergence logic reconciles against; an empty result means "no
// network declared" (the VM keeps whatever adapters it has — we never strip
// a VM down to zero NICs implicitly).
func (c *VMConfig) desiredSwitches() []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(name string) {
		if name == "" {
			return
		}
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	add(c.SwitchName)
	for _, n := range c.SwitchNames {
		add(n)
	}
	return out
}

// normalizeSwitches collapses SwitchName + SwitchNames into the canonical form:
// SwitchNames holds the full ordered de-duplicated set and SwitchName holds the
// first element (back-compat primary). Idempotent.
func (c *VMConfig) normalizeSwitches() {
	desired := c.desiredSwitches()
	c.SwitchNames = stringOrStringList(desired)
	if len(desired) > 0 {
		c.SwitchName = desired[0]
	} else {
		c.SwitchName = ""
	}
}

// parseSwitchNamesJSON normalises the SwitchNames field from a parsed Get-VM
// JSON response into a []string. ConvertTo-Json renders a PowerShell array as
// a JSON array, but a single-element array can collapse to a bare string on
// some PS versions; an empty array becomes null. All three shapes are handled.
// Duplicate and empty entries are dropped, preserving first-seen order.
func parseSwitchNamesJSON(v interface{}) stringOrStringList {
	var raw []string
	switch t := v.(type) {
	case string:
		if t != "" {
			raw = []string{t}
		}
	case []interface{}:
		for _, e := range t {
			if s, ok := e.(string); ok {
				raw = append(raw, s)
			}
		}
	}
	seen := make(map[string]struct{}, len(raw))
	var out stringOrStringList
	for _, s := range raw {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// switchSetDiff computes, for a desired set vs a current set of switch names,
// which switches need a new adapter connected (toConnect) and which connected
// adapters sit on a switch no longer desired (toDisconnect). Order of the
// desired set is preserved in toConnect. When desired == current both slices
// are empty (idempotent — no PS mutation runs).
func switchSetDiff(desired, current []string) (toConnect, toDisconnect []string) {
	desiredSet := make(map[string]struct{}, len(desired))
	for _, d := range desired {
		desiredSet[d] = struct{}{}
	}
	currentSet := make(map[string]struct{}, len(current))
	for _, c := range current {
		currentSet[c] = struct{}{}
	}
	for _, d := range desired {
		if _, ok := currentSet[d]; !ok {
			toConnect = append(toConnect, d)
		}
	}
	for _, c := range current {
		if _, ok := desiredSet[c]; !ok {
			toDisconnect = append(toDisconnect, c)
		}
	}
	return toConnect, toDisconnect
}

// Validate checks all VMConfig fields against their respective constraints.
func (c *VMConfig) Validate() error {
	if !vmNamePattern.MatchString(c.Name) {
		return ErrInvalidVMName
	}
	// 0 means "accept the default" (Generation 2). 1 and 2 are explicitly valid
	// per ADR-009 §5, which lifted the Gen-2-only restriction.
	if c.Generation != 0 && c.Generation != 1 && c.Generation != 2 {
		return ErrInvalidGeneration
	}
	if c.VHDPath != "" && !vhdPathPattern.MatchString(c.VHDPath) {
		return ErrInvalidVHDPath
	}
	// Every desired switch name must satisfy the switch allowlist — the same
	// guard the standalone vswitch resource applies — so a malformed name can
	// never reach Add-VMNetworkAdapter even though it travels via ArgumentList.
	for _, sw := range c.desiredSwitches() {
		if !switchNamePattern.MatchString(sw) {
			return ErrInvalidSwitchName
		}
	}
	if c.Source != nil {
		if err := c.Source.validate(); err != nil {
			return err
		}
	}
	return nil
}

// validate checks all SourceConfig fields against their constraints.
func (s *SourceConfig) validate() error {
	if !vhdPathPattern.MatchString(s.ISO) {
		return ErrInvalidSourceISO
	}
	switch s.OSFamily {
	case "linux", "windows":
	default:
		return ErrInvalidSourceOSFamily
	}
	if s.Unattend != "" && !strings.HasPrefix(s.Unattend, "profile://") {
		return ErrInvalidSourceUnattend
	}
	if s.Completion.Mode != "" && s.Completion.Mode != "steward-registration" {
		return ErrInvalidSourceCompletionMode
	}
	if s.Completion.Timeout != "" {
		if _, err := time.ParseDuration(s.Completion.Timeout); err != nil {
			return ErrInvalidSourceCompletionTimeout
		}
	}
	switch s.OnExisting {
	case "", "never", "recreate":
	default:
		return ErrInvalidSourceOnExisting
	}
	return nil
}

// AsMap implements modules.ConfigState.
//
// switch_name carries the primary (first) desired switch for back-compat;
// switch_names carries the FULL desired/observed set ([]string) that the
// convergence logic reconciles against.
func (c *VMConfig) AsMap() map[string]interface{} {
	desired := c.desiredSwitches()
	m := map[string]interface{}{
		"name":         c.Name,
		"memory_mb":    c.MemoryMB,
		"cpu_count":    c.CPUCount,
		"vhd_path":     c.VHDPath,
		"switch_name":  switchNameField(desired),
		"switch_names": desired,
		"generation":   c.Generation,
		"state":        c.State,
		"source":       nil,
	}
	if c.Source != nil {
		m["source"] = map[string]interface{}{
			"iso":       c.Source.ISO,
			"os_family": c.Source.OSFamily,
			"unattend":  c.Source.Unattend,
			"completion": map[string]interface{}{
				"mode":    c.Source.Completion.Mode,
				"timeout": c.Source.Completion.Timeout,
			},
			"on_existing": c.Source.OnExisting,
		}
	}
	return m
}

// switchNameField renders the desired switch SET as the value the drift
// comparator sees for the "switch_name" managed field. It must reflect the FULL
// set (not just the primary) so removing a switch from a multi-NIC VM is
// detected as drift — otherwise the executor's "skip Set when unchanged"
// optimisation never triggers the reconcile that disconnects the adapter.
// Single switch -> a bare string (matches the common single-NIC user config and
// keeps it idempotent); multiple -> a []interface{} list (matching the YAML
// list type a multi-NIC config decodes to, so equal sets compare equal).
func switchNameField(desired []string) interface{} {
	switch len(desired) {
	case 0:
		return ""
	case 1:
		return desired[0]
	default:
		out := make([]interface{}, len(desired))
		for i, s := range desired {
			out[i] = s
		}
		return out
	}
}

// ToYAML serializes the configuration to YAML.
func (c *VMConfig) ToYAML() ([]byte, error) {
	c.normalizeSwitches()
	return yaml.Marshal(c)
}

// FromYAML deserializes YAML data into the configuration.
func (c *VMConfig) FromYAML(data []byte) error {
	if err := yaml.Unmarshal(data, c); err != nil {
		return err
	}
	c.normalizeSwitches()
	return nil
}

// GetManagedFields returns the list of fields this configuration manages.
func (c *VMConfig) GetManagedFields() []string {
	return []string{"name", "memory_mb", "cpu_count", "vhd_path", "switch_name", "generation", "state", "source"}
}

// psGetVM is the script block passed to ExecutePS for VM retrieval.
// $Name is the only parameter; its value is transmitted via ArgumentList.
//
// Path is read from Get-VMHardDiskDrive (the path of the first attached
// hard disk), not Get-VM.Path which is the VM configuration directory.
// VMConfig.VHDPath stores the disk path; conflating it with the config
// directory caused #1887 B1 verification to flag 2-changed drift on
// every successful create.
const psGetVM = `$vm = Get-VM -Name $Name -ErrorAction SilentlyContinue; if (-not $vm) { Write-Output '{"found":false}'; return }; $adapters = @(Get-VMNetworkAdapter -VMName $Name -ErrorAction SilentlyContinue); $switchNames = @($adapters | ForEach-Object { $_.SwitchName } | Where-Object { $_ }); $disk = Get-VMHardDiskDrive -VMName $Name -ErrorAction SilentlyContinue | Select-Object -First 1; $mem = Get-VMMemory -VMName $Name -ErrorAction SilentlyContinue; $startupBytes = if ($mem) { [long]$mem.Startup } else { 0 }; $result = @{ found=$true; Name=$vm.Name; MemoryStartupBytes=$startupBytes; ProcessorCount=[int]$vm.ProcessorCount; Generation=[int]$vm.Generation; Path=if ($disk) { $disk.Path } else { "" }; SwitchName=if ($switchNames.Count -gt 0) { $switchNames[0] } else { "" }; SwitchNames=$switchNames; State=$vm.State.ToString() }; ConvertTo-Json $result -Compress -Depth 4`

// psCreateVM is the script block passed to ExecutePS for VM creation.
// All user-supplied values are transmitted via ArgumentList — none are
// interpolated into the script text.
//
// Notes:
//   - New-VM does NOT accept -ProcessorCount (real PS pitfall surfaced by
//     the #1887 live-validation B1 bucket — previously masked because
//     WinRM was broken and this command never actually ran). CPU count
//     is set with a separate Set-VMProcessor call after the VM exists.
//     A newly created Generation-2 VM defaults to 1 vCPU which we only
//     resize if the desired count differs.
//   - -NewVHDPath also requires -NewVHDSizeBytes; the cmdlet doesn't
//     auto-default a size. Hardcoded to 64 GB here (matches Hyper-V
//     Manager's default new-VM size and is the minimum sensible value
//     for any Server 2022/2025 guest). The schema does not currently
//     expose vhd_size_gb; future #1887 follow-up should add it.
const psCreateVM = `New-VM -Name $Name -MemoryStartupBytes ($MemoryMB * 1MB) -NewVHDPath $VHDPath -NewVHDSizeBytes 64GB -SwitchName $SwitchName -Generation 2 | Out-Null; if ($CPU -ne 1) { Set-VMProcessor -VMName $Name -Count $CPU }`

// psRemoveVM deletes a VM. Hyper-V refuses to remove a VM that is not Off
// ("the operation cannot be performed while the object is in its current
// state"), which in turn keeps any connected vSwitch "in use" and blocks its
// deletion — so a running VM is hard-powered-off first, then removed. A no-op
// when the VM is already gone. $Name travels via ArgumentList.
const psRemoveVM = `$vm = Get-VM -Name $Name -ErrorAction SilentlyContinue; if ($vm) { if ($vm.State -ne 'Off') { Stop-VM -Name $Name -Force -TurnOff }; Remove-VM -Name $Name -Force }`

// psConnectVMNic connects a NEW network adapter on the VM to the named switch.
// Both $Name (host-side VM name) and $SwitchName travel via ArgumentList —
// never interpolated into the script text. This is the declarative connect
// primitive used by reconcileNetwork; it resurrects the injection-safe
// Add-VMNetworkAdapter logic from the removed vmattach resource (#1903) but is
// driven by the VM's desired switch set rather than a standalone resource.
const psConnectVMNic = `Add-VMNetworkAdapter -VMName $Name -SwitchName $SwitchName`

// psDisconnectVMNic removes the (first) network adapter connected to the named
// switch on the VM. Both values travel via ArgumentList — never interpolated.
// Selecting by SwitchName (rather than a stored adapter name) keeps the
// primitive driven purely by the declarative desired set: removing a switch
// from the set removes the adapter sitting on it.
const psDisconnectVMNic = `$a = Get-VMNetworkAdapter -VMName $Name -ErrorAction SilentlyContinue | Where-Object { $_.SwitchName -eq $SwitchName } | Select-Object -First 1; if ($a) { Remove-VMNetworkAdapter -VMNetworkAdapter $a }`

// psStartVM starts a VM that already exists on the host.
const psStartVM = `Start-VM -Name $Name`

// psStopVM stops a running VM (Force prevents interactive confirmation).
const psStopVM = `Stop-VM -Name $Name -Force`

// psSetVMProcessor updates the virtual processor count on an existing VM.
const psSetVMProcessor = `Set-VMProcessor -VMName $Name -Count $CPU`

// psSetVMMemory updates the startup memory on an existing VM.
// Set-VMMemory is not a standard Hyper-V cmdlet; Set-VM with MemoryStartupBytes is used instead.
const psSetVMMemory = `Set-VM -Name $Name -MemoryStartupBytes ($MemoryMB * 1MB)`

// getVM returns the current state of a VM on the host, queried by its exact name.
//
// Contract (matches the directory/file modules):
//   - resource exists  → (&VMConfig{State: "running"|"stopped"|..., ...}, nil)
//   - resource absent  → (&VMConfig{Name, State: "absent"}, nil)
//   - module not ready → (nil, ErrVMNotFound)
//   - transport failed → (nil, wrapped error)
//
// Returning state:"absent" rather than an error lets the unified executor
// detect drift against a desired state:"present"/"running" config and
// proceed to Set, instead of treating "absent" as a fatal Get failure.
func (m *hypervModule) getVM(ctx context.Context, vmName string) (*VMConfig, error) {
	if m.transport == nil {
		return nil, ErrVMNotFound
	}

	output, err := m.transport.ExecutePS(ctx, psGetVM, map[string]string{"Name": vmName})
	if err != nil {
		return nil, fmt.Errorf("hyperv: get vm %q: %w", vmName, err)
	}

	var parsed map[string]interface{}
	if jsonErr := json.Unmarshal([]byte(strings.TrimSpace(output)), &parsed); jsonErr != nil {
		return nil, fmt.Errorf("hyperv: parse get-vm response for %q: %w", vmName, jsonErr)
	}

	found, _ := parsed["found"].(bool)
	if !found {
		// Absent is a valid current state — the executor compares this against
		// the desired state and calls Set to create the resource when needed.
		return &VMConfig{Name: vmName, State: "absent"}, nil
	}

	// The host returns the VM by its exact name — no prefix to strip.
	cfg := &VMConfig{Name: vmName}

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
	// Adapter-reported switch names are the exact names admins specified; the
	// drift comparison is name vs name with no translation.
	if v, ok := parsed["SwitchName"].(string); ok {
		cfg.SwitchName = v
	}
	// SwitchNames is the full observed set of connected switches (one per
	// network adapter). ConvertTo-Json emits an array for 0/2+ elements and
	// may collapse a single element to a scalar string on some PS versions,
	// so accept both shapes.
	cfg.SwitchNames = append(cfg.SwitchNames, parseSwitchNamesJSON(parsed["SwitchNames"])...)
	// Back-compat: if the host returned no explicit SwitchNames array but did
	// report a primary SwitchName, treat that as the single-element set.
	if len(cfg.SwitchNames) == 0 && cfg.SwitchName != "" {
		cfg.SwitchNames = stringOrStringList{cfg.SwitchName}
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
//
// Dispatch logic:
//   - state == "absent"                 → removeVM
//   - VM exists in cache or on host:
//     state == "running"               → Start-VM (with optional stop/resize/start if resize needed)
//     state == "stopped"               → Stop-VM (with optional resize after)
//   - VM not found:
//     state == "running"               → New-VM, then Start-VM
//     state == "stopped"               → New-VM (Hyper-V starts VMs in Off state by default)
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
	// switch_name (the user-facing key) accepts a single string OR a list of
	// switch names. The desired config arrives here as a generic config map
	// (config.AsMap), so parse BOTH shapes into the desired set — the
	// stringOrStringList YAML unmarshal only runs when the module decodes its
	// own YAML, not on this executor-supplied map. switch_names (plural) is also
	// accepted as an alias for callers that build the map via VMConfig.AsMap.
	parseSwitches := func(v interface{}) {
		switch sn := v.(type) {
		case string:
			if sn != "" {
				cfg.SwitchNames = append(cfg.SwitchNames, sn)
			}
		case []string:
			cfg.SwitchNames = append(cfg.SwitchNames, sn...)
		case stringOrStringList:
			cfg.SwitchNames = append(cfg.SwitchNames, sn...)
		case []interface{}:
			for _, e := range sn {
				if s, ok := e.(string); ok {
					cfg.SwitchNames = append(cfg.SwitchNames, s)
				}
			}
		}
	}
	parseSwitches(configMap["switch_name"])
	parseSwitches(configMap["switch_names"])
	if v, ok := configMap["generation"].(int); ok {
		cfg.Generation = v
	}
	cfg.State = state

	// Also handle *VMConfig passed directly
	if vc, ok := config.(*VMConfig); ok {
		*cfg = *vc
		cfg.Name = vmName
	}

	// Collapse SwitchName + SwitchNames into the canonical ordered set.
	cfg.normalizeSwitches()

	// ALWAYS read the live host state via getVM as the source of truth for the
	// reconcile decision — never the in-memory cache. The executor's drift
	// detection reads the host directly, so the apply path must reconcile against
	// the same host truth. Using the cache as "current" let SET/delete diverge
	// silently when the cache went stale (e.g. an adapter added or removed
	// out-of-band), computing needed actions as no-ops. The write-through cache is
	// still updated after a successful apply for the benefit of Get, but it is
	// never the basis for an apply decision.
	current, err := m.getVM(ctx, vmName)
	if err != nil {
		// getVM no longer returns a sentinel for "not found" — absence is
		// signalled by State=="absent" with err==nil. Any real error here
		// (module not configured, transport down, malformed response) is
		// fatal for this Set call.
		return fmt.Errorf("hyperv: check VM %q existence: %w", vmName, err)
	}
	var vmExists bool
	var currentVM VMConfig
	if current.State != "absent" {
		vmExists = true
		currentVM = *current
	}

	// The host object name is the exact VM name — no namespacing.
	hostName := vmName

	// Validate the desired config on BOTH the create and update paths so the
	// switch-name allowlist (and VM-name / VHD checks) is enforced uniformly:
	// the update path now routes switch names to Add/Remove-VMNetworkAdapter,
	// so a malformed name must be rejected before reconcileNetwork, not only on
	// create (defense-in-depth, even though values also travel via ArgumentList).
	if err := cfg.Validate(); err != nil {
		return err
	}

	if vmExists {
		return m.applyVMState(ctx, vmName, hostName, cfg, &currentVM, state)
	}

	// VM does not exist — create it.

	psArgs := map[string]string{
		"Name":       hostName,
		"MemoryMB":   fmt.Sprintf("%d", cfg.MemoryMB),
		"CPU":        fmt.Sprintf("%d", cfg.CPUCount),
		"VHDPath":    cfg.VHDPath,
		"SwitchName": cfg.SwitchName,
	}

	_, psErr := m.transport.ExecutePS(ctx, psCreateVM, psArgs)
	recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "New-VM", hostName, psErr)
	if psErr != nil {
		return fmt.Errorf("hyperv: create VM %q: %w", vmName, psErr)
	}

	// New-VM -SwitchName connected the first desired switch (cfg.SwitchName).
	// Connect one additional adapter for every remaining switch in the desired
	// set so a multi-NIC declaration materialises all adapters at create time.
	desired := cfg.desiredSwitches()
	for _, sw := range desired[min(1, len(desired)):] {
		if err := m.connectVMToSwitch(ctx, vmName, hostName, sw); err != nil {
			return err
		}
	}

	if state == "running" {
		if err := m.execStartVM(ctx, vmName, hostName); err != nil {
			return err
		}
	}

	// Write-through: update cache on success
	cfgCopy := *cfg
	cfgCopy.Name = vmName
	m.vmsMu.Lock()
	m.vms[vmName] = cfgCopy
	m.vmsMu.Unlock()

	return nil
}

// applyVMState transitions an existing VM to the desired power state, applying
// CPU/memory resize when the desired values differ from current.
func (m *hypervModule) applyVMState(ctx context.Context, vmName, hostName string, desired, current *VMConfig, state string) error {
	// Reconcile the VM's network adapters to the desired switch set before any
	// power-state change. Add-VMNetworkAdapter / Remove-VMNetworkAdapter both
	// operate on running and stopped VMs, so ordering relative to start/stop
	// does not matter. reconcileNetwork mutates current.SwitchNames in place so
	// the cache write at the end of this function reflects the converged set.
	if err := m.reconcileNetwork(ctx, vmName, hostName, desired, current); err != nil {
		return err
	}

	needsCPUResize := desired.CPUCount != 0 && desired.CPUCount != current.CPUCount
	needsMemResize := desired.MemoryMB != 0 && desired.MemoryMB != current.MemoryMB
	needsResize := needsCPUResize || needsMemResize

	switch state {
	case "running":
		if needsResize {
			// CPU/memory can only be changed on a stopped VM. Stop ONLY IF the
			// VM is not already stopped, apply the resize, then (re)start below.
			// Gating on current.State keeps the transition idempotent: a VM that
			// is already stopped is not issued a redundant Stop-VM.
			if current.State != "stopped" {
				if err := m.execStopVM(ctx, vmName, hostName); err != nil {
					return err
				}
			}
			if needsCPUResize {
				if err := m.execSetVMProcessor(ctx, vmName, hostName, desired.CPUCount); err != nil {
					return err
				}
			}
			if needsMemResize {
				if err := m.execSetVMMemory(ctx, vmName, hostName, desired.MemoryMB); err != nil {
					return err
				}
			}
			// A resize always ends with the VM stopped, so the desired running
			// state requires an unconditional Start-VM here.
			if err := m.execStartVM(ctx, vmName, hostName); err != nil {
				return err
			}
		} else if current.State != "running" {
			// No resize needed — only start the VM if it is not already running.
			// Re-applying a config whose power state already matches issues no
			// Start-VM (Hyper-V errors "already in the running state" otherwise).
			if err := m.execStartVM(ctx, vmName, hostName); err != nil {
				return err
			}
		}
		m.vmsMu.Lock()
		updated := *current
		updated.State = "running"
		m.vms[vmName] = updated
		m.vmsMu.Unlock()

	case "stopped":
		// Stop ONLY IF the VM is not already stopped — re-applying a stopped
		// config on an already-stopped VM issues no Stop-VM.
		if current.State != "stopped" {
			if err := m.execStopVM(ctx, vmName, hostName); err != nil {
				return err
			}
		}
		// The VM is stopped (or was already), so resize can proceed.
		if needsCPUResize {
			if err := m.execSetVMProcessor(ctx, vmName, hostName, desired.CPUCount); err != nil {
				return err
			}
		}
		if needsMemResize {
			if err := m.execSetVMMemory(ctx, vmName, hostName, desired.MemoryMB); err != nil {
				return err
			}
		}
		m.vmsMu.Lock()
		updated := *current
		updated.State = "stopped"
		m.vms[vmName] = updated
		m.vmsMu.Unlock()
	}

	return nil
}

// reconcileNetwork converges the VM's connected switches to desired.desiredSwitches().
// It connects an adapter for each desired switch that has no adapter and removes
// the adapter for each connected switch no longer desired. When the sets are
// equal it issues NO PowerShell mutation (idempotent — drift reports no network
// change). On success it rewrites current.SwitchNames/SwitchName to the desired
// set so the caller's cache write reflects the converged state.
//
// Switch names are passed to the connect/disconnect primitives exactly as the
// VM create path passes them to New-VM -SwitchName (the literal name the admin
// specified — no prefix or suffix is added on the host).
func (m *hypervModule) reconcileNetwork(ctx context.Context, vmName, hostName string, desired, current *VMConfig) error {
	desiredSet := desired.desiredSwitches()
	// No network declared on the desired config → leave the VM's adapters
	// untouched (never implicitly strip a VM to zero NICs).
	if len(desiredSet) == 0 {
		return nil
	}

	toConnect, toDisconnect := switchSetDiff(desiredSet, current.desiredSwitches())
	for _, sw := range toConnect {
		if err := m.connectVMToSwitch(ctx, vmName, hostName, sw); err != nil {
			return err
		}
	}
	for _, sw := range toDisconnect {
		if err := m.disconnectVMFromSwitch(ctx, vmName, hostName, sw); err != nil {
			return err
		}
	}

	// Reflect the converged set on current so the cache write is accurate.
	current.SwitchNames = stringOrStringList(desiredSet)
	current.SwitchName = desiredSet[0]
	return nil
}

// connectVMToSwitch connects a new network adapter on the VM to switchName.
// switchName travels via ArgumentList — never interpolated into script text.
func (m *hypervModule) connectVMToSwitch(ctx context.Context, vmName, hostName, switchName string) error {
	// switchName is the exact switch name the admin specified — used verbatim so
	// Add-VMNetworkAdapter targets the switch by the name on the host.
	_, psErr := m.transport.ExecutePS(ctx, psConnectVMNic, map[string]string{
		"Name":       hostName,
		"SwitchName": switchName,
	})
	recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Add-VMNetworkAdapter", hostName, psErr)
	if psErr != nil {
		return fmt.Errorf("hyperv: connect VM %q to switch %q: %w", vmName, switchName, psErr)
	}
	return nil
}

// disconnectVMFromSwitch removes the network adapter connected to switchName on
// the VM. switchName travels via ArgumentList — never interpolated.
func (m *hypervModule) disconnectVMFromSwitch(ctx context.Context, vmName, hostName, switchName string) error {
	// switchName is the exact switch name; the adapter's SwitchName on the host is
	// the same literal name, so it travels verbatim for the Where-Object match.
	_, psErr := m.transport.ExecutePS(ctx, psDisconnectVMNic, map[string]string{
		"Name":       hostName,
		"SwitchName": switchName,
	})
	recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Remove-VMNetworkAdapter", hostName, psErr)
	if psErr != nil {
		return fmt.Errorf("hyperv: disconnect VM %q from switch %q: %w", vmName, switchName, psErr)
	}
	return nil
}

func (m *hypervModule) execStartVM(ctx context.Context, vmName, hostName string) error {
	_, psErr := m.transport.ExecutePS(ctx, psStartVM, map[string]string{"Name": hostName})
	recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Start-VM", hostName, psErr)
	if psErr != nil {
		return fmt.Errorf("hyperv: Start-VM %q: %w", vmName, psErr)
	}
	return nil
}

func (m *hypervModule) execStopVM(ctx context.Context, vmName, hostName string) error {
	_, psErr := m.transport.ExecutePS(ctx, psStopVM, map[string]string{"Name": hostName})
	recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Stop-VM", hostName, psErr)
	if psErr != nil {
		return fmt.Errorf("hyperv: Stop-VM %q: %w", vmName, psErr)
	}
	return nil
}

func (m *hypervModule) execSetVMProcessor(ctx context.Context, vmName, hostName string, cpuCount int) error {
	_, psErr := m.transport.ExecutePS(ctx, psSetVMProcessor, map[string]string{
		"Name": hostName,
		"CPU":  fmt.Sprintf("%d", cpuCount),
	})
	recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Set-VMProcessor", hostName, psErr)
	if psErr != nil {
		return fmt.Errorf("hyperv: Set-VMProcessor %q: %w", vmName, psErr)
	}
	return nil
}

func (m *hypervModule) execSetVMMemory(ctx context.Context, vmName, hostName string, memoryMB int64) error {
	_, psErr := m.transport.ExecutePS(ctx, psSetVMMemory, map[string]string{
		"Name":     hostName,
		"MemoryMB": fmt.Sprintf("%d", memoryMB),
	})
	recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Set-VMMemory", hostName, psErr)
	if psErr != nil {
		return fmt.Errorf("hyperv: Set-VMMemory %q: %w", vmName, psErr)
	}
	return nil
}

// removeVM deletes a VM from the host.
// Write-through cache semantics: transport is called first; cache updated on success only.
func (m *hypervModule) removeVM(ctx context.Context, vmName string) error {
	// The host object name is the exact VM name — no namespacing.
	hostName := vmName

	_, psErr := m.transport.ExecutePS(ctx, psRemoveVM, map[string]string{"Name": hostName})
	recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Remove-VM", hostName, psErr)
	if psErr != nil {
		return fmt.Errorf("hyperv: remove VM %q: %w", vmName, psErr)
	}

	m.vmsMu.Lock()
	delete(m.vms, vmName)
	m.vmsMu.Unlock()

	return nil
}
