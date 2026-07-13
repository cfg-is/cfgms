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
	"github.com/cfgis/cfgms/pkg/logging"
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

	// ErrInvalidSourceImage is returned when a linux cloud-init source image field is not an absolute Windows path.
	ErrInvalidSourceImage = errors.New("hyperv: invalid source image: must be an absolute Windows path to a .raw or .vhdx cloud image (e.g. C:\\images\\debian.raw)")

	// ErrInvalidSourceMedia is returned when a linux source declares neither iso (preseed) nor image (cloud-init).
	ErrInvalidSourceMedia = errors.New("hyperv: invalid source: a linux source requires either image (cloud-init) or iso (netinst+preseed)")

	// ErrInvalidSourceResize is returned when source resize_gb is negative or exceeds the VHDX maximum (64 TiB).
	ErrInvalidSourceResize = errors.New("hyperv: invalid source resize_gb: must be between 0 and 65536 (GiB)")

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

	// ErrInvalidHARoleSeedDir is returned when an HA-role VM places its primary
	// VHDX on a Cluster Shared Volume but the module-level seed_dir is empty or
	// also on CSV. The provisioning seed directory must be host-local so the
	// ephemeral seed media never lands on the clustered volume (which would hang
	// the build); this is enforced eagerly at validate-time rather than letting
	// the provisioning path stall (see vm_provision.go CSV seed-dir hang).
	ErrInvalidHARoleSeedDir = errors.New("hyperv: invalid ha_role: a CSV primary vhd_path requires a host-local seed_dir (seed_dir must be set and not under C:\\ClusterStorage\\)")
)

// csvPathPrefix is the Cluster Shared Volume mount root. A VHDX or seed dir under
// this prefix lives on shared cluster storage.
const csvPathPrefix = `C:\ClusterStorage\`

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
	// ISO is the absolute Windows path to the installation ISO. Required for
	// os_family: windows (autounattend) and for the legacy os_family: linux
	// netinst+preseed path. Ignored when Image is set (cloud-init).
	ISO string `yaml:"iso,omitempty"`
	// Image is the absolute Windows host path to a cloud image (.raw or .vhdx)
	// for the os_family: linux cloud-init path. When set, the module prepares the
	// VM's boot disk from this image (raw → fixed VHD → dynamic VHDX) and delivers
	// enrollment via a NoCloud CIDATA seed instead of a netinst ISO + preseed.
	// This is the default/recommended Linux path (no boot-media repack, Secure
	// Boot intact). Ignored for os_family: windows.
	Image string `yaml:"image,omitempty"`
	// ResizeGB optionally grows the cloud-image boot disk to this many GB after
	// conversion (cloud-init growpart expands the root filesystem on first boot).
	// 0 leaves the image at its native size. Cloud-init (Image) path only.
	ResizeGB int `yaml:"resize_gb,omitempty"`
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
	// Edition is the exact Windows image name the autounattend ImageInstall step
	// selects (the /IMAGE/NAME value, e.g. "Windows Server 2025 Standard
	// Evaluation (Desktop Experience)"). Optional; when empty the built-in
	// defaultWindowsEdition is used. Ignored for os_family: linux.
	Edition string `yaml:"edition,omitempty"`
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
	// HARole, when non-nil, registers the VM as a clustered HA role on the named
	// failover cluster after creation (see setVM). Absent: the VM is a standalone
	// (non-HA) resource with unchanged behavior.
	HARole *HARoleConfig `yaml:"ha_role,omitempty"`

	// ConfigLocation is the OBSERVED configuration-file location (Hyper-V
	// ConfigurationLocation), populated by getVM and exposed on the Get/DNA
	// surface. It is never declared in config — the desired location is always
	// derived as dir(vhd_path) (the VM's home, #2411) — so it is deliberately
	// absent from GetManagedFields to keep the executor's comparison free of
	// false drift.
	ConfigLocation string `yaml:"configuration_location,omitempty"`

	// CheckpointCount is the OBSERVED number of checkpoints (snapshots) on the
	// VM, populated by getVM and exposed on the Get/DNA surface. A checkpoint
	// layers a differencing disk (.avhdx) over the configured base .vhdx; getVM
	// reports the chain ROOT as VHDPath so a checkpointed VM does not falsely
	// drift on vhd_path (#2626). Like ConfigLocation it is never declared and is
	// deliberately absent from GetManagedFields — visible as DNA, never drift.
	CheckpointCount int `yaml:"checkpoint_count,omitempty"`

	// seedDir is the module-level provisioning seed directory (m.seedDir),
	// injected by setVM before Validate so the HA-role CSV seed-dir rule can be
	// checked. It is NOT a per-VM YAML field (seed_dir is module-level config) —
	// hence unexported and untagged so it never round-trips through YAML/AsMap.
	seedDir string
}

// HARoleConfig declares that a vm resource is a highly-available clustered role.
// When present on a VMConfig, setVM registers the VM as a clustered VM role on
// the named failover cluster after creation, reusing the cluster module's CNO
// gate and idempotency (registered exactly once cluster-wide; a no-op on a
// non-owner node).
type HARoleConfig struct {
	// ClusterName is the target failover cluster (must equal the module's
	// declared cluster_name; setCluster enforces the scope cap).
	ClusterName string `yaml:"cluster_name"`
	// ResourceGroupName is the optional cluster resource-group name. It defaults
	// to the VM name (the clustered role is registered under the VM name).
	ResourceGroupName string `yaml:"resource_group_name,omitempty"`
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
	// HA-role CSV seed-dir rule: when the primary VHDX is on a Cluster Shared
	// Volume, the provisioning seed_dir must be host-local — empty or also-on-CSV
	// would hang the build, so reject it eagerly here.
	if c.HARole != nil && isUnderCSV(c.VHDPath) {
		if c.seedDir == "" || isUnderCSV(c.seedDir) {
			return ErrInvalidHARoleSeedDir
		}
	}
	return nil
}

// isUnderCSV reports whether a Windows path is under the Cluster Shared Volume
// root (case-insensitive).
func isUnderCSV(path string) bool {
	return strings.HasPrefix(strings.ToLower(path), strings.ToLower(csvPathPrefix))
}

// isCloudInit reports whether this source uses the cloud-init/NoCloud path: a
// linux source that declares a cloud image (source.image). The alternative linux
// path is the legacy netinst ISO + preseed (Image empty, ISO set).
func (s *SourceConfig) isCloudInit() bool {
	return s.OSFamily == "linux" && s.Image != ""
}

// validate checks all SourceConfig fields against their constraints.
func (s *SourceConfig) validate() error {
	switch s.OSFamily {
	case "windows":
		// Windows requires an install ISO (autounattend).
		if !vhdPathPattern.MatchString(s.ISO) {
			return ErrInvalidSourceISO
		}
	case "linux":
		// Linux accepts EITHER a cloud image (cloud-init, default/recommended) OR
		// a netinst ISO (legacy preseed). At least one must be a valid path.
		switch {
		case s.Image != "":
			// Reject a UNC image path (\\server\share) — the cloud image must live
			// on a local/CSV drive, never an arbitrary network share (matches the
			// seed-path guard). A drive-letter absolute path is required.
			if strings.HasPrefix(s.Image, `\\`) || !vhdPathPattern.MatchString(s.Image) {
				return ErrInvalidSourceImage
			}
		case s.ISO != "":
			if !vhdPathPattern.MatchString(s.ISO) {
				return ErrInvalidSourceISO
			}
		default:
			return ErrInvalidSourceMedia
		}
	default:
		return ErrInvalidSourceOSFamily
	}
	// resize_gb (cloud-init only) must be non-negative and within the VHDX max.
	if s.ResizeGB < 0 || s.ResizeGB > 65536 {
		return ErrInvalidSourceResize
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

// parseSourceMap reconstructs a *SourceConfig from the generic config map shape
// produced by VMConfig.AsMap (and by the executor). Returns nil when no source
// block is present, so the create path stays on the plain lifecycle.
func parseSourceMap(v interface{}) *SourceConfig {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	src := &SourceConfig{}
	src.ISO, _ = m["iso"].(string)
	src.Image, _ = m["image"].(string)
	src.OSFamily, _ = m["os_family"].(string)
	src.Unattend, _ = m["unattend"].(string)
	src.OnExisting, _ = m["on_existing"].(string)
	src.Edition, _ = m["edition"].(string)
	// resize_gb may arrive as int or int64 (YAML/JSON numeric shapes).
	switch v := m["resize_gb"].(type) {
	case int:
		src.ResizeGB = v
	case int64:
		src.ResizeGB = int(v)
	case float64:
		src.ResizeGB = int(v)
	}
	if comp, ok := m["completion"].(map[string]interface{}); ok {
		src.Completion.Mode, _ = comp["mode"].(string)
		src.Completion.Timeout, _ = comp["timeout"].(string)
	}
	// An entirely empty source map (all fields zero) is treated as no source.
	if src.ISO == "" && src.Image == "" && src.OSFamily == "" && src.Unattend == "" &&
		src.OnExisting == "" && src.Completion.Mode == "" && src.Completion.Timeout == "" {
		return nil
	}
	return src
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
		// Observed-only (#2411, #2626): reported for the Get/DNA surface, absent
		// from GetManagedFields so they never participate in drift comparison.
		"configuration_location": c.ConfigLocation,
		"checkpoint_count":       c.CheckpointCount,
	}
	if c.Source != nil {
		m["source"] = map[string]interface{}{
			"iso":       c.Source.ISO,
			"image":     c.Source.Image,
			"resize_gb": c.Source.ResizeGB,
			"os_family": c.Source.OSFamily,
			"unattend":  c.Source.Unattend,
			"completion": map[string]interface{}{
				"mode":    c.Source.Completion.Mode,
				"timeout": c.Source.Completion.Timeout,
			},
			"on_existing": c.Source.OnExisting,
			"edition":     c.Source.Edition,
		}
	}
	// ha_role is only emitted when present so a non-HA VMConfig round-trips
	// unchanged (omitempty parity with the YAML tag).
	if c.HARole != nil {
		m["ha_role"] = map[string]interface{}{
			"cluster_name":        c.HARole.ClusterName,
			"resource_group_name": c.HARole.ResourceGroupName,
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
	return []string{"name", "memory_mb", "cpu_count", "vhd_path", "switch_name", "generation", "state", "source", "ha_role"}
}

// psGetVM is the script block passed to ExecutePS for VM retrieval.
// $Name is the only parameter; its value is transmitted via ArgumentList.
//
// Path is read from Get-VMHardDiskDrive (the path of the first attached
// hard disk), not Get-VM.Path which is the VM configuration directory.
// VMConfig.VHDPath stores the disk path; conflating it with the config
// directory caused #1887 B1 verification to flag 2-changed drift on
// every successful create.
const psGetVM = `$vm = Get-VM -Name $Name -ErrorAction SilentlyContinue; if (-not $vm) { Write-Output '{"found":false}'; return }; $adapters = @(Get-VMNetworkAdapter -VMName $Name -ErrorAction SilentlyContinue); $switchNames = @($adapters | ForEach-Object { $_.SwitchName } | Where-Object { $_ }); $disk = Get-VMHardDiskDrive -VMName $Name -ErrorAction SilentlyContinue | Select-Object -First 1; $diskPath = if ($disk) { $disk.Path } else { "" }; $rootPath = $diskPath; if ($diskPath) { try { $v = Get-VHD -Path $diskPath -ErrorAction Stop; while ($v.ParentPath) { $rootPath = $v.ParentPath; $v = Get-VHD -Path $v.ParentPath -ErrorAction Stop } } catch { } }; $checkpointCount = @(Get-VMSnapshot -VMName $Name -ErrorAction SilentlyContinue).Count; $mem = Get-VMMemory -VMName $Name -ErrorAction SilentlyContinue; $startupBytes = if ($mem) { [long]$mem.Startup } else { 0 }; $result = @{ found=$true; Name=$vm.Name; MemoryStartupBytes=$startupBytes; ProcessorCount=[int]$vm.ProcessorCount; Generation=[int]$vm.Generation; Path=$rootPath; ConfigurationLocation=[string]$vm.ConfigurationLocation; CheckpointCount=[int]$checkpointCount; SwitchName=if ($switchNames.Count -gt 0) { $switchNames[0] } else { "" }; SwitchNames=$switchNames; State=$vm.State.ToString() }; ConvertTo-Json $result -Compress -Depth 4`

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
//   - -Generation is now a parameter ($Generation), not hardcoded to 2.
//     ADR-009 §5 supports Gen1 and Gen2 VMs (the seed VHDX boots on both,
//     no floppy needed). setVM passes cfg.Generation (defaulting to 2 when
//     0). The value travels via ArgumentList as a bare integer literal.
//   - -Path is passed via a splat guard: when $Path is non-empty the VM's
//     configuration files start under dir(vhd_path) rather than the host
//     default on the system drive (#2411). New-VM appends a VM-name
//     subfolder to -Path, so createVM follows with a config-only
//     Move-VMStorage (psSetVMHome) to land at exactly the declared home.
const psCreateVM = `$vmArgs = @{}; if ($Path) { $vmArgs['Path'] = $Path }; New-VM -Name $Name -MemoryStartupBytes ($MemoryMB * 1MB) -NewVHDPath $VHDPath -NewVHDSizeBytes 64GB -SwitchName $SwitchName -Generation $Generation @vmArgs | Out-Null; if ($CPU -ne 1) { Set-VMProcessor -VMName $Name -Count $CPU }`

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

// isHealthyVMState reports whether a getVM-normalised state string represents a
// healthy, operable VM. getVM maps the Hyper-V "Running" → "running" and "Off" →
// "stopped"; every other Hyper-V State (e.g. "Critical", "Off-Critical",
// "Paused-Critical") is lower-cased verbatim. Per ADR-009 §2 the existence-gating
// degraded surface treats any state that is neither running nor stopped (nor the
// synthetic "absent") as broken. "off" and "paused"/"saved" are accepted as
// non-broken benign power states; only states carrying a "-critical"/"critical"
// (or otherwise unrecognised) health signal mark the VM degraded.
func isHealthyVMState(state string) bool {
	switch strings.ToLower(state) {
	case "running", "stopped", "off", "paused", "saved", "absent":
		return true
	default:
		return false
	}
}

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
		// The cluster-role membership probe still runs (#2420): a locally-absent
		// VM whose name is already a registered clustered role signals "hosted
		// elsewhere" to setVM's existence gate, closing the duplicate-VM window
		// when the identical ha_role resource cascades to every member steward.
		return &VMConfig{
			Name:   vmName,
			State:  "absent",
			HARole: m.probeClusterRoleMembership(ctx, vmName),
		}, nil
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
	// ConfigurationLocation is the VM's configuration-file directory (#2411).
	// Observed-only: the desired location is derived as dir(vhd_path).
	if v, ok := parsed["ConfigurationLocation"].(string); ok {
		cfg.ConfigLocation = v
	}
	// CheckpointCount is the observed number of checkpoints (#2626). Observed-only
	// DNA; JSON numbers decode to float64. VHDPath above is already the chain root
	// (Cfgms-GetVM/psGetVM resolve past any .avhdx differencing disks).
	if v, ok := parsed["CheckpointCount"].(float64); ok {
		cfg.CheckpointCount = int(v)
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

	// Cluster-role membership probe (#2372/#2420) — see
	// probeClusterRoleMembership for the scope-cap and degrade semantics.
	cfg.HARole = m.probeClusterRoleMembership(ctx, vmName)

	// Write-through: update cache on successful read
	m.vmsMu.Lock()
	m.vms[vmName] = *cfg
	m.vmsMu.Unlock()

	return cfg, nil
}

// probeClusterRoleMembership reports whether vmName is a registered clustered
// HA role in the module's scope-capped cluster (#2372), on BOTH the found and
// locally-absent getVM paths (#2420). The probe requires the module-level
// cluster_name scope cap (S5) — on demote the desired config no longer carries
// ha_role, so the scope cap is the only cluster the module may ask. It reuses
// the same scope-capped readResourceOwners read as setCluster's owner path; a
// read needs no CNO ownership gate. Without a configured scope no HA-role
// state is observable — skip entirely, never error. A failing probe degrades
// to nil rather than failing every VM read on a transient cluster-service
// error; the degradation defers convergence one cycle in every direction (a
// missed membership re-promotes idempotently; a pending demote reads nil→nil
// and waits; a locally-absent HA VM falls back to the pre-#2421 create logic
// unchanged) — each converges on the next cycle once the probe recovers.
func (m *hypervModule) probeClusterRoleMembership(ctx context.Context, vmName string) *HARoleConfig {
	if m.clusterName == "" {
		return nil
	}
	owners, roErr := m.readResourceOwners(ctx, m.clusterName)
	if roErr != nil {
		if logger, ok := m.GetLogger(); ok {
			logger.Warn("hyperv: cluster-role membership probe failed; reporting no HA role this cycle",
				"vm_name", logging.SanitizeLogValue(vmName),
				"cluster", logging.SanitizeLogValue(m.clusterName),
				"error", roErr.Error())
		}
		return nil
	}
	if _, isMember := owners[vmName]; isMember {
		return &HARoleConfig{ClusterName: m.clusterName}
	}
	return nil
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
		// Snapshot current state for the audit before-capture (best-effort: nil is
		// acceptable if the VM is already absent or the host is unreachable). cur
		// also carries the removed VM's HARole + VHDPath, used below to route the
		// provisioning-record delete to the same store it was written to.
		var deleteBefore map[string]interface{}
		cur, gErr := m.getVM(ctx, vmName)
		if gErr == nil && cur != nil && cur.State != "absent" {
			deleteBefore = map[string]interface{}{
				"cpu":       cur.CPUCount,
				"memory_mb": cur.MemoryMB,
				"state":     cur.State,
			}
		}
		if err := m.removeVM(ctx, vmName, deleteBefore); err != nil {
			return err
		}
		// Delete the provisioning record so a subsequent source: declaration
		// provisions cleanly without hitting the surface-and-wait wedge.
		// Mirrors the on_existing: recreate path in applySourceGated. Route via
		// storeFor(cur) so an ha_role+CSV VM's record is deleted from the CSV
		// store it was written to; cur may be nil (already absent) → host-local.
		if err := m.storeFor(cur).DeleteProvision(ctx, vmName); err != nil && !errors.Is(err, ErrProvisionNotFound) {
			return err
		}
		// Delete any storage-move record (#2411) so a later same-named VM
		// starts clean rather than inheriting an in-flight/failed move.
		if err := m.moveStore().DeleteMove(ctx, vmName); err != nil && !errors.Is(err, ErrMoveNotFound) {
			return err
		}
		return nil
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

	// source (the ISO provisioning block) arrives as a nested map on the
	// executor-supplied config map. Parse it into a SourceConfig so the
	// create-from-source path activates for the generic map shape too — the
	// SourceConfig YAML unmarshal only runs when the module decodes its own
	// YAML, not on this executor-supplied map.
	cfg.Source = parseSourceMap(configMap["source"])

	// ha_role (the clustered HA-role block) arrives as a nested map on the
	// executor-supplied config map. Parse it so the create path registers the VM
	// as a clustered role; absent ⇒ standalone VM (unchanged behavior).
	cfg.HARole = parseHARoleMap(configMap["ha_role"])

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
	// Inject the module-level seed_dir so the HA-role CSV seed-dir rule can be
	// enforced in Validate (seed_dir is module-level config, not a per-VM field).
	cfg.seedDir = m.seedDir
	if err := cfg.Validate(); err != nil {
		return err
	}

	// Cluster-wide existence gate (#2420): the identical ha_role resource
	// cascades to every member steward, so a steward where the VM is locally
	// absent but the clustered role it names is already registered cluster-wide
	// (owned by ANY node — getVM's membership probe reports this on the absent
	// path) must take no create action at all. This closes the duplicate-VM
	// window: the same declaration on ≥2 members can never produce two New-VM
	// calls. It sits BEFORE the source/plain dispatch so it gates both
	// applySourceGated provisioning and plain-lifecycle createVM. Who owns the
	// role is deliberately not consulted here (#2421 handles owner-side create);
	// existence alone is the skip condition. Coordination, not an error.
	if !vmExists && cfg.HARole != nil && current.HARole != nil {
		recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.nodeHostname,
			"vm-set-skip-hosted-elsewhere", "vm:"+vmName, nil,
			map[string]interface{}{
				"skipped":      true,
				"cluster_name": current.HARole.ClusterName,
				"locally":      "absent",
			}, nil)
		return nil
	}

	// CNO-owner creation gate (#2421): the role does not exist ANYWHERE in the
	// cluster yet (locally absent AND no clustered role registered — the #2420
	// probe reports cluster-wide membership on the absent path), so exactly one
	// node must perform the first-ever create. Reuse the cluster module's
	// coordination primitive: only the CNO-owner steward proceeds to
	// create/provision (the gate sits BEFORE the source/plain dispatch, so
	// expensive provisioning is owner-gated too); every other member records an
	// audit skip and returns nil — coordination, not authorization, mirroring
	// reconcileRoleMembership's non-owner shape. Non-owners converge once the
	// owner creates: their next getVM sees the registered role and the #2420
	// gate above takes over. A transient "CNO has no current owner" cycle
	// returns (false, nil, nil) — no node creates that cycle, which is safe
	// (creation is delayed one cycle, never duplicated). A helper error is
	// fail-safe: it fails the Set rather than being swallowed into a skip.
	if !vmExists && cfg.HARole != nil && current.HARole == nil {
		ownsCNO, _, ownErr := m.clusterOwnershipHelper(ctx, cfg.HARole.ClusterName)
		if ownErr != nil {
			return fmt.Errorf("hyperv: set VM %q: CNO ownership for first-ever ha_role create: %w", vmName, ownErr)
		}
		if !ownsCNO {
			cnoOwner := m.readCNOOwner(ctx, cfg.HARole.ClusterName)
			recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.nodeHostname,
				"vm-set-skip-not-cno-owner", "vm:"+vmName, nil,
				map[string]interface{}{
					"owns_cno":     false,
					"cno_owner":    cnoOwner,
					"skipped":      true,
					"cluster_name": cfg.HARole.ClusterName,
					"locally":      "absent",
				}, nil)
			return nil
		}
	}

	// Existence-gating safety invariant (ADR-009 §2): source provisioning is
	// existence-gated, never health-gated. When a source block is declared, the
	// create/destroy decision is made HERE — before any plain-lifecycle apply —
	// so that an existing VM can never be auto-destroyed or recreated by default,
	// regardless of its health. The decision tree:
	//
	//   1. VM absent, own incomplete provisioning record → surface-and-wait.
	//   2. VM absent, no in-progress record               → provision (create).
	//   3. VM exists, on_existing == recreate             → removeVM + provision.
	//   4. VM exists, broken state, on_existing != recreate → degraded surface.
	//   5. VM exists, healthy, on_existing != recreate    → source inert;
	//                                                        drive finalize +
	//                                                        plain lifecycle.
	if cfg.Source != nil {
		return m.applySourceGated(ctx, vmName, hostName, cfg, &currentVM, vmExists, state)
	}

	if vmExists {
		return m.applyVMState(ctx, vmName, hostName, cfg, &currentVM, state)
	}

	// VM does not exist — create it (plain lifecycle, no source block).
	if err := m.createVM(ctx, vmName, hostName, cfg); err != nil {
		return err
	}

	// HA-role registration: after the VM is created and before the power-state
	// transition, register it as a clustered VM role. Reuses the cluster module's
	// CNO gate + idempotency — registered exactly once cluster-wide, a no-op on a
	// non-owner node.
	if cfg.HARole != nil {
		if err := m.registerClusteredRole(ctx, cfg); err != nil {
			return err
		}
	}

	if state == "running" {
		if err := m.execStartVM(ctx, "vm:"+vmName, hostName,
			map[string]interface{}{"state": "stopped"},
			map[string]interface{}{"state": "running"}); err != nil {
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

// parseHARoleMap extracts an HARoleConfig from the generic executor-supplied
// config map. Returns nil when no ha_role block is present (standalone VM).
func parseHARoleMap(v interface{}) *HARoleConfig {
	m, ok := v.(map[string]interface{})
	if !ok || len(m) == 0 {
		return nil
	}
	cluster, _ := m["cluster_name"].(string)
	if strings.TrimSpace(cluster) == "" {
		return nil
	}
	rg, _ := m["resource_group_name"].(string)
	return &HARoleConfig{ClusterName: cluster, ResourceGroupName: rg}
}

// registerClusteredRole registers a VM as a clustered HA role — the promote
// half of the single-surface ha_role setting (#2372), called from every path a
// VM can converge through (plain create, applyVMState on an existing VM, and
// finalizeProvision for a source-provisioned VM). It delegates to
// reconcileRoleMembership, which applies the S5 scope cap, the CNO ownership
// gate, and existence-based idempotency — so the role is added exactly once
// cluster-wide and re-converges are no-ops. The clustered role name is the VM
// name (the default cluster group name Add-ClusterVirtualMachineRole assigns);
// resource_group_name is reserved for an explicit group name and currently
// defaults to the VM name.
func (m *hypervModule) registerClusteredRole(ctx context.Context, cfg *VMConfig) error {
	return m.reconcileRoleMembership(ctx, cfg.HARole.ClusterName, cfg.Name, "present", false)
}

// demoteClusteredRole removes a VM's clustered-role membership — the demote
// half of the single-surface ha_role setting (#2372): an ha_role removed from a
// previously-HA vm resource converges by removing the ROLE, never the VM.
// allowDestructive is passed true unconditionally: this path only ever issues
// Remove-ClusterGroup against the role, so the S6 destructive gate (which
// protects hyperv.cluster's standalone destructive surface) has nothing to
// protect here, and demote must not require a second operator opt-in (AC1).
func (m *hypervModule) demoteClusteredRole(ctx context.Context, cfg *VMConfig, clusterName string) error {
	return m.reconcileRoleMembership(ctx, clusterName, cfg.Name, "absent", true)
}

// applySourceGated enforces the ADR-009 §2 existence-gating safety invariant for
// a hyperv.vm resource that declares a source block. It is the SINGLE place that
// decides whether source provisioning creates, resumes, recreates, or stands
// inert — so that an existing VM is NEVER auto-destroyed or recreated under the
// default (on_existing: never / absent) regardless of its health.
//
// Decision tree (mirrors ADR-009 §2 and the story #2048 implementation notes):
//
//	VM absent + own incomplete record  → surface-and-wait (no New-VM, no retry).
//	VM absent + no in-progress record  → createVM + provisionVM (normal create).
//	VM exists + on_existing==recreate  → removeVM, reset record, then provision.
//	VM exists + broken state           → degraded record; never destroyed.
//	VM exists + healthy                → source inert; finalize + plain lifecycle.
func (m *hypervModule) applySourceGated(ctx context.Context, vmName, hostName string, cfg *VMConfig, currentVM *VMConfig, vmExists bool, state string) error {
	onExisting := cfg.Source.OnExisting // "" is treated as "never"

	if !vmExists {
		// The VM is absent on the host. Distinguish our OWN incomplete
		// provisioning attempt (a record at creating/installing/finalizing —
		// provably holds no operator workload, safe to resume) from a fresh
		// create. Auto-retry of an own-incomplete attempt is OFF by default
		// (surface-and-wait, ADR-009 §2): the install may simply be mid-flight
		// and a half-built VM transiently absent from Get-VM. We do NOT re-issue
		// New-VM — that is what protects against thrashing an in-progress build.
		own, ownErr := m.isOwnIncompleteAttempt(ctx, cfg)
		if ownErr != nil {
			// CSV (cluster-visible) record was unreadable → fail loud. Creation
			// must NOT proceed while the cluster record state is unknown, or a
			// mid-provision CNO failover could produce the duplicate Option A
			// exists to prevent. (Host-local reads never reach here — they swallow.)
			return fmt.Errorf("hyperv: cannot determine provisioning state for VM %q: %w", vmName, ownErr)
		}
		if own {
			// An in-progress record exists. On this node it may be our own mid-flight
			// build; on a NEW CNO owner after a failover it is another node's in-flight
			// attempt visible via the CSV record. Both surface-and-wait (no auto-retry,
			// no New-VM) — the record on the CSV is what lets the new owner see it.
			if logger, ok := m.GetLogger(); ok {
				logger.Warn("hyperv: in-progress provisioning attempt; surface-and-wait (no auto-retry)",
					"vm_name", logging.SanitizeLogValue(vmName))
			}
			recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.nodeHostname,
				"vm-provision-skip-in-progress-elsewhere", "vm:"+vmName, nil,
				map[string]interface{}{"reason": "provision in progress"}, nil)
			return nil
		}
		// No in-progress record → normal create-from-source path.
		if err := m.createVM(ctx, vmName, hostName, cfg); err != nil {
			return err
		}
		if err := m.provisionVM(ctx, vmName, hostName, cfg); err != nil {
			return err
		}
		cfgCopy := *cfg
		cfgCopy.Name = vmName
		m.vmsMu.Lock()
		m.vms[vmName] = cfgCopy
		m.vmsMu.Unlock()
		return nil
	}

	// ── The VM EXISTS on the host. ──────────────────────────────────────────
	// Existence-gating: existence alone makes source inert by default. The ONLY
	// path that may destroy an existing VM is the explicit on_existing: recreate
	// opt-in. Health/bootability is NEVER the trigger — a broken VM is surfaced
	// as degraded, not rebuilt.
	if onExisting == "recreate" {
		// Explicit destructive opt-in. Tear the existing VM down, reset any
		// provisioning record so the create path starts clean (absent), then
		// provision from source.
		var recreateBefore map[string]interface{}
		if vmExists && currentVM != nil {
			recreateBefore = map[string]interface{}{
				"cpu":       currentVM.CPUCount,
				"memory_mb": currentVM.MemoryMB,
				"state":     currentVM.State,
			}
		}
		if err := m.removeVM(ctx, vmName, recreateBefore); err != nil {
			return err
		}
		// Route via storeFor(cfg): an ha_role+CSV recreate must reset the
		// cluster-visible record, not a stale host-local one.
		if err := m.storeFor(cfg).DeleteProvision(ctx, vmName); err != nil && !errors.Is(err, ErrProvisionNotFound) {
			return err
		}
		if err := m.createVM(ctx, vmName, hostName, cfg); err != nil {
			return err
		}
		if err := m.provisionVM(ctx, vmName, hostName, cfg); err != nil {
			return err
		}
		cfgCopy := *cfg
		cfgCopy.Name = vmName
		m.vmsMu.Lock()
		m.vms[vmName] = cfgCopy
		m.vmsMu.Unlock()
		return nil
	}

	// on_existing is never (or empty). The VM is never destroyed.
	if !isHealthyVMState(currentVM.State) {
		// Existing-but-broken VM → surface as degraded (ADR-009 §2). Never
		// delete-and-rebuild. The record records the observed state so the
		// operator (and the controller-side reconciler) can see it.
		record, err := m.loadOrInitProvision(ctx, cfg, vmName)
		if err != nil {
			return err
		}
		return m.degradeProvision(ctx, cfg, vmName, record, currentVM.State)
	}

	// Existing healthy VM → source is inert. Log the inert decision, then drive
	// the create-from-source convergence (installing → finalizing detach, a
	// no-op unless an own record is at installing and settle conditions hold)
	// and the plain lifecycle (power/resize/NIC) so an already-provisioned VM
	// still converges to its declared running/stopped state without provisioning.
	if logger, ok := m.GetLogger(); ok {
		logger.Warn("hyperv: VM exists; source is inert (on_existing: never)",
			"vm_name", logging.SanitizeLogValue(vmName),
			"observed_state", logging.SanitizeLogValue(currentVM.State))
	}
	if err := m.finalizeProvision(ctx, vmName, hostName, cfg); err != nil {
		return err
	}
	// TTL sweep: clean up orphaned seed media for any stale provision records
	// (ADR-010 §5). Called after finalizeProvision so the just-advanced record
	// (UpdatedAt = now) is naturally excluded by the TTL check. Best-effort —
	// a sweep failure does not block convergence.
	m.sweepStaleSeedMedia(ctx)
	return m.applyVMState(ctx, vmName, hostName, cfg, currentVM, state)
}

// createVM issues New-VM with the desired generation and connects every
// additional desired switch as a separate adapter. Generation defaults to 2
// when unset (0). It does NOT power the VM on — the caller decides whether to
// start (plain lifecycle) or hand off to provisionVM (create-from-source).
func (m *hypervModule) createVM(ctx context.Context, vmName, hostName string, cfg *VMConfig) error {
	// 0 means "accept the default" — ADR-009 §5 default is Generation 2.
	generation := cfg.Generation
	if generation == 0 {
		generation = 2
	}

	// home is the VM's storage home — the directory of the declared vhd_path
	// (#2411). New-VM receives it as -Path so the configuration files start
	// co-located with the disk; because New-VM appends a VM-name subfolder to
	// -Path, a config-only Move-VMStorage follows the create to land the
	// configuration at exactly the home (zero location drift on a fresh VM).
	home := vmHomeDir(cfg.VHDPath)

	psArgs := map[string]string{
		"Name":       hostName,
		"MemoryMB":   fmt.Sprintf("%d", cfg.MemoryMB),
		"CPU":        fmt.Sprintf("%d", cfg.CPUCount),
		"VHDPath":    cfg.VHDPath,
		"SwitchName": cfg.SwitchName,
		"Generation": fmt.Sprintf("%d", generation),
		"Path":       home,
	}

	cfgResourceID := "vm:" + vmName
	// after captures the non-sensitive scalar desired state for audit; VHD path
	// and switch names are deliberately omitted (sensitive / not scalar).
	after := map[string]interface{}{
		"cpu":       cfg.CPUCount,
		"memory_mb": cfg.MemoryMB,
		"state":     "stopped", // New-VM always creates in Off state
	}

	// cloud-init (Linux VM-from-cloud-image): the boot disk IS the cloud image,
	// not a freshly-created empty VHD. Prepare it (raw → fixed VHD → dynamic VHDX,
	// optional resize) and create the VM attaching the EXISTING disk
	// (New-VM -VHDPath) instead of New-VM -NewVHDPath.
	if cfg.Source != nil && cfg.Source.isCloudInit() {
		resizeBytes := int64(cfg.Source.ResizeGB) * gibibyte
		if _, psErr := m.transport.ExecutePS(ctx, psPrepCloudBootDisk, map[string]string{
			"ImagePath":   cfg.Source.Image,
			"VhdPath":     cfg.VHDPath,
			"ResizeBytes": fmt.Sprintf("%d", resizeBytes),
		}); psErr != nil {
			recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Convert-VHD", cfgResourceID, nil, nil, psErr)
			return fmt.Errorf("hyperv: prepare cloud boot disk for VM %q: %w", vmName, psErr)
		}
		recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Convert-VHD", cfgResourceID, nil, nil, nil)
		_, psErr := m.transport.ExecutePS(ctx, psCreateVMFromDisk, psArgs)
		recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "New-VM", cfgResourceID, nil, after, psErr)
		if psErr != nil {
			return fmt.Errorf("hyperv: create VM %q from cloud image: %w", vmName, psErr)
		}
		if home != "" {
			if err := m.execSetVMHome(ctx, cfgResourceID, hostName, home); err != nil {
				return err
			}
		}
		return m.connectAdditionalNics(ctx, cfgResourceID, vmName, hostName, cfg)
	}

	_, psErr := m.transport.ExecutePS(ctx, psCreateVM, psArgs)
	recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "New-VM", cfgResourceID, nil, after, psErr)
	if psErr != nil {
		return fmt.Errorf("hyperv: create VM %q: %w", vmName, psErr)
	}

	if home != "" {
		if err := m.execSetVMHome(ctx, cfgResourceID, hostName, home); err != nil {
			return err
		}
	}

	return m.connectAdditionalNics(ctx, cfgResourceID, vmName, hostName, cfg)
}

// connectAdditionalNics connects one extra network adapter for every desired
// switch beyond the first (New-VM -SwitchName already connected the first), so a
// multi-NIC declaration materialises all adapters at create time. Shared by the
// empty-VHD and cloud-image create paths.
func (m *hypervModule) connectAdditionalNics(ctx context.Context, cfgResourceID, vmName, hostName string, cfg *VMConfig) error {
	desired := cfg.desiredSwitches()
	for _, sw := range desired[min(1, len(desired)):] {
		if err := m.connectVMToSwitch(ctx, cfgResourceID, vmName, hostName, sw); err != nil {
			return err
		}
	}
	return nil
}

// applyVMState transitions an existing VM to the desired power state, applying
// CPU/memory resize when the desired values differ from current.
func (m *hypervModule) applyVMState(ctx context.Context, vmName, hostName string, desired, current *VMConfig, state string) error {
	cfgResourceID := "vm:" + vmName

	// Role-owner gate (#2422): lifecycle convergence (storage move, NIC reconcile,
	// promote/demote, resize, power) for an ha_role VM runs ONLY on the node that
	// currently owns the role. A non-owner — most importantly the PREVIOUS owner
	// right after a failover, whose local Get-VM view may transiently still show
	// the VM — takes no lifecycle action and goes quiet; the new owner converges
	// instead. This makes success criterion #3 ("after failover the new owner
	// converges and the previous owner goes quiet") hold even in the edge case
	// where local Get-VM visibility lags cluster-role ownership, not just when they
	// already agree.
	//
	// Skip only on an AFFIRMATIVE different-owner report: the owner map contains an
	// entry for this VM AND that entry is a node other than us. A MISSING entry
	// (role not yet registered — the first-time promote of an existing standalone
	// VM to ha_role) does NOT skip: local possession decides, and this node holds
	// the VM locally (applyVMState is the existing-VM path), so it proceeds and the
	// promote/demote switch below registers the role (founder ruling 2026-07-08:
	// promotion happens on the host that owns the VM first; only then does the
	// definition move from the steward config to the cluster config).
	//
	// A probe error here is fail-safe-QUIET, deliberately UNLIKE #2421's
	// clusterOwnershipHelper (which propagates): that call happens once, at
	// first-creation time, where fail-safe-loud is correct. This call happens on
	// every convergence tick of every already-existing HA VM, so a transient
	// cluster-service hiccup must not surface as a steward error state or spam the
	// error log — treat it as "cannot determine ownership this cycle" and skip,
	// letting the next tick retry. A future reviewer must not "fix" this to match
	// #2421/S2. Standalone VMs (desired.HARole == nil) skip this block entirely —
	// zero added transport calls, zero behavior change.
	//
	// An UNRESOLVED owner (the map has an entry for the VM but the owner string is
	// empty — Get-ClusterGroup reports "" for a role with no current OwnerNode, the
	// in-flight-failover window this story targets) is treated the same as a
	// different owner: the node goes quiet. This is the safe bias — while ownership
	// is unsettled, EVERY member reads "" and waits, so no two nodes ever act at
	// once; it self-heals the moment the cluster settles an owner. Proceeding on
	// local possession here would instead risk two nodes converging the same role
	// during the settle window.
	if desired.HARole != nil {
		clusterName := desired.HARole.ClusterName
		// Scope cap (S5): never issue a transport call for a cluster this steward is
		// not permitted to read — the same invariant every other cluster-touching
		// function enforces before the transport (clusterOwnershipHelper,
		// reconcileRoleMembership, getCluster). A mismatched ha_role.cluster_name is
		// a persistent misconfiguration, not a transient probe failure, so it fails
		// LOUD (exactly as the downstream promote path's reconcileRoleMembership
		// would) rather than taking the fail-safe-quiet path below.
		if m.clusterName != "" && clusterName != m.clusterName {
			return fmt.Errorf("hyperv: apply VM state %q: %w", vmName, ErrClusterNotDeclared)
		}
		owners, roErr := m.readResourceOwners(ctx, clusterName)
		if roErr != nil {
			if logger, ok := m.GetLogger(); ok {
				logger.Warn("hyperv: ha_role owner probe failed; skipping lifecycle convergence this cycle",
					"vm_name", logging.SanitizeLogValue(vmName),
					"cluster", logging.SanitizeLogValue(clusterName),
					"error", roErr.Error())
			}
			return nil
		}
		if owner, isMember := owners[vmName]; isMember && !strings.EqualFold(owner, m.nodeHostname) {
			recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.nodeHostname,
				"vm-lifecycle-skip-not-owner", cfgResourceID, nil,
				map[string]interface{}{
					"skipped":      true,
					"cluster_name": clusterName,
					"owner":        owner,
				}, nil)
			return nil
		}
	}

	// Storage-location convergence (#2411) runs FIRST: an ha_role registration
	// on a mislocated VM fails (Add-ClusterVirtualMachineRole refuses a VM whose
	// configuration files are off cluster storage), and power/resize actions are
	// deferred while a live move is in flight. proceed=false means a move was
	// started or is in flight — the rest of this cycle is a cheap no-op and the
	// lifecycle resumes once the location converges.
	proceed, err := m.convergeStorageLocation(ctx, vmName, hostName, desired, current)
	if err != nil {
		return err
	}
	if !proceed {
		return nil
	}

	// Reconcile the VM's network adapters to the desired switch set before any
	// power-state change. Add-VMNetworkAdapter / Remove-VMNetworkAdapter both
	// operate on running and stopped VMs, so ordering relative to start/stop
	// does not matter. reconcileNetwork mutates current.SwitchNames in place so
	// the cache write at the end of this function reflects the converged set.
	if err := m.reconcileNetwork(ctx, cfgResourceID, vmName, hostName, desired, current); err != nil {
		return err
	}

	// Cluster-role membership reconcile (#2372): ha_role is convergent on the
	// existing-VM path, not create-only. current.HARole comes from getVM's
	// membership probe; both mutations run before any power-state transition,
	// mirroring the create path's register-before-start ordering.
	//
	//   nil → non-nil  promote (register the clustered role)
	//   non-nil → nil  demote (remove the role — the VM is never touched)
	//   both non-nil   no-op: already a member; moving a registered VM to a
	//                  different cluster in one step has no defined semantics
	//                  (out of scope, #2372) and the same-cluster case is
	//                  already converged.
	switch {
	case desired.HARole != nil && current.HARole == nil:
		promoteCfg := *desired
		promoteCfg.Name = vmName
		if err := m.registerClusteredRole(ctx, &promoteCfg); err != nil {
			return err
		}
	case desired.HARole == nil && current.HARole != nil:
		demoteCfg := *desired
		demoteCfg.Name = vmName
		if err := m.demoteClusteredRole(ctx, &demoteCfg, current.HARole.ClusterName); err != nil {
			return err
		}
	}

	needsCPUResize := desired.CPUCount != 0 && desired.CPUCount != current.CPUCount
	needsMemResize := desired.MemoryMB != 0 && desired.MemoryMB != current.MemoryMB
	needsResize := needsCPUResize || needsMemResize

	// Build per-operation before/after snapshots for resize auditing. Only
	// non-sensitive scalars (cpu count, memory MB) are included — no VHD paths,
	// no switch names, no live host values.
	var cpuBefore, cpuAfter, memBefore, memAfter map[string]interface{}
	if needsCPUResize {
		cpuBefore = map[string]interface{}{"cpu": current.CPUCount}
		cpuAfter = map[string]interface{}{"cpu": desired.CPUCount}
	}
	if needsMemResize {
		memBefore = map[string]interface{}{"memory_mb": current.MemoryMB}
		memAfter = map[string]interface{}{"memory_mb": desired.MemoryMB}
	}

	switch state {
	case "running":
		if needsResize {
			// CPU/memory can only be changed on a stopped VM. Stop ONLY IF the
			// VM is not already stopped, apply the resize, then (re)start below.
			// Gating on current.State keeps the transition idempotent: a VM that
			// is already stopped is not issued a redundant Stop-VM.
			if current.State != "stopped" {
				if err := m.execStopVM(ctx, cfgResourceID, hostName,
					map[string]interface{}{"state": current.State},
					map[string]interface{}{"state": "stopped"}); err != nil {
					return err
				}
			}
			if needsCPUResize {
				if err := m.execSetVMProcessor(ctx, cfgResourceID, hostName, desired.CPUCount, cpuBefore, cpuAfter); err != nil {
					return err
				}
			}
			if needsMemResize {
				if err := m.execSetVMMemory(ctx, cfgResourceID, hostName, desired.MemoryMB, memBefore, memAfter); err != nil {
					return err
				}
			}
			// A resize always ends with the VM stopped, so the desired running
			// state requires an unconditional Start-VM here.
			if err := m.execStartVM(ctx, cfgResourceID, hostName,
				map[string]interface{}{"state": "stopped"},
				map[string]interface{}{"state": "running"}); err != nil {
				return err
			}
		} else if current.State != "running" {
			// No resize needed — only start the VM if it is not already running.
			// Re-applying a config whose power state already matches issues no
			// Start-VM (Hyper-V errors "already in the running state" otherwise).
			if err := m.execStartVM(ctx, cfgResourceID, hostName,
				map[string]interface{}{"state": current.State},
				map[string]interface{}{"state": "running"}); err != nil {
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
			if err := m.execStopVM(ctx, cfgResourceID, hostName,
				map[string]interface{}{"state": current.State},
				map[string]interface{}{"state": "stopped"}); err != nil {
				return err
			}
		}
		// The VM is stopped (or was already), so resize can proceed.
		if needsCPUResize {
			if err := m.execSetVMProcessor(ctx, cfgResourceID, hostName, desired.CPUCount, cpuBefore, cpuAfter); err != nil {
				return err
			}
		}
		if needsMemResize {
			if err := m.execSetVMMemory(ctx, cfgResourceID, hostName, desired.MemoryMB, memBefore, memAfter); err != nil {
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
func (m *hypervModule) reconcileNetwork(ctx context.Context, cfgResourceID, vmName, hostName string, desired, current *VMConfig) error {
	desiredSet := desired.desiredSwitches()
	// No network declared on the desired config → leave the VM's adapters
	// untouched (never implicitly strip a VM to zero NICs).
	if len(desiredSet) == 0 {
		return nil
	}

	toConnect, toDisconnect := switchSetDiff(desiredSet, current.desiredSwitches())
	for _, sw := range toConnect {
		if err := m.connectVMToSwitch(ctx, cfgResourceID, vmName, hostName, sw); err != nil {
			return err
		}
	}
	for _, sw := range toDisconnect {
		if err := m.disconnectVMFromSwitch(ctx, cfgResourceID, vmName, hostName, sw); err != nil {
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
func (m *hypervModule) connectVMToSwitch(ctx context.Context, cfgResourceID, vmName, hostName, switchName string) error {
	// switchName is the exact switch name the admin specified — used verbatim so
	// Add-VMNetworkAdapter targets the switch by the name on the host.
	_, psErr := m.transport.ExecutePS(ctx, psConnectVMNic, map[string]string{
		"Name":       hostName,
		"SwitchName": switchName,
	})
	after := map[string]interface{}{"switch": "vswitch:" + switchName}
	recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Add-VMNetworkAdapter", cfgResourceID, nil, after, psErr)
	if psErr != nil {
		return fmt.Errorf("hyperv: connect VM %q to switch %q: %w", vmName, switchName, psErr)
	}
	return nil
}

// disconnectVMFromSwitch removes the network adapter connected to switchName on
// the VM. switchName travels via ArgumentList — never interpolated.
func (m *hypervModule) disconnectVMFromSwitch(ctx context.Context, cfgResourceID, vmName, hostName, switchName string) error {
	// switchName is the exact switch name; the adapter's SwitchName on the host is
	// the same literal name, so it travels verbatim for the Where-Object match.
	_, psErr := m.transport.ExecutePS(ctx, psDisconnectVMNic, map[string]string{
		"Name":       hostName,
		"SwitchName": switchName,
	})
	before := map[string]interface{}{"switch": "vswitch:" + switchName}
	recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Remove-VMNetworkAdapter", cfgResourceID, before, nil, psErr)
	if psErr != nil {
		return fmt.Errorf("hyperv: disconnect VM %q from switch %q: %w", vmName, switchName, psErr)
	}
	return nil
}

func (m *hypervModule) execStartVM(ctx context.Context, cfgResourceID, hostName string, before, after map[string]interface{}) error {
	_, psErr := m.transport.ExecutePS(ctx, psStartVM, map[string]string{"Name": hostName})
	recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Start-VM", cfgResourceID, before, after, psErr)
	if psErr != nil {
		return fmt.Errorf("hyperv: Start-VM %q: %w", hostName, psErr)
	}
	return nil
}

func (m *hypervModule) execStopVM(ctx context.Context, cfgResourceID, hostName string, before, after map[string]interface{}) error {
	_, psErr := m.transport.ExecutePS(ctx, psStopVM, map[string]string{"Name": hostName})
	recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Stop-VM", cfgResourceID, before, after, psErr)
	if psErr != nil {
		return fmt.Errorf("hyperv: Stop-VM %q: %w", hostName, psErr)
	}
	return nil
}

func (m *hypervModule) execSetVMProcessor(ctx context.Context, cfgResourceID, hostName string, cpuCount int, before, after map[string]interface{}) error {
	_, psErr := m.transport.ExecutePS(ctx, psSetVMProcessor, map[string]string{
		"Name": hostName,
		"CPU":  fmt.Sprintf("%d", cpuCount),
	})
	recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Set-VMProcessor", cfgResourceID, before, after, psErr)
	if psErr != nil {
		return fmt.Errorf("hyperv: Set-VMProcessor %q: %w", hostName, psErr)
	}
	return nil
}

func (m *hypervModule) execSetVMMemory(ctx context.Context, cfgResourceID, hostName string, memoryMB int64, before, after map[string]interface{}) error {
	_, psErr := m.transport.ExecutePS(ctx, psSetVMMemory, map[string]string{
		"Name":     hostName,
		"MemoryMB": fmt.Sprintf("%d", memoryMB),
	})
	recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Set-VMMemory", cfgResourceID, before, after, psErr)
	if psErr != nil {
		return fmt.Errorf("hyperv: Set-VMMemory %q: %w", hostName, psErr)
	}
	return nil
}

// removeVM deletes a VM from the host.
// before captures the non-sensitive scalar state (cpu, memory_mb, state) prior to
// deletion for the audit record; pass nil when the state is unknown.
// Write-through cache semantics: transport is called first; cache updated on success only.
func (m *hypervModule) removeVM(ctx context.Context, vmName string, before map[string]interface{}) error {
	// The host object name is the exact VM name — no namespacing.
	hostName := vmName
	cfgResourceID := "vm:" + vmName

	_, psErr := m.transport.ExecutePS(ctx, psRemoveVM, map[string]string{"Name": hostName})
	recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Remove-VM", cfgResourceID, before, nil, psErr)
	if psErr != nil {
		return fmt.Errorf("hyperv: remove VM %q: %w", vmName, psErr)
	}

	m.vmsMu.Lock()
	delete(m.vms, vmName)
	m.vmsMu.Unlock()

	return nil
}
