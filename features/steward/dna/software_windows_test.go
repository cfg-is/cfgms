//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package dna

import (
	"context"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// intAttr fetches an attribute, requires it to be present, and parses it as an
// integer. Every count the software collector emits is a decimal string, so a
// value that does not parse is a defect regardless of the host it ran on.
func intAttr(t *testing.T, attrs map[string]string, key string) int {
	t.Helper()
	raw, ok := attrs[key]
	require.True(t, ok, "%s must be set", key)
	n, err := strconv.Atoi(raw)
	require.NoError(t, err, "%s must parse as an integer: %q", key, raw)
	return n
}

// TestWindowsSoftwareCollector_CollectOS runs CollectOS against the real host and
// asserts the shape of every attribute it emits.
func TestWindowsSoftwareCollector_CollectOS(t *testing.T) {
	col := &WindowsSoftwareCollector{}
	attrs := make(map[string]string)

	require.NoError(t, col.CollectOS(context.Background(), attrs))

	// Runtime facts are exact, not shape-checked.
	assert.Equal(t, "windows", attrs["os"])
	assert.Equal(t, "windows", attrs["runtime_os"])
	assert.Equal(t, runtime.GOARCH, attrs["runtime_arch"])
	assert.Equal(t, runtime.Compiler, attrs["runtime_compiler"])
	assert.Equal(t, runtime.Version(), attrs["go_version"])
	assert.Equal(t, runtime.Version(), attrs["runtime_version"])

	// Registry-sourced OS identity. ProductName and CurrentBuildNumber exist on
	// every Windows SKU the steward supports.
	assert.NotEmpty(t, attrs["windows_caption"], "windows_caption must be read from the registry")
	build := intAttr(t, attrs, "windows_build_number")
	assert.Greater(t, build, 0, "windows_build_number must be a positive build number")

	// CurrentMajorVersionNumber / CurrentMinorVersionNumber exist on Windows 10 /
	// Server 2016 and later, so the composed version string must be present.
	version, ok := attrs["windows_version"]
	require.True(t, ok, "windows_version must be set")
	assert.Regexp(t, regexp.MustCompile(`^\d+\.\d+\.\d+$`), version,
		"windows_version must be major.minor.build")
	assert.True(t, strings.HasSuffix(version, "."+attrs["windows_build_number"]),
		"windows_version %q must end in the build number %q", version, attrs["windows_build_number"])

	// Always set: "0" when no service pack is recorded (Windows 10+).
	assert.NotEmpty(t, attrs["windows_service_pack"], "windows_service_pack must always be set")

	arch, ok := attrs["windows_os_architecture"]
	require.True(t, ok, "windows_os_architecture must be set")
	assert.Contains(t, []string{"64-bit", "32-bit", "ARM 64-bit"}, arch,
		"windows_os_architecture must be a translated architecture label")

	// Boot time is derived from GetTickCount64, which is present on every
	// supported SKU. It must be a real timestamp in the past.
	bootRaw, ok := attrs["windows_last_boot_time"]
	require.True(t, ok, "windows_last_boot_time must be set")
	boot, err := time.ParseInLocation("2006-01-02 15:04:05", bootRaw, time.Local)
	require.NoError(t, err, "windows_last_boot_time must parse: %q", bootRaw)
	assert.True(t, boot.Before(time.Now()), "boot time %s must be in the past", bootRaw)
	assert.True(t, boot.After(time.Date(2000, 1, 1, 0, 0, 0, 0, time.Local)),
		"boot time %s must be a plausible timestamp, not an epoch artefact", bootRaw)

	if installRaw, present := attrs["windows_install_date"]; present {
		_, parseErr := time.ParseInLocation("2006-01-02 15:04:05", installRaw, time.Local)
		assert.NoError(t, parseErr, "windows_install_date must parse: %q", installRaw)
	}

	// Windows PowerShell 5.1 ships in-box on every supported SKU, so the
	// concurrently collected version must have made it into the shared map.
	psVersion, ok := attrs["powershell_version"]
	require.True(t, ok, "powershell_version must be set")
	assert.Regexp(t, regexp.MustCompile(`^\d+\.\d+`), psVersion,
		"powershell_version must start with major.minor: %q", psVersion)

	// The .NET CLI is optional; the .NET Framework registry scan is not asserted
	// as present because a Server Core image may carry no NDP subkeys, but any
	// value emitted must carry a version.
	if runtimes, present := attrs["dotnet_core_runtimes"]; present {
		assert.NotEmpty(t, runtimes, "dotnet_core_runtimes must not be emitted empty")
	}
	if frameworks, present := attrs["dotnet_framework_versions"]; present {
		assert.Regexp(t, regexp.MustCompile(`^v\d`), frameworks,
			"dotnet_framework_versions entries are keyed by the vN.N registry subkey: %q", frameworks)
	}
}

// TestWindowsSoftwareCollector_CollectPackages runs CollectPackages against the
// real host, asserts the shape of the registry-sourced inventory, and pins the
// DISM opt-in gate: Get-WindowsOptionalFeature must not run unless
// CFGMS_DNA_COLLECT_DISM_FEATURES is set.
func TestWindowsSoftwareCollector_CollectPackages(t *testing.T) {
	t.Setenv("CFGMS_DNA_COLLECT_DISM_FEATURES", "")

	col := &WindowsSoftwareCollector{}
	attrs := make(map[string]string)

	require.NoError(t, col.CollectPackages(context.Background(), attrs))

	// The Uninstall registry hives are populated on every real Windows install.
	programCount := intAttr(t, attrs, "installed_program_count")
	assert.Greater(t, programCount, 0, "installed_program_count must be > 0 on a real host")

	if sample, ok := attrs["installed_programs_sample"]; ok {
		entries := strings.Split(sample, "; ")
		assert.LessOrEqual(t, len(entries), 20, "the program sample is capped at 20 entries")
		assert.LessOrEqual(t, len(entries), programCount,
			"the sample cannot hold more entries than were counted")
		for _, entry := range entries {
			assert.NotEmpty(t, entry, "no sampled program may be an empty string")
		}
	}

	// The CBS Packages hive needs elevation; when it is readable the KB list must
	// be deduplicated and correctly shaped.
	if _, ok := attrs["installed_update_count"]; ok {
		updateCount := intAttr(t, attrs, "installed_update_count")
		assert.GreaterOrEqual(t, updateCount, 0)
		if sample, present := attrs["installed_updates_sample"]; present {
			kbs := strings.Split(sample, "; ")
			assert.LessOrEqual(t, len(kbs), 10, "the update sample is capped at 10 entries")
			seen := make(map[string]bool, len(kbs))
			for _, kb := range kbs {
				assert.True(t, strings.HasPrefix(kb, "KB"),
					"sampled updates are KB identifiers: %q", kb)
				assert.False(t, seen[kb], "KB numbers must be deduplicated, %q repeated", kb)
				seen[kb] = true
			}
		}
	}

	// The DISM gate is off, so no feature attribute may exist.
	for key := range attrs {
		assert.False(t, strings.HasPrefix(key, "windows_features_"),
			"%s must not be collected unless CFGMS_DNA_COLLECT_DISM_FEATURES is set", key)
	}

	// Third-party package managers are optional, but a count that is emitted must
	// agree with the sample beside it.
	for _, mgrName := range []string{"chocolatey", "winget"} {
		if _, ok := attrs[mgrName+"_package_count"]; !ok {
			continue
		}
		count := intAttr(t, attrs, mgrName+"_package_count")
		assert.Greater(t, count, 0,
			"%s_package_count is only emitted when packages were found", mgrName)
		assert.NotEmpty(t, attrs[mgrName+"_packages_sample"],
			"%s_packages_sample must accompany a non-zero count", mgrName)
	}
}

// TestWindowsSoftwareCollector_CollectServices runs CollectServices against the
// real host. It asserts the service counters are internally consistent whichever
// path produced them (native SCM or the wmic fallback), plus the process count and
// startup-program scan that always run.
func TestWindowsSoftwareCollector_CollectServices(t *testing.T) {
	col := &WindowsSoftwareCollector{}
	attrs := make(map[string]string)

	require.NoError(t, col.CollectServices(context.Background(), attrs))

	total := intAttr(t, attrs, "total_service_count")
	assert.Greater(t, total, 0, "a real Windows host always has services")

	running := intAttr(t, attrs, "running_service_count")
	stopped := intAttr(t, attrs, "stopped_service_count")
	auto := intAttr(t, attrs, "auto_start_service_count")
	manual := intAttr(t, attrs, "manual_start_service_count")

	assert.GreaterOrEqual(t, running, 0)
	assert.GreaterOrEqual(t, stopped, 0)
	assert.LessOrEqual(t, running+stopped, total,
		"running and stopped are disjoint subsets of the total")
	assert.LessOrEqual(t, auto+manual, total,
		"auto-start and demand-start are disjoint subsets of the total")

	procs := intAttr(t, attrs, "running_process_count")
	assert.Greater(t, procs, 0, "the test process itself is running, so the count cannot be 0")

	startup := intAttr(t, attrs, "startup_program_count")
	assert.GreaterOrEqual(t, startup, 0)
	if sample, ok := attrs["startup_programs_sample"]; ok {
		entries := strings.Split(sample, "; ")
		assert.LessOrEqual(t, len(entries), 10, "the startup sample is capped at 10 entries")
		assert.LessOrEqual(t, len(entries), startup,
			"the sample cannot hold more entries than were counted")
	}
}

// TestWindowsSoftwareCollector_CollectServicesViaSCM exercises the native Service
// Control Manager path on its own. mgr.Connect asks for SC_MANAGER_ALL_ACCESS, so
// an unelevated host is refused — in that case the function must fail without
// writing partial counters, which is what makes the wmic fallback in
// CollectServices safe to run afterwards.
func TestWindowsSoftwareCollector_CollectServicesViaSCM(t *testing.T) {
	col := &WindowsSoftwareCollector{}
	attrs := make(map[string]string)

	err := col.collectServicesViaSCM(attrs)
	if err != nil {
		assert.Empty(t, attrs,
			"a failed SCM connection must leave the attribute map untouched for the fallback")
		return
	}

	total := intAttr(t, attrs, "total_service_count")
	assert.Greater(t, total, 0, "ListServices must enumerate at least one service")
	running := intAttr(t, attrs, "running_service_count")
	stopped := intAttr(t, attrs, "stopped_service_count")
	assert.Greater(t, running, 0, "core Windows services are always running")
	assert.LessOrEqual(t, running+stopped, total)
	assert.LessOrEqual(t,
		intAttr(t, attrs, "auto_start_service_count")+intAttr(t, attrs, "manual_start_service_count"),
		total)
}

// TestWindowsSoftwareCollector_CollectProcesses runs CollectProcesses against the
// real host and asserts both the identity attributes and the snapshot aggregates,
// including the descending order of the top-process ranking.
func TestWindowsSoftwareCollector_CollectProcesses(t *testing.T) {
	col := &WindowsSoftwareCollector{}
	attrs := make(map[string]string)

	require.NoError(t, col.CollectProcesses(context.Background(), attrs))

	assert.Equal(t, strconv.Itoa(os.Getpid()), attrs["current_pid"])
	assert.Equal(t, strconv.Itoa(os.Getppid()), attrs["parent_pid"])
	assert.NotEmpty(t, attrs["current_user"], "current_user must resolve via os/user")
	assert.Greater(t, intAttr(t, attrs, "goroutine_count"), 0)

	total := intAttr(t, attrs, "total_process_count")
	assert.Greater(t, total, 0, "the snapshot must see at least this test process")

	uniqueNames := intAttr(t, attrs, "unique_process_names")
	assert.Greater(t, uniqueNames, 0)
	assert.LessOrEqual(t, uniqueNames, total,
		"distinct executable names cannot outnumber processes")

	uniqueUsers := intAttr(t, attrs, "unique_process_users")
	assert.LessOrEqual(t, uniqueUsers, total,
		"distinct owners cannot outnumber processes")

	top, ok := attrs["top_processes"]
	require.True(t, ok, "top_processes must be set when any process was seen")
	entries := strings.Split(top, ", ")
	require.LessOrEqual(t, len(entries), 5, "the ranking is capped at 5 entries")

	entryRe := regexp.MustCompile(`^(.+)\((\d+)\)$`)
	previous := -1
	for _, entry := range entries {
		match := entryRe.FindStringSubmatch(entry)
		require.NotNil(t, match, "top_processes entry must be name(count): %q", entry)
		assert.NotEmpty(t, match[1], "a ranked process must have a name")
		count, convErr := strconv.Atoi(match[2])
		require.NoError(t, convErr)
		assert.GreaterOrEqual(t, count, 1, "a ranked process runs at least once")
		if previous >= 0 {
			assert.LessOrEqual(t, count, previous,
				"top_processes must be ordered by instance count, descending: %q", top)
		}
		previous = count
	}
}

// TestWindowsCountProcesses exercises the standalone snapshot counter used by
// CollectServices.
func TestWindowsCountProcesses(t *testing.T) {
	count := countProcesses()
	assert.Greater(t, count, 0,
		"CreateToolhelp32Snapshot must see at least the running test process")
}

// TestWindowsLookupProcessOwner covers the token-based owner lookup and its SID
// cache. The test's own PID is always openable with
// PROCESS_QUERY_LIMITED_INFORMATION, so the resolved owner is deterministic.
func TestWindowsLookupProcessOwner(t *testing.T) {
	cache := make(map[string]string)

	owner := lookupProcessOwner(uint32(os.Getpid()), cache)
	require.NotEmpty(t, owner, "the test process's own owner must resolve")
	assert.Contains(t, owner, `\`, "owner must be reported as DOMAIN\\account: %q", owner)
	assert.Len(t, cache, 1, "the resolved SID must be cached")

	// Second call must be served from the cache and return the identical value.
	assert.Equal(t, owner, lookupProcessOwner(uint32(os.Getpid()), cache),
		"a cached SID must resolve to the same account")
	assert.Len(t, cache, 1, "a cache hit must not add another entry")

	// PID 0 is the System Idle Process; OpenProcess always refuses it, so the
	// lookup must fail closed with an empty owner and no cache entry.
	before := len(cache)
	assert.Empty(t, lookupProcessOwner(0, cache),
		"an unopenable process must yield an empty owner, not a partial one")
	assert.Len(t, cache, before, "a failed OpenProcess must not populate the cache")
}

// TestWindowsSoftwareCollector_ParseCSVLine covers the quoted-field CSV splitter
// used for Get-AppxPackage output.
func TestWindowsSoftwareCollector_ParseCSVLine(t *testing.T) {
	col := &WindowsSoftwareCollector{}

	tests := []struct {
		name string
		line string
		want []string
	}{
		{
			name: "quoted fields are unwrapped",
			line: `"Microsoft.WindowsCalculator","11.2.2.0"`,
			want: []string{"Microsoft.WindowsCalculator", "11.2.2.0"},
		},
		{
			name: "a comma inside quotes does not split the field",
			line: `"Acme Corp, Inc.","1.0"`,
			want: []string{"Acme Corp, Inc.", "1.0"},
		},
		{
			name: "unquoted fields split on commas",
			line: `a,b,c`,
			want: []string{"a", "b", "c"},
		},
		{
			name: "surrounding whitespace is trimmed",
			line: `"a" , "b"`,
			want: []string{"a", "b"},
		},
		{
			name: "an empty line yields a single empty field",
			line: ``,
			want: []string{""},
		},
		{
			name: "an empty quoted field is preserved as a positional empty",
			line: `"name","","1.0"`,
			want: []string{"name", "", "1.0"},
		},
		{
			name: "an unterminated quote consumes the remainder",
			line: `"unterminated`,
			want: []string{"unterminated"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, col.parseCSVLine(tc.line))
		})
	}
}

// TestWindowsSoftwareCollector_ParseWMIServicesOutput covers the wmic fallback
// parser: header-driven column mapping, header and blank-line filtering, and the
// five counters it always emits.
func TestWindowsSoftwareCollector_ParseWMIServicesOutput(t *testing.T) {
	col := &WindowsSoftwareCollector{}

	t.Run("counts states and start modes from the header positions", func(t *testing.T) {
		// wmic emits Node first, then the requested properties alphabetically.
		output := "\r\n" +
			"Node,Name,ServiceType,StartMode,State\r\n" +
			"HOST-A,Dhcp,Own Process,Auto,Running\r\n" +
			"HOST-A,Spooler,Own Process,Manual,Stopped\r\n" +
			"HOST-A,Fax,Own Process,Disabled,Stopped\r\n" +
			"\r\n"

		attrs := make(map[string]string)
		col.parseWMIServicesOutput(output, attrs)

		assert.Equal(t, "3", attrs["total_service_count"])
		assert.Equal(t, "1", attrs["running_service_count"])
		assert.Equal(t, "2", attrs["stopped_service_count"])
		assert.Equal(t, "1", attrs["auto_start_service_count"])
		assert.Equal(t, "1", attrs["manual_start_service_count"])
	})

	t.Run("column order is taken from the header, not assumed", func(t *testing.T) {
		// The same rows with State and StartMode transposed must produce the same
		// counters — the header, not a fixed index, decides which column is which.
		output := "Node,Name,ServiceType,State,StartMode\r\n" +
			"HOST-A,Dhcp,Own Process,Running,Auto\r\n" +
			"HOST-A,Spooler,Own Process,Stopped,Manual\r\n"

		attrs := make(map[string]string)
		col.parseWMIServicesOutput(output, attrs)

		assert.Equal(t, "2", attrs["total_service_count"])
		assert.Equal(t, "1", attrs["running_service_count"])
		assert.Equal(t, "1", attrs["stopped_service_count"])
		assert.Equal(t, "1", attrs["auto_start_service_count"])
		assert.Equal(t, "1", attrs["manual_start_service_count"])
	})

	t.Run("headerless output falls back to the alphabetical layout", func(t *testing.T) {
		output := "HOST-A,Dhcp,Own Process,Auto,Running\r\n"

		attrs := make(map[string]string)
		col.parseWMIServicesOutput(output, attrs)

		assert.Equal(t, "1", attrs["total_service_count"])
		assert.Equal(t, "1", attrs["running_service_count"])
		assert.Equal(t, "1", attrs["auto_start_service_count"])
	})

	t.Run("short rows are not counted", func(t *testing.T) {
		output := "Node,Name,ServiceType,StartMode,State\r\n" +
			"HOST-A,Truncated,Row\r\n" +
			"HOST-A,Dhcp,Own Process,Auto,Running\r\n"

		attrs := make(map[string]string)
		col.parseWMIServicesOutput(output, attrs)

		assert.Equal(t, "1", attrs["total_service_count"],
			"a row missing columns is not a service observation")
		assert.Equal(t, "1", attrs["running_service_count"])
	})

	t.Run("empty output still emits every counter as zero", func(t *testing.T) {
		attrs := make(map[string]string)
		col.parseWMIServicesOutput("", attrs)

		for _, key := range []string{
			"total_service_count",
			"running_service_count",
			"stopped_service_count",
			"auto_start_service_count",
			"manual_start_service_count",
		} {
			assert.Equal(t, "0", attrs[key], "%s must be emitted as 0, not omitted", key)
		}
	})
}

// TestWindowsSoftwareCollector_RegistryHelpersAreIndependent asserts that each
// registry helper populates its own attributes without depending on a prior call,
// so a partial collection cannot silently inherit another helper's values.
func TestWindowsSoftwareCollector_RegistryHelpersAreIndependent(t *testing.T) {
	col := &WindowsSoftwareCollector{}

	osAttrs := make(map[string]string)
	col.collectOSVersion(osAttrs)
	assert.NotEmpty(t, osAttrs["windows_caption"])
	assert.NotContains(t, osAttrs, "installed_program_count",
		"collectOSVersion must not emit package attributes")

	pkgAttrs := make(map[string]string)
	col.collectInstalledPrograms(pkgAttrs)
	assert.Greater(t, intAttr(t, pkgAttrs, "installed_program_count"), 0)
	assert.NotContains(t, pkgAttrs, "windows_caption",
		"collectInstalledPrograms must not emit OS attributes")

	startupAttrs := make(map[string]string)
	col.collectStartupPrograms(startupAttrs)
	assert.GreaterOrEqual(t, intAttr(t, startupAttrs, "startup_program_count"), 0)

	procAttrs := make(map[string]string)
	col.collectProcessSnapshot(procAttrs)
	assert.Greater(t, intAttr(t, procAttrs, "total_process_count"), 0)
}
