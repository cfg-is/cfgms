//go:build darwin

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package dna

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const darwinHwCmdTimeout = 30 * time.Second

// CollectCPU gathers detailed CPU information on macOS using system_profiler
func (d *DarwinHardwareCollector) CollectCPU(ctx context.Context, attributes map[string]string) error {
	// Basic CPU count
	attributes["cpu_count"] = fmt.Sprintf("%d", runtime.NumCPU())
	attributes["cpu_arch"] = runtime.GOARCH

	// Get detailed CPU info using sysctl
	if brand, err := d.getSysctl(ctx, "machdep.cpu.brand_string"); err == nil {
		attributes["cpu_model"] = strings.TrimSpace(brand)
	}

	if family, err := d.getSysctl(ctx, "machdep.cpu.family"); err == nil {
		attributes["cpu_family"] = strings.TrimSpace(family)
	}

	if model, err := d.getSysctl(ctx, "machdep.cpu.model"); err == nil {
		attributes["cpu_model_id"] = strings.TrimSpace(model)
	}

	if stepping, err := d.getSysctl(ctx, "machdep.cpu.stepping"); err == nil {
		attributes["cpu_stepping"] = strings.TrimSpace(stepping)
	}

	// CPU frequency (if available)
	if freq, err := d.getSysctl(ctx, "hw.cpufrequency"); err == nil {
		if freqInt, parseErr := strconv.ParseInt(strings.TrimSpace(freq), 10, 64); parseErr == nil {
			attributes["cpu_frequency_hz"] = fmt.Sprintf("%d", freqInt)
			attributes["cpu_frequency_mhz"] = fmt.Sprintf("%.0f", float64(freqInt)/1000000)
		}
	}

	// Physical and logical core counts
	if physCores, err := d.getSysctl(ctx, "hw.physicalcpu"); err == nil {
		attributes["cpu_physical_cores"] = strings.TrimSpace(physCores)
	}

	if logCores, err := d.getSysctl(ctx, "hw.logicalcpu"); err == nil {
		attributes["cpu_logical_cores"] = strings.TrimSpace(logCores)
	}

	return nil
}

// CollectMemory gathers detailed memory information on macOS
func (d *DarwinHardwareCollector) CollectMemory(ctx context.Context, attributes map[string]string) error {
	// Physical memory size
	if memSize, err := d.getSysctl(ctx, "hw.memsize"); err == nil {
		if memInt, parseErr := strconv.ParseInt(strings.TrimSpace(memSize), 10, 64); parseErr == nil {
			attributes["memory_total_bytes"] = fmt.Sprintf("%d", memInt)
			attributes["memory_total_gb"] = fmt.Sprintf("%.2f", float64(memInt)/1024/1024/1024)
		}
	}

	// Memory type and speed (if available)
	if pageSize, err := d.getSysctl(ctx, "hw.pagesize"); err == nil {
		attributes["memory_page_size"] = strings.TrimSpace(pageSize)
	}

	// Additional memory info from vm_stat if available
	cmdCtx, cancel := context.WithTimeout(ctx, darwinHwCmdTimeout)
	defer cancel()

	if vmstat, err := exec.CommandContext(cmdCtx, "vm_stat").Output(); err == nil {
		d.parseVMStat(string(vmstat), attributes)
	}

	return nil
}

// CollectDisk gathers disk and storage information on macOS
func (d *DarwinHardwareCollector) CollectDisk(ctx context.Context, attributes map[string]string) error {
	// Get disk information using diskutil
	cmdCtx, cancel := context.WithTimeout(ctx, darwinHwCmdTimeout)
	if _, err := exec.CommandContext(cmdCtx, "diskutil", "list", "-plist").Output(); err == nil {
		// For now, just indicate we have disk info available
		// Could parse the plist output for detailed disk information
		attributes["disk_info_available"] = "true"
		attributes["disk_collection_method"] = "diskutil"
	}
	cancel()

	// Get filesystem information using df
	cmdCtx2, cancel2 := context.WithTimeout(ctx, darwinHwCmdTimeout)
	defer cancel2()

	if output, err := exec.CommandContext(cmdCtx2, "df", "-h").Output(); err == nil {
		d.parseDiskUsage(string(output), attributes)
	}

	return nil
}

// CollectMotherboard gathers motherboard and system information on macOS
func (d *DarwinHardwareCollector) CollectMotherboard(ctx context.Context, attributes map[string]string) error {
	// Hardware model
	if model, err := d.getSysctl(ctx, "hw.model"); err == nil {
		attributes["hardware_model"] = strings.TrimSpace(model)
	}

	// System version
	cmdCtx, cancel := context.WithTimeout(ctx, darwinHwCmdTimeout)
	if version, err := exec.CommandContext(cmdCtx, "sw_vers", "-productVersion").Output(); err == nil {
		attributes["os_version"] = strings.TrimSpace(string(version))
	}
	cancel()

	cmdCtx2, cancel2 := context.WithTimeout(ctx, darwinHwCmdTimeout)
	if build, err := exec.CommandContext(cmdCtx2, "sw_vers", "-buildVersion").Output(); err == nil {
		attributes["os_build"] = strings.TrimSpace(string(build))
	}
	cancel2()

	cmdCtx3, cancel3 := context.WithTimeout(ctx, darwinHwCmdTimeout)
	if name, err := exec.CommandContext(cmdCtx3, "sw_vers", "-productName").Output(); err == nil {
		attributes["os_name"] = strings.TrimSpace(string(name))
	}
	cancel3()

	// Hardware UUID (if available)
	if uuid, err := d.getSysctl(ctx, "kern.uuid"); err == nil {
		attributes["hardware_uuid"] = strings.TrimSpace(uuid)
	}

	// Boot time
	if boottime, err := d.getSysctl(ctx, "kern.boottime"); err == nil {
		attributes["boot_time"] = strings.TrimSpace(boottime)
	}

	return nil
}

// getSysctl executes sysctl to get system information
func (d *DarwinHardwareCollector) getSysctl(ctx context.Context, key string) (string, error) {
	cmdCtx, cancel := context.WithTimeout(ctx, darwinHwCmdTimeout)
	defer cancel()

	output, err := exec.CommandContext(cmdCtx, "sysctl", "-n", key).Output()
	if err != nil {
		return "", err
	}
	return string(output), nil
}

// parseVMStat parses vm_stat output for memory statistics
func (d *DarwinHardwareCollector) parseVMStat(vmstat string, attributes map[string]string) {
	lines := strings.Split(vmstat, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "Pages free:") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				attributes["memory_pages_free"] = strings.TrimSuffix(parts[2], ".")
			}
		} else if strings.Contains(line, "Pages active:") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				attributes["memory_pages_active"] = strings.TrimSuffix(parts[2], ".")
			}
		} else if strings.Contains(line, "Pages inactive:") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				attributes["memory_pages_inactive"] = strings.TrimSuffix(parts[2], ".")
			}
		}
	}
}

// parseDiskUsage parses df output for disk usage information
func (d *DarwinHardwareCollector) parseDiskUsage(dfOutput string, attributes map[string]string) {
	lines := strings.Split(dfOutput, "\n")
	var diskCount int

	for i, line := range lines {
		if i == 0 { // Skip header
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 6 && strings.HasPrefix(fields[0], "/dev/") {
			diskCount++
			prefix := fmt.Sprintf("disk_%d", diskCount)
			attributes[prefix+"_device"] = fields[0]
			attributes[prefix+"_size"] = fields[1]
			attributes[prefix+"_used"] = fields[2]
			attributes[prefix+"_available"] = fields[3]
			attributes[prefix+"_use_percent"] = fields[4]
			attributes[prefix+"_mount"] = fields[5]
		}
	}

	if diskCount > 0 {
		attributes["disk_count"] = fmt.Sprintf("%d", diskCount)
	}
}
