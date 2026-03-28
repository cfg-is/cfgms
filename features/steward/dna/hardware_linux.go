//go:build linux

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

const linuxCmdTimeout = 30 * time.Second

// CollectCPU gathers detailed CPU information on Linux using /proc and utilities
func (l *LinuxHardwareCollector) CollectCPU(ctx context.Context, attributes map[string]string) error {
	// Basic CPU count
	attributes["cpu_count"] = fmt.Sprintf("%d", runtime.NumCPU())
	attributes["cpu_arch"] = runtime.GOARCH

	// Parse /proc/cpuinfo for detailed CPU information
	cmdCtx, cancel := context.WithTimeout(ctx, linuxCmdTimeout)
	if output, err := exec.CommandContext(cmdCtx, "cat", "/proc/cpuinfo").Output(); err == nil {
		l.parseProcCPUInfo(string(output), attributes)
		l.parseCPUFrequency(ctx, string(output), attributes)
	}
	cancel()

	// CPU architecture details using lscpu if available
	cmdCtx2, cancel2 := context.WithTimeout(ctx, linuxCmdTimeout)
	if output, err := exec.CommandContext(cmdCtx2, "lscpu").Output(); err == nil {
		l.parseLSCPUOutput(string(output), attributes)
	}
	cancel2()

	return nil
}

// CollectMemory gathers detailed memory information on Linux
func (l *LinuxHardwareCollector) CollectMemory(ctx context.Context, attributes map[string]string) error {
	// Parse /proc/meminfo for memory details
	cmdCtx, cancel := context.WithTimeout(ctx, linuxCmdTimeout)
	if output, err := exec.CommandContext(cmdCtx, "cat", "/proc/meminfo").Output(); err == nil {
		l.parseProcMemInfo(string(output), attributes)
	}
	cancel()

	// Memory hardware information using dmidecode if available
	cmdCtx2, cancel2 := context.WithTimeout(ctx, linuxCmdTimeout)
	if output, err := exec.CommandContext(cmdCtx2, "dmidecode", "-t", "memory").Output(); err == nil {
		l.parseDMIDecodeMemory(string(output), attributes)
	}
	cancel2()

	// Memory usage summary
	cmdCtx3, cancel3 := context.WithTimeout(ctx, linuxCmdTimeout)
	if output, err := exec.CommandContext(cmdCtx3, "free", "-h").Output(); err == nil {
		l.parseMemoryUsage(string(output), attributes)
	}
	cancel3()

	return nil
}

// CollectDisk gathers disk and storage information on Linux
func (l *LinuxHardwareCollector) CollectDisk(ctx context.Context, attributes map[string]string) error {
	// Disk usage using df
	cmdCtx, cancel := context.WithTimeout(ctx, linuxCmdTimeout)
	if output, err := exec.CommandContext(cmdCtx, "df", "-h").Output(); err == nil {
		l.parseDiskUsage(string(output), attributes)
	}
	cancel()

	// Block device information using lsblk
	cmdCtx2, cancel2 := context.WithTimeout(ctx, linuxCmdTimeout)
	if output, err := exec.CommandContext(cmdCtx2, "lsblk", "-d", "-o", "NAME,SIZE,TYPE,MODEL,VENDOR").Output(); err == nil {
		l.parseLSBLKOutput(string(output), attributes)
	}
	cancel2()

	// Disk hardware information using fdisk if available
	cmdCtx3, cancel3 := context.WithTimeout(ctx, linuxCmdTimeout)
	if output, err := exec.CommandContext(cmdCtx3, "fdisk", "-l").Output(); err == nil {
		l.parseFdiskOutput(string(output), attributes)
	}
	cancel3()

	// SMART information for health status (if smartctl is available)
	l.collectSMARTInfo(ctx, attributes)

	return nil
}

// CollectMotherboard gathers motherboard and system information on Linux
func (l *LinuxHardwareCollector) CollectMotherboard(ctx context.Context, attributes map[string]string) error {
	// System information using dmidecode
	dmidecodeKeys := []struct {
		flag string
		attr string
	}{
		{"system-manufacturer", "system_manufacturer"},
		{"system-product-name", "system_product_name"},
		{"system-version", "system_version"},
		{"system-serial-number", "system_serial_number"},
		{"system-uuid", "system_uuid"},
		{"bios-vendor", "bios_vendor"},
		{"bios-version", "bios_version"},
		{"bios-release-date", "bios_release_date"},
		{"baseboard-manufacturer", "motherboard_manufacturer"},
		{"baseboard-product-name", "motherboard_product"},
		{"baseboard-version", "motherboard_version"},
	}

	for _, kv := range dmidecodeKeys {
		cmdCtx, cancel := context.WithTimeout(ctx, linuxCmdTimeout)
		if output, err := exec.CommandContext(cmdCtx, "dmidecode", "-s", kv.flag).Output(); err == nil {
			attributes[kv.attr] = strings.TrimSpace(string(output))
		}
		cancel()
	}

	// System uptime
	cmdCtx, cancel := context.WithTimeout(ctx, linuxCmdTimeout)
	if output, err := exec.CommandContext(cmdCtx, "uptime").Output(); err == nil {
		attributes["system_uptime"] = strings.TrimSpace(string(output))
	}
	cancel()

	// Kernel information
	cmdCtx2, cancel2 := context.WithTimeout(ctx, linuxCmdTimeout)
	if output, err := exec.CommandContext(cmdCtx2, "uname", "-r").Output(); err == nil {
		attributes["kernel_version"] = strings.TrimSpace(string(output))
	}
	cancel2()

	cmdCtx3, cancel3 := context.WithTimeout(ctx, linuxCmdTimeout)
	if output, err := exec.CommandContext(cmdCtx3, "uname", "-a").Output(); err == nil {
		attributes["kernel_info"] = strings.TrimSpace(string(output))
	}
	cancel3()

	return nil
}

// parseProcCPUInfo parses /proc/cpuinfo for CPU details
func (l *LinuxHardwareCollector) parseProcCPUInfo(output string, attributes map[string]string) {
	lines := strings.Split(output, "\n")
	cpuCount := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "processor":
			cpuCount++
		case "model name":
			if attributes["cpu_model"] == "" { // Only set for first CPU
				attributes["cpu_model"] = value
			}
		case "vendor_id":
			if attributes["cpu_vendor"] == "" {
				attributes["cpu_vendor"] = value
			}
		case "cpu family":
			if attributes["cpu_family"] == "" {
				attributes["cpu_family"] = value
			}
		case "model":
			if attributes["cpu_model_id"] == "" {
				attributes["cpu_model_id"] = value
			}
		case "stepping":
			if attributes["cpu_stepping"] == "" {
				attributes["cpu_stepping"] = value
			}
		case "cpu MHz":
			if attributes["cpu_frequency_mhz"] == "" {
				attributes["cpu_frequency_mhz"] = value
			}
		case "cache size":
			if attributes["cpu_cache_size"] == "" {
				attributes["cpu_cache_size"] = value
			}
		case "flags":
			if attributes["cpu_flags"] == "" {
				// Store first few flags as sample
				flags := strings.Fields(value)
				if len(flags) > 10 {
					flags = flags[:10]
				}
				attributes["cpu_flags"] = strings.Join(flags, " ")
			}
		}
	}

	attributes["proc_cpu_count"] = fmt.Sprintf("%d", cpuCount)
}

// parseCPUFrequency parses CPU frequency information
func (l *LinuxHardwareCollector) parseCPUFrequency(ctx context.Context, output string, attributes map[string]string) {
	// Try to get current CPU frequency from /proc/cpuinfo
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "cpu MHz") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				freq := strings.TrimSpace(parts[1])
				if freqFloat, err := strconv.ParseFloat(freq, 64); err == nil {
					attributes["cpu_current_frequency_mhz"] = fmt.Sprintf("%.0f", freqFloat)
					attributes["cpu_current_frequency_ghz"] = fmt.Sprintf("%.2f", freqFloat/1000)
				}
				break
			}
		}
	}

	// Try to get min/max frequencies from cpufreq sysfs files
	cmdCtx, cancel := context.WithTimeout(ctx, linuxCmdTimeout)
	if out, err := exec.CommandContext(cmdCtx, "cat", "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_min_freq").Output(); err == nil {
		if minFreq, parseErr := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64); parseErr == nil {
			attributes["cpu_min_frequency_khz"] = fmt.Sprintf("%d", minFreq)
			attributes["cpu_min_frequency_mhz"] = fmt.Sprintf("%.0f", float64(minFreq)/1000)
		}
	}
	cancel()

	cmdCtx2, cancel2 := context.WithTimeout(ctx, linuxCmdTimeout)
	if out, err := exec.CommandContext(cmdCtx2, "cat", "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq").Output(); err == nil {
		if maxFreq, parseErr := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64); parseErr == nil {
			attributes["cpu_max_frequency_khz"] = fmt.Sprintf("%d", maxFreq)
			attributes["cpu_max_frequency_mhz"] = fmt.Sprintf("%.0f", float64(maxFreq)/1000)
		}
	}
	cancel2()
}

// parseLSCPUOutput parses lscpu output for CPU architecture details
func (l *LinuxHardwareCollector) parseLSCPUOutput(output string, attributes map[string]string) {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "Architecture":
			attributes["cpu_architecture"] = value
		case "CPU op-mode(s)":
			attributes["cpu_op_modes"] = value
		case "Byte Order":
			attributes["cpu_byte_order"] = value
		case "CPU(s)":
			attributes["cpu_logical_count"] = value
		case "On-line CPU(s) list":
			attributes["cpu_online_list"] = value
		case "Thread(s) per core":
			attributes["cpu_threads_per_core"] = value
		case "Core(s) per socket":
			attributes["cpu_cores_per_socket"] = value
		case "Socket(s)":
			attributes["cpu_sockets"] = value
		case "NUMA node(s)":
			attributes["cpu_numa_nodes"] = value
		case "Vendor ID":
			attributes["cpu_vendor_lscpu"] = value
		case "CPU family":
			attributes["cpu_family_lscpu"] = value
		case "Model":
			attributes["cpu_model_lscpu"] = value
		case "Model name":
			attributes["cpu_model_name_lscpu"] = value
		case "Stepping":
			attributes["cpu_stepping_lscpu"] = value
		case "CPU MHz":
			attributes["cpu_frequency_lscpu"] = value
		case "BogoMIPS":
			attributes["cpu_bogomips"] = value
		case "Virtualization":
			attributes["cpu_virtualization"] = value
		case "L1d cache":
			attributes["cpu_l1d_cache"] = value
		case "L1i cache":
			attributes["cpu_l1i_cache"] = value
		case "L2 cache":
			attributes["cpu_l2_cache"] = value
		case "L3 cache":
			attributes["cpu_l3_cache"] = value
		}
	}
}

// parseProcMemInfo parses /proc/meminfo for memory details
func (l *LinuxHardwareCollector) parseProcMemInfo(output string, attributes map[string]string) {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		key := strings.TrimSuffix(parts[0], ":")
		value := parts[1]
		unit := ""
		if len(parts) > 2 {
			unit = parts[2]
		}

		switch key {
		case "MemTotal":
			attributes["memory_total_kb"] = value
			if unit == "kB" {
				if kb, err := strconv.ParseInt(value, 10, 64); err == nil {
					attributes["memory_total_mb"] = fmt.Sprintf("%.0f", float64(kb)/1024)
					attributes["memory_total_gb"] = fmt.Sprintf("%.2f", float64(kb)/1024/1024)
				}
			}
		case "MemFree":
			attributes["memory_free_kb"] = value
		case "MemAvailable":
			attributes["memory_available_kb"] = value
		case "Buffers":
			attributes["memory_buffers_kb"] = value
		case "Cached":
			attributes["memory_cached_kb"] = value
		case "SwapTotal":
			attributes["swap_total_kb"] = value
		case "SwapFree":
			attributes["swap_free_kb"] = value
		case "Dirty":
			attributes["memory_dirty_kb"] = value
		case "Writeback":
			attributes["memory_writeback_kb"] = value
		case "AnonPages":
			attributes["memory_anon_pages_kb"] = value
		case "Mapped":
			attributes["memory_mapped_kb"] = value
		case "Shmem":
			attributes["memory_shared_kb"] = value
		}
	}
}

// parseDMIDecodeMemory parses dmidecode memory output
func (l *LinuxHardwareCollector) parseDMIDecodeMemory(output string, attributes map[string]string) {
	// This would parse dmidecode output for memory module details
	// For now, just indicate that dmidecode info is available
	if strings.Contains(output, "Memory Device") {
		attributes["memory_dmidecode_available"] = "true"

		// Count memory slots
		slotCount := strings.Count(output, "Memory Device")
		attributes["memory_slot_count"] = fmt.Sprintf("%d", slotCount)
	}
}

// parseMemoryUsage parses free command output
func (l *LinuxHardwareCollector) parseMemoryUsage(output string, attributes map[string]string) {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Mem:") {
			fields := strings.Fields(line)
			if len(fields) >= 7 {
				attributes["memory_total_human"] = fields[1]
				attributes["memory_used_human"] = fields[2]
				attributes["memory_free_human"] = fields[3]
				attributes["memory_shared_human"] = fields[4]
				attributes["memory_buff_cache_human"] = fields[5]
				attributes["memory_available_human"] = fields[6]
			}
			break
		}
	}
}

// parseDiskUsage parses df output for disk usage
func (l *LinuxHardwareCollector) parseDiskUsage(output string, attributes map[string]string) {
	lines := strings.Split(output, "\n")
	var diskCount int

	for i, line := range lines {
		if i == 0 { // Skip header
			continue
		}

		line = strings.TrimSpace(line)
		if line == "" {
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
		attributes["disk_mount_count"] = fmt.Sprintf("%d", diskCount)
	}
}

// parseLSBLKOutput parses lsblk output for block device information
func (l *LinuxHardwareCollector) parseLSBLKOutput(output string, attributes map[string]string) {
	lines := strings.Split(output, "\n")
	var blockDeviceCount int

	for i, line := range lines {
		if i == 0 { // Skip header
			continue
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 3 {
			blockDeviceCount++
			prefix := fmt.Sprintf("block_device_%d", blockDeviceCount)

			attributes[prefix+"_name"] = fields[0]
			attributes[prefix+"_size"] = fields[1]
			attributes[prefix+"_type"] = fields[2]

			if len(fields) > 3 {
				attributes[prefix+"_model"] = fields[3]
			}
			if len(fields) > 4 {
				attributes[prefix+"_vendor"] = fields[4]
			}
		}
	}

	if blockDeviceCount > 0 {
		attributes["block_device_count"] = fmt.Sprintf("%d", blockDeviceCount)
	}
}

// parseFdiskOutput parses fdisk output for disk information
func (l *LinuxHardwareCollector) parseFdiskOutput(output string, attributes map[string]string) {
	// Count disks mentioned in fdisk output
	diskCount := strings.Count(output, "Disk /dev/")
	if diskCount > 0 {
		attributes["fdisk_disk_count"] = fmt.Sprintf("%d", diskCount)
	}

	// Look for disk size information
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "Disk /dev/") && strings.Contains(line, "bytes") {
			// Extract disk info - this is a simple approach
			if strings.Contains(line, "GiB") || strings.Contains(line, "GB") {
				attributes["fdisk_sample_disk"] = line
				break
			}
		}
	}
}

// collectSMARTInfo collects SMART information if available
func (l *LinuxHardwareCollector) collectSMARTInfo(ctx context.Context, attributes map[string]string) {
	// Try to get SMART info for first few drives
	drives := []string{"sda", "sdb", "nvme0n1", "nvme1n1"}

	for _, drive := range drives {
		cmdCtx, cancel := context.WithTimeout(ctx, linuxCmdTimeout)
		// #nosec G204 - Hardware discovery requires system command execution
		if output, err := exec.CommandContext(cmdCtx, "smartctl", "-H", "/dev/"+drive).Output(); err == nil {
			if strings.Contains(string(output), "PASSED") {
				attributes["smart_"+drive+"_health"] = "PASSED"
			} else if strings.Contains(string(output), "FAILED") {
				attributes["smart_"+drive+"_health"] = "FAILED"
			}
		}
		cancel()
	}
}
