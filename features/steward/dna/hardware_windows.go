//go:build windows

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

const windowsHwCmdTimeout = 30 * time.Second

// CollectCPU gathers detailed CPU information on Windows using WMI
func (w *WindowsHardwareCollector) CollectCPU(ctx context.Context, attributes map[string]string) error {
	// Basic CPU count
	attributes["cpu_count"] = fmt.Sprintf("%d", runtime.NumCPU())
	attributes["cpu_arch"] = runtime.GOARCH

	// Get detailed CPU info using wmic
	cmdCtx, cancel := context.WithTimeout(ctx, windowsHwCmdTimeout)
	output, err := exec.CommandContext(cmdCtx, "wmic", "cpu", "get",
		"Name,Manufacturer,MaxClockSpeed,NumberOfCores,NumberOfLogicalProcessors,Architecture",
		"/format:csv").Output()
	cancel()

	if err == nil {
		w.parseWMICPUOutput(string(output), attributes)
	} else {
		// Fallback: PowerShell with Get-CimInstance (only if wmic failed)
		cmdCtx2, cancel2 := context.WithTimeout(ctx, windowsHwCmdTimeout)
		if output2, err2 := exec.CommandContext(cmdCtx2, "powershell", "-NoProfile", "-Command",
			"Get-CimInstance -ClassName Win32_Processor | Select-Object Name,Manufacturer,MaxClockSpeed,NumberOfCores,NumberOfLogicalProcessors,Architecture | ConvertTo-Csv -NoTypeInformation").Output(); err2 == nil {
			w.parsePowerShellCPUOutput(string(output2), attributes)
		}
		cancel2()
	}

	return nil
}

// CollectMemory gathers detailed memory information on Windows
func (w *WindowsHardwareCollector) CollectMemory(ctx context.Context, attributes map[string]string) error {
	// Physical memory using wmic
	cmdCtx, cancel := context.WithTimeout(ctx, windowsHwCmdTimeout)
	output, err := exec.CommandContext(cmdCtx, "wmic", "computersystem", "get",
		"TotalPhysicalMemory", "/format:csv").Output()
	cancel()

	if err == nil {
		w.parseWMIMemoryOutput(string(output), attributes)
	} else {
		// Fallback: PowerShell (only if wmic failed)
		cmdCtx2, cancel2 := context.WithTimeout(ctx, windowsHwCmdTimeout)
		if output2, err2 := exec.CommandContext(cmdCtx2, "powershell", "-NoProfile", "-Command",
			"Get-CimInstance -ClassName Win32_PageFileUsage | Select-Object AllocatedBaseSize,CurrentUsage | ConvertTo-Csv -NoTypeInformation").Output(); err2 == nil {
			w.parsePowerShellVirtualMemoryOutput(string(output2), attributes)
		}
		cancel2()
	}

	// Memory modules information
	cmdCtx3, cancel3 := context.WithTimeout(ctx, windowsHwCmdTimeout)
	if output3, err3 := exec.CommandContext(cmdCtx3, "wmic", "memorychip", "get",
		"Capacity,Speed,MemoryType,FormFactor", "/format:csv").Output(); err3 == nil {
		w.parseWMIMemoryModulesOutput(string(output3), attributes)
	}
	cancel3()

	return nil
}

// CollectDisk gathers disk and storage information on Windows
func (w *WindowsHardwareCollector) CollectDisk(ctx context.Context, attributes map[string]string) error {
	// Physical disk information using wmic
	cmdCtx, cancel := context.WithTimeout(ctx, windowsHwCmdTimeout)
	if output, err := exec.CommandContext(cmdCtx, "wmic", "diskdrive", "get",
		"Model,Size,MediaType,InterfaceType", "/format:csv").Output(); err == nil {
		w.parseWMIDiskOutput(string(output), attributes)
	}
	cancel()

	// Logical disk information (drive letters and free space)
	cmdCtx2, cancel2 := context.WithTimeout(ctx, windowsHwCmdTimeout)
	output2, err2 := exec.CommandContext(cmdCtx2, "wmic", "logicaldisk", "get",
		"Size,FreeSpace,FileSystem,DriveType,DeviceID", "/format:csv").Output()
	cancel2()

	if err2 == nil {
		w.parseWMILogicalDiskOutput(string(output2), attributes)
	} else {
		// Fallback: PowerShell (only if wmic failed)
		cmdCtx3, cancel3 := context.WithTimeout(ctx, windowsHwCmdTimeout)
		if output3, err3 := exec.CommandContext(cmdCtx3, "powershell", "-NoProfile", "-Command",
			"Get-CimInstance -ClassName Win32_LogicalDisk | Select-Object DeviceID,Size,FreeSpace,FileSystem | ConvertTo-Csv -NoTypeInformation").Output(); err3 == nil {
			w.parsePowerShellDiskUsageOutput(string(output3), attributes)
		}
		cancel3()
	}

	return nil
}

// CollectMotherboard gathers motherboard and system information on Windows
func (w *WindowsHardwareCollector) CollectMotherboard(ctx context.Context, attributes map[string]string) error {
	// Computer system information
	cmdCtx, cancel := context.WithTimeout(ctx, windowsHwCmdTimeout)
	if output, err := exec.CommandContext(cmdCtx, "wmic", "computersystem", "get",
		"Manufacturer,Model,TotalPhysicalMemory", "/format:csv").Output(); err == nil {
		w.parseWMIComputerSystemOutput(string(output), attributes)
	}
	cancel()

	// BIOS information
	cmdCtx2, cancel2 := context.WithTimeout(ctx, windowsHwCmdTimeout)
	if output, err := exec.CommandContext(cmdCtx2, "wmic", "bios", "get",
		"Manufacturer,SMBIOSBIOSVersion,ReleaseDate", "/format:csv").Output(); err == nil {
		w.parseWMIBIOSOutput(string(output), attributes)
	}
	cancel2()

	// Motherboard information
	cmdCtx3, cancel3 := context.WithTimeout(ctx, windowsHwCmdTimeout)
	if output, err := exec.CommandContext(cmdCtx3, "wmic", "baseboard", "get",
		"Manufacturer,Product,Version,SerialNumber", "/format:csv").Output(); err == nil {
		w.parseWMIMotherboardOutput(string(output), attributes)
	}
	cancel3()

	// System UUID
	cmdCtx4, cancel4 := context.WithTimeout(ctx, windowsHwCmdTimeout)
	if output, err := exec.CommandContext(cmdCtx4, "wmic", "csproduct", "get",
		"UUID", "/format:csv").Output(); err == nil {
		w.parseWMIUUIDOutput(string(output), attributes)
	}
	cancel4()

	// Windows version information (using wmic; no PowerShell fallback needed)
	cmdCtx5, cancel5 := context.WithTimeout(ctx, windowsHwCmdTimeout)
	if output, err := exec.CommandContext(cmdCtx5, "wmic", "os", "get",
		"Caption,Version,BuildNumber", "/format:csv").Output(); err == nil {
		w.parseWMIOSVersionOutput(string(output), attributes)
	}
	cancel5()

	return nil
}

// parseWMICPUOutput parses WMI CPU output
func (w *WindowsHardwareCollector) parseWMICPUOutput(output string, attributes map[string]string) {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Node") {
			continue
		}

		fields := strings.Split(line, ",")
		if len(fields) >= 7 {
			// Skip the Node field (first field)
			if len(fields) > 1 && fields[1] != "" {
				attributes["cpu_architecture"] = fields[1]
			}
			if len(fields) > 2 && fields[2] != "" {
				attributes["cpu_max_clock_speed"] = fields[2] + "MHz"
			}
			if len(fields) > 3 && fields[3] != "" {
				attributes["cpu_manufacturer"] = fields[3]
			}
			if len(fields) > 4 && fields[4] != "" {
				attributes["cpu_name"] = fields[4]
			}
			if len(fields) > 5 && fields[5] != "" {
				attributes["cpu_cores"] = fields[5]
			}
			if len(fields) > 6 && fields[6] != "" {
				attributes["cpu_logical_processors"] = fields[6]
			}
		}
	}
}

// parsePowerShellCPUOutput parses PowerShell CPU output as fallback
func (w *WindowsHardwareCollector) parsePowerShellCPUOutput(output string, attributes map[string]string) {
	lines := strings.Split(output, "\n")
	for i, line := range lines {
		if i == 0 { // Skip header
			continue
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Parse CSV format from PowerShell
		fields := w.parseCSVLine(line)
		if len(fields) >= 6 {
			if fields[0] != "" {
				attributes["cpu_architecture_ps"] = fields[0]
			}
			if fields[1] != "" {
				attributes["cpu_manufacturer_ps"] = fields[1]
			}
			if fields[2] != "" {
				attributes["cpu_max_clock_speed_ps"] = fields[2] + "MHz"
			}
			if fields[3] != "" {
				attributes["cpu_name_ps"] = fields[3]
			}
			if fields[4] != "" {
				attributes["cpu_cores_ps"] = fields[4]
			}
			if fields[5] != "" {
				attributes["cpu_logical_processors_ps"] = fields[5]
			}
		}
		break // Only process first CPU for now
	}
}

// parseWMIMemoryOutput parses WMI memory output
func (w *WindowsHardwareCollector) parseWMIMemoryOutput(output string, attributes map[string]string) {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Node") {
			continue
		}

		fields := strings.Split(line, ",")
		if len(fields) >= 2 && fields[1] != "" {
			if totalMem, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
				attributes["memory_total_bytes"] = fmt.Sprintf("%d", totalMem)
				attributes["memory_total_gb"] = fmt.Sprintf("%.2f", float64(totalMem)/1024/1024/1024)
			}
		}
	}
}

// parseWMIMemoryModulesOutput parses WMI memory modules output
func (w *WindowsHardwareCollector) parseWMIMemoryModulesOutput(output string, attributes map[string]string) {
	lines := strings.Split(output, "\n")
	var moduleCount int
	var totalCapacity int64

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Node") {
			continue
		}

		fields := strings.Split(line, ",")
		if len(fields) >= 5 {
			moduleCount++
			if capacity, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
				totalCapacity += capacity
			}

			// Store first module details as sample
			if moduleCount == 1 {
				if fields[1] != "" {
					attributes["memory_module_capacity"] = fields[1]
				}
				if fields[2] != "" {
					attributes["memory_module_form_factor"] = fields[2]
				}
				if fields[3] != "" {
					attributes["memory_module_type"] = fields[3]
				}
				if fields[4] != "" {
					attributes["memory_module_speed"] = fields[4] + "MHz"
				}
			}
		}
	}

	if moduleCount > 0 {
		attributes["memory_module_count"] = fmt.Sprintf("%d", moduleCount)
		attributes["memory_modules_total_capacity"] = fmt.Sprintf("%d", totalCapacity)
	}
}

// parsePowerShellVirtualMemoryOutput parses PowerShell virtual memory output
func (w *WindowsHardwareCollector) parsePowerShellVirtualMemoryOutput(output string, attributes map[string]string) {
	lines := strings.Split(output, "\n")
	for i, line := range lines {
		if i == 0 { // Skip header
			continue
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := w.parseCSVLine(line)
		if len(fields) >= 2 {
			if fields[0] != "" {
				attributes["pagefile_allocated_size"] = fields[0] + "MB"
			}
			if fields[1] != "" {
				attributes["pagefile_current_usage"] = fields[1] + "MB"
			}
		}
		break // Only process first pagefile
	}
}

// parseWMIDiskOutput parses WMI physical disk output
func (w *WindowsHardwareCollector) parseWMIDiskOutput(output string, attributes map[string]string) {
	lines := strings.Split(output, "\n")
	var diskCount int

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Node") {
			continue
		}

		fields := strings.Split(line, ",")
		if len(fields) >= 5 {
			diskCount++
			prefix := fmt.Sprintf("physical_disk_%d", diskCount)

			if fields[1] != "" {
				attributes[prefix+"_interface"] = fields[1]
			}
			if fields[2] != "" {
				attributes[prefix+"_media_type"] = fields[2]
			}
			if fields[3] != "" {
				attributes[prefix+"_model"] = fields[3]
			}
			if fields[4] != "" {
				if size, err := strconv.ParseInt(fields[4], 10, 64); err == nil {
					attributes[prefix+"_size_bytes"] = fmt.Sprintf("%d", size)
					attributes[prefix+"_size_gb"] = fmt.Sprintf("%.2f", float64(size)/1024/1024/1024)
				}
			}
		}
	}

	if diskCount > 0 {
		attributes["physical_disk_count"] = fmt.Sprintf("%d", diskCount)
	}
}

// parseWMILogicalDiskOutput parses WMI logical disk output
func (w *WindowsHardwareCollector) parseWMILogicalDiskOutput(output string, attributes map[string]string) {
	lines := strings.Split(output, "\n")
	var driveCount int

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Node") {
			continue
		}

		fields := strings.Split(line, ",")
		if len(fields) >= 6 && fields[1] != "" {
			driveCount++
			prefix := fmt.Sprintf("logical_drive_%s", strings.Replace(fields[1], ":", "", -1))

			attributes[prefix+"_device"] = fields[1]
			if fields[2] != "" {
				attributes[prefix+"_drive_type"] = fields[2]
			}
			if fields[3] != "" {
				attributes[prefix+"_filesystem"] = fields[3]
			}
			if fields[4] != "" {
				if freeSpace, err := strconv.ParseInt(fields[4], 10, 64); err == nil {
					attributes[prefix+"_free_space_gb"] = fmt.Sprintf("%.2f", float64(freeSpace)/1024/1024/1024)
				}
			}
			if fields[5] != "" {
				if totalSize, err := strconv.ParseInt(fields[5], 10, 64); err == nil {
					attributes[prefix+"_total_size_gb"] = fmt.Sprintf("%.2f", float64(totalSize)/1024/1024/1024)
				}
			}
		}
	}

	if driveCount > 0 {
		attributes["logical_drive_count"] = fmt.Sprintf("%d", driveCount)
	}
}

// parsePowerShellDiskUsageOutput parses PowerShell disk usage output
func (w *WindowsHardwareCollector) parsePowerShellDiskUsageOutput(output string, attributes map[string]string) {
	lines := strings.Split(output, "\n")
	for i, line := range lines {
		if i == 0 { // Skip header
			continue
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := w.parseCSVLine(line)
		if len(fields) >= 4 && fields[0] != "" {
			prefix := fmt.Sprintf("ps_drive_%s", strings.Replace(fields[0], ":", "", -1))

			if fields[1] != "" {
				attributes[prefix+"_filesystem"] = fields[1]
			}
			if fields[2] != "" {
				if freeSpace, err := strconv.ParseInt(fields[2], 10, 64); err == nil {
					attributes[prefix+"_free_space_gb"] = fmt.Sprintf("%.2f", float64(freeSpace)/1024/1024/1024)
				}
			}
			if fields[3] != "" {
				if totalSize, err := strconv.ParseInt(fields[3], 10, 64); err == nil {
					attributes[prefix+"_total_size_gb"] = fmt.Sprintf("%.2f", float64(totalSize)/1024/1024/1024)
				}
			}
		}
	}
}

func (w *WindowsHardwareCollector) parseWMIComputerSystemOutput(output string, attributes map[string]string) {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Node") {
			continue
		}

		fields := strings.Split(line, ",")
		if len(fields) >= 4 {
			if fields[1] != "" {
				attributes["system_manufacturer"] = fields[1]
			}
			if fields[2] != "" {
				attributes["system_model"] = fields[2]
			}
			if fields[3] != "" {
				if totalMem, err := strconv.ParseInt(fields[3], 10, 64); err == nil {
					attributes["system_total_memory"] = fmt.Sprintf("%.2f GB", float64(totalMem)/1024/1024/1024)
				}
			}
		}
	}
}

func (w *WindowsHardwareCollector) parseWMIBIOSOutput(output string, attributes map[string]string) {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Node") {
			continue
		}

		fields := strings.Split(line, ",")
		if len(fields) >= 4 {
			if fields[1] != "" {
				attributes["bios_manufacturer"] = fields[1]
			}
			if fields[2] != "" {
				attributes["bios_release_date"] = fields[2]
			}
			if fields[3] != "" {
				attributes["bios_version"] = fields[3]
			}
		}
	}
}

func (w *WindowsHardwareCollector) parseWMIMotherboardOutput(output string, attributes map[string]string) {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Node") {
			continue
		}

		fields := strings.Split(line, ",")
		if len(fields) >= 5 {
			if fields[1] != "" {
				attributes["motherboard_manufacturer"] = fields[1]
			}
			if fields[2] != "" {
				attributes["motherboard_product"] = fields[2]
			}
			if fields[3] != "" {
				attributes["motherboard_serial"] = fields[3]
			}
			if fields[4] != "" {
				attributes["motherboard_version"] = fields[4]
			}
		}
	}
}

func (w *WindowsHardwareCollector) parseWMIUUIDOutput(output string, attributes map[string]string) {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Node") {
			continue
		}

		fields := strings.Split(line, ",")
		if len(fields) >= 2 && fields[1] != "" {
			attributes["system_uuid"] = fields[1]
		}
	}
}

func (w *WindowsHardwareCollector) parseWMIOSVersionOutput(output string, attributes map[string]string) {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Node") {
			continue
		}

		fields := strings.Split(line, ",")
		if len(fields) >= 4 {
			if fields[1] != "" {
				attributes["windows_build_number"] = fields[1]
			}
			if fields[2] != "" {
				attributes["windows_caption"] = fields[2]
			}
			if fields[3] != "" {
				attributes["windows_version"] = fields[3]
			}
		}
	}
}

// parseCSVLine handles basic CSV parsing with quoted fields
func (w *WindowsHardwareCollector) parseCSVLine(line string) []string {
	var fields []string
	var current strings.Builder
	inQuotes := false

	for _, char := range line {
		switch char {
		case '"':
			inQuotes = !inQuotes
		case ',':
			if !inQuotes {
				fields = append(fields, strings.TrimSpace(current.String()))
				current.Reset()
			} else {
				current.WriteRune(char)
			}
		default:
			current.WriteRune(char)
		}
	}

	// Add the last field
	fields = append(fields, strings.TrimSpace(current.String()))

	return fields
}
