// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package dna

import (
	"fmt"
	"strconv"
	"strings"
)

// Parsers for `Get-CimInstance ... | ConvertTo-Csv -NoTypeInformation` output,
// used as the fallback when `wmic` is absent (deprecated/removed on Windows
// Server 2025 / Windows 11 24H2+; #2147). They live in this NON build-tagged
// file (and are tested in hardware_parse_test.go) so the parse logic is covered
// by Linux CI even though the WindowsHardwareCollector that calls them is
// //go:build windows.
//
// CIM CSV differs from `wmic /format:csv`: fields are double-quoted, there is no
// leading "Node" (hostname) column, and the column order is the Select-Object
// order rather than alphabetical. Each parser therefore expects a specific
// Select-Object order (documented per function) and populates exactly the same
// attribute keys as its wmic primary parser — no new host-identifying field.

// splitCSVLine splits one ConvertTo-Csv line into unquoted fields, honoring
// double-quoted fields, embedded commas, and "" escaped quotes (RFC 4180).
func splitCSVLine(line string) []string {
	var fields []string
	var cur strings.Builder
	inQuotes := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '"':
			if inQuotes && i+1 < len(line) && line[i+1] == '"' {
				cur.WriteByte('"')
				i++
			} else {
				inQuotes = !inQuotes
			}
		case c == ',' && !inQuotes:
			fields = append(fields, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	fields = append(fields, cur.String())
	return fields
}

// cimDataRows returns the data rows of ConvertTo-Csv -NoTypeInformation output,
// skipping the single header row and any blank lines. Each row is split into
// unquoted fields.
func cimDataRows(csv string) [][]string {
	var rows [][]string
	seenHeader := false
	for _, raw := range strings.Split(csv, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if !seenHeader {
			seenHeader = true // first non-empty line is the header
			continue
		}
		rows = append(rows, splitCSVLine(line))
	}
	return rows
}

// parseCIMComputerSystem parses Win32_ComputerSystem selected as
// Manufacturer,Model,TotalPhysicalMemory. Mirrors parseWMIComputerSystemOutput.
func parseCIMComputerSystem(csv string, attributes map[string]string) {
	rows := cimDataRows(csv)
	if len(rows) == 0 {
		return
	}
	f := rows[0]
	if len(f) >= 3 {
		if f[0] != "" {
			attributes["system_manufacturer"] = f[0]
		}
		if f[1] != "" {
			attributes["system_model"] = f[1]
		}
		if f[2] != "" {
			if total, err := strconv.ParseInt(f[2], 10, 64); err == nil {
				attributes["system_total_memory"] = fmt.Sprintf("%.2f GB", float64(total)/1024/1024/1024)
			}
		}
	}
}

// parseCIMBIOS parses Win32_BIOS selected as
// Manufacturer,ReleaseDate,SMBIOSBIOSVersion. Mirrors parseWMIBIOSOutput.
func parseCIMBIOS(csv string, attributes map[string]string) {
	rows := cimDataRows(csv)
	if len(rows) == 0 {
		return
	}
	f := rows[0]
	if len(f) >= 3 {
		if f[0] != "" {
			attributes["bios_manufacturer"] = f[0]
		}
		if f[1] != "" {
			attributes["bios_release_date"] = f[1]
		}
		if f[2] != "" {
			attributes["bios_version"] = f[2]
		}
	}
}

// parseCIMBaseboard parses Win32_BaseBoard selected as
// Manufacturer,Product,SerialNumber,Version. Mirrors parseWMIMotherboardOutput.
func parseCIMBaseboard(csv string, attributes map[string]string) {
	rows := cimDataRows(csv)
	if len(rows) == 0 {
		return
	}
	f := rows[0]
	if len(f) >= 4 {
		if f[0] != "" {
			attributes["motherboard_manufacturer"] = f[0]
		}
		if f[1] != "" {
			attributes["motherboard_product"] = f[1]
		}
		if f[2] != "" {
			attributes["motherboard_serial"] = f[2]
		}
		if f[3] != "" {
			attributes["motherboard_version"] = f[3]
		}
	}
}

// parseCIMSystemUUID parses Win32_ComputerSystemProduct selected as UUID.
// Mirrors parseWMIUUIDOutput.
func parseCIMSystemUUID(csv string, attributes map[string]string) {
	rows := cimDataRows(csv)
	if len(rows) == 0 {
		return
	}
	if f := rows[0]; len(f) >= 1 && f[0] != "" {
		attributes["system_uuid"] = f[0]
	}
}

// parseCIMMemoryModules parses Win32_PhysicalMemory selected as
// Capacity,FormFactor,MemoryType,Speed. Mirrors parseWMIMemoryModulesOutput
// exactly: it counts every module, sums the parseable capacities into
// memory_modules_total_capacity, emits memory_module_count, and stores the
// FIRST module's details as the representative sample.
func parseCIMMemoryModules(csv string, attributes map[string]string) {
	var moduleCount int
	var totalCapacity int64
	for _, f := range cimDataRows(csv) {
		if len(f) < 4 {
			continue
		}
		moduleCount++
		if capacity, err := strconv.ParseInt(f[0], 10, 64); err == nil {
			totalCapacity += capacity
		}
		// First module's details as the representative sample.
		if moduleCount == 1 {
			if f[0] != "" {
				attributes["memory_module_capacity"] = f[0]
			}
			if f[1] != "" {
				attributes["memory_module_form_factor"] = f[1]
			}
			if f[2] != "" {
				attributes["memory_module_type"] = f[2]
			}
			if f[3] != "" {
				attributes["memory_module_speed"] = f[3] + "MHz"
			}
		}
	}
	if moduleCount > 0 {
		attributes["memory_module_count"] = fmt.Sprintf("%d", moduleCount)
		attributes["memory_modules_total_capacity"] = fmt.Sprintf("%d", totalCapacity)
	}
}

// parseCIMPhysicalDisks parses Win32_DiskDrive selected as
// InterfaceType,MediaType,Model,Size. Mirrors parseWMIDiskOutput, including the
// 1-based physical_disk_<n>_* indexing and physical_disk_count.
func parseCIMPhysicalDisks(csv string, attributes map[string]string) {
	var diskCount int
	for _, f := range cimDataRows(csv) {
		if len(f) < 4 {
			continue
		}
		diskCount++
		prefix := fmt.Sprintf("physical_disk_%d", diskCount)
		if f[0] != "" {
			attributes[prefix+"_interface"] = f[0]
		}
		if f[1] != "" {
			attributes[prefix+"_media_type"] = f[1]
		}
		if f[2] != "" {
			attributes[prefix+"_model"] = f[2]
		}
		if f[3] != "" {
			if size, err := strconv.ParseInt(f[3], 10, 64); err == nil {
				attributes[prefix+"_size_bytes"] = fmt.Sprintf("%d", size)
				attributes[prefix+"_size_gb"] = fmt.Sprintf("%.2f", float64(size)/1024/1024/1024)
			}
		}
	}
	if diskCount > 0 {
		attributes["physical_disk_count"] = fmt.Sprintf("%d", diskCount)
	}
}
