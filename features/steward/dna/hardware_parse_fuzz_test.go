// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package dna

import (
	"testing"
)

// No build tag — hardware_parse.go is also build-tag-free (confirmed: it
// compiles clean under GOOS=linux) so these targets run in the normal Linux CI
// job alongside hardware_parse_test.go.

// FuzzSplitCSVLine fuzzes the RFC-4180 CSV parser (hardware_parse.go:27).
// Real untrusted-input boundary: if the WMI/CIM tool's output is malformed,
// truncated, or the invoked binary is compromised, the parser must not panic.
func FuzzSplitCSVLine(f *testing.F) {
	// Seeds are real ConvertTo-Csv -NoTypeInformation lines from a Windows Server
	// 2025 host (same fixtures as hardware_parse_test.go).
	seeds := []string{
		`"HP","HP ProDesk 600 G5 SFF","34123063296"`,
		`"HP","1/11/2026 7:00:00 PM","R07 Ver. 02.25.00"`,
		`"HP","8597","PJEAP0DMVDH6K9","KBC Version 08.09.22"`,
		`"3B4602D8-1C05-7372-352B-45BF6B1453FD"`,
		`"17179869184","8","0","2667"`,
		`"SCSI","Fixed hard disk media","Microsoft Storage Space Device","322101964800"`,
		`"with, comma","plain"`,
		`"he said ""hi""","x"`,
		`a,b,c`,
		``,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, line string) {
		// Any panic is a bug. The return value is discarded — only crash-freedom matters.
		_ = splitCSVLine(line)
	})
}

// FuzzCimDataRows fuzzes the multi-row CSV splitter (hardware_parse.go:55).
// Exercises header-skip + blank-line-skip logic on arbitrary byte sequences.
func FuzzCimDataRows(f *testing.F) {
	seeds := []string{
		"\"Manufacturer\",\"Model\",\"TotalPhysicalMemory\"\r\n\"HP\",\"HP ProDesk 600 G5 SFF\",\"34123063296\"\r\n",
		"\"Capacity\",\"FormFactor\",\"MemoryType\",\"Speed\"\r\n\"17179869184\",\"8\",\"0\",\"2667\"\r\n\"8589934592\",\"8\",\"0\",\"3200\"\r\n",
		"\"InterfaceType\",\"MediaType\",\"Model\",\"Size\"\r\n\"SCSI\",\"Fixed hard disk media\",\"Microsoft Storage Space Device\",\"322101964800\"\r\n",
		"\"Manufacturer\",\"ReleaseDate\",\"SMBIOSBIOSVersion\"\r\n",
		"",
		"\n\n\n",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, csv string) {
		_ = cimDataRows(csv)
	})
}

// FuzzParseCIMComputerSystem fuzzes the full parse pipeline for
// Win32_ComputerSystem CIM output (hardware_parse.go:74), including the
// strconv.ParseInt path on the TotalPhysicalMemory field.
func FuzzParseCIMComputerSystem(f *testing.F) {
	seeds := []string{
		"\"Manufacturer\",\"Model\",\"TotalPhysicalMemory\"\r\n\"HP\",\"HP ProDesk 600 G5 SFF\",\"34123063296\"\r\n",
		"\"Manufacturer\",\"Model\",\"TotalPhysicalMemory\"\r\n\"Dell\",\"OptiPlex 7080\",\"not-a-number\"\r\n",
		"\"Manufacturer\",\"Model\",\"TotalPhysicalMemory\"\r\n",
		"",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, csv string) {
		attrs := map[string]string{}
		parseCIMComputerSystem(csv, attrs)
	})
}

// FuzzParseCIMMemoryModules fuzzes the multi-row memory parser
// (hardware_parse.go:157), which sums capacities and counts modules across
// arbitrarily many rows — higher combinatorial complexity than single-row parsers.
func FuzzParseCIMMemoryModules(f *testing.F) {
	seeds := []string{
		"\"Capacity\",\"FormFactor\",\"MemoryType\",\"Speed\"\r\n\"17179869184\",\"8\",\"0\",\"2667\"\r\n\"8589934592\",\"8\",\"0\",\"3200\"\r\n",
		"\"Capacity\",\"FormFactor\",\"MemoryType\",\"Speed\"\r\n\"n/a\",\"8\",\"0\",\"2667\"\r\n",
		"\"Capacity\",\"FormFactor\",\"MemoryType\",\"Speed\"\r\n",
		"",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, csv string) {
		attrs := map[string]string{}
		parseCIMMemoryModules(csv, attrs)
	})
}
