// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package dna

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests run on every platform (no build tag), so the CIM-fallback parse
// logic for the wmic-less Windows path (#2147) is covered by Linux CI even
// though WindowsHardwareCollector is //go:build windows. The sample inputs are
// real `Get-CimInstance ... | ConvertTo-Csv -NoTypeInformation` output captured
// on a Windows Server 2025 host.

func TestSplitCSVLine(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{`"a","b","c"`, []string{"a", "b", "c"}},
		{`"HP","HP ProDesk 600 G5 SFF","34123063296"`, []string{"HP", "HP ProDesk 600 G5 SFF", "34123063296"}},
		{`"with, comma","plain"`, []string{"with, comma", "plain"}}, // embedded comma inside quotes
		{`"he said ""hi""","x"`, []string{`he said "hi"`, "x"}},     // escaped quotes
		{`a,b,c`, []string{"a", "b", "c"}},                          // unquoted
		{``, []string{""}},                                          // empty
	}
	for _, c := range cases {
		assert.Equal(t, c.want, splitCSVLine(c.in), "splitCSVLine(%q)", c.in)
	}
}

func TestParseCIMComputerSystem(t *testing.T) {
	csv := "\"Manufacturer\",\"Model\",\"TotalPhysicalMemory\"\r\n\"HP\",\"HP ProDesk 600 G5 SFF\",\"34123063296\"\r\n"
	a := map[string]string{}
	parseCIMComputerSystem(csv, a)
	assert.Equal(t, "HP", a["system_manufacturer"])
	assert.Equal(t, "HP ProDesk 600 G5 SFF", a["system_model"])
	assert.Equal(t, "31.78 GB", a["system_total_memory"])

	// Header-only / empty / malformed → no attributes, no panic.
	for _, bad := range []string{"", "\"Manufacturer\",\"Model\",\"TotalPhysicalMemory\"\r\n", "\"x\",\"y\"\r\n\"a\",\"b\"\r\n"} {
		m := map[string]string{}
		require.NotPanics(t, func() { parseCIMComputerSystem(bad, m) })
		assert.Empty(t, m)
	}
}

func TestParseCIMBIOS(t *testing.T) {
	csv := "\"Manufacturer\",\"ReleaseDate\",\"SMBIOSBIOSVersion\"\r\n\"HP\",\"1/11/2026 7:00:00 PM\",\"R07 Ver. 02.25.00\"\r\n"
	a := map[string]string{}
	parseCIMBIOS(csv, a)
	assert.Equal(t, "HP", a["bios_manufacturer"])
	assert.Equal(t, "1/11/2026 7:00:00 PM", a["bios_release_date"])
	assert.Equal(t, "R07 Ver. 02.25.00", a["bios_version"])
}

func TestParseCIMBaseboard(t *testing.T) {
	csv := "\"Manufacturer\",\"Product\",\"SerialNumber\",\"Version\"\r\n\"HP\",\"8597\",\"PJEAP0DMVDH6K9\",\"KBC Version 08.09.22\"\r\n"
	a := map[string]string{}
	parseCIMBaseboard(csv, a)
	assert.Equal(t, "HP", a["motherboard_manufacturer"])
	assert.Equal(t, "8597", a["motherboard_product"])
	assert.Equal(t, "PJEAP0DMVDH6K9", a["motherboard_serial"])
	assert.Equal(t, "KBC Version 08.09.22", a["motherboard_version"])
}

func TestParseCIMSystemUUID(t *testing.T) {
	csv := "\"UUID\"\r\n\"3B4602D8-1C05-7372-352B-45BF6B1453FD\"\r\n"
	a := map[string]string{}
	parseCIMSystemUUID(csv, a)
	assert.Equal(t, "3B4602D8-1C05-7372-352B-45BF6B1453FD", a["system_uuid"])
}

func TestParseCIMMemoryModules(t *testing.T) {
	// Two DIFFERENT modules: the FIRST module is the representative sample,
	// count is all modules, and total_capacity is the sum (mirrors the wmic
	// parser exactly).
	csv := "\"Capacity\",\"FormFactor\",\"MemoryType\",\"Speed\"\r\n" +
		"\"17179869184\",\"8\",\"0\",\"2667\"\r\n" +
		"\"8589934592\",\"8\",\"0\",\"3200\"\r\n"
	a := map[string]string{}
	parseCIMMemoryModules(csv, a)
	assert.Equal(t, "17179869184", a["memory_module_capacity"], "first module wins")
	assert.Equal(t, "8", a["memory_module_form_factor"])
	assert.Equal(t, "0", a["memory_module_type"])
	assert.Equal(t, "2667MHz", a["memory_module_speed"], "first module's speed")
	assert.Equal(t, "2", a["memory_module_count"])
	assert.Equal(t, "25769803776", a["memory_modules_total_capacity"], "17179869184 + 8589934592")

	// A row whose Capacity is non-integer is still counted (mirrors wmic: the
	// raw value is stored, but it does not contribute to total_capacity).
	m := map[string]string{}
	parseCIMMemoryModules("\"Capacity\",\"FormFactor\",\"MemoryType\",\"Speed\"\r\n\"n/a\",\"8\",\"0\",\"2667\"\r\n", m)
	assert.Equal(t, "n/a", m["memory_module_capacity"])
	assert.Equal(t, "1", m["memory_module_count"])
	assert.Equal(t, "0", m["memory_modules_total_capacity"])

	// Empty / header-only → no attributes, no panic.
	for _, bad := range []string{"", "\"Capacity\",\"FormFactor\",\"MemoryType\",\"Speed\"\r\n"} {
		e := map[string]string{}
		require.NotPanics(t, func() { parseCIMMemoryModules(bad, e) })
		assert.Empty(t, e)
	}
}

func TestParseCIMPhysicalDisks(t *testing.T) {
	csv := "\"InterfaceType\",\"MediaType\",\"Model\",\"Size\"\r\n" +
		"\"SCSI\",\"Fixed hard disk media\",\"Microsoft Storage Space Device\",\"322101964800\"\r\n" +
		"\"SCSI\",\"Fixed hard disk media\",\"SAMSUNG MZVLB1T0HBLR-000L7\",\"1024203640320\"\r\n"
	a := map[string]string{}
	parseCIMPhysicalDisks(csv, a)
	assert.Equal(t, "2", a["physical_disk_count"])
	assert.Equal(t, "SCSI", a["physical_disk_1_interface"])
	assert.Equal(t, "Fixed hard disk media", a["physical_disk_1_media_type"])
	assert.Equal(t, "Microsoft Storage Space Device", a["physical_disk_1_model"])
	assert.Equal(t, "322101964800", a["physical_disk_1_size_bytes"])
	assert.NotEmpty(t, a["physical_disk_1_size_gb"])
	assert.Equal(t, "SCSI", a["physical_disk_2_interface"])
	assert.Equal(t, "Fixed hard disk media", a["physical_disk_2_media_type"])
	assert.Equal(t, "SAMSUNG MZVLB1T0HBLR-000L7", a["physical_disk_2_model"])
	assert.Equal(t, "1024203640320", a["physical_disk_2_size_bytes"])
	assert.NotEmpty(t, a["physical_disk_2_size_gb"])

	// Empty / header-only → no disks, no panic.
	for _, bad := range []string{"", "\"InterfaceType\",\"MediaType\",\"Model\",\"Size\"\r\n"} {
		e := map[string]string{}
		require.NotPanics(t, func() { parseCIMPhysicalDisks(bad, e) })
		assert.Empty(t, e)
	}
}
