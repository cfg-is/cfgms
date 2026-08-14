// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestArtifactKind(t *testing.T) {
	cases := []struct {
		name   string
		header []byte
		expect string
	}{
		{"elf", []byte{0x7f, 'E', 'L', 'F'}, "ELF binary"},
		{"macho64le", []byte{0xcf, 0xfa, 0xed, 0xfe}, "Mach-O binary"},
		{"macho32le", []byte{0xce, 0xfa, 0xed, 0xfe}, "Mach-O binary"},
		{"machoBE", []byte{0xfe, 0xed, 0xfa, 0xce}, "Mach-O binary"},
		{"machoBE64", []byte{0xfe, 0xed, 0xfa, 0xcf}, "Mach-O binary"},
		{"machoFat", []byte{0xca, 0xfe, 0xba, 0xbe}, "Mach-O universal binary or Java class data"},
		{"machoFatBE", []byte{0xbe, 0xba, 0xfe, 0xca}, "Mach-O universal binary or Java class data"},
		{"pe", []byte{'M', 'Z', 0x90, 0x00}, "PE32/MS-DOS executable"},
		{"peTruncated", []byte{'M', 'Z'}, "PE32/MS-DOS executable"},
		{"wasm", []byte{0x00, 'a', 's', 'm'}, "WebAssembly binary module"},
		{"text", []byte("pack"), ""},
		{"short", []byte{0x7f, 'E'}, ""},
		{"empty", []byte{}, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expect, artifactKind(tc.header))
		})
	}
}

func TestHasCompiledExtension(t *testing.T) {
	assert.True(t, hasCompiledExtension("lib/thing.so"))
	assert.True(t, hasCompiledExtension("build/steward.exe"))
	assert.False(t, hasCompiledExtension("main.go"))
	assert.False(t, hasCompiledExtension("README.md"))
}

func TestCheckFile_DetectsMagicAndExtension(t *testing.T) {
	dir := t.TempDir()

	elfPath := filepath.Join(dir, "steward")
	require.NoError(t, os.WriteFile(elfPath, []byte{0x7f, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00}, 0o644))
	findings := checkFile(elfPath)
	require.Len(t, findings, 1)
	assert.Contains(t, findings[0], "tracked compiled artifact: "+elfPath)
	assert.Contains(t, findings[0], "ELF binary")

	soPath := filepath.Join(dir, "vendor.so")
	require.NoError(t, os.WriteFile(soPath, []byte("not really a shared object\n"), 0o644))
	findings = checkFile(soPath)
	require.Len(t, findings, 1)
	assert.Contains(t, findings[0], "tracked compiled artifact extension: "+soPath)

	bothPath := filepath.Join(dir, "steward.exe")
	require.NoError(t, os.WriteFile(bothPath, []byte{'M', 'Z', 0x90, 0x00}, 0o644))
	findings = checkFile(bothPath)
	require.Len(t, findings, 2, "a file matching both magic and extension must report both findings: %v", findings)
}

func TestCheckFile_AllowsShortAndEmptyTextFiles(t *testing.T) {
	dir := t.TempDir()

	empty := filepath.Join(dir, "empty.txt")
	require.NoError(t, os.WriteFile(empty, []byte{}, 0o644))
	assert.Empty(t, checkFile(empty))

	tiny := filepath.Join(dir, "tiny.txt")
	require.NoError(t, os.WriteFile(tiny, []byte("x"), 0o644))
	assert.Empty(t, checkFile(tiny))

	short := filepath.Join(dir, "short.txt")
	require.NoError(t, os.WriteFile(short, []byte("ok\n"), 0o644))
	assert.Empty(t, checkFile(short))
}

func TestCheckFile_MissingFileIsSkippedNotErrored(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "does-not-exist.go")
	assert.Empty(t, checkFile(missing))

	missingSO := filepath.Join(dir, "does-not-exist.so")
	// A missing file still trips the extension arm (mirrors the shell
	// implementation, which checks the extension unconditionally via a case
	// statement regardless of whether -f succeeded for the magic-byte arm).
	findings := checkFile(missingSO)
	require.Len(t, findings, 1)
	assert.Contains(t, findings[0], "tracked compiled artifact extension: "+missingSO)
}
