// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package main implements the compiled-artifact gate for CFGMS.
//
// It classifies every git-tracked file by its leading magic bytes rather than
// by shelling out to file(1) (an optional distro package) so the gate works
// anywhere git and a Go toolchain are available — CI, dev containers, and the
// Makefile security targets.
//
// This exists as a Go program rather than the pure-shell implementation
// scripts/check-binary-artifacts.sh falls back to when go is unavailable:
// the shell version spawns two subprocesses (od + tr) per tracked file, which
// is cheap on Linux's fast fork/exec but pathologically slow on hosts where
// process creation carries real overhead (observed: real-time antivirus
// scanning on a Windows dev host turned a several-thousand-file repo scan
// into 5-10+ minutes — even after parallelizing and batching the shell
// version, still dominated by wait time, not CPU time). Reading every file's
// header in one process, with no subprocess spawned per file at all, is not
// an optimization of that approach — it is a different approach that isn't
// subject to per-process overhead in the first place.
//
// Exit codes: 0 = clean, 1 = a tracked file is a compiled artifact.
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// Magic values:
//
//	7f454c46                                \x7fELF     ELF executable / shared object / object file
//	feedface feedfacf cefaedfe cffaedfe      Mach-O 32/64-bit, both byte orders
//	cafebabe bebafeca                        Mach-O universal binary (also Java class data)
//	4d5a....                                 MZ          PE32/PE32+ and MS-DOS executables
//	0061736d                                 \0asm       WebAssembly binary module
func artifactKind(header []byte) string {
	// MZ is a TWO-byte signature; every other magic below is four bytes. Guarding
	// the whole function at four bytes meant a two-byte "MZ" file never reached
	// the MZ case and passed the gate — even though two bytes is a complete PE
	// signature, not a truncated one. A committed DOS/PE stub trimmed to its
	// magic would have been waved through.
	//
	// Checked before the four-byte guard, and safe to check first: no other
	// signature here begins 0x4d 0x5a.
	if len(header) >= 2 && header[0] == 'M' && header[1] == 'Z' {
		return "PE32/MS-DOS executable"
	}
	if len(header) < 4 {
		return ""
	}
	switch {
	case bytes.Equal(header, []byte{0x7f, 'E', 'L', 'F'}):
		return "ELF binary"
	case bytes.Equal(header, []byte{0xfe, 0xed, 0xfa, 0xce}),
		bytes.Equal(header, []byte{0xfe, 0xed, 0xfa, 0xcf}),
		bytes.Equal(header, []byte{0xce, 0xfa, 0xed, 0xfe}),
		bytes.Equal(header, []byte{0xcf, 0xfa, 0xed, 0xfe}):
		return "Mach-O binary"
	case bytes.Equal(header, []byte{0xca, 0xfe, 0xba, 0xbe}),
		bytes.Equal(header, []byte{0xbe, 0xba, 0xfe, 0xca}):
		return "Mach-O universal binary or Java class data"
	case bytes.Equal(header, []byte{0x00, 'a', 's', 'm'}):
		return "WebAssembly binary module"
	default:
		return ""
	}
}

var compiledExtensions = []string{
	".a", ".o", ".obj", ".lib", ".dll", ".dylib", ".so", ".wasm", ".exe",
}

func hasCompiledExtension(path string) bool {
	for _, ext := range compiledExtensions {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

func trackedFiles() ([]string, error) {
	cmd := exec.Command("git", "ls-files", "-z")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git ls-files: %w", err)
	}
	var files []string
	for _, f := range bytes.Split(out, []byte{0}) {
		if len(f) == 0 {
			continue
		}
		files = append(files, string(f))
	}
	return files, nil
}

func checkFile(path string) []string {
	var findings []string

	f, err := os.Open(path) //nolint:gosec // path comes from `git ls-files`, a controlled source
	if err != nil {
		if os.IsNotExist(err) {
			// A file git reports but that is missing locally is skipped, not an
			// error (e.g. a submodule placeholder or a deleted-but-staged path).
			if hasCompiledExtension(path) {
				findings = append(findings, fmt.Sprintf("tracked compiled artifact extension: %s", path))
			}
			return findings
		}
		// Exists but can't be opened (e.g. permissions stripped) — fail closed.
		// A gate that silently skips a file it cannot inspect can be defeated
		// by chmod 000-ing a committed binary.
		findings = append(findings, fmt.Sprintf("unreadable tracked file: %s (cannot inspect magic bytes)", path))
		if hasCompiledExtension(path) {
			findings = append(findings, fmt.Sprintf("tracked compiled artifact extension: %s", path))
		}
		return findings
	}
	defer func() { _ = f.Close() }()

	header := make([]byte, 4)
	n, err := io.ReadFull(bufio.NewReader(f), header)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		// A short read (0-3 bytes: ErrUnexpectedEOF/EOF) is not itself an error:
		// the truncated header is still classified below, and two bytes is enough
		// to identify an MZ stub. Any other read error leaves the header
		// unclassifiable and must fail closed the same way as an unopenable file
		// above.
		findings = append(findings, fmt.Sprintf("unreadable tracked file: %s (cannot inspect magic bytes)", path))
		if hasCompiledExtension(path) {
			findings = append(findings, fmt.Sprintf("tracked compiled artifact extension: %s", path))
		}
		return findings
	}

	if kind := artifactKind(header[:n]); kind != "" {
		findings = append(findings, fmt.Sprintf("tracked compiled artifact: %s (%s)", path, kind))
	}
	if hasCompiledExtension(path) {
		findings = append(findings, fmt.Sprintf("tracked compiled artifact extension: %s", path))
	}
	return findings
}

func run() int {
	files, err := trackedFiles()
	if err != nil {
		fmt.Fprintln(os.Stderr, "check-binary-artifacts:", err)
		return 2
	}

	var findings []string
	for _, path := range files {
		findings = append(findings, checkFile(path)...)
	}

	if len(findings) > 0 {
		for _, line := range findings {
			fmt.Fprintln(os.Stderr, line)
		}
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "compiled artifacts must be produced by the release pipeline, not committed to source")
		return 1
	}

	fmt.Println("binary-artifact check passed")
	return 0
}

func main() {
	os.Exit(run())
}
