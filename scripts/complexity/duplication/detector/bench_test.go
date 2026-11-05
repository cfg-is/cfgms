// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package detector

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// BenchmarkDetectRepo measures Detect over every Go file in the repository.
func BenchmarkDetectRepo(b *testing.B) {
	root, err := filepath.Abs("../../../..")
	if err != nil {
		b.Fatal(err)
	}
	var files []File
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", ".claude":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") {
			return nil
		}
		src, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		files = append(files, File{Path: filepath.ToSlash(rel), Src: src})
		return nil
	})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Detect(files, DefaultThreshold); err != nil {
			b.Fatal(err)
		}
	}
}
