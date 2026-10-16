//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package file

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestSet_RefusesJunctionEscapingBase(t *testing.T) {
	base := t.TempDir()
	outside := t.TempDir()
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", filepath.Join(base, "sub"), outside).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J failed: %v: %s", err, out)
	}

	tests := []struct {
		name   string
		path   string
		config *FileConfig
	}{
		{"file", `sub\x.txt`, &FileConfig{State: "present", Content: "escaped", AllowedBasePath: base}},
		{"directory", `sub\d1`, &FileConfig{Type: "directory", State: "present", AllowedBasePath: base}},
		{"recursive directory", `sub\d2\d3`, &FileConfig{Type: "directory", State: "present", Recursive: true, AllowedBasePath: base}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := New().Set(context.Background(), filepath.Join(base, tt.path), tt.config); err == nil {
				t.Fatal("Set must refuse a path through a junction pointing outside the allowed base")
			}
		})
	}

	entries, err := os.ReadDir(outside)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Errorf("Set created %q outside the allowed base", e.Name())
	}
}

func TestSet_FollowsJunctionInsideBase(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0700); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", filepath.Join(base, "in"), real).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J failed: %v: %s", err, out)
	}

	cfg := &FileConfig{State: "present", Content: "inside", AllowedBasePath: base}
	if err := New().Set(context.Background(), filepath.Join(base, `in\x.txt`), cfg); err != nil {
		t.Fatalf("Set through an in-base junction: %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(real, "x.txt")); err != nil || string(data) != "inside" {
		t.Fatalf("file not written at the junction target: %q, %v", data, err)
	}
}
