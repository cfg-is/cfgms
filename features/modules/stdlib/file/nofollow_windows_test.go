//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package file

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/cfgis/cfgms/features/modules"
)

func TestSetFileACL_RejectsReparsePointLeaf(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	junction := filepath.Join(dir, "junc")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", junction, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J failed: %v: %s", err, out)
	}
	acl := &modules.WindowsACL{Entries: []modules.ACLEntry{{Principal: "BUILTIN\\Users", Access: "Read"}}}
	if err := setFileACL(junction, acl); err == nil {
		t.Fatal("setFileACL must refuse a reparse-point leaf")
	}
}
