// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//go:build windows

package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A file name containing U+2019 (a PowerShell single-quote delimiter) must be
// handled as data: verifying an unsigned file reports "no signature found".
func TestAuthenticodeVerify_TypographicQuoteInName(t *testing.T) {
	path := filepath.Join(t.TempDir(), "o\u2019brien; calc.ps1")
	if err := os.WriteFile(path, []byte("Write-Output 'hi'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := authenticodeVerify(path)
	if err == nil {
		t.Fatal("expected error for unsigned file")
	}
	if !strings.Contains(err.Error(), "no signature found") {
		t.Errorf("expected 'no signature found', got: %v", err)
	}
}
