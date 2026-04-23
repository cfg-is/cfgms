// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

//go:build integration

package main

import (
	"bytes"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBinaryExcludesLibPQ verifies that github.com/lib/pq is not in the steward
// binary's transitive dependency graph. The PostgreSQL driver must not be linked
// into the endpoint binary — it belongs only in cmd/controller.
func TestBinaryExcludesLibPQ(t *testing.T) {
	// Locate the repository root (two directories up from cmd/steward).
	_, filename, _, ok := runtime.Caller(0)
	require.True(t, ok, "runtime.Caller failed")
	repoRoot := filepath.Join(filepath.Dir(filename), "..", "..")

	cmd := exec.Command("go", "list", "-f", `{{join .Deps "\n"}}`, "./cmd/steward/")
	cmd.Dir = repoRoot

	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut

	err := cmd.Run()
	require.NoError(t, err, "go list failed: %s", errOut.String())

	deps := out.String()
	assert.False(t, strings.Contains(deps, "github.com/lib/pq"),
		"steward binary must not depend on github.com/lib/pq (PostgreSQL driver belongs in controller only)\nfull dep list:\n%s", deps)
}
