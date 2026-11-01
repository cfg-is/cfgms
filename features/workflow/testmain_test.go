// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

//go:build !windows

package workflow

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// integrationEchoModuleBin is the path to the compiled workflow echo_module
// binary used by integration tests. Set by TestMain before any tests run;
// empty string means the binary could not be compiled.
var integrationEchoModuleBin string

// integrationBinaryCleanupDir is cleaned up after all tests complete.
var integrationBinaryCleanupDir string

func TestMain(m *testing.M) {
	os.Exit(runTestSuite(m))
}

func runTestSuite(m *testing.M) int {
	var err error
	integrationBinaryCleanupDir, err = os.MkdirTemp("", "cfgms-wf-int-bin-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "workflow_test: failed to create temp dir for echo_module: %v\n", err)
		return 1
	}
	defer func() { _ = os.RemoveAll(integrationBinaryCleanupDir) }()

	bin := filepath.Join(integrationBinaryCleanupDir, "echo_module")
	// Path is relative to the features/workflow/ package directory where tests run.
	cmd := exec.Command("go", "build", "-o", bin, "./runtime/testdata/echo_module")
	if out, buildErr := cmd.CombinedOutput(); buildErr != nil {
		fmt.Fprintf(os.Stderr, "workflow_test: echo_module build failed (integration tests will be skipped): %s: %v\n", out, buildErr)
		// Non-fatal: unit tests in this package do not need the binary.
	} else {
		integrationEchoModuleBin = bin
	}

	return m.Run()
}
