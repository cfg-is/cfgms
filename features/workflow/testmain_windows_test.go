// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

//go:build windows

package workflow

import (
	"os"
	"testing"
)

// integrationEchoModuleBin is empty on Windows: the echo_module binary uses
// Unix sockets and cannot run on Windows. Integration tests that depend on it
// are skipped automatically when this is the empty string.
var integrationEchoModuleBin string

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
