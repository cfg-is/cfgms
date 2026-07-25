// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #2993: argon2id removed — passkey-only login. TestMain no longer needs
// to override cost parameters. The file is retained as the package-level test entry
// point in case future TestMain logic is needed.
package api

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
