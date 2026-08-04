// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #2993: argon2id removed — passkey-only login. TestMain no longer needs
// to override cost parameters; it now provisions only the durable secret-store
// contract the API server requires at construction.
package api

import (
	"fmt"
	"os"
	"testing"

	pkgtestutil "github.com/cfgis/cfgms/pkg/testutil"
)

func TestMain(m *testing.M) {
	cleanup, err := pkgtestutil.ProvisionSecretsEnv("cfgms-api-test-secrets-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "provision api test secrets: %v\n", err)
		os.Exit(1)
	}

	code := m.Run()
	cleanup()
	os.Exit(code)
}
