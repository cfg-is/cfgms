// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"fmt"
	"os"
	"testing"

	pkgtestutil "github.com/cfgis/cfgms/pkg/testutil"
)

// TestMain provisions the same external-key and durable secret-data contracts
// required by production. Tests that exercise path isolation can still override
// CFGMS_SECRETS_REPO_PATH with t.Setenv.
func TestMain(m *testing.M) {
	cleanup, err := pkgtestutil.ProvisionSecretsEnv("cfgms-server-secrets-test-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "provision server test secrets: %v\n", err)
		os.Exit(1)
	}

	exitCode := m.Run()
	cleanup()
	os.Exit(exitCode)
}
