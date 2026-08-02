// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package controller

import (
	"fmt"
	"os"
	"testing"

	pkgtestutil "github.com/cfgis/cfgms/pkg/testutil"
)

// TestMain provisions the durable secret-store contract the controller requires
// at construction: the audit manager's signing key is persisted through the
// secrets provider, which refuses to start without an external key file.
func TestMain(m *testing.M) {
	cleanup, err := pkgtestutil.ProvisionSecretsEnv("cfgms-unit-controller-secrets-test-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "provision controller test secrets: %v\n", err)
		os.Exit(1)
	}

	code := m.Run()
	cleanup()
	os.Exit(code)
}
