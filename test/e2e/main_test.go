// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package e2e

import (
	"fmt"
	"os"
	"testing"

	"github.com/cfgis/cfgms/pkg/testutil"
)

// TestMain provisions the external secrets key this package's controllers require.
//
// Scenarios that stand up a controller in-process (scenarios_test.go and the
// steward cross-platform suites) fail at initialization without
// CFGMS_SECRETS_KEY_FILE — plaintext secret storage is prohibited. Container-based
// fleet scenarios get their key from the compose mount instead; this covers the
// in-process half.
func TestMain(m *testing.M) {
	cleanup, err := testutil.ProvisionSecretsEnv("cfgms-e2e-secrets-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "provision test secrets environment: %v\n", err)
		os.Exit(1)
	}
	code := m.Run()
	cleanup()
	os.Exit(code)
}
