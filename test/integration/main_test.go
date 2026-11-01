// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package integration

import (
	"fmt"
	"os"
	"testing"

	"github.com/cfgis/cfgms/pkg/testutil"
)

// TestMain provisions the external secrets key this package's controllers require.
//
// The controller refuses to initialize its durable audit signing key store without
// CFGMS_SECRETS_KEY_FILE — plaintext secret storage is prohibited. That contract is
// enforced in production code, so the tests must satisfy it the same way a real
// deployment does rather than by relaxing it: a real key file, generated fresh per
// run, removed on exit.
func TestMain(m *testing.M) {
	cleanup, err := testutil.ProvisionSecretsEnv("cfgms-integration-secrets-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "provision test secrets environment: %v\n", err)
		os.Exit(1)
	}
	code := m.Run()
	cleanup()
	os.Exit(code)
}
