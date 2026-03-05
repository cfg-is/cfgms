// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package testutil

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/initialization"
	"github.com/cfgis/cfgms/pkg/cert"
)

// PreInitControllerForTest creates a test CA and writes an initialization
// marker, satisfying the controller's first-run init guard (Story #410).
//
// certPath is the CertPath (parent directory for certificates).
// caPath is the Certificate.CAPath where the CA is stored.
// The cert manager stores the CA at certPath/ca/ which must match caPath.
func PreInitControllerForTest(t *testing.T, certPath, caPath string) {
	t.Helper()

	_, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath: certPath,
		CAConfig: &cert.CAConfig{
			Organization: "Test Org",
			Country:      "US",
			ValidityDays: 3650,
			StoragePath:  caPath,
		},
		LoadExistingCA: false,
	})
	require.NoError(t, err, "PreInitControllerForTest: failed to create CA")

	err = initialization.CreateLegacyMarker(caPath)
	require.NoError(t, err, "PreInitControllerForTest: failed to write init marker")
}
