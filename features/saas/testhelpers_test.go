// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package saas_test

import (
	"encoding/base64"
	"fmt"
	"os"
	"testing"

	"github.com/cfgis/cfgms/features/modules/m365/auth"
	saas "github.com/cfgis/cfgms/features/saas"
	stewardprovider "github.com/cfgis/cfgms/pkg/secrets/providers/steward"
	"github.com/stretchr/testify/require"
)

// newTestCredentialStore creates a SecretStoreCredentialStore backed by a real steward
// store in a temporary directory. Tests are skipped when /etc/machine-id is absent
// (required for OS-native key derivation on Linux).
func newTestCredentialStore(t *testing.T) auth.CredentialStore {
	t.Helper()
	if _, err := os.Stat("/etc/machine-id"); os.IsNotExist(err) {
		t.Skip("skipping: /etc/machine-id not available (required for platform key derivation on Linux)")
	}

	tmpDir := t.TempDir()
	provider := &stewardprovider.StewardProvider{}
	store, err := provider.CreateSecretStore(map[string]interface{}{
		"secrets_dir": tmpDir,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("failed to close secret store: %v", err)
		}
	})

	return saas.NewSecretStoreCredentialStore(store)
}

// newBenchCredentialStore creates a SecretStoreCredentialStore backed by a real steward
// store for use in benchmarks.
func newBenchCredentialStore(b *testing.B) auth.CredentialStore {
	b.Helper()
	if _, err := os.Stat("/etc/machine-id"); os.IsNotExist(err) {
		b.Skip("skipping: /etc/machine-id not available (required for platform key derivation on Linux)")
	}

	tmpDir := b.TempDir()
	provider := &stewardprovider.StewardProvider{}
	store, err := provider.CreateSecretStore(map[string]interface{}{
		"secrets_dir": tmpDir,
	})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		if err := store.Close(); err != nil {
			b.Errorf("failed to close secret store: %v", err)
		}
	})

	return saas.NewSecretStoreCredentialStore(store)
}

// makeTestJWT creates a minimal three-segment JWT with the given tid claim.
// The signature segment is a placeholder — signature verification is out of scope.
func makeTestJWT(tid string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"tid":%q,"sub":"user123"}`, tid)))
	return header + "." + payload + ".fakesignature"
}
