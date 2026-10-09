// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const secretLiteral = "s3cr3t-literal-value"

func loadSecretConfig(t *testing.T, content string) (*Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "controller.cfg")
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))
	t.Setenv("CFGMS_STORAGE_CLUSTER_POSTGRES_DSN", "")
	t.Setenv("CFGMS_STORAGE_CLUSTER_SESSION_HMAC_KEY", "")
	t.Setenv("CFGMS_HA_MODE", "")
	return LoadWithPath(path)
}

// keyYAML renders a one-key config for a dotted path with the given scalar.
func keyYAML(path, value string) string {
	parts := strings.Split(path, ".")
	var b strings.Builder
	for i, p := range parts[:len(parts)-1] {
		b.WriteString(strings.Repeat("  ", i) + p + ":\n")
	}
	b.WriteString(strings.Repeat("  ", len(parts)-1) + parts[len(parts)-1] + ": " + value + "\n")
	return b.String()
}

func TestSecretBearingKeys_Table(t *testing.T) {
	t.Setenv("CFGMS_TEST_SECRET_VAL", "resolved-value")
	for _, spec := range SecretBearingKeys {
		path := spec.pathString()
		t.Run(path, func(t *testing.T) {
			_, err := loadSecretConfig(t, keyYAML(path, `"`+secretLiteral+`"`))
			require.Error(t, err, "literal must be refused")
			assert.Contains(t, err.Error(), path)
			assert.Contains(t, err.Error(), "accepted forms")
			assert.NotContains(t, err.Error(), secretLiteral)

			_, err = loadSecretConfig(t, keyYAML(path, `"${CFGMS_TEST_SECRET_VAL}"`))
			assert.NoError(t, err, "${VAR} must load")

			_, err = loadSecretConfig(t, keyYAML(path, `"${CFGMS_TEST_SECRET_VAL:-`+secretLiteral+`}"`))
			require.Error(t, err, "${VAR:-default} must be refused")
			assert.Contains(t, err.Error(), path)
			assert.NotContains(t, err.Error(), secretLiteral)
		})
	}
}

func TestSecretBearingKeys_DSNPasswords(t *testing.T) {
	t.Setenv("CFGMS_TEST_SECRET_VAL", "resolved-value")
	cases := []struct {
		name, dsn string
		ok        bool
	}{
		{"keyword literal", "host=pg user=u password=" + secretLiteral + " sslmode=require", false},
		{"keyword quoted literal", "host=pg password='" + secretLiteral + "'", false},
		{"keyword default form", "host=pg password=${CFGMS_TEST_SECRET_VAL:-" + secretLiteral + "}", false},
		{"keyword var", "host=pg user=u password=${CFGMS_TEST_SECRET_VAL} sslmode=disable", true},
		{"keyword no password", "host=pg user=u sslmode=verify-full", true},
		{"uri literal", "postgres://u:" + secretLiteral + "@pg:5432/db", false},
		{"uri query literal", "postgresql://u@pg/db?password=" + secretLiteral, false},
		{"uri var", "postgres://u:${CFGMS_TEST_SECRET_VAL}@pg:5432/db?sslmode=require", true},
		{"uri no password", "postgres://u@pg:5432/db", true},
		{"whole var", "${CFGMS_TEST_SECRET_VAL}", true},
		{"malformed", "host=pg password", false},
	}
	for _, key := range []string{"storage.cluster.postgres_dsn", "storage.config.dsn"} {
		for _, tc := range cases {
			t.Run(key+"/"+tc.name, func(t *testing.T) {
				_, err := loadSecretConfig(t, keyYAML(key, `"`+tc.dsn+`"`))
				if tc.ok {
					assert.NoError(t, err)
					return
				}
				require.Error(t, err)
				assert.Contains(t, err.Error(), key)
				assert.NotContains(t, err.Error(), secretLiteral)
			})
		}
	}
}

func TestSecretBearingKeys_AliasAndFlowRefused(t *testing.T) {
	cases := map[string]string{
		"anchor alias": "x-s: &s " + secretLiteral + "\nstorage:\n  cluster:\n    session_hmac_key: *s\n",
		"flow map":     "storage: {cluster: {session_hmac_key: " + secretLiteral + "}}\n",
		"merge key":    "base: &b {session_hmac_key: " + secretLiteral + "}\nstorage:\n  cluster:\n    <<: *b\n",
		"aliased map":  "c: &c {s3: {secret_access_key: " + secretLiteral + "}}\nstorage:\n  cluster: *c\n",
		"non-scalar":   "storage:\n  cluster:\n    session_hmac_key: [" + secretLiteral + "]\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := loadSecretConfig(t, content)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "literal secret refused")
			assert.NotContains(t, err.Error(), secretLiteral)
		})
	}
}

func TestSecretBearingKeys_EnvOverrideLiteralLoads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "controller.cfg")
	// A file with no literal at all, literal supplied only via the environment.
	require.NoError(t, os.WriteFile(path, []byte("log_level: info\n"), 0600))
	t.Setenv("CFGMS_STORAGE_CLUSTER_POSTGRES_DSN", "")
	t.Setenv("CFGMS_HA_MODE", "")
	t.Setenv("CFGMS_STORAGE_CLUSTER_SESSION_HMAC_KEY", secretLiteral)
	cfg, err := LoadWithPath(path)
	require.NoError(t, err)
	require.NotNil(t, cfg.Storage.Cluster)
	assert.Equal(t, secretLiteral, cfg.Storage.Cluster.SessionHMACKey)
}
