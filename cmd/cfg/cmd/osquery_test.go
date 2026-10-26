// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOsqueryCatalogCommand(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "/api/v1/osquery/catalog", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": []map[string]interface{}{
				{"id": "host_info", "params": []interface{}{}},
				{"id": "listening_ports", "params": []map[string]interface{}{
					{"name": "proto", "type": "enum", "allowed_values": []string{"tcp", "udp"}},
				}},
				{"id": "file_info", "params": []map[string]interface{}{{"name": "path", "type": "charset"}}},
			},
		})
	}))
	defer srv.Close()

	bundleFilePath := filepath.Join(t.TempDir(), "admin.bundle.yaml")
	generateTestBundleFile(t, bundleFilePath, "https://placeholder.local:9443")
	origURL, origInsecure, origBundle, origNoBundle := osqueryURL, osqueryTLSInsecure, bundlePath, noBundle
	osqueryURL, osqueryTLSInsecure, bundlePath, noBundle = srv.URL, true, bundleFilePath, false
	defer func() {
		osqueryURL, osqueryTLSInsecure, bundlePath, noBundle = origURL, origInsecure, origBundle, origNoBundle
	}()

	var out bytes.Buffer
	osqueryCatalogCmd.SetOut(&out)
	require.NoError(t, runOsqueryCatalog(osqueryCatalogCmd, nil))

	assert.Contains(t, out.String(), "host_info")
	assert.Contains(t, out.String(), "proto (enum: tcp|udp)")
	assert.Contains(t, out.String(), "path (charset)")
}
