// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setHypervProfileFlags wires the module-level flags for a test run,
// authenticated via a generated admin mTLS bundle (mirrors setRoleFlags).
func setHypervProfileFlags(t *testing.T, url string) func() {
	t.Helper()
	bundleFilePath := filepath.Join(t.TempDir(), "admin.bundle.yaml")
	generateTestBundleFile(t, bundleFilePath, "https://placeholder.local:9443")

	origURL := hypervProfileURL
	origInsecure := hypervProfileTLSInsecure
	origBundlePath := bundlePath
	origNoBundle := noBundle
	hypervProfileURL = url
	hypervProfileTLSInsecure = true
	bundlePath = bundleFilePath
	noBundle = false
	return func() {
		hypervProfileURL = origURL
		hypervProfileTLSInsecure = origInsecure
		bundlePath = origBundlePath
		noBundle = origNoBundle
	}
}

// writeHypervProfileFile writes a minimal valid profile YAML file and returns its path.
func writeHypervProfileFile(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "profile.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`os_family: linux
answer_format: preseed
template: "hostname={{ .VMName }}"
enroll:
  registration_token_secret_key: hyperv/enroll/regtoken
  bundle_url: https://controller.example/bundle
`), 0600))
	return path
}

// TestHypervProfileCreateCmd_HappyPath verifies that runHypervProfileCreate
// sends the correct POST body and prints a success message.
func TestHypervProfileCreateCmd_HappyPath(t *testing.T) {
	var capturedBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/api/v1/hyperv/profiles", r.URL.Path)
		require.NoError(t, json.NewDecoder(r.Body).Decode(&capturedBody))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"name":          "debian-12-acme-corp",
				"os_family":     "linux",
				"answer_format": "preseed",
			},
		})
	}))
	defer srv.Close()

	cleanup := setHypervProfileFlags(t, srv.URL)
	defer cleanup()

	origFile := hypervProfileFilePath
	hypervProfileFilePath = writeHypervProfileFile(t)
	defer func() { hypervProfileFilePath = origFile }()

	var out bytes.Buffer
	hypervProfileCreateCmd.SetOut(&out)
	err := runHypervProfileCreate(hypervProfileCreateCmd, []string{"debian-12-acme-corp"})
	require.NoError(t, err)
	assert.Contains(t, out.String(), "debian-12-acme-corp")

	assert.Equal(t, "debian-12-acme-corp", capturedBody["name"])
	assert.Equal(t, "linux", capturedBody["os_family"])
	assert.Equal(t, "preseed", capturedBody["answer_format"])
	assert.Equal(t, "hostname={{ .VMName }}", capturedBody["template"])
	enroll, ok := capturedBody["enroll"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "hyperv/enroll/regtoken", enroll["registration_token_secret_key"])
}

// TestHypervProfileCreateCmd_MissingFile verifies that a missing profile file
// is reported without contacting the server.
func TestHypervProfileCreateCmd_MissingFile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not reach server when profile file is missing")
	}))
	defer srv.Close()

	cleanup := setHypervProfileFlags(t, srv.URL)
	defer cleanup()

	origFile := hypervProfileFilePath
	hypervProfileFilePath = "/nonexistent/path/profile.yaml"
	defer func() { hypervProfileFilePath = origFile }()

	err := runHypervProfileCreate(hypervProfileCreateCmd, []string{"my-profile"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read profile file")
}

// TestHypervProfileCreateCmd_InvalidProfileRejected verifies a 400 from the
// server (author-time rejection) is surfaced as an error, not swallowed.
func TestHypervProfileCreateCmd_InvalidProfileRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error": map[string]interface{}{"code": "INVALID_TEMPLATE", "message": "hyperv: invalid profile template"},
		})
	}))
	defer srv.Close()

	cleanup := setHypervProfileFlags(t, srv.URL)
	defer cleanup()

	origFile := hypervProfileFilePath
	hypervProfileFilePath = writeHypervProfileFile(t)
	defer func() { hypervProfileFilePath = origFile }()

	err := runHypervProfileCreate(hypervProfileCreateCmd, []string{"bad-profile"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create failed")
}

// TestHypervProfileLsCmd_HappyPath verifies that runHypervProfileLs prints a
// table with profile names.
func TestHypervProfileLsCmd_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "/api/v1/hyperv/profiles", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"profiles": []string{"debian-12-base", "windows-server-default"},
			},
		})
	}))
	defer srv.Close()

	cleanup := setHypervProfileFlags(t, srv.URL)
	defer cleanup()

	var out bytes.Buffer
	hypervProfileLsCmd.SetOut(&out)
	err := runHypervProfileLs(hypervProfileLsCmd, nil)
	require.NoError(t, err)

	output := out.String()
	assert.Contains(t, output, "debian-12-base")
	assert.Contains(t, output, "windows-server-default")
}

// TestHypervProfileLsCmd_Empty verifies that runHypervProfileLs prints a
// helpful message when empty.
func TestHypervProfileLsCmd_Empty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{"profiles": []string{}},
		})
	}))
	defer srv.Close()

	cleanup := setHypervProfileFlags(t, srv.URL)
	defer cleanup()

	var out bytes.Buffer
	hypervProfileLsCmd.SetOut(&out)
	err := runHypervProfileLs(hypervProfileLsCmd, nil)
	require.NoError(t, err)
	assert.Contains(t, out.String(), "No hyperv profiles found")
}

// TestHypervProfileShowCmd_HappyPath verifies that runHypervProfileShow prints
// profile details.
func TestHypervProfileShowCmd_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		assert.True(t, strings.HasSuffix(r.URL.Path, "/debian-12-acme-corp"), "path: %s", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"name":          "debian-12-acme-corp",
				"os_family":     "linux",
				"answer_format": "preseed",
				"template":      "hostname={{ .VMName }}",
			},
		})
	}))
	defer srv.Close()

	cleanup := setHypervProfileFlags(t, srv.URL)
	defer cleanup()

	var out bytes.Buffer
	hypervProfileShowCmd.SetOut(&out)
	err := runHypervProfileShow(hypervProfileShowCmd, []string{"debian-12-acme-corp"})
	require.NoError(t, err)

	output := out.String()
	assert.Contains(t, output, "debian-12-acme-corp")
	assert.Contains(t, output, "preseed")
	assert.Contains(t, output, "hostname={{ .VMName }}")
}

// TestHypervProfileShowCmd_NotFound verifies that runHypervProfileShow returns
// an error on 404.
func TestHypervProfileShowCmd_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	cleanup := setHypervProfileFlags(t, srv.URL)
	defer cleanup()

	err := runHypervProfileShow(hypervProfileShowCmd, []string{"missing"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestHypervProfileDeleteCmd_HappyPath verifies that runHypervProfileDelete
// sends DELETE and prints confirmation.
func TestHypervProfileDeleteCmd_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodDelete, r.Method)
		assert.True(t, strings.HasSuffix(r.URL.Path, "/debian-12-acme-corp"), "path: %s", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{"deleted": "debian-12-acme-corp"}})
	}))
	defer srv.Close()

	cleanup := setHypervProfileFlags(t, srv.URL)
	defer cleanup()

	var out bytes.Buffer
	hypervProfileDeleteCmd.SetOut(&out)
	err := runHypervProfileDelete(hypervProfileDeleteCmd, []string{"debian-12-acme-corp"})
	require.NoError(t, err)
	assert.Contains(t, out.String(), "debian-12-acme-corp")
}

// TestHypervProfileDeleteCmd_NotFound verifies that runHypervProfileDelete
// returns an error on 404.
func TestHypervProfileDeleteCmd_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	cleanup := setHypervProfileFlags(t, srv.URL)
	defer cleanup()

	err := runHypervProfileDelete(hypervProfileDeleteCmd, []string{"missing"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}
