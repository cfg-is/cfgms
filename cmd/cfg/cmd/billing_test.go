// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cfgis/cfgms/pkg/secrets/interfaces"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const rootBillingFixture = `{"msps":[{"id":"msp-a","name":"MSP A","tech_count":4,"endpoint_count":214,"client_count":2,` +
	`"metrics":{"endpoints_online":200,"endpoints_offline":10,"endpoints_pending":4,"endpoints_by_platform":{"windows":150,"linux":64},"endpoints_by_version":{"1.2.0":214}},` +
	`"msp_own":{"tech_count":1,"endpoint_count":4},` +
	`"clients":[{"label":"client-aaa111","endpoint_count":120,"tech_count":2},{"label":"client-bbb222","endpoint_count":90,"tech_count":1}]}]}`

// newBillingServer serves a fixed status and body for the given path.
func newBillingServer(t *testing.T, path string, status int, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet || r.URL.Path != path {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

func withBillingClient(t *testing.T, server *httptest.Server) {
	t.Helper()
	origURL, origInsecure, origJSON := billingAPIURL, billingTLSInsecure, billingJSONOutput
	t.Cleanup(func() {
		billingAPIURL, billingTLSInsecure, billingJSONOutput = origURL, origInsecure, origJSON
	})
	billingAPIURL = server.URL
	billingTLSInsecure = true
	billingJSONOutput = false
}

func TestBillingReport_JSONByteIdentical(t *testing.T) {
	server := newBillingServer(t, "/api/v1/billing/report", http.StatusOK,
		`{"data":`+rootBillingFixture+`,"timestamp":"2026-01-01T00:00:00Z"}`)
	defer server.Close()
	withBillingClient(t, server)
	billingJSONOutput = true

	out := captureStdout(t, func() { require.NoError(t, runBillingReport(billingReportCmd, nil)) })
	assert.Equal(t, rootBillingFixture+"\n", out)
}

func TestBillingReport_TextShowsLabelsNotClientNames(t *testing.T) {
	server := newBillingServer(t, "/api/v1/billing/report", http.StatusOK, `{"data":`+rootBillingFixture+`}`)
	defer server.Close()
	withBillingClient(t, server)

	out := captureStdout(t, func() { require.NoError(t, runBillingReport(billingReportCmd, nil)) })
	assert.Contains(t, out, "MSP A")
	assert.Regexp(t, `client-aaa111\s+120\s+2`, out)
	assert.Regexp(t, `client-bbb222\s+90\s+1`, out)
	assert.Contains(t, out, "windows=150")
	// Names that exist only in a tenant list fixture must never appear.
	for _, name := range []string{"Acme Dental", "Globex Legal"} {
		assert.NotContains(t, out, name)
	}
}

func TestBillingReport_Forbidden(t *testing.T) {
	server := newBillingServer(t, "/api/v1/billing/report", http.StatusForbidden,
		`{"error":{"code":"BILLING_ROOT_ONLY","message":"the cross-MSP billing report is available to the root operator only"}}`)
	defer server.Close()
	withBillingClient(t, server)

	var err error
	out := captureStdout(t, func() { err = runBillingReport(billingReportCmd, nil) })
	require.Error(t, err)
	assert.Contains(t, err.Error(), "available to the root operator only")
	assert.Empty(t, out)
}

func TestBillingReport_Empty(t *testing.T) {
	server := newBillingServer(t, "/api/v1/billing/report", http.StatusOK, `{"data":{"msps":[]}}`)
	defer server.Close()
	withBillingClient(t, server)

	out := captureStdout(t, func() { require.NoError(t, runBillingReport(billingReportCmd, nil)) })
	assert.Contains(t, out, "no tenants")
}

func TestBillingReport_NoLabelArgument(t *testing.T) {
	assert.Error(t, billingReportCmd.Args(billingReportCmd, []string{"client-aaa111"}))
	assert.True(t, strings.HasPrefix(tenantBillingCmd.Use, "billing"))
}

// TestGetBillingAPIClient_NoURLNoCleartextFallback verifies that with no
// --url, no CFGMS_API_URL, no bundle and no session, the billing client is
// not silently built against a cleartext http:// default controller URL.
func TestGetBillingAPIClient_NoURLNoCleartextFallback(t *testing.T) {
	tmpDir := t.TempDir()

	origURL, origInsecure := billingAPIURL, billingTLSInsecure
	origBundlePath, origNoBundle := bundlePath, noBundle
	origUserConfigDirFn, origSystemBundlePathFn := userConfigDirFn, systemBundlePathFn
	origSessionStoreFn := sessionStoreFn
	t.Cleanup(func() {
		billingAPIURL, billingTLSInsecure = origURL, origInsecure
		bundlePath, noBundle = origBundlePath, origNoBundle
		userConfigDirFn, systemBundlePathFn = origUserConfigDirFn, origSystemBundlePathFn
		sessionStoreFn = origSessionStoreFn
	})

	billingAPIURL = ""
	billingTLSInsecure = false
	bundlePath = ""
	noBundle = false
	userConfigDirFn = func() (string, error) { return filepath.Join(tmpDir, "no-userconfig"), nil }
	systemBundlePathFn = func() string { return filepath.Join(tmpDir, "no-system.bundle.yaml") }
	sessionStoreFn = func() (interfaces.SecretStore, error) { return nil, nil }
	t.Setenv("CFGMS_ADMIN_BUNDLE", "")
	t.Setenv("CFGMS_API_URL", "")
	t.Setenv("CFGMS_TLS_INSECURE", "")

	client, err := getBillingAPIClient()
	require.Error(t, err, "billing client must not fall back to a default controller URL")
	assert.Nil(t, client)
	assert.Contains(t, err.Error(), "--url")
	assert.Contains(t, err.Error(), "CFGMS_API_URL")
}
