// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const tenantBillingFixture = `{"id":"msp-a","name":"MSP A","tech_count":4,"endpoint_count":214,"client_count":1,` +
	`"metrics":{"endpoints_online":200,"endpoints_offline":10,"endpoints_pending":4,"endpoints_by_platform":{"windows":214},"endpoints_by_version":{}},` +
	`"msp_own":{"tech_count":1,"endpoint_count":4},` +
	`"clients":[{"id":"acme-dental","name":"Acme Dental","endpoint_count":210,"tech_count":3}]}`

func TestTenantBilling_TextShowsNamedClients(t *testing.T) {
	server := newBillingServer(t, "/api/v1/tenants/msp-a/billing-report", http.StatusOK, `{"data":`+tenantBillingFixture+`}`)
	defer server.Close()
	withTenantClient(t, server)

	out := captureStdout(t, func() { require.NoError(t, runTenantBilling(tenantBillingCmd, []string{"msp-a"})) })
	assert.Contains(t, out, "MSP A")
	assert.Regexp(t, `Acme Dental\s+acme-dental\s+210\s+3`, out)
}

func TestTenantBilling_JSONByteIdentical(t *testing.T) {
	server := newBillingServer(t, "/api/v1/tenants/msp-a/billing-report", http.StatusOK, `{"data":`+tenantBillingFixture+`}`)
	defer server.Close()
	withTenantClient(t, server)
	tenantJSONOutput = true

	out := captureStdout(t, func() { require.NoError(t, runTenantBilling(tenantBillingCmd, []string{"msp-a"})) })
	assert.Equal(t, tenantBillingFixture+"\n", out)
}

func TestTenantBilling_NotFound(t *testing.T) {
	server := newBillingServer(t, "/api/v1/tenants/ghost/billing-report", http.StatusNotFound,
		`{"error":{"code":"TENANT_NOT_FOUND","message":"tenant not found"}}`)
	defer server.Close()
	withTenantClient(t, server)

	var err error
	out := captureStdout(t, func() { err = runTenantBilling(tenantBillingCmd, []string{"ghost"}) })
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tenant not found")
	assert.Empty(t, out)
}

func TestTenantBilling_NoClients(t *testing.T) {
	server := newBillingServer(t, "/api/v1/tenants/msp-a/billing-report", http.StatusOK,
		`{"data":{"id":"msp-a","name":"MSP A","clients":[]}}`)
	defer server.Close()
	withTenantClient(t, server)

	out := captureStdout(t, func() { require.NoError(t, runTenantBilling(tenantBillingCmd, []string{"msp-a"})) })
	assert.Contains(t, out, "no clients")
}
