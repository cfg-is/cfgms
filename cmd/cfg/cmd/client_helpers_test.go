// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClientFromFlags_EmptyCACert_SystemPool(t *testing.T) {
	client, err := newClientFromFlags("https://example.com", "test-key", "", false)
	require.NoError(t, err)
	require.NotNil(t, client)

	transport := client.httpClient.Transport.(*http.Transport)
	assert.Nil(t, transport.TLSClientConfig.RootCAs)
	assert.False(t, transport.TLSClientConfig.InsecureSkipVerify)
}

func TestNewClientFromFlags_Insecure(t *testing.T) {
	client, err := newClientFromFlags("https://example.com", "test-key", "", true)
	require.NoError(t, err)
	require.NotNil(t, client)

	transport := client.httpClient.Transport.(*http.Transport)
	assert.True(t, transport.TLSClientConfig.InsecureSkipVerify)
}

func TestNewClientFromFlags_ValidCACert(t *testing.T) {
	certPEM := generateTestCACert(t)

	tmpFile, err := os.CreateTemp(t.TempDir(), "ca-cert-*.pem")
	require.NoError(t, err)
	_, err = tmpFile.Write(certPEM)
	require.NoError(t, err)
	require.NoError(t, tmpFile.Close())

	client, err := newClientFromFlags("https://example.com", "test-key", tmpFile.Name(), false)
	require.NoError(t, err)
	require.NotNil(t, client)

	transport := client.httpClient.Transport.(*http.Transport)
	assert.NotNil(t, transport.TLSClientConfig.RootCAs)
	assert.False(t, transport.TLSClientConfig.InsecureSkipVerify)
}

func TestNewClientFromFlags_MissingCACertFile(t *testing.T) {
	client, err := newClientFromFlags("https://example.com", "test-key", "/nonexistent/path/ca.pem", false)
	assert.Nil(t, client)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read CA certificate")
}
