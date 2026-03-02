// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

//go:build windows

package steward

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDPAPIEncryptor_RoundTrip(t *testing.T) {
	enc, err := newPlatformEncryptor("")
	require.NoError(t, err)
	require.NotNil(t, enc)

	assert.Equal(t, "DPAPI", enc.Algorithm())

	testData := []byte("DPAPI test secret data")
	encrypted, err := enc.Encrypt(testData)
	require.NoError(t, err)
	assert.NotEqual(t, testData, encrypted)

	decrypted, err := enc.Decrypt(encrypted)
	require.NoError(t, err)
	assert.Equal(t, testData, decrypted)
}

func TestDPAPIEncryptor_EmptyInput(t *testing.T) {
	enc, err := newPlatformEncryptor("")
	require.NoError(t, err)

	_, err = enc.Encrypt(nil)
	assert.Error(t, err)

	_, err = enc.Encrypt([]byte{})
	assert.Error(t, err)

	_, err = enc.Decrypt(nil)
	assert.Error(t, err)

	_, err = enc.Decrypt([]byte{})
	assert.Error(t, err)
}
