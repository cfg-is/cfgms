// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package cmd implements the CLI commands for cfg
package cmd

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateRegistrationCode_Validation(t *testing.T) {
	// Save and restore package-level flag vars
	origTenantID := tenantID
	origControllerURL := controllerURL
	origGroup := group
	t.Cleanup(func() {
		tenantID = origTenantID
		controllerURL = origControllerURL
		group = origGroup
	})

	t.Run("valid host:port format accepted", func(t *testing.T) {
		tenantID = "test-tenant"
		controllerURL = "controller.example.com:4433"
		group = ""

		err := generateRegistrationCode()
		require.NoError(t, err)
	})

	t.Run("valid host:port with IP address accepted", func(t *testing.T) {
		tenantID = "test-tenant"
		controllerURL = "192.168.1.1:4433"
		group = ""

		err := generateRegistrationCode()
		require.NoError(t, err)
	})

	t.Run("bare hostname without port rejected", func(t *testing.T) {
		tenantID = "test-tenant"
		controllerURL = "controller.example.com"
		group = ""

		err := generateRegistrationCode()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "HOST:PORT")
	})

	t.Run("old mqtt:// scheme format rejected", func(t *testing.T) {
		tenantID = "test-tenant"
		controllerURL = "mqtt://controller.example.com:8883"
		group = ""

		err := generateRegistrationCode()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "HOST:PORT")
	})

	t.Run("empty controller URL rejected", func(t *testing.T) {
		tenantID = "test-tenant"
		controllerURL = ""
		group = ""

		err := generateRegistrationCode()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--controller-url is required")
	})

	t.Run("empty tenant ID rejected", func(t *testing.T) {
		tenantID = ""
		controllerURL = "controller:4433"
		group = ""

		err := generateRegistrationCode()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--tenant-id is required")
	})

	t.Run("host:port with empty host rejected", func(t *testing.T) {
		tenantID = "test-tenant"
		controllerURL = ":4433"
		group = ""

		err := generateRegistrationCode()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "HOST:PORT")
	})

	t.Run("host:port with empty port rejected", func(t *testing.T) {
		tenantID = "test-tenant"
		controllerURL = "controller:"
		group = ""

		err := generateRegistrationCode()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "HOST:PORT")
	})

	t.Run("error message includes example", func(t *testing.T) {
		tenantID = "test-tenant"
		controllerURL = "bad-format"
		group = ""

		err := generateRegistrationCode()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "controller.example.com:4433")
	})
}

func TestDecodeRegistrationCode(t *testing.T) {
	t.Run("valid registration code decoded", func(t *testing.T) {
		regCode := RegistrationCode{
			TenantID:      "test-tenant",
			ControllerURL: "controller.example.com:4433",
			Group:         "production",
			Version:       1,
		}
		jsonData, err := json.Marshal(regCode)
		require.NoError(t, err)
		encoded := base64.StdEncoding.EncodeToString(jsonData)

		err = decodeRegistrationCode([]string{encoded})
		require.NoError(t, err)
	})

	t.Run("no arguments rejected", func(t *testing.T) {
		err := decodeRegistrationCode([]string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "registration code is required")
	})

	t.Run("invalid base64 rejected", func(t *testing.T) {
		err := decodeRegistrationCode([]string{"not-valid-base64!!!"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid base64")
	})
}
