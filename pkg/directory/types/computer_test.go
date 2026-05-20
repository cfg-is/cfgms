// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package types

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDirectoryComputer(t *testing.T) {
	t.Run("zero value is valid struct", func(t *testing.T) {
		c := DirectoryComputer{}
		assert.Equal(t, "", c.ID)
		assert.Equal(t, "", c.Name)
		assert.Equal(t, "", c.SAMAccountName)
		assert.Equal(t, "", c.OperatingSystem)
		assert.Equal(t, "", c.OperatingSystemVersion)
		assert.Nil(t, c.LastLogon)
		assert.False(t, c.Enabled)
	})

	t.Run("fully populated computer", func(t *testing.T) {
		now := time.Now()
		c := DirectoryComputer{
			ID:                     "guid-001",
			Name:                   "WORKSTATION01",
			SAMAccountName:         "WORKSTATION01$",
			DNSHostName:            "workstation01.example.com",
			DN:                     "CN=WORKSTATION01,OU=Computers,DC=example,DC=com",
			OU:                     "Computers",
			OperatingSystem:        "Windows 11 Pro",
			OperatingSystemVersion: "10.0 (22000)",
			Enabled:                true,
			LastLogon:              &now,
			Source:                 "activedirectory",
			ProviderAttributes:     map[string]interface{}{"userAccountControl": uint64(4096)},
		}

		assert.Equal(t, "guid-001", c.ID)
		assert.Equal(t, "WORKSTATION01", c.Name)
		assert.Equal(t, "WORKSTATION01$", c.SAMAccountName)
		assert.Equal(t, "workstation01.example.com", c.DNSHostName)
		assert.Equal(t, "CN=WORKSTATION01,OU=Computers,DC=example,DC=com", c.DN)
		assert.Equal(t, "Computers", c.OU)
		assert.Equal(t, "Windows 11 Pro", c.OperatingSystem)
		assert.Equal(t, "10.0 (22000)", c.OperatingSystemVersion)
		assert.True(t, c.Enabled)
		assert.NotNil(t, c.LastLogon)
		assert.Equal(t, "activedirectory", c.Source)
	})

	t.Run("disabled computer", func(t *testing.T) {
		c := DirectoryComputer{
			ID:      "guid-002",
			Name:    "DISABLED01",
			Enabled: false,
			Source:  "activedirectory",
		}
		assert.False(t, c.Enabled)
	})
}
