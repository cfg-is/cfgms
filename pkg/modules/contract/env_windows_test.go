// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

//go:build windows

package contract

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestModuleEnv_WindowsCaseInsensitiveMatch(t *testing.T) {
	parent := []string{
		`=C:=C:\work`,
		`=ExitCode=00000000`,
		"VENDOR_A_REGION=eu-1",
		"Path=C:\\Windows",
		"SECRET_THING=x",
	}
	res, err := BuildModuleEnv(parent, []string{"Vendor_A_Region"}, `\\.\pipe\m`)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{
		"VENDOR_A_REGION=eu-1",
		"Path=C:\\Windows",
		SocketEnvVar + `=\\.\pipe\m`,
	}, res.Env)
	assert.Empty(t, res.MissingDeclared)
}
