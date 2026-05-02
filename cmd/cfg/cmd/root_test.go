// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package cmd implements the CLI commands for cfg
package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/cfgis/cfgms/pkg/version"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVersionCmd_OutputContainsPkgVersion(t *testing.T) {
	buf := new(bytes.Buffer)
	versionCmd.SetOut(buf)
	versionCmd.SetErr(buf)
	t.Cleanup(func() { versionCmd.SetOut(nil); versionCmd.SetErr(nil) })

	versionCmd.Run(versionCmd, []string{})

	out := buf.String()
	require.NotEmpty(t, out, "version command produced no output")
	assert.True(t, strings.HasPrefix(out, "cfg "), "output must start with 'cfg ', got: %q", out)
	assert.Contains(t, out, version.Info(), "output must contain the string from pkg/version.Info()")
	assert.NotContains(t, out, "0.3.0-alpha", "output must not contain the old hardcoded version")
}

func TestRootCmd_ConfigFlagNotRegistered(t *testing.T) {
	flag := rootCmd.PersistentFlags().Lookup("config")
	assert.Nil(t, flag, "--config flag must not be registered on rootCmd")

	shortFlag := rootCmd.PersistentFlags().ShorthandLookup("c")
	assert.Nil(t, shortFlag, "-c shorthand must not be registered on rootCmd")
}
