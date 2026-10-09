// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package cmd

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// nonControllerURLFlags names URL-style flags that are a different concept from the
// controller REST API URL and so are exempt from the "must be --url" rule.
var nonControllerURLFlags = map[string]bool{
	// Transport address stewards connect to, not the REST API endpoint.
	"controller-url": true,
}

// apiCallingCommands lists command paths (relative to the root, space separated)
// that call the controller REST API and must expose --url. A new API-calling
// command that registers any other URL-style flag fails the tree walk below.
var apiCallingCommands = []string{
	"installer upload",
	"installer download-url",
	"installer publish",
	"module list",
	"billing report",
	"config list",
	"config show",
	"config delete",
	"config diff",
	"config rollback",
	"config upload",
	"tenant list",
	"account create",
	"token list",
	"registration pending",
	"steward refresh list",
	"credential renew",
	"credential revoke-by-token",
	"credential request-signing-cert",
	"steward list",
	"role ls",
	"job status",
	"workflow list",
}

// removedFlag is the retired spelling of --url; no alias is kept.
const removedFlag = "api" + "-url"

func isURLStyleFlag(name string) bool {
	return name == "url" || strings.HasSuffix(name, "-url")
}

// TestControllerURLFlagIsNamedURL walks the whole command tree and fails if any
// command registers a controller-URL flag under a name other than "url".
func TestControllerURLFlagIsNamedURL(t *testing.T) {
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		c.Flags().VisitAll(func(f *pflag.Flag) {
			if !isURLStyleFlag(f.Name) || f.Name == "url" || nonControllerURLFlags[f.Name] {
				return
			}
			t.Errorf("command %q registers URL flag --%s; controller URL flags must be --url", c.CommandPath(), f.Name)
		})
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(rootCmd)
}

// TestAPICallingCommandsHaveURLFlag asserts every command on the API-calling list
// resolves a --url flag (local or inherited).
func TestAPICallingCommandsHaveURLFlag(t *testing.T) {
	for _, path := range apiCallingCommands {
		t.Run(path, func(t *testing.T) {
			c, _, err := rootCmd.Find(strings.Fields(path))
			require.NoError(t, err)
			require.NotNil(t, c)
			require.Equal(t, path, strings.TrimPrefix(c.CommandPath(), rootCmd.Name()+" "), "command path not found")
			assert.NotNil(t, c.Flag("url"), "%q must take --url", path)
			assert.Nil(t, c.Flag(removedFlag), "%q must not take the removed flag --%s", path, removedFlag)
		})
	}
}
