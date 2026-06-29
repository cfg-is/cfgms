// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

var connectionsListJSON bool

var connectionsCmd = &cobra.Command{
	Use:   "connections",
	Short: "Manage known controller connections",
	Long: `Commands for managing the local registry of known controller connections.

The connection registry stores non-secret metadata (name, controller URL, admin
identity, last used, unlock method) in the cfgms user config directory:

  Linux:   $XDG_CONFIG_HOME/cfgms/connections.json
  macOS:   ~/Library/Application Support/cfgms/connections.json
  Windows: %APPDATA%\cfgms\connections.json

No credential or token material is ever written to this file.`,
}

var connectionsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List registered controller connections",
	Long: `List all registered controller connections from the local registry.

Prints a table with name, URL, admin identity, and last-used timestamp for each
registered connection. Use --json to emit a JSON array instead.

Examples:
  cfg connections list
  cfg connections list --json`,
	RunE: runConnectionsList,
}

func init() {
	connectionsListCmd.Flags().BoolVar(&connectionsListJSON, "json", false, "Emit JSON array instead of human-readable table")
	connectionsCmd.AddCommand(connectionsListCmd)
}

func runConnectionsList(cmd *cobra.Command, args []string) error {
	reg, err := newConnectionRegistry()
	if err != nil {
		return fmt.Errorf("failed to open connection registry: %w", err)
	}

	entries, err := reg.List()
	if err != nil {
		return fmt.Errorf("failed to list connections: %w", err)
	}

	if connectionsListJSON {
		return json.NewEncoder(os.Stdout).Encode(entries)
	}

	if len(entries) == 0 {
		fmt.Println("No connections configured.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(w, "NAME\tURL\tIDENTITY\tLAST USED"); err != nil {
		return err
	}
	for _, e := range entries {
		lastUsed := "-"
		if !e.LastUsed.IsZero() {
			lastUsed = e.LastUsed.Format(time.RFC3339)
		}
		if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			e.Name,
			e.ControllerURL,
			e.AdminIdentity,
			lastUsed,
		); err != nil {
			return err
		}
	}
	return w.Flush()
}
