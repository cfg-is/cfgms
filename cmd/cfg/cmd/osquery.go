// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

var (
	osqueryURL         string
	osqueryTLSCACert   string
	osqueryTLSInsecure bool
	osqueryServerName  string
)

// osqueryCmd is the parent command: cfg osquery ...
var osqueryCmd = &cobra.Command{
	Use:   "osquery",
	Short: "Work with the osquery query catalog on the controller",
}

// osqueryCatalogCmd implements cfg osquery catalog.
var osqueryCatalogCmd = &cobra.Command{
	Use:   "catalog",
	Short: "List osquery catalog entries and their parameters",
	Long: `List the osquery catalog entries the controller accepts, with each entry's
parameter names and types. Query text is never shown.

Examples:
  cfg osquery catalog --url https://controller.example.com --bundle /path/to/admin.bundle.yaml`,
	RunE: runOsqueryCatalog,
}

func init() {
	osqueryCatalogCmd.Flags().StringVar(&osqueryURL, "url", "", "Controller API URL (env: CFGMS_API_URL)")
	osqueryCatalogCmd.Flags().StringVar(&osqueryTLSCACert, "tls-ca-cert", "", "Path to CA certificate (env: CFGMS_TLS_CA_CERT)")
	osqueryCatalogCmd.Flags().BoolVar(&osqueryTLSInsecure, "tls-insecure", false, "Skip TLS verification (env: CFGMS_TLS_INSECURE)")
	osqueryCatalogCmd.Flags().StringVar(&osqueryServerName, "server-name", "", "Override TLS server name for certificate verification")

	osqueryCmd.AddCommand(osqueryCatalogCmd)
	rootCmd.AddCommand(osqueryCmd)
}

// getOsqueryClient returns an API client for osquery commands, mirroring getHypervProfileClient.
func getOsqueryClient() (*APIClient, error) {
	apiURL := osqueryURL
	if apiURL == "" {
		apiURL = os.Getenv("CFGMS_API_URL")
	}
	tlsInsecure := osqueryTLSInsecure
	if !tlsInsecure {
		tlsInsecure = os.Getenv("CFGMS_TLS_INSECURE") == "true"
	}
	return requireSessionOrBundleClient(apiURL, tlsInsecure, osqueryServerName)
}

func runOsqueryCatalog(cmd *cobra.Command, _ []string) error {
	client, err := getOsqueryClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	entries, err := client.ListOsqueryCatalog(context.Background())
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No osquery catalog entries found.")
		return nil
	}

	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "ID\tPARAMETERS")
	_, _ = fmt.Fprintln(w, "--\t----------")
	for _, e := range entries {
		params := make([]string, 0, len(e.Params))
		for _, p := range e.Params {
			desc := p.Name + " (" + p.Type
			if len(p.AllowedValues) > 0 {
				desc += ": " + strings.Join(p.AllowedValues, "|")
			}
			params = append(params, desc+")")
		}
		list := "-"
		if len(params) > 0 {
			list = strings.Join(params, ", ")
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\n", e.ID, list)
	}
	return w.Flush()
}
