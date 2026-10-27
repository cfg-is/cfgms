// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"unicode"

	"github.com/spf13/cobra"
)

var (
	osqueryURL         string
	osqueryTLSCACert   string
	osqueryTLSInsecure bool
	osqueryServerName  string
	osquerySelector    string
	osqueryParams      []string
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

// osqueryQueryCmd implements cfg osquery query.
var osqueryQueryCmd = &cobra.Command{
	Use:   "query <catalog-id>",
	Short: "Run a catalog osquery against a fleet selector",
	Long: `Run a catalog osquery against the stewards matched by a selector and print the
rows per steward. A steward that failed is shown with its error, apart from a
steward that returned no rows. Find catalog ids and their parameters with
'cfg osquery catalog'.

The route requires a strong credential plus a presence check; the presence
challenge is answered through the same relay other presence-gated commands use.

Examples:
  cfg osquery query listening_ports --selector tenant:acme --param proto=tcp`,
	Args: cobra.ExactArgs(1),
	RunE: runOsqueryQuery,
}

func init() {
	osqueryCatalogCmd.Flags().StringVar(&osqueryURL, "url", "", "Controller API URL (env: CFGMS_API_URL)")
	osqueryCatalogCmd.Flags().StringVar(&osqueryTLSCACert, "tls-ca-cert", "", "Path to CA certificate (env: CFGMS_TLS_CA_CERT)")
	osqueryCatalogCmd.Flags().BoolVar(&osqueryTLSInsecure, "tls-insecure", false, "Skip TLS verification (env: CFGMS_TLS_INSECURE)")
	osqueryCatalogCmd.Flags().StringVar(&osqueryServerName, "server-name", "", "Override TLS server name for certificate verification")

	osqueryQueryCmd.Flags().StringVar(&osqueryURL, "url", "", "Controller API URL (env: CFGMS_API_URL)")
	osqueryQueryCmd.Flags().StringVar(&osqueryTLSCACert, "tls-ca-cert", "", "Path to CA certificate (env: CFGMS_TLS_CA_CERT)")
	osqueryQueryCmd.Flags().BoolVar(&osqueryTLSInsecure, "tls-insecure", false, "Skip TLS verification (env: CFGMS_TLS_INSECURE)")
	osqueryQueryCmd.Flags().StringVar(&osqueryServerName, "server-name", "", "Override TLS server name for certificate verification")
	osqueryQueryCmd.Flags().StringVar(&osquerySelector, "selector", "", "Fleet selector choosing the stewards to query (required)")
	osqueryQueryCmd.Flags().StringArrayVar(&osqueryParams, "param", nil, "Catalog parameter as k=v (repeatable)")
	_ = osqueryQueryCmd.MarkFlagRequired("selector")

	osqueryCmd.AddCommand(osqueryCatalogCmd)
	osqueryCmd.AddCommand(osqueryQueryCmd)
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

// parseOsqueryParams turns repeated k=v flags into a map. An empty value (k=)
// is kept as an empty string; a missing "=" or a repeated key is an error.
func parseOsqueryParams(args []string) (map[string]string, error) {
	params := make(map[string]string, len(args))
	for _, a := range args {
		k, v, ok := strings.Cut(a, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("invalid --param %q: expected k=v", a)
		}
		if _, dup := params[k]; dup {
			return nil, fmt.Errorf("parameter %s given twice", k)
		}
		params[k] = v
	}
	return params, nil
}

// escapeControl renders control characters (C0, C1, DEL, including ESC, tab and
// newline) as visible \xNN / \uNNNN escapes. Steward-originated strings are
// untrusted, so they must not reach the terminal raw.
func escapeControl(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r < 0x100 && unicode.IsControl(r):
			fmt.Fprintf(&b, "\\x%02x", r)
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r):
			fmt.Fprintf(&b, "\\u%04x", r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func escapeAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = escapeControl(s)
	}
	return out
}

func runOsqueryQuery(cmd *cobra.Command, args []string) error {
	if strings.TrimSpace(osquerySelector) == "" {
		return fmt.Errorf("--selector is required and must not be empty")
	}
	params, err := parseOsqueryParams(osqueryParams)
	if err != nil {
		return err
	}

	client, err := getOsqueryClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	results, err := client.QueryOsquery(context.Background(), args[0], params, osquerySelector)
	if err != nil {
		return err
	}
	if len(results) == 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No stewards matched the selector.")
		return nil
	}

	out := cmd.OutOrStdout()
	for _, r := range results {
		_, _ = fmt.Fprintf(out, "STEWARD %s\n", escapeControl(r.StewardID))
		if r.Error != "" {
			_, _ = fmt.Fprintf(out, "  error: %s\n", escapeControl(r.Error))
			continue
		}
		if len(r.Rows) == 0 {
			_, _ = fmt.Fprintln(out, "  (no rows)")
			continue
		}
		cols := map[string]struct{}{}
		for _, row := range r.Rows {
			for c := range row {
				cols[c] = struct{}{}
			}
		}
		names := make([]string, 0, len(cols))
		for c := range cols {
			names = append(names, c)
		}
		sort.Strings(names)
		w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		_, _ = fmt.Fprintln(w, "  "+strings.Join(escapeAll(names), "\t"))
		for _, row := range r.Rows {
			vals := make([]string, len(names))
			for i, c := range names {
				vals[i] = escapeControl(row[c])
			}
			_, _ = fmt.Fprintln(w, "  "+strings.Join(vals, "\t"))
		}
		if err := w.Flush(); err != nil {
			return err
		}
	}
	return nil
}
