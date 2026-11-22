// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"
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
result per steward. Find catalog ids and their parameters with
'cfg osquery catalog'.

The first line is a summary: how many stewards the selector matched, how many
answered, how many were not reached and how many failed, and the time the query
ran. The stewards follow, grouped by outcome:

  answered     the steward returned a result, possibly no rows; its rows are
               printed
  not reached  the steward had no connection to the controller node that ran
               the query, so nothing was sent to it; shown with the time it
               was last seen, or "no check-in recorded" when it has never
               checked in
  failed       the query ended in an error on that steward; shown with the
               error

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

	res, err := client.QueryOsquery(context.Background(), args[0], params, osquerySelector)
	if err != nil {
		return err
	}
	return printOsqueryQueryResult(cmd.OutOrStdout(), res)
}

// Per-steward query outcomes as the controller reports them.
const (
	osqueryOutcomeAnswered     = "answered"
	osqueryOutcomeNotConnected = "not_connected"
	osqueryOutcomeFailed       = "failed"
)

// osqueryOutcome returns the steward's outcome. not_connected and failed are
// kept as sent. An error always wins over answered, so a result that carries an
// error is failed and its error is shown, never dropped. A missing or unknown
// outcome (an older controller) is derived the same way: an error means failed,
// otherwise answered.
func osqueryOutcome(r OsqueryStewardResult) string {
	switch r.Outcome {
	case osqueryOutcomeNotConnected, osqueryOutcomeFailed:
		return r.Outcome
	}
	if r.Error != "" {
		return osqueryOutcomeFailed
	}
	return osqueryOutcomeAnswered
}

// osqueryGroups holds the results split by outcome, each in server order.
type osqueryGroups struct {
	answered, notReached, failed []OsqueryStewardResult
}

func groupOsqueryResults(results []OsqueryStewardResult) osqueryGroups {
	var g osqueryGroups
	for _, r := range results {
		switch osqueryOutcome(r) {
		case osqueryOutcomeNotConnected:
			g.notReached = append(g.notReached, r)
		case osqueryOutcomeFailed:
			g.failed = append(g.failed, r)
		default:
			g.answered = append(g.answered, r)
		}
	}
	return g
}

// formatOsqueryTime renders t in UTC, RFC 3339, second precision.
func formatOsqueryTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

// osquerySummaryLine renders the first output line. The server's counts win
// when it sent a summary; otherwise the counts are derived from the groups and
// the line ends after the counts.
func osquerySummaryLine(summary *OsquerySummary, g osqueryGroups) string {
	s := OsquerySummary{
		Matched:      len(g.answered) + len(g.notReached) + len(g.failed),
		Answered:     len(g.answered),
		NotConnected: len(g.notReached),
		Failed:       len(g.failed),
	}
	if summary != nil {
		s = *summary
	}
	line := fmt.Sprintf("%d matched: %d answered, %d not reached, %d failed.",
		s.Matched, s.Answered, s.NotConnected, s.Failed)
	if s.QueriedAt != nil {
		line += " Queried at " + formatOsqueryTime(*s.QueriedAt) + "."
	}
	return line
}

func printOsqueryQueryResult(out io.Writer, res *OsqueryQueryResult) error {
	g := groupOsqueryResults(res.Results)
	_, _ = fmt.Fprintln(out, osquerySummaryLine(res.Summary, g))
	if len(res.Results) == 0 {
		_, _ = fmt.Fprintln(out, "No stewards matched the selector.")
		return nil
	}
	var queriedAt *time.Time
	if res.Summary != nil {
		queriedAt = res.Summary.QueriedAt
	}
	if err := printOsqueryAnswered(out, g.answered); err != nil {
		return err
	}
	if err := printOsqueryNotReached(out, g.notReached, queriedAt); err != nil {
		return err
	}
	return printOsqueryFailed(out, g.failed)
}

func printOsqueryAnswered(out io.Writer, results []OsqueryStewardResult) error {
	if len(results) == 0 {
		return nil
	}
	_, _ = fmt.Fprintf(out, "\nANSWERED (%d)\n", len(results))
	for _, r := range results {
		_, _ = fmt.Fprintf(out, "STEWARD %s\n", escapeControl(r.StewardID))
		if err := printOsqueryRows(out, r.Rows); err != nil {
			return err
		}
	}
	return nil
}

// printOsqueryRows prints one steward's rows as a table with sorted columns.
func printOsqueryRows(out io.Writer, rows []map[string]string) error {
	if len(rows) == 0 {
		_, _ = fmt.Fprintln(out, "  (no rows)")
		return nil
	}
	cols := map[string]struct{}{}
	for _, row := range rows {
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
	for _, row := range rows {
		vals := make([]string, len(names))
		for i, c := range names {
			vals[i] = escapeControl(row[c])
		}
		_, _ = fmt.Fprintln(w, "  "+strings.Join(vals, "\t"))
	}
	return w.Flush()
}

// osqueryAge renders d as a compact floor-unit age: seconds under a minute,
// minutes under an hour, hours under a day, otherwise days (e.g. 23m, 2d).
func osqueryAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int64(d/time.Second))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int64(d/time.Minute))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int64(d/time.Hour))
	default:
		return fmt.Sprintf("%dd", int64(d/(24*time.Hour)))
	}
}

// osqueryLastSeen describes when a not-reached steward last checked in, with
// its age at query time when that is known and not negative. A missing or zero
// last_seen means the steward has never checked in.
func osqueryLastSeen(lastSeen, queriedAt *time.Time) string {
	if lastSeen == nil || lastSeen.IsZero() {
		return "no check-in recorded"
	}
	desc := "last seen " + formatOsqueryTime(*lastSeen)
	if queriedAt == nil {
		return desc
	}
	age := queriedAt.Sub(*lastSeen)
	if age < 0 {
		return desc
	}
	return desc + " (" + osqueryAge(age) + " before the query)"
}

// printOsqueryNotReached prints the stewards that had no connection when the
// query ran. Their error text is deliberately not shown.
func printOsqueryNotReached(out io.Writer, results []OsqueryStewardResult, queriedAt *time.Time) error {
	if len(results) == 0 {
		return nil
	}
	_, _ = fmt.Fprintf(out, "\nNOT REACHED (%d)\n", len(results))
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	for _, r := range results {
		_, _ = fmt.Fprintf(w, "  %s\t%s\n", escapeControl(r.StewardID), osqueryLastSeen(r.LastSeen, queriedAt))
	}
	return w.Flush()
}

func printOsqueryFailed(out io.Writer, results []OsqueryStewardResult) error {
	if len(results) == 0 {
		return nil
	}
	_, _ = fmt.Fprintf(out, "\nFAILED (%d)\n", len(results))
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	for _, r := range results {
		_, _ = fmt.Fprintf(w, "  %s\terror: %s\n", escapeControl(r.StewardID), escapeControl(r.Error))
	}
	return w.Flush()
}
