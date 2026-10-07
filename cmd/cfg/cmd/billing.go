// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

var (
	billingAPIURL      string
	billingTLSInsecure bool
	billingServerName  string
	billingJSONOutput  bool
)

// billingCmd is the parent of the root-level billing verbs.
var billingCmd = &cobra.Command{
	Use:   "billing",
	Short: "Read billing reports",
}

// billingReportCmd prints the root cross-MSP billing report.
var billingReportCmd = &cobra.Command{
	Use:   "report",
	Short: "Show the cross-MSP billing report (root operator)",
	Long: `Show the cross-MSP billing report from GET /api/v1/billing/report.

Each MSP is listed with its counts and metrics, and its clients under opaque
labels. No client name or tenant ID is shown. The report is available to the
root operator only; any other caller receives the server's refusal.

With --json the response body is printed as received.

Examples:
  cfg billing report
  cfg billing report --json`,
	Args: cobra.NoArgs,
	RunE: runBillingReport,
}

func init() {
	billingCmd.PersistentFlags().StringVar(&billingAPIURL, "api-url", "", "Controller REST API URL (env: CFGMS_API_URL)")
	billingCmd.PersistentFlags().BoolVar(&billingTLSInsecure, "tls-insecure", false, "Skip TLS verification (development only)")
	billingCmd.PersistentFlags().StringVar(&billingServerName, "server-name", "", "Override TLS server name for certificate verification")
	billingReportCmd.Flags().BoolVar(&billingJSONOutput, "json", false, "Emit JSON output instead of human-readable text")

	billingCmd.AddCommand(billingReportCmd)
	rootCmd.AddCommand(billingCmd)
}

// APIBillingMetrics are the per-MSP endpoint metrics of a billing report.
type APIBillingMetrics struct {
	EndpointsOnline     int            `json:"endpoints_online"`
	EndpointsOffline    int            `json:"endpoints_offline"`
	EndpointsPending    int            `json:"endpoints_pending"`
	EndpointsByPlatform map[string]int `json:"endpoints_by_platform"`
	EndpointsByVersion  map[string]int `json:"endpoints_by_version"`
}

// APIBillingOwn is an MSP's own (non-client) tech and endpoint counts.
type APIBillingOwn struct {
	TechCount     int `json:"tech_count"`
	EndpointCount int `json:"endpoint_count"`
}

// APIRootBillingClient is one client as root sees it: a label and sizes only.
type APIRootBillingClient struct {
	Label         string `json:"label"`
	EndpointCount int    `json:"endpoint_count"`
	TechCount     int    `json:"tech_count"`
}

// APIRootBillingMSP is one MSP row of the root billing report.
type APIRootBillingMSP struct {
	ID            string                 `json:"id"`
	Name          string                 `json:"name"`
	TechCount     int                    `json:"tech_count"`
	EndpointCount int                    `json:"endpoint_count"`
	ClientCount   int                    `json:"client_count"`
	Metrics       APIBillingMetrics      `json:"metrics"`
	MSPOwn        APIBillingOwn          `json:"msp_own"`
	Clients       []APIRootBillingClient `json:"clients"`
}

// APIRootBillingReport is the GET /api/v1/billing/report payload.
type APIRootBillingReport struct {
	MSPs []APIRootBillingMSP `json:"msps"`
}

// APITenantBillingClient is one named client in an MSP's own report.
type APITenantBillingClient struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	EndpointCount int    `json:"endpoint_count"`
	TechCount     int    `json:"tech_count"`
}

// APITenantBillingReport is the GET /api/v1/tenants/{id}/billing-report payload.
type APITenantBillingReport struct {
	ID            string                   `json:"id"`
	Name          string                   `json:"name"`
	TechCount     int                      `json:"tech_count"`
	EndpointCount int                      `json:"endpoint_count"`
	ClientCount   int                      `json:"client_count"`
	Metrics       APIBillingMetrics        `json:"metrics"`
	MSPOwn        APIBillingOwn            `json:"msp_own"`
	Clients       []APITenantBillingClient `json:"clients"`
}

// getBillingReportData GETs path and returns the envelope's data payload exactly as
// the server sent it. Any non-200 status is an error carrying the server's message.
func (c *APIClient) getBillingReportData(ctx context.Context, path string) (json.RawMessage, error) {
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("billing report request failed (HTTP %d)%s", resp.StatusCode, serverMessageSuffix(resp))
	}
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return envelope.Data, nil
}

// GetRootBillingReport calls GET /api/v1/billing/report.
func (c *APIClient) GetRootBillingReport(ctx context.Context) (*APIRootBillingReport, json.RawMessage, error) {
	raw, err := c.getBillingReportData(ctx, "/api/v1/billing/report")
	if err != nil {
		return nil, nil, err
	}
	var report APIRootBillingReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, nil, fmt.Errorf("failed to decode billing report: %w", err)
	}
	return &report, raw, nil
}

// GetTenantBillingReport calls GET /api/v1/tenants/{id}/billing-report.
func (c *APIClient) GetTenantBillingReport(ctx context.Context, tenantID string) (*APITenantBillingReport, json.RawMessage, error) {
	raw, err := c.getBillingReportData(ctx, "/api/v1/tenants/"+url.PathEscape(tenantID)+"/billing-report")
	if err != nil {
		return nil, nil, err
	}
	var report APITenantBillingReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, nil, fmt.Errorf("failed to decode billing report: %w", err)
	}
	return &report, raw, nil
}

func getBillingAPIClient() (*APIClient, error) {
	apiURL := billingAPIURL
	if apiURL == "" {
		apiURL = os.Getenv("CFGMS_API_URL")
	}
	tlsInsecure := billingTLSInsecure
	if !tlsInsecure {
		tlsInsecure = os.Getenv("CFGMS_TLS_INSECURE") == "true"
	}
	client, err := resolveSessionOrBundleClient(apiURL, tlsInsecure, billingServerName)
	if err != nil {
		return nil, fmt.Errorf("bundle lookup failed: %w", err)
	}
	if client != nil {
		return client, nil
	}
	// No cleartext default: billing data is root-operator only, so the
	// controller URL must be supplied explicitly when no session or bundle
	// resolves a client.
	if apiURL == "" {
		return nil, fmt.Errorf("controller API URL not configured: set --api-url or CFGMS_API_URL (or run 'cfg connect')")
	}
	return newClientFromFlags(apiURL, "", tlsInsecure)
}

// sortedCounts renders a count map as "key=n" pairs in key order.
func sortedCounts(m map[string]int) string {
	if len(m) == 0 {
		return "-"
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := ""
	for i, k := range keys {
		if i > 0 {
			out += " "
		}
		out += fmt.Sprintf("%s=%d", k, m[k])
	}
	return out
}

// writeBillingSummary writes the counts, metrics and own-counts lines shared by both reports.
func writeBillingSummary(w io.Writer, tech, endpoints, clients int, m APIBillingMetrics, own APIBillingOwn) {
	_, _ = fmt.Fprintf(w, "  techs: %d  endpoints: %d  clients: %d\n", tech, endpoints, clients)
	_, _ = fmt.Fprintf(w, "  online: %d  offline: %d  pending: %d\n", m.EndpointsOnline, m.EndpointsOffline, m.EndpointsPending)
	_, _ = fmt.Fprintf(w, "  platforms: %s\n", sortedCounts(m.EndpointsByPlatform))
	_, _ = fmt.Fprintf(w, "  versions: %s\n", sortedCounts(m.EndpointsByVersion))
	_, _ = fmt.Fprintf(w, "  msp own: techs %d, endpoints %d\n", own.TechCount, own.EndpointCount)
}

// renderRootBillingReport writes one block per MSP, then its clients by opaque label.
func renderRootBillingReport(w io.Writer, report *APIRootBillingReport) {
	if len(report.MSPs) == 0 {
		_, _ = fmt.Fprintln(w, "no tenants")
		return
	}
	for i, msp := range report.MSPs {
		if i > 0 {
			_, _ = fmt.Fprintln(w)
		}
		_, _ = fmt.Fprintf(w, "MSP %s (%s)\n", msp.Name, msp.ID)
		writeBillingSummary(w, msp.TechCount, msp.EndpointCount, msp.ClientCount, msp.Metrics, msp.MSPOwn)
		if len(msp.Clients) == 0 {
			continue
		}
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "  LABEL\tENDPOINTS\tTECHS")
		for _, c := range msp.Clients {
			_, _ = fmt.Fprintf(tw, "  %s\t%d\t%d\n", c.Label, c.EndpointCount, c.TechCount)
		}
		_ = tw.Flush()
	}
}

func runBillingReport(_ *cobra.Command, _ []string) error {
	client, err := getBillingAPIClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}
	report, raw, err := client.GetRootBillingReport(context.Background())
	if err != nil {
		return err
	}
	if billingJSONOutput {
		fmt.Printf("%s\n", raw)
		return nil
	}
	renderRootBillingReport(os.Stdout, report)
	return nil
}
