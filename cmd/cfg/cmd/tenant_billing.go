// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

// tenantBillingCmd prints an MSP's own-subtree billing report.
var tenantBillingCmd = &cobra.Command{
	Use:   "billing <tenant-id>",
	Short: "Show the billing report for a tenant's subtree",
	Long: `Show the billing report for one tenant (typically an MSP) from
GET /api/v1/tenants/{id}/billing-report, with its clients by name.

Exits non-zero, printing the server's message and no report, when the tenant is
unknown or outside the caller's scope.

With --json the response body is printed as received.

Examples:
  cfg tenant billing msp-a
  cfg tenant billing msp-a --json`,
	Args: cobra.ExactArgs(1),
	RunE: runTenantBilling,
}

func init() {
	tenantBillingCmd.Flags().BoolVar(&tenantJSONOutput, "json", false, "Emit JSON output instead of human-readable text")
	tenantCmd.AddCommand(tenantBillingCmd)
}

// renderTenantBillingReport writes the MSP's summary block and its named clients.
func renderTenantBillingReport(w io.Writer, r *APITenantBillingReport) {
	_, _ = fmt.Fprintf(w, "Tenant %s (%s)\n", r.Name, r.ID)
	writeBillingSummary(w, r.TechCount, r.EndpointCount, r.ClientCount, r.Metrics, r.MSPOwn)
	if len(r.Clients) == 0 {
		_, _ = fmt.Fprintln(w, "no clients")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "  CLIENT\tID\tENDPOINTS\tTECHS")
	for _, c := range r.Clients {
		_, _ = fmt.Fprintf(tw, "  %s\t%s\t%d\t%d\n", c.Name, c.ID, c.EndpointCount, c.TechCount)
	}
	_ = tw.Flush()
}

func runTenantBilling(_ *cobra.Command, args []string) error {
	client, err := getTenantAPIClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}
	report, raw, err := client.GetTenantBillingReport(context.Background(), args[0])
	if err != nil {
		return err
	}
	if tenantJSONOutput {
		fmt.Printf("%s\n", raw)
		return nil
	}
	renderTenantBillingReport(os.Stdout, report)
	return nil
}
