// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
)

const (
	// Bounds mirror the controller's handlers_tenant_crossing.go so a bad value is
	// refused before any request is made.
	crossingJustificationMinLen = 10
	crossingJustificationMaxLen = 1000
	crossingGrantMinDuration    = time.Minute
	crossingGrantMaxDuration    = 24 * time.Hour

	// crossingBreakGlassWindow is the fixed server-side window, shown in the confirm prompt.
	crossingBreakGlassWindow = "30 minutes"
)

var (
	tenantBreakGlassJustification string
	tenantGrantPrincipal          string
	tenantGrantDuration           string
	tenantCrossingYes             bool
)

var tenantBreakGlassCmd = &cobra.Command{
	Use:   "break-glass <tenant>",
	Short: "Invoke tenant-crossing break-glass into a tenant",
	Long: `Invoke a justified, audited break-glass elevation into a tenant.

Only root-scoped callers may use break-glass. The elevation window is fixed by the
controller at ` + crossingBreakGlassWindow + `; there is no duration flag. The justification
(10-1000 characters) is sent only in the X-Justification request header and is recorded
in the audit trail.

The command is step-up gated: when the controller asks for presence verification the
CLI completes it and replays the request.

It prints what it will do and asks for confirmation. --yes skips the prompt; without a
terminal and without --yes the command refuses and exits non-zero.

Examples:
  cfg tenant break-glass client-1 --justification "P1 outage, ticket INC-1234"
  cfg tenant break-glass client-1 --justification "P1 outage, ticket INC-1234" --yes --json`,
	Args: cobra.ExactArgs(1),
	RunE: runTenantBreakGlass,
}

var tenantGrantCmd = &cobra.Command{
	Use:   "grant <tenant>",
	Short: "Grant a support principal time-boxed access into a tenant",
	Long: `Authorise a different operator principal to cross into a tenant for a limited time.

Only an MSP administrator of the tenant may grant; root-scoped callers use break-glass
instead. --duration is a Go duration of whole minutes between 1m and 24h (for example
30m, 90m, 2h). The command is step-up gated.

It prints what it will do and asks for confirmation. --yes skips the prompt; without a
terminal and without --yes the command refuses and exits non-zero.

Examples:
  cfg tenant grant client-1 --principal support-op-7 --duration 90m
  cfg tenant grant client-1 --principal support-op-7 --duration 2h --yes --json`,
	Args: cobra.ExactArgs(1),
	RunE: runTenantGrant,
}

var tenantCrossingsCmd = &cobra.Command{
	Use:   "crossings <tenant>",
	Short: "List grants and break-glass sessions for a tenant",
	Long: `List the tenant-crossing records (access grants and break-glass sessions) for a tenant.

Only active crossings are listed; expired and ended ones are omitted. With --json the
response is printed exactly as received, including inactive records. This command is
read-only and never prompts.

Examples:
  cfg tenant crossings client-1
  cfg tenant crossings client-1 --json`,
	Args: cobra.ExactArgs(1),
	RunE: runTenantCrossings,
}

var tenantEndCrossingCmd = &cobra.Command{
	Use:   "end-crossing <tenant> <crossing-id>",
	Short: "End an active grant or break-glass session early",
	Long: `End an active tenant-crossing record before it expires.

A grant is ended by the MSP administrator of the tenant; a break-glass session is ended
by the root principal that invoked it or by an administrator of the tenant. The command
is step-up gated.

It prints what it will do and asks for confirmation. --yes skips the prompt; without a
terminal and without --yes the command refuses and exits non-zero.

Examples:
  cfg tenant end-crossing client-1 5b0c2f0e-1111-4222-8333-944455556666
  cfg tenant end-crossing client-1 5b0c2f0e-1111-4222-8333-944455556666 --yes`,
	Args: cobra.ExactArgs(2),
	RunE: runTenantEndCrossing,
}

func init() {
	tenantBreakGlassCmd.Flags().StringVar(&tenantBreakGlassJustification, "justification", "", "Reason for the elevation, 10-1000 characters (required)")
	_ = tenantBreakGlassCmd.MarkFlagRequired("justification")
	tenantGrantCmd.Flags().StringVar(&tenantGrantPrincipal, "principal", "", "Operator principal ID being granted access (required)")
	tenantGrantCmd.Flags().StringVar(&tenantGrantDuration, "duration", "", "Grant length: whole minutes as a Go duration, 1m to 24h (required)")
	_ = tenantGrantCmd.MarkFlagRequired("principal")
	_ = tenantGrantCmd.MarkFlagRequired("duration")

	for _, c := range []*cobra.Command{tenantBreakGlassCmd, tenantGrantCmd, tenantEndCrossingCmd} {
		c.Flags().BoolVarP(&tenantCrossingYes, "yes", "y", false, "Skip the confirmation prompt")
	}
	for _, c := range []*cobra.Command{tenantBreakGlassCmd, tenantGrantCmd, tenantCrossingsCmd, tenantEndCrossingCmd} {
		c.Flags().BoolVar(&tenantJSONOutput, "json", false, "Emit the response as received instead of human-readable text")
		tenantCmd.AddCommand(c)
	}
}

// validateCrossingJustification applies the controller's bounds to the trimmed value.
func validateCrossingJustification(j string) (string, error) {
	j = strings.TrimSpace(j)
	if len(j) < crossingJustificationMinLen || len(j) > crossingJustificationMaxLen {
		return "", fmt.Errorf("justification must be %d-%d characters (got %d)",
			crossingJustificationMinLen, crossingJustificationMaxLen, len(j))
	}
	return j, nil
}

// parseCrossingGrantMinutes parses --duration into whole minutes within 1m-24h.
func parseCrossingGrantMinutes(s string) (int, error) {
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid --duration %q: use a Go duration such as 30m, 90m or 2h", s)
	}
	if d < crossingGrantMinDuration || d > crossingGrantMaxDuration {
		return 0, fmt.Errorf("--duration must be between %s and %s", crossingGrantMinDuration, crossingGrantMaxDuration)
	}
	if d%time.Minute != 0 {
		return 0, fmt.Errorf("--duration must be a whole number of minutes")
	}
	return int(d / time.Minute), nil
}

// confirmCrossingAction prints what is about to happen and asks the operator to
// confirm. --yes skips the prompt; with no TTY and no --yes it refuses.
func confirmCrossingAction(summary string, yes bool) error {
	fmt.Fprintln(os.Stderr, summary)
	if yes {
		return nil
	}
	if !isatty.IsTerminal(os.Stdin.Fd()) {
		return fmt.Errorf("refusing to proceed without confirmation; pass --yes/-y, or run interactively")
	}
	fmt.Fprint(os.Stderr, "Proceed? [y/N]: ")
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		answer := strings.TrimSpace(strings.ToLower(scanner.Text()))
		if answer == "y" || answer == "yes" {
			return nil
		}
	}
	return fmt.Errorf("aborted by operator")
}

func crossingClient() (*APIClient, error) {
	client, err := getTenantAPIClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create API client: %w", err)
	}
	return client, nil
}

func runTenantBreakGlass(_ *cobra.Command, args []string) error {
	tenantID := args[0]
	justification, err := validateCrossingJustification(tenantBreakGlassJustification)
	if err != nil {
		return err
	}
	if err := confirmCrossingAction(fmt.Sprintf(
		"This will start a break-glass session into tenant %q for %s. The session is audited at critical severity.",
		tenantID, crossingBreakGlassWindow), tenantCrossingYes); err != nil {
		return err
	}
	client, err := crossingClient()
	if err != nil {
		return err
	}
	cr, raw, err := client.BreakGlassTenant(context.Background(), tenantID, justification)
	if err != nil {
		return err
	}
	if tenantJSONOutput {
		fmt.Printf("%s\n", raw)
		return nil
	}
	fmt.Printf("break-glass started: %s\n", cr.ID)
	fmt.Printf("Tenant:     %s\n", orDash(cr.TenantID))
	fmt.Printf("Expires at: %s\n", orDash(cr.ExpiresAt))
	return nil
}

func runTenantGrant(_ *cobra.Command, args []string) error {
	tenantID := args[0]
	minutes, err := parseCrossingGrantMinutes(tenantGrantDuration)
	if err != nil {
		return err
	}
	if strings.TrimSpace(tenantGrantPrincipal) == "" {
		return fmt.Errorf("--principal must not be empty")
	}
	if err := confirmCrossingAction(fmt.Sprintf(
		"This will grant principal %q access into tenant %q for %d minute(s).",
		tenantGrantPrincipal, tenantID, minutes), tenantCrossingYes); err != nil {
		return err
	}
	client, err := crossingClient()
	if err != nil {
		return err
	}
	cr, raw, err := client.CreateTenantAccessGrant(context.Background(), tenantID,
		&APICrossingGrantRequest{PrincipalID: tenantGrantPrincipal, DurationMinutes: minutes})
	if err != nil {
		return err
	}
	if tenantJSONOutput {
		fmt.Printf("%s\n", raw)
		return nil
	}
	fmt.Printf("access grant created: %s\n", cr.ID)
	fmt.Printf("Tenant:     %s\n", orDash(cr.TenantID))
	fmt.Printf("Principal:  %s\n", orDash(cr.PrincipalID))
	fmt.Printf("Expires at: %s\n", orDash(cr.ExpiresAt))
	return nil
}

// crossingIsActive reports whether the record is unrevoked and unexpired at now.
func crossingIsActive(c APITenantCrossing, now time.Time) bool {
	if c.RevokedAt != nil {
		return false
	}
	exp, err := time.Parse(time.RFC3339Nano, c.ExpiresAt)
	if err != nil {
		return false
	}
	return exp.After(now)
}

// renderCrossings writes the active crossings as a table, or an explicit line when none.
func renderCrossings(w io.Writer, list []APITenantCrossing, now time.Time) {
	var active []APITenantCrossing
	for _, c := range list {
		if crossingIsActive(c, now) {
			active = append(active, c)
		}
	}
	if len(active) == 0 {
		_, _ = fmt.Fprintln(w, "no active crossings")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "ID\tKIND\tPRINCIPAL\tGRANTED BY\tEXPIRES AT")
	for _, c := range active {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", c.ID, orDash(c.Kind), orDash(c.PrincipalID), orDash(c.GrantedBy), orDash(c.ExpiresAt))
	}
	_ = tw.Flush()
}

func runTenantCrossings(_ *cobra.Command, args []string) error {
	client, err := crossingClient()
	if err != nil {
		return err
	}
	list, raw, err := client.ListTenantCrossings(context.Background(), args[0])
	if err != nil {
		return err
	}
	if tenantJSONOutput {
		fmt.Printf("%s\n", raw)
		return nil
	}
	renderCrossings(os.Stdout, list, time.Now())
	return nil
}

func runTenantEndCrossing(_ *cobra.Command, args []string) error {
	tenantID, crossingID := args[0], args[1]
	if err := confirmCrossingAction(fmt.Sprintf(
		"This will end crossing %q on tenant %q immediately.", crossingID, tenantID), tenantCrossingYes); err != nil {
		return err
	}
	client, err := crossingClient()
	if err != nil {
		return err
	}
	cr, raw, err := client.EndTenantCrossing(context.Background(), tenantID, crossingID)
	if err != nil {
		return err
	}
	if tenantJSONOutput {
		fmt.Printf("%s\n", raw)
		return nil
	}
	fmt.Printf("crossing ended: %s\n", cr.ID)
	return nil
}
