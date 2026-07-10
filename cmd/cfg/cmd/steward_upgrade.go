// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

// upgradeWaitPollInterval is the delay between upgrade status polls in the --wait loop.
// Overridable in tests to avoid real sleeps.
var upgradeWaitPollInterval = 5 * time.Second

var (
	stewardUpgradeVersion     string
	stewardUpgradePlatform    string
	stewardUpgradeArch        string
	stewardUpgradeWait        bool
	stewardUpgradeWaitTimeout time.Duration
	stewardUpgradeID          string
	stewardUpgradeToVersion   string
	stewardUpgradeJSONOutput  bool
)

// stewardUpgradeCmd dispatches a steward binary upgrade to matching stewards.
var stewardUpgradeCmd = &cobra.Command{
	Use:   "upgrade <selector>",
	Short: "Upgrade steward binary on matching hosts",
	Long: `Dispatch a steward binary upgrade to all stewards matching the selector.

The selector identifies which stewards receive the upgrade command. The upgrade
is dispatched asynchronously by default; use --wait to block until completion.

Examples:
  # Upgrade a specific steward
  cfg steward upgrade id:steward-abc123 --version v0.5.12

  # Upgrade all stewards in a group with --wait
  cfg steward upgrade group:production --version v0.5.12 --wait

  # Upgrade with explicit platform
  cfg steward upgrade id:steward-abc123 --version v0.5.12 --platform linux --arch amd64`,
	Args: cobra.ExactArgs(1),
	RunE: runStewardUpgrade,
}

// stewardUpgradeStatusCmd shows per-steward upgrade status.
var stewardUpgradeStatusCmd = &cobra.Command{
	Use:   "status [selector]",
	Short: "Show upgrade status for stewards",
	Long: `Display per-steward upgrade status.

Pass a selector positional argument to query the most recent upgrade status for
each matching steward, or use --upgrade-id to query a specific upgrade record.

Examples:
  # Show status for a specific upgrade
  cfg steward upgrade status --upgrade-id abc123-upgrade-id

  # Show most recent upgrade status for matching stewards
  cfg steward upgrade status id:steward-abc123`,
	RunE: runStewardUpgradeStatus,
}

// stewardUpgradeRollbackCmd rolls back a dispatched upgrade.
var stewardUpgradeRollbackCmd = &cobra.Command{
	Use:   "rollback",
	Short: "Roll back a dispatched upgrade",
	Long: `Roll back a steward upgrade to a prior version.

Requires --upgrade-id to identify the specific upgrade record. Use --to-version
to specify the rollback target version (optional when --upgrade-id is provided).

Examples:
  # Roll back a specific upgrade
  cfg steward upgrade rollback --upgrade-id abc123-upgrade-id

  # Roll back to a specific version
  cfg steward upgrade rollback --upgrade-id abc123-upgrade-id --to-version v0.5.10`,
	RunE: runStewardUpgradeRollback,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

func runStewardUpgrade(cmd *cobra.Command, args []string) error {
	if stewardUpgradeVersion == "" {
		return fmt.Errorf("required flag --version was not set")
	}

	selector := args[0]

	client, err := getStewardClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	matches, err := resolveOrFailFast(context.Background(), client, selector)
	if err != nil {
		return err
	}
	if err := confirmMultiHost(matches, stewardYes); err != nil {
		return err
	}

	req := &APIDispatchUpgradeRequest{
		Selector: selector,
		Version:  stewardUpgradeVersion,
		Platform: stewardUpgradePlatform,
		Arch:     stewardUpgradeArch,
	}

	result, err := client.DispatchUpgrade(context.Background(), req)
	if err != nil {
		return err
	}

	if stewardUpgradeJSONOutput {
		return emitKeyedDispatchOutput(matches, map[string]interface{}{
			"upgrade_id":    result.UpgradeID,
			"steward_count": result.StewardCount,
		})
	}

	fmt.Printf("Upgrade id: %s\n", result.UpgradeID)
	fmt.Printf("Dispatched to: %d stewards\n", result.StewardCount)

	if stewardUpgradeWait {
		return waitForUpgrade(context.Background(), client, result.UpgradeID, stewardUpgradeWaitTimeout)
	}

	return nil
}

func runStewardUpgradeStatus(_ *cobra.Command, args []string) error {
	client, err := getStewardClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	var statusResp *APIUpgradeStatusResponse

	switch {
	case stewardUpgradeID != "":
		statusResp, err = client.GetUpgradeStatus(context.Background(), stewardUpgradeID)
	case len(args) > 0:
		statusResp, err = client.ListUpgradeStatusBySelector(context.Background(), args[0])
	default:
		return fmt.Errorf("requires a selector argument or --upgrade-id flag")
	}

	if err != nil {
		return err
	}

	if len(statusResp.Stewards) == 0 {
		fmt.Println("No upgrade records found.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(w, "STEWARD\tVERSION\tSTATUS\tCOMPLETED_AT"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "-------\t-------\t------\t------------"); err != nil {
		return err
	}
	for _, s := range statusResp.Stewards {
		if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", s.Device, s.Version, s.Status, s.CompletedAt); err != nil {
			return err
		}
	}
	return w.Flush()
}

func runStewardUpgradeRollback(_ *cobra.Command, _ []string) error {
	if stewardUpgradeID == "" && stewardUpgradeToVersion == "" {
		return fmt.Errorf("rollback requires --upgrade-id or --to-version")
	}

	if stewardUpgradeID == "" {
		return fmt.Errorf("rollback requires --upgrade-id; --to-version may only be combined with --upgrade-id to specify a target version")
	}

	client, err := getStewardClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	req := &APIRollbackRequest{
		ToVersion: stewardUpgradeToVersion,
	}

	result, err := client.RollbackUpgrade(context.Background(), stewardUpgradeID, req)
	if err != nil {
		return err
	}

	if len(result.Stewards) == 0 {
		fmt.Println("No stewards in rollback result.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(w, "DEVICE\tSTATUS"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "------\t------"); err != nil {
		return err
	}
	for _, s := range result.Stewards {
		if _, err := fmt.Fprintf(w, "%s\t%s\n", s.Device, s.Status); err != nil {
			return err
		}
	}
	return w.Flush()
}

// ---------------------------------------------------------------------------
// Wait / polling
// ---------------------------------------------------------------------------

// isUpgradeTerminal returns true when the per-steward status is a terminal state.
func isUpgradeTerminal(status string) bool {
	return status == "committed" || status == "rolled_back" || status == "failed"
}

// allUpgradeTerminal returns true when every steward in the status response has
// reached a terminal state.
func allUpgradeTerminal(stewards []APIUpgradeStewardStatus) bool {
	for _, s := range stewards {
		if !isUpgradeTerminal(s.Status) {
			return false
		}
	}
	return true
}

// waitForUpgrade polls GET /api/v1/stewards/upgrade/{upgradeID} every
// upgradeWaitPollInterval until all stewards reach a terminal state or the
// timeout elapses. Aborts immediately on the first 401 or 403 response.
// Returns non-nil error if any steward reached failed or rolled_back.
func waitForUpgrade(ctx context.Context, client *APIClient, upgradeID string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for {
		// GetUpgradeStatusWithHTTPStatus returns a non-nil error for 401/403,
		// causing an immediate abort without retry — satisfying the AC requirement.
		statusResp, _, err := client.GetUpgradeStatusWithHTTPStatus(ctx, upgradeID)
		if err != nil {
			return err
		}

		if allUpgradeTerminal(statusResp.Stewards) {
			return printUpgradeSummary(statusResp.Stewards)
		}

		if time.Now().After(deadline) {
			return fmt.Errorf("timed out after %s waiting for upgrade %s", timeout, upgradeID)
		}

		pending := countNonTerminal(statusResp.Stewards)
		fmt.Printf("Waiting... %d of %d stewards still in progress\n", pending, len(statusResp.Stewards))

		select {
		case <-time.After(upgradeWaitPollInterval):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// countNonTerminal returns the number of stewards that have not yet reached a
// terminal state.
func countNonTerminal(stewards []APIUpgradeStewardStatus) int {
	n := 0
	for _, s := range stewards {
		if !isUpgradeTerminal(s.Status) {
			n++
		}
	}
	return n
}

// printUpgradeSummary prints a tabular DEVICE/STATUS summary and returns an
// error if any steward reached failed or rolled_back.
func printUpgradeSummary(stewards []APIUpgradeStewardStatus) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(w, "DEVICE\tSTATUS"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "------\t------"); err != nil {
		return err
	}
	var hasFailure bool
	for _, s := range stewards {
		if _, err := fmt.Fprintf(w, "%s\t%s\n", s.Device, s.Status); err != nil {
			return err
		}
		if s.Status == "failed" || s.Status == "rolled_back" {
			hasFailure = true
		}
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if hasFailure {
		return fmt.Errorf("one or more stewards reached a failed or rolled_back state")
	}
	return nil
}
