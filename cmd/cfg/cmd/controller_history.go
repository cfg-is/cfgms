// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/cfgis/cfgms/features/controller/cutover"
	"github.com/spf13/cobra"
)

var (
	historyLimit    int
	historyJSONMode bool
	historyPath     string
)

var controllerUpgradeHistoryCmd = &cobra.Command{
	Use:   "history",
	Short: "Show the last N controller upgrade events (Issue #1921)",
	Long: `cfg controller upgrade history reads the persistent
upgrade-event log and prints the most recent N events with timestamps,
event type, binary paths, and durations.

Default behaviour is human-readable text; --json emits the raw
UpgradeEvent stream so dashboards / alerting can consume it directly.

The log lives next to the cutover state file (default:
/var/lib/cfgms/cutover.history.jsonl on Linux,
%ProgramData%\cfgms\cutover.history.jsonl on Windows). Each cutover
appends one line per transition (staged, smoketest_passed/failed,
committed, rolled_back, quarantine_expired, validation_failed,
aborted, pruned).

Examples:
  cfg controller upgrade history
  cfg controller upgrade history --limit 5
  cfg controller upgrade history --json | jq '.[] | select(.event_type=="upgrade.rolled_back")'`,
	RunE: runControllerUpgradeHistory,
}

func init() {
	controllerUpgradeHistoryCmd.Flags().IntVar(&historyLimit, "limit", 10, "Maximum number of events to show (default 10)")
	controllerUpgradeHistoryCmd.Flags().BoolVar(&historyJSONMode, "json", false, "Emit JSON instead of human-readable text")
	controllerUpgradeHistoryCmd.Flags().StringVar(&historyPath, "history", defaultCutoverHistoryPath(), "Path to the cutover history file")

	controllerUpgradeCmd.AddCommand(controllerUpgradeHistoryCmd)
}

// defaultCutoverHistoryPath returns the OS-conventional history path.
// Mirrors defaultCutoverStatePath's location so the two files sit
// together in the controller's data directory.
func defaultCutoverHistoryPath() string {
	if isWindows() {
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, "cfgms", "cutover.history.jsonl")
	}
	return "/var/lib/cfgms/cutover.history.jsonl"
}

func runControllerUpgradeHistory(_ *cobra.Command, _ []string) error {
	h := cutover.NewHistory(historyPath)
	events, err := h.Recent(historyLimit)
	if err != nil {
		return fmt.Errorf("history: read %s: %w", historyPath, err)
	}
	if historyJSONMode {
		raw, _ := json.MarshalIndent(events, "", "  ")
		fmt.Println(string(raw))
		return nil
	}
	if len(events) == 0 {
		fmt.Printf("No upgrade events recorded at %s yet.\n", historyPath)
		return nil
	}
	fmt.Printf("Last %d upgrade event(s) (newest first) — %s:\n\n", len(events), historyPath)
	for i, ev := range events {
		printEvent(i+1, ev)
	}
	return nil
}

// printEvent is the human-readable rendering of one event. Kept
// compact so an operator can fit a screen-full at the default
// terminal width.
func printEvent(idx int, ev cutover.UpgradeEvent) {
	ts := ev.Timestamp.Format(time.RFC3339)
	fmt.Printf("%2d. %s  %s\n", idx, ts, ev.EventType)
	if ev.BinaryPath != "" {
		fmt.Printf("    binary:    %s\n", ev.BinaryPath)
	}
	if ev.CanonicalBinary != "" && ev.CanonicalBinary != ev.BinaryPath {
		fmt.Printf("    canonical: %s\n", ev.CanonicalBinary)
	}
	if ev.PreviousBinary != "" {
		fmt.Printf("    previous:  %s\n", ev.PreviousBinary)
	}
	if ev.DurationMS > 0 {
		fmt.Printf("    duration:  %dms\n", ev.DurationMS)
	}
	if ev.Reason != "" {
		fmt.Printf("    reason:    %s\n", ev.Reason)
	}
	fmt.Println()
}
