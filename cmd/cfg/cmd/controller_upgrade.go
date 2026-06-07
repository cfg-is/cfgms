// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/cfgis/cfgms/features/controller/cutover"
	"github.com/spf13/cobra"
)

// Flags / shared state for the cutover subcommands.
var (
	upgradeBinaryPath        string
	upgradeStatePath         string
	upgradeConfigPath        string
	upgradeCandidateAPIAddr  string
	upgradeCandidateTransAdr string
	upgradeCanonicalAPIAddr  string
	upgradeCanonicalTransAdr string
	upgradeQuarantineWindow  time.Duration
	upgradeSmoketestTimeout  time.Duration
	upgradeStatusJSON        bool
)

// controllerUpgradeCmd is the parent for the upgrade-flow subcommands.
var controllerUpgradeCmd = &cobra.Command{
	Use:   "upgrade",
	Short: "Blue/green upgrade flow for the local cfgms-controller (Issue #1920)",
	Long: `cfg controller upgrade orchestrates a blue/green controller upgrade
via the port-ownership-swap pattern.

Subcommands:
  upgrade              Stage a new binary, smoketest it, and cut over.
  upgrade status       Show which binary is canonical and which is in quarantine.
  upgrade rollback     Restore the previously-quarantined binary as canonical.

State is persisted to --state (default: /var/lib/cfgms/cutover.state.json on
Linux, %ProgramData%\cfgms\cutover.state.json on Windows). The operator
running these commands must have permission to spawn the controller binary.

Run --help on each subcommand for details.`,
}

var controllerUpgradeRunCmd = &cobra.Command{
	Use:   "run",
	Short: "Stage a new controller binary, smoketest, and cut over",
	Long: `Runs the full cutover orchestration synchronously:

  1. Validate the new binary exists and is executable.
  2. Spawn it on the candidate listen addresses for smoketesting.
  3. Probe its /healthz endpoint until it responds (or smoketest timeout).
  4. Drain the current canonical binary, wait for canonical ports to free,
     stop the smoketest-time candidate, and spawn a fresh instance of the
     new binary on the canonical ports.
  5. Probe the new canonical's readiness.
  6. Park the previous binary as the quarantined rollback target.

The whole flow typically completes in 5-15 seconds. Stewards experience
~1-3 seconds of API unavailability during the port handoff, well under
the 10s AC bound. Configurable timeouts at every stage.

Examples:
  cfg controller upgrade run --binary /opt/cfgms/cfgms-controller-v0.5.11 \
      --config /etc/cfgms/controller.cfg`,
	RunE: runControllerUpgrade,
}

var controllerUpgradeStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show which controller binary is canonical and which is quarantined",
	RunE:  runControllerUpgradeStatus,
}

var controllerUpgradeRollbackCmd = &cobra.Command{
	Use:   "rollback",
	Short: "Restore the previously-quarantined controller binary as canonical",
	RunE:  runControllerUpgradeRollback,
}

func init() {
	controllerUpgradeRunCmd.Flags().StringVar(&upgradeBinaryPath, "binary", "", "Path to the new cfgms-controller binary (required)")
	controllerUpgradeRunCmd.Flags().StringVar(&upgradeConfigPath, "config", "", "Path to controller.cfg (passed to spawned controllers; required)")
	controllerUpgradeRunCmd.Flags().StringVar(&upgradeStatePath, "state", defaultCutoverStatePath(), "Path to the cutover state file")
	controllerUpgradeRunCmd.Flags().StringVar(&upgradeCanonicalAPIAddr, "canonical-api-addr", ":8080", "Canonical API listen address")
	controllerUpgradeRunCmd.Flags().StringVar(&upgradeCanonicalTransAdr, "canonical-transport-addr", ":4433", "Canonical transport listen address")
	controllerUpgradeRunCmd.Flags().StringVar(&upgradeCandidateAPIAddr, "candidate-api-addr", ":8081", "Candidate API address used during smoketest")
	controllerUpgradeRunCmd.Flags().StringVar(&upgradeCandidateTransAdr, "candidate-transport-addr", ":4434", "Candidate transport address used during smoketest")
	controllerUpgradeRunCmd.Flags().DurationVar(&upgradeQuarantineWindow, "quarantine-window", time.Hour, "How long the previous binary stays available for rollback")
	controllerUpgradeRunCmd.Flags().DurationVar(&upgradeSmoketestTimeout, "smoketest-timeout", 30*time.Second, "Cap on the smoketest probe duration")
	_ = controllerUpgradeRunCmd.MarkFlagRequired("binary")
	_ = controllerUpgradeRunCmd.MarkFlagRequired("config")

	controllerUpgradeStatusCmd.Flags().StringVar(&upgradeStatePath, "state", defaultCutoverStatePath(), "Path to the cutover state file")
	controllerUpgradeStatusCmd.Flags().BoolVar(&upgradeStatusJSON, "json", false, "Emit JSON instead of human-readable text")

	controllerUpgradeRollbackCmd.Flags().StringVar(&upgradeStatePath, "state", defaultCutoverStatePath(), "Path to the cutover state file")
	controllerUpgradeRollbackCmd.Flags().StringVar(&upgradeConfigPath, "config", "", "Path to controller.cfg (passed to spawned controllers; required)")
	controllerUpgradeRollbackCmd.Flags().StringVar(&upgradeCanonicalAPIAddr, "canonical-api-addr", ":8080", "Canonical API listen address")
	controllerUpgradeRollbackCmd.Flags().StringVar(&upgradeCanonicalTransAdr, "canonical-transport-addr", ":4433", "Canonical transport listen address")
	controllerUpgradeRollbackCmd.Flags().StringVar(&upgradeCandidateAPIAddr, "candidate-api-addr", ":8081", "Candidate API address used during the rollback handoff")
	controllerUpgradeRollbackCmd.Flags().StringVar(&upgradeCandidateTransAdr, "candidate-transport-addr", ":4434", "Candidate transport address used during the rollback handoff")
	_ = controllerUpgradeRollbackCmd.MarkFlagRequired("config")

	controllerUpgradeCmd.AddCommand(controllerUpgradeRunCmd, controllerUpgradeStatusCmd, controllerUpgradeRollbackCmd)
	controllerCmd.AddCommand(controllerUpgradeCmd)
}

// defaultCutoverStatePath returns the OS-conventional cutover state
// path. Operators can override with --state for testing or non-standard
// installs.
func defaultCutoverStatePath() string {
	if isWindows() {
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, "cfgms", "cutover.state.json")
	}
	return "/var/lib/cfgms/cutover.state.json"
}

func isWindows() bool { return os.PathSeparator == '\\' }

// runControllerUpgrade is the entry point for `cfg controller upgrade run`.
func runControllerUpgrade(_ *cobra.Command, _ []string) error {
	if upgradeBinaryPath == "" {
		return fmt.Errorf("--binary is required")
	}
	if upgradeConfigPath == "" {
		return fmt.Errorf("--config is required")
	}
	info, err := os.Stat(upgradeBinaryPath)
	if err != nil {
		return fmt.Errorf("upgrade: --binary %s not accessible: %w", upgradeBinaryPath, err)
	}
	if info.IsDir() {
		return fmt.Errorf("upgrade: --binary %s is a directory, not an executable", upgradeBinaryPath)
	}

	previous, err := cutover.LoadPersistedState(upgradeStatePath)
	if err != nil {
		return fmt.Errorf("upgrade: load state: %w", err)
	}
	canonicalBinary := previous.CanonicalBinary
	if canonicalBinary == "" {
		// First-ever upgrade — no previous canonical recorded. Assume
		// the binary currently serving on the canonical ports is at the
		// same path as the one operators have been running by hand.
		// Use the new binary path as the fallback so the cutover can
		// still proceed; the orchestrator just won't have a meaningful
		// rollback target.
		canonicalBinary = upgradeBinaryPath
	}

	current := cutover.NewExecProcessHandle(canonicalBinary, upgradeConfigPath)
	orch, swap, err := newOrchestrator(current)
	if err != nil {
		return err
	}

	ctx, cancel := makeUpgradeContext(2 * time.Minute)
	defer cancel()
	if err := orch.Upgrade(ctx, upgradeBinaryPath); err != nil {
		return fmt.Errorf("upgrade failed: %w", err)
	}

	snap := orch.Status()
	// PortSwapTarget's LastPromoted is the freshly-spawned handle; the
	// orchestrator already promoted it via the SwapTarget contract.
	// Persist + report.
	if err := cutover.SavePersistedState(upgradeStatePath, cutover.SnapshotToPersisted(snap)); err != nil {
		return fmt.Errorf("upgrade succeeded but state persist failed: %w", err)
	}
	_ = swap // exposed for tests via newOrchestrator's return tuple
	fmt.Printf("controller upgrade complete\n")
	fmt.Printf("  canonical:   %s\n", snap.CanonicalBinary)
	fmt.Printf("  quarantined: %s (expires %s)\n", snap.QuarantinedBinary, snap.QuarantineExpiresAt.Format(time.RFC3339))
	return nil
}

// runControllerUpgradeStatus prints the current cutover state.
func runControllerUpgradeStatus(_ *cobra.Command, _ []string) error {
	ps, err := cutover.LoadPersistedState(upgradeStatePath)
	if err != nil {
		return fmt.Errorf("status: load state: %w", err)
	}
	if upgradeStatusJSON {
		raw, _ := json.MarshalIndent(ps, "", "  ")
		fmt.Println(string(raw))
		return nil
	}
	if ps.CanonicalBinary == "" {
		fmt.Println("No upgrade state recorded — fresh install or pre-cutover system.")
		return nil
	}
	fmt.Printf("State file:   %s\n", upgradeStatePath)
	fmt.Printf("Canonical:    %s\n", ps.CanonicalBinary)
	fmt.Printf("  Started at: %s\n", ps.CanonicalStartedAt.Format(time.RFC3339))
	if ps.QuarantinedBinary != "" {
		fmt.Printf("Quarantined:  %s\n", ps.QuarantinedBinary)
		fmt.Printf("  Started at: %s\n", ps.QuarantinedStartedAt.Format(time.RFC3339))
		fmt.Printf("  Expires:    %s\n", ps.QuarantineExpiresAt.Format(time.RFC3339))
	} else {
		fmt.Println("Quarantined:  (none — no rollback target available)")
	}
	return nil
}

// runControllerUpgradeRollback restores the quarantined binary as canonical.
func runControllerUpgradeRollback(_ *cobra.Command, _ []string) error {
	if upgradeConfigPath == "" {
		return fmt.Errorf("--config is required")
	}
	ps, err := cutover.LoadPersistedState(upgradeStatePath)
	if err != nil {
		return fmt.Errorf("rollback: load state: %w", err)
	}
	if ps.QuarantinedBinary == "" {
		return fmt.Errorf("rollback: no quarantined binary available — was a recent upgrade run?")
	}

	// Reconstruct an orchestrator whose canonical points at the
	// currently-serving binary (CanonicalBinary on disk) and whose
	// quarantined slot points at the rollback target.
	currentHandle := cutover.NewExecProcessHandle(ps.CanonicalBinary, upgradeConfigPath)
	orch, _, err := newOrchestrator(currentHandle)
	if err != nil {
		return err
	}
	// Seed quarantined slot via a direct Upgrade(quarantined) → no,
	// that would actually upgrade. Use SetQuarantined helper instead.
	quarantinedHandle := cutover.NewExecProcessHandle(ps.QuarantinedBinary, upgradeConfigPath)
	cutover.SetQuarantinedForRollback(orch, quarantinedHandle, ps.QuarantinedStartedAt, ps.QuarantineExpiresAt)

	ctx, cancel := makeUpgradeContext(1 * time.Minute)
	defer cancel()
	if err := orch.Rollback(ctx); err != nil {
		return fmt.Errorf("rollback failed: %w", err)
	}

	snap := orch.Status()
	if err := cutover.SavePersistedState(upgradeStatePath, cutover.SnapshotToPersisted(snap)); err != nil {
		return fmt.Errorf("rollback succeeded but state persist failed: %w", err)
	}
	fmt.Printf("controller rollback complete — canonical is now %s\n", snap.CanonicalBinary)
	return nil
}

// newOrchestrator wires the production cutover orchestrator with
// ExecProcessHandle-based spawning, PortSwapTarget swap, and
// HTTPSmoketester probing. Returns the orchestrator + the swap target
// (so callers can inspect LastPromoted if needed).
func newOrchestrator(initial *cutover.ExecProcessHandle) (*cutover.Orchestrator, *cutover.PortSwapTarget, error) {
	spawn := func(binaryPath string) cutover.ProcessHandle {
		h := cutover.NewExecProcessHandle(binaryPath, upgradeConfigPath)
		h.Stdout = os.Stdout
		h.Stderr = os.Stderr
		return h
	}
	smoketester := &cutover.HTTPSmoketester{
		ReadyTimeout:   upgradeSmoketestTimeout,
		RequestTimeout: 5 * time.Second,
		SkipTLSVerify:  true, // controller default cert is self-signed
	}
	swap := &cutover.PortSwapTarget{
		PortHandoffTimeout: 5 * time.Second,
		CandidateSpawner:   spawn,
		ReadinessProbe:     smoketester,
	}
	orch := cutover.NewOrchestrator(
		cutover.Config{
			CanonicalAPIAddr:       upgradeCanonicalAPIAddr,
			CanonicalTransportAddr: upgradeCanonicalTransAdr,
			CandidateAPIAddr:       upgradeCandidateAPIAddr,
			CandidateTransportAddr: upgradeCandidateTransAdr,
			QuarantineWindow:       upgradeQuarantineWindow,
			SmoketestTimeout:       upgradeSmoketestTimeout,
		},
		initial,
		nil, // no Validator yet — bundle signature verification is Issue #1882
		smoketester,
		swap,
		spawn,
	)
	// Story #1921: structured event emission for
	// `cfg controller upgrade history`.
	orch.History = cutover.NewHistory(defaultCutoverHistoryPath())
	return orch, swap, nil
}

func makeUpgradeContext(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}
