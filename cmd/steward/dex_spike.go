// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/cfgis/cfgms/features/steward/dex"
)

// buildDexSpikeCommand returns the hidden `cfgms-steward dex-spike` diagnostic
// subcommand (Issue #2540). It runs the existing features/steward/dex acquisition
// collector (#2517) in-process and prints the SpikeReport — the throwaway
// measurement output the spike (#2516) was for. It is DIAGNOSTIC ONLY: it adds no
// persistence, no DNA/temporal/controller storage, and no production DEX / cfg /
// control-plane surface. It has no effect on normal service operation.
//
// ETW StartTrace requires a privileged context (the steward service's SYSTEM
// context or an elevated session); run under one, and with an active interactive
// desktop session so the Win32k/DWM providers emit events. Without ETW privilege
// the collector reports every provider as unreachable — a real result to record,
// but NOT the measurement this spike needs.
func buildDexSpikeCommand() *cobra.Command {
	var (
		windowSec int
		maxEvents int
		asJSON    bool
	)

	cmd := &cobra.Command{
		Use:    "dex-spike",
		Short:  "Diagnostic: run the DEX ETW/WMI acquisition spike and print the SpikeReport",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := dex.DefaultConfig()
			if windowSec > 0 {
				cfg.OverheadWindowSec = windowSec
			}
			if maxEvents > 0 {
				cfg.MaxEventsPerClass = maxEvents
			}

			// The spike only needs the report summary + counts; discard the raw
			// event stream rather than flooding stdout.
			collector := dex.NewCollector(cfg, dex.NewSink(io.Discard))

			// Bound the run generously: StartTrace + per-provider probes + the
			// overhead window + teardown.
			timeout := time.Duration(cfg.OverheadWindowSec+120) * time.Second
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			report, err := collector.Run(ctx)
			if err != nil {
				if errors.Is(err, dex.ErrPlatformNotSupported) {
					if _, werr := fmt.Fprintln(cmd.OutOrStdout(),
						"dex-spike: platform not supported — ETW/WMI acquisition requires Windows."); werr != nil {
						return fmt.Errorf("dex-spike write output: %w", werr)
					}
					return nil
				}
				return fmt.Errorf("dex-spike run: %w", err)
			}

			if asJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(report)
			}
			if _, werr := fmt.Fprint(cmd.OutOrStdout(), report.String()); werr != nil {
				return fmt.Errorf("dex-spike write output: %w", werr)
			}
			return nil
		},
	}

	cmd.Flags().IntVar(&windowSec, "overhead-window-sec", 0,
		"CPU overhead measurement window in seconds (0 = DefaultConfig)")
	cmd.Flags().IntVar(&maxEvents, "max-events-per-class", 0,
		"cap events collected per signal class (0 = DefaultConfig)")
	cmd.Flags().BoolVar(&asJSON, "json", false,
		"emit the raw SpikeReport as JSON instead of the human-readable summary")

	return cmd
}
