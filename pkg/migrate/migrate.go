// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package migrate provides thin step-based helpers for multi-store migrations.
//
// Step, Report, RunSteps, and PrintReport are a minimal utility layer for
// provider-agnostic migration work. They are not a generic migration engine:
// no resumability, no parallelism, no retry. Steps run sequentially; a
// failing step does not stop subsequent steps (non-fatal-warnings semantics).
//
// S3 (cfg secrets migrate) and S4 (cfg blob migrate) must follow the same
// flag/report convention established here: --from, --to, --dry-run, and a
// PrintReport-shaped summary.
package migrate

import (
	"context"
	"fmt"
	"io"
)

// Step is a named unit of migration work. Run performs the source read and,
// when dryRun is false, the destination write. When dryRun is true, Run must
// read from source and return the source record count without writing.
type Step struct {
	Name string
	Run  func(ctx context.Context, dryRun bool) (count int, err error)
}

// Report carries the result of a single Step execution.
type Report struct {
	Name  string
	Count int
	Err   error
}

// RunSteps executes each step sequentially. A failing step records its error
// in the corresponding Report and does not prevent subsequent steps from running.
func RunSteps(ctx context.Context, dryRun bool, steps []Step) []Report {
	reports := make([]Report, len(steps))
	for i, step := range steps {
		count, err := step.Run(ctx, dryRun)
		reports[i] = Report{Name: step.Name, Count: count, Err: err}
	}
	return reports
}

// PrintReport writes a human-readable per-step summary to w. Successful steps
// show their record count; failed steps show a WARNING line. A Total line
// sums counts from all successful steps.
func PrintReport(w io.Writer, reports []Report) {
	total := 0
	for _, r := range reports {
		if r.Err != nil {
			fmt.Fprintf(w, "  %-30s WARNING: %v\n", r.Name+":", r.Err)
		} else {
			fmt.Fprintf(w, "  %-30s %d records\n", r.Name+":", r.Count)
			total += r.Count
		}
	}
	fmt.Fprintf(w, "  %-30s %d records\n", "Total:", total)
}
