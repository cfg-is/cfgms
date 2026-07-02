// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package migrate_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/migrate"
)

// TestRunSteps_DryRunSkipsWritePath verifies the dry-run contract:
// each step's read logic is invoked (returning source counts) while the
// write path is not reached when dryRun is true. A subsequent live run
// against the same source must produce identical counts.
func TestRunSteps_DryRunSkipsWritePath(t *testing.T) {
	ctx := context.Background()

	writeCount := 0
	steps := []migrate.Step{
		{
			Name: "config_store",
			Run: func(ctx context.Context, dryRun bool) (int, error) {
				if !dryRun {
					writeCount++
				}
				return 3, nil
			},
		},
		{
			Name: "tenant_store",
			Run: func(ctx context.Context, dryRun bool) (int, error) {
				if !dryRun {
					writeCount++
				}
				return 2, nil
			},
		},
	}

	// Dry run: read-only, no writes, counts reflect source data.
	dryReports := migrate.RunSteps(ctx, true, steps)
	require.Len(t, dryReports, 2)
	assert.Equal(t, 0, writeCount, "dry-run must not reach write path")
	assert.Equal(t, "config_store", dryReports[0].Name)
	assert.Equal(t, 3, dryReports[0].Count, "dry-run must report source record count")
	assert.NoError(t, dryReports[0].Err)
	assert.Equal(t, "tenant_store", dryReports[1].Name)
	assert.Equal(t, 2, dryReports[1].Count, "dry-run must report source record count")
	assert.NoError(t, dryReports[1].Err)

	// Live run: same counts as dry run, write path is reached.
	liveReports := migrate.RunSteps(ctx, false, steps)
	require.Len(t, liveReports, 2)
	assert.Equal(t, 2, writeCount, "live run must reach write path for each step")
	assert.Equal(t, dryReports[0].Count, liveReports[0].Count,
		"live run count must match dry-run count for config_store")
	assert.Equal(t, dryReports[1].Count, liveReports[1].Count,
		"live run count must match dry-run count for tenant_store")
}

// TestRunSteps_FailingStepContinues verifies that a step error does not
// prevent subsequent steps from executing — matching the non-fatal-warnings
// semantics of the inline git migration fallback.
func TestRunSteps_FailingStepContinues(t *testing.T) {
	ctx := context.Background()
	secondRan := false

	steps := []migrate.Step{
		{
			Name: "failing_step",
			Run: func(ctx context.Context, dryRun bool) (int, error) {
				return 0, errors.New("simulated step failure")
			},
		},
		{
			Name: "succeeding_step",
			Run: func(ctx context.Context, dryRun bool) (int, error) {
				secondRan = true
				return 5, nil
			},
		},
	}

	reports := migrate.RunSteps(ctx, false, steps)
	require.Len(t, reports, 2)
	assert.Error(t, reports[0].Err, "failing step must record its error")
	assert.True(t, secondRan, "succeeding step must run even after a prior failure")
	assert.NoError(t, reports[1].Err)
	assert.Equal(t, 5, reports[1].Count)
}

// TestPrintReport_OutputFormat verifies that PrintReport emits per-step lines
// and a Total line that sums only successful steps.
func TestPrintReport_OutputFormat(t *testing.T) {
	reports := []migrate.Report{
		{Name: "config_store", Count: 7, Err: nil},
		{Name: "token_store", Count: 0, Err: errors.New("listing failed")},
		{Name: "tenant_store", Count: 3, Err: nil},
	}

	var b strings.Builder
	migrate.PrintReport(&b, reports)
	out := b.String()

	assert.Contains(t, out, "config_store", "must include config_store step")
	assert.Contains(t, out, "7 records", "must show count for config_store")
	assert.Contains(t, out, "WARNING", "must flag the failed token_store step")
	assert.Contains(t, out, "listing failed", "must include error message")
	assert.Contains(t, out, "tenant_store", "must include tenant_store step")
	assert.Contains(t, out, "Total:", "must include a Total line")
	// Total must be 7+3=10 (token_store failed, excluded from total).
	assert.Contains(t, out, "10 records", "Total must sum only successful step counts")
}
