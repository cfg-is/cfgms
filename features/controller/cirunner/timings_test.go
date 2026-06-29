// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package cirunner

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestProvisionTimings constructs a ProvisionTimings value with injected
// timestamps (never time.Now()) and asserts all three phase durations are
// computed correctly with no wall-clock dependency.
func TestProvisionTimings(t *testing.T) {
	// Fixed, injected anchor — deterministic, no time.Now().
	base := time.Date(2026, 6, 29, 12, 0, 0, 0, time.UTC)

	timings := ProvisionTimings{
		StartedAt:             base,
		TokenMintedAt:         base.Add(2 * time.Second),  // token-mint took 2s
		SyncTriggeredAt:       base.Add(5 * time.Second),  // sync-trigger 3s after mint
		EnrollmentConfirmedAt: base.Add(35 * time.Second), // enrollment 30s after sync
	}

	assert.Equal(t, 2*time.Second, timings.TokenMintDuration(), "token-mint phase")
	assert.Equal(t, 3*time.Second, timings.SyncTriggerDuration(), "sync-trigger phase")
	assert.Equal(t, 30*time.Second, timings.EnrollmentDuration(), "enrollment-confirmed phase")
	assert.Equal(t, 35*time.Second, timings.TotalDuration(), "total end-to-end")
	assert.True(t, timings.Valid(), "monotonic, fully-populated timings are valid")

	// The three phases sum to the total — no wall-clock drift, pure arithmetic.
	assert.Equal(t,
		timings.TotalDuration(),
		timings.TokenMintDuration()+timings.SyncTriggerDuration()+timings.EnrollmentDuration(),
		"phase durations must sum to the total",
	)

	// String summary is non-empty and mentions every phase.
	summary := timings.String()
	for _, want := range []string{"token-mint", "sync-trigger", "enrollment", "total"} {
		assert.Contains(t, summary, want)
	}
}

// TestProvisionTimings_Invalid covers non-monotonic and incomplete milestone
// sets — Valid() must reject them.
func TestProvisionTimings_Invalid(t *testing.T) {
	base := time.Date(2026, 6, 29, 12, 0, 0, 0, time.UTC)

	// Out-of-order: sync before token mint.
	nonMonotonic := ProvisionTimings{
		StartedAt:             base,
		TokenMintedAt:         base.Add(5 * time.Second),
		SyncTriggeredAt:       base.Add(2 * time.Second),
		EnrollmentConfirmedAt: base.Add(10 * time.Second),
	}
	assert.False(t, nonMonotonic.Valid(), "non-monotonic milestones are invalid")

	// Incomplete: enrollment never confirmed.
	incomplete := ProvisionTimings{
		StartedAt:       base,
		TokenMintedAt:   base.Add(2 * time.Second),
		SyncTriggeredAt: base.Add(5 * time.Second),
	}
	assert.False(t, incomplete.Valid(), "zero EnrollmentConfirmedAt is invalid")
}
