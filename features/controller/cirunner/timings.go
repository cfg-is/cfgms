// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package cirunner holds controller-side helpers for the CI-runner provisioning
// de-risking spike (epic #565). It is plain data + functions — not a central
// provider and not a module.
package cirunner

import (
	"fmt"
	"time"
)

// ProvisionTimings records the wall-clock milestones of one CI-runner
// provisioning sequence so the de-risking spike can measure each phase:
//
//	StartedAt ──► TokenMintedAt ──► SyncTriggeredAt ──► EnrollmentConfirmedAt
//	          token-mint        sync-trigger        enrollment-confirmed
//
// Timestamps are injected by the caller (recorded as each milestone is reached)
// rather than read from time.Now() inside the duration math, so the phase
// computations are deterministic and unit-testable with no wall-clock
// dependency.
type ProvisionTimings struct {
	// StartedAt is when provisioning began (before token mint).
	StartedAt time.Time
	// TokenMintedAt is when the registration token was minted.
	TokenMintedAt time.Time
	// SyncTriggeredAt is when the config-sync to the steward was triggered.
	SyncTriggeredAt time.Time
	// EnrollmentConfirmedAt is when the github_runner module first reported the
	// runner service enrolled and running.
	EnrollmentConfirmedAt time.Time
	// CheckpointCreatedAt is when a Hyper-V checkpoint of the enrolled runner
	// VM was taken. Optional bonus measurement — zero when not captured.
	CheckpointCreatedAt time.Time
	// CheckpointRevertedAt is when the checkpoint restore completed. Optional
	// bonus measurement — zero when not captured.
	CheckpointRevertedAt time.Time
}

// TokenMintDuration is the time spent minting the registration token
// (StartedAt → TokenMintedAt).
func (t ProvisionTimings) TokenMintDuration() time.Duration {
	return t.TokenMintedAt.Sub(t.StartedAt)
}

// SyncTriggerDuration is the time from token mint to config-sync trigger
// (TokenMintedAt → SyncTriggeredAt).
func (t ProvisionTimings) SyncTriggerDuration() time.Duration {
	return t.SyncTriggeredAt.Sub(t.TokenMintedAt)
}

// EnrollmentDuration is the time from config-sync trigger to enrollment
// confirmation (SyncTriggeredAt → EnrollmentConfirmedAt) — the wait-for-runner
// phase.
func (t ProvisionTimings) EnrollmentDuration() time.Duration {
	return t.EnrollmentConfirmedAt.Sub(t.SyncTriggeredAt)
}

// TotalDuration is the end-to-end provisioning time
// (StartedAt → EnrollmentConfirmedAt).
func (t ProvisionTimings) TotalDuration() time.Duration {
	return t.EnrollmentConfirmedAt.Sub(t.StartedAt)
}

// CheckpointCreateDuration is the time from enrollment confirmation to the
// Hyper-V checkpoint being taken (EnrollmentConfirmedAt → CheckpointCreatedAt).
func (t ProvisionTimings) CheckpointCreateDuration() time.Duration {
	return t.CheckpointCreatedAt.Sub(t.EnrollmentConfirmedAt)
}

// CheckpointRevertDuration is the time to restore the checkpoint
// (CheckpointCreatedAt → CheckpointRevertedAt).
func (t ProvisionTimings) CheckpointRevertDuration() time.Duration {
	return t.CheckpointRevertedAt.Sub(t.CheckpointCreatedAt)
}

// Valid reports whether the milestones are monotonically non-decreasing and
// all set — i.e. the three phase durations are non-negative and meaningful.
func (t ProvisionTimings) Valid() bool {
	if t.StartedAt.IsZero() || t.TokenMintedAt.IsZero() ||
		t.SyncTriggeredAt.IsZero() || t.EnrollmentConfirmedAt.IsZero() {
		return false
	}
	return !t.TokenMintedAt.Before(t.StartedAt) &&
		!t.SyncTriggeredAt.Before(t.TokenMintedAt) &&
		!t.EnrollmentConfirmedAt.Before(t.SyncTriggeredAt)
}

// String renders a one-line summary of the three phases and the total, for the
// spike's provisioning report. When both optional checkpoint milestones are
// set, the checkpoint create/revert durations are appended.
func (t ProvisionTimings) String() string {
	s := fmt.Sprintf(
		"cirunner provisioning: token-mint=%s sync-trigger=%s enrollment=%s total=%s",
		t.TokenMintDuration(), t.SyncTriggerDuration(), t.EnrollmentDuration(), t.TotalDuration(),
	)
	if !t.CheckpointCreatedAt.IsZero() && !t.CheckpointRevertedAt.IsZero() {
		s += fmt.Sprintf(" checkpoint-create=%s checkpoint-revert=%s",
			t.CheckpointCreateDuration(), t.CheckpointRevertDuration())
	}
	return s
}
