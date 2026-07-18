// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package telemetry

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestProcessFragmentID verifies the ADR-017 object-canonical process id shape.
func TestProcessFragmentID(t *testing.T) {
	assert.Equal(t, "process:sshd", processFragmentID("sshd"))
	assert.Equal(t, "process:chrome.exe", processFragmentID("chrome.exe"))
	assert.Equal(t, "process:unknown", processFragmentID(""))
}

// TestServiceFragmentID verifies the ADR-017 service id shape. The helper itself
// does NOT trim ".service" — that systemd-specific normalization is applied by
// the Linux collector before calling this (a Windows service literally named
// "com.docker.service" must keep its name verbatim).
func TestServiceFragmentID(t *testing.T) {
	assert.Equal(t, "service:sshd", serviceFragmentID("sshd"))
	assert.Equal(t, "service:Spooler", serviceFragmentID("Spooler"), "Windows SCM name kept verbatim")
	assert.Equal(t, "service:com.docker.service", serviceFragmentID("com.docker.service"), "Windows name ending in .service is not trimmed")
	assert.Equal(t, "service:unknown", serviceFragmentID(""))
}

// TestErrPlatformNotSupported ensures the sentinel is a distinct, non-nil error
// so callers (and the stub collector) can rely on it.
func TestErrPlatformNotSupported(t *testing.T) {
	assert.Error(t, ErrPlatformNotSupported)
	assert.Contains(t, ErrPlatformNotSupported.Error(), "platform not supported")
}

// TestNewCollectorNonNil verifies the platform NewCollector always returns a
// usable (non-nil) Collector on every build target, including the stub.
func TestNewCollectorNonNil(t *testing.T) {
	assert.NotNil(t, NewCollector())
}

// TestSnapshotHonorsCanceledContext verifies Snapshot returns an error promptly
// when handed an already-canceled context, on every build target. On Linux and
// Windows the collector returns ctx.Err(); on the stub platform it returns
// ErrPlatformNotSupported — both are errors, so a canceled Snapshot never
// silently returns a partial success.
func TestSnapshotHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := NewCollector().Snapshot(ctx)
	require.Error(t, err, "a canceled-context Snapshot must return an error, not a partial result")
}
