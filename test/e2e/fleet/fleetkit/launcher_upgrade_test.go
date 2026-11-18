// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package fleetkit

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestContainerShellReportsFailure covers the error path: a command run in a
// container that does not exist returns an error instead of succeeding silently.
// It holds with or without a Docker daemon.
func TestContainerShellReportsFailure(t *testing.T) {
	_, err := ContainerShell("fleetkit-no-such-container", "true", 10*time.Second)
	require.Error(t, err)
}

// TestLauncherFixturesAreDistinct pins that the three launcher version labels are
// distinct and that the launcher test container is one the helpers may drive.
func TestLauncherFixturesAreDistinct(t *testing.T) {
	require.NotEqual(t, LauncherInitialVersion, LauncherHappyVersion)
	require.NotEqual(t, LauncherInitialVersion, LauncherBrokenVersion)
	require.NotEqual(t, LauncherHappyVersion, LauncherBrokenVersion)
	require.NoError(t, ValidateFleetContainer(LauncherTestContainer))
	require.Error(t, ValidateFleetContainer("not-a-fleet-container"))
}
