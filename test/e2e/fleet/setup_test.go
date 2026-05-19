// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package fleet

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestFleetComposeStartup verifies that fleet-controller, fleet-steward-1, and fleet-steward-2
// all reach healthy state within 60 seconds.
// Requires: docker compose --profile fleet -f docker-compose.test.yml up -d
func TestFleetComposeStartup(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping fleet compose startup test in short mode — requires Docker fleet infrastructure")
	}

	containers := []string{"fleet-controller", "fleet-steward-1", "fleet-steward-2"}

	for _, name := range containers {
		name := name
		t.Run(name, func(t *testing.T) {
			deadline := time.Now().Add(60 * time.Second)
			for time.Now().Before(deadline) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				out, err := exec.CommandContext(ctx, "docker", "ps",
					"--filter", "name="+name,
					"--filter", "health=healthy",
					"--format", "{{.Names}}").CombinedOutput()
				cancel()

				if err == nil && strings.Contains(string(out), name) {
					return
				}
				time.Sleep(2 * time.Second)
			}
			t.Errorf("container %s did not reach healthy state within 60s", name)
		})
	}
}
