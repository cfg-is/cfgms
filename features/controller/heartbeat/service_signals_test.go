// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package heartbeat

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
)

// TestFreshHeartbeatCount proves the count follows controller receipt time
// against StewardOfflineTimeout, independent of the Healthy flag (which only
// flips on the monitorHeartbeats tick) and of the steward-supplied timestamp.
func TestFreshHeartbeatCount(t *testing.T) {
	const offlineTimeout = 300 * time.Millisecond
	// CheckInterval stays at the default 5s, so no tick marks a steward
	// unhealthy during the test: only receipt time can age a steward out.
	svc, cp := newTestService(t, func(c *Config) { c.StewardOfflineTimeout = offlineTimeout })
	t.Cleanup(func() { _ = svc.Stop(context.Background()) })
	ctx := context.Background()

	assert.Equal(t, 0, svc.FreshHeartbeatCount(), "no stewards, no fresh heartbeats")

	send := func(id string, supplied time.Time) {
		t.Helper()
		require.NoError(t, cp.sendHeartbeat(ctx, &controlplaneTypes.Heartbeat{
			StewardID: id,
			Status:    controlplaneTypes.StatusHealthy,
			Timestamp: supplied,
		}))
	}

	send("steward-a", time.Now())
	assert.Equal(t, 1, svc.FreshHeartbeatCount())

	// A steward-supplied timestamp far in the past must not make a heartbeat
	// that was just received look stale.
	send("steward-b", time.Now().Add(-time.Hour))
	assert.Equal(t, 2, svc.FreshHeartbeatCount(), "steward-supplied time must not affect freshness")

	// A steward-supplied timestamp in the future must not keep it fresh.
	send("steward-c", time.Now().Add(time.Hour))
	assert.Equal(t, 3, svc.FreshHeartbeatCount())

	// A repeated heartbeat is one steward, not two.
	send("steward-a", time.Now())
	assert.Equal(t, 3, svc.FreshHeartbeatCount())

	// All three age past the timeout. Healthy has not flipped, because the
	// check tick has not run, yet none is fresh.
	require.Eventually(t, func() bool { return svc.FreshHeartbeatCount() == 0 },
		5*time.Second, 10*time.Millisecond, "heartbeats older than StewardOfflineTimeout must stop counting")
	status, ok := svc.GetStatus("steward-a")
	require.True(t, ok)
	assert.True(t, status.Healthy, "Healthy lags until the monitor tick; the fresh count must not depend on it")

	// A new heartbeat revives only its steward.
	send("steward-b", time.Now())
	assert.Equal(t, 1, svc.FreshHeartbeatCount())
}
