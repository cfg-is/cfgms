// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package registration

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingIPTrustStore is a real, in-memory IPTrustStore for evaluator tests.
// It is NOT a mock — it fully implements the IPTrustStore contract using
// net.ParseCIDR-based containment checks, matching production behaviour.
type recordingIPTrustStore struct {
	mu      sync.Mutex
	entries []*business.IPTrustEntry
	seq     int
	calls   []string // records AddTrustedRange cidr arguments for assertion
}

func (s *recordingIPTrustStore) AddTrustedRange(_ context.Context, tenantID, cidr string, preSeeded bool) error {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	normalised := ipNet.String()

	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, tenantID+"/"+normalised)

	for _, e := range s.entries {
		if e.TenantID == tenantID && e.CIDR == normalised {
			e.PreSeeded = preSeeded
			e.TrustedSince = time.Now()
			e.Revoked = false
			e.RevokedAt = nil
			return nil
		}
	}
	s.seq++
	s.entries = append(s.entries, &business.IPTrustEntry{
		ID:           fmt.Sprintf("entry-%d", s.seq),
		TenantID:     tenantID,
		CIDR:         normalised,
		PreSeeded:    preSeeded,
		TrustedSince: time.Now(),
	})
	return nil
}

func (s *recordingIPTrustStore) IsTrusted(_ context.Context, tenantID, ip string) (bool, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false, fmt.Errorf("invalid IP: %s", ip)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.entries {
		if e.TenantID != tenantID || e.Revoked {
			continue
		}
		_, ipNet, err := net.ParseCIDR(e.CIDR)
		if err != nil {
			continue
		}
		if ipNet.Contains(parsed) {
			return true, nil
		}
	}
	return false, nil
}

func (s *recordingIPTrustStore) ListTrustedRanges(_ context.Context, tenantID string) ([]*business.IPTrustEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*business.IPTrustEntry
	for _, e := range s.entries {
		if e.TenantID == tenantID {
			cp := *e
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (s *recordingIPTrustStore) RevokeTrustedRange(_ context.Context, tenantID, cidr string) error {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	normalised := ipNet.String()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.entries {
		if e.TenantID == tenantID && e.CIDR == normalised && !e.Revoked {
			now := time.Now()
			e.Revoked = true
			e.RevokedAt = &now
			return nil
		}
	}
	return business.ErrIPTrustEntryNotFound
}

func (s *recordingIPTrustStore) RecordHealthySteward(_ context.Context, _, _ string, _ time.Time) error {
	return nil
}

func (s *recordingIPTrustStore) GetLastActivity(_ context.Context, _, _ string) (*business.IPTrustActivity, error) {
	return nil, nil
}

// addTrustedRangeCalls returns a snapshot of all AddTrustedRange call arguments.
func (s *recordingIPTrustStore) addTrustedRangeCalls() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.calls))
	copy(out, s.calls)
	return out
}

// Compile-time: ensure recordingIPTrustStore satisfies the interface.
var _ business.IPTrustStore = (*recordingIPTrustStore)(nil)

func newTestEvaluator(t *testing.T, threshold time.Duration) (*IPTrustEvaluator, *recordingIPTrustStore) {
	t.Helper()
	store := &recordingIPTrustStore{}
	ev := NewIPTrustEvaluator(IPTrustEvaluatorConfig{
		Store:     store,
		Threshold: threshold,
		Logger:    logging.NewLogger("debug"),
	})
	return ev, store
}

// TestIPTrustEvaluator_ThresholdNotMet_NoTrust verifies that repeated healthy
// calls arriving just under the threshold do not call AddTrustedRange.
// Acceptance criterion: trust is not granted before the threshold is reached.
func TestIPTrustEvaluator_ThresholdNotMet_NoTrust(t *testing.T) {
	threshold := 5 * time.Second
	ev, store := newTestEvaluator(t, threshold)
	ctx := context.Background()

	// Start the liveness clock.
	require.NoError(t, ev.RecordLiveness(ctx, "tenant-1", "steward-1", "10.0.0.1", true))

	// Simulate multiple healthy calls but back-date firstSeen to just under threshold.
	ev.mu.Lock()
	key := "tenant-1\x0010.0.0.1"
	ev.timers[key] = time.Now().Add(-(threshold - time.Millisecond))
	ev.mu.Unlock()

	// One more healthy call — elapsed is still < threshold.
	require.NoError(t, ev.RecordLiveness(ctx, "tenant-1", "steward-1", "10.0.0.1", true))

	assert.Empty(t, store.addTrustedRangeCalls(),
		"AddTrustedRange must not be called when threshold is not yet met")
}

// TestIPTrustEvaluator_ThresholdMet_AddsTrust verifies that a healthy call
// spanning ≥ threshold results in AddTrustedRange called exactly once.
// Acceptance criterion: trust is granted exactly when threshold is met.
func TestIPTrustEvaluator_ThresholdMet_AddsTrust(t *testing.T) {
	threshold := 5 * time.Second
	ev, store := newTestEvaluator(t, threshold)
	ctx := context.Background()

	// Start the liveness clock.
	require.NoError(t, ev.RecordLiveness(ctx, "tenant-1", "steward-1", "10.0.0.1", true))

	// Back-date firstSeen to exactly the threshold ago so the next call tips over.
	ev.mu.Lock()
	key := "tenant-1\x0010.0.0.1"
	ev.timers[key] = time.Now().Add(-threshold)
	ev.mu.Unlock()

	// This call must tip over the threshold and call AddTrustedRange.
	require.NoError(t, ev.RecordLiveness(ctx, "tenant-1", "steward-1", "10.0.0.1", true))

	calls := store.addTrustedRangeCalls()
	require.Len(t, calls, 1, "AddTrustedRange must be called exactly once")
	assert.Equal(t, "tenant-1/10.0.0.1/32", calls[0], "CIDR must be a /32 host entry")

	// Timer entry must be cleared after promotion.
	ev.mu.Lock()
	_, timerExists := ev.timers[key]
	ev.mu.Unlock()
	assert.False(t, timerExists, "timer entry must be cleared after trust promotion")

	// A second call should NOT trigger another AddTrustedRange (timer is cleared,
	// so it starts fresh and the threshold won't be met immediately).
	require.NoError(t, ev.RecordLiveness(ctx, "tenant-1", "steward-1", "10.0.0.1", true))
	assert.Len(t, store.addTrustedRangeCalls(), 1,
		"AddTrustedRange must not be called again before threshold is met again")
}

// TestIPTrustEvaluator_OfflineResetsTimer verifies that healthy → offline →
// healthy again restarts the timer; trust is not granted until the threshold
// is met from the new start.
// Acceptance criterion: an intervening healthy=false resets the liveness timer.
func TestIPTrustEvaluator_OfflineResetsTimer(t *testing.T) {
	threshold := 5 * time.Second
	ev, store := newTestEvaluator(t, threshold)
	ctx := context.Background()

	// First healthy call starts the timer.
	require.NoError(t, ev.RecordLiveness(ctx, "tenant-1", "steward-1", "10.0.0.1", true))

	// Back-date firstSeen to just under threshold.
	ev.mu.Lock()
	key := "tenant-1\x0010.0.0.1"
	ev.timers[key] = time.Now().Add(-(threshold - time.Millisecond))
	ev.mu.Unlock()

	// Steward goes offline — timer must be cleared.
	require.NoError(t, ev.RecordLiveness(ctx, "tenant-1", "steward-1", "10.0.0.1", false))

	ev.mu.Lock()
	_, timerExists := ev.timers[key]
	ev.mu.Unlock()
	assert.False(t, timerExists, "timer must be cleared after offline event")
	assert.Empty(t, store.addTrustedRangeCalls(), "no trust before offline was cleared")

	// Steward comes back — starts fresh. A single call with elapsed < threshold must not trust.
	require.NoError(t, ev.RecordLiveness(ctx, "tenant-1", "steward-1", "10.0.0.1", true))
	assert.Empty(t, store.addTrustedRangeCalls(),
		"trust must not be granted immediately after restart; threshold must be met from scratch")

	// Now tip the new timer over the threshold.
	ev.mu.Lock()
	ev.timers[key] = time.Now().Add(-threshold)
	ev.mu.Unlock()

	require.NoError(t, ev.RecordLiveness(ctx, "tenant-1", "steward-1", "10.0.0.1", true))

	calls := store.addTrustedRangeCalls()
	require.Len(t, calls, 1, "trust must be granted after threshold met from new start")
}

// TestIPTrustEvaluator_ConcurrentCalls verifies that concurrent calls from
// multiple goroutines are race-free (run with -race to detect violations).
func TestIPTrustEvaluator_ConcurrentCalls(t *testing.T) {
	ev, _ := newTestEvaluator(t, time.Hour) // large threshold so no AddTrustedRange races
	ctx := context.Background()

	const goroutines = 20
	var wg sync.WaitGroup
	errs := make(chan error, goroutines*50)
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			ip := fmt.Sprintf("10.0.0.%d", i+1)
			for j := 0; j < 50; j++ {
				if err := ev.RecordLiveness(ctx, "tenant-1", fmt.Sprintf("steward-%d", i), ip, j%3 != 0); err != nil {
					errs <- err
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err, "concurrent RecordLiveness must not return errors")
	}
}

// TestIPTrustEvaluator_EmptyIPIsNoop verifies that an empty IP string is
// silently ignored and does not cause a panic or store call.
func TestIPTrustEvaluator_EmptyIPIsNoop(t *testing.T) {
	ev, store := newTestEvaluator(t, time.Millisecond)
	ctx := context.Background()

	require.NoError(t, ev.RecordLiveness(ctx, "tenant-1", "steward-1", "", true))
	assert.Empty(t, store.addTrustedRangeCalls())
}

// TestIPTrustEvaluator_DefaultThreshold verifies that zero-threshold in config
// defaults to 30 minutes.
func TestIPTrustEvaluator_DefaultThreshold(t *testing.T) {
	ev, _ := newTestEvaluator(t, 0)
	assert.Equal(t, defaultIPTrustThreshold, ev.threshold,
		"zero threshold must default to 30 minutes")
}

// TestIPTrustEvaluator_MultiTenantIsolation verifies that two tenants sharing
// the same IP are tracked independently.
func TestIPTrustEvaluator_MultiTenantIsolation(t *testing.T) {
	threshold := 5 * time.Second
	ev, store := newTestEvaluator(t, threshold)
	ctx := context.Background()

	// Start timers for both tenants.
	require.NoError(t, ev.RecordLiveness(ctx, "tenant-A", "steward-1", "10.0.0.1", true))
	require.NoError(t, ev.RecordLiveness(ctx, "tenant-B", "steward-2", "10.0.0.1", true))

	// Back-date only tenant-A's timer to exceed threshold.
	ev.mu.Lock()
	ev.timers["tenant-A\x0010.0.0.1"] = time.Now().Add(-threshold)
	ev.mu.Unlock()

	require.NoError(t, ev.RecordLiveness(ctx, "tenant-A", "steward-1", "10.0.0.1", true))

	calls := store.addTrustedRangeCalls()
	require.Len(t, calls, 1)
	assert.Equal(t, "tenant-A/10.0.0.1/32", calls[0],
		"only tenant-A must be promoted; tenant-B timer is still running")
}
