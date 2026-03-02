// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package authdefense

import (
	"sync"
	"time"
)

// LightweightAuditEntry is a compact audit entry (24 bytes vs 300+ for full proto)
// used for failed auth attempts during high-volume attacks to reduce memory pressure.
type LightweightAuditEntry struct {
	Timestamp time.Time
	SubjectID string
	Result    byte // 0 = failure, 1 = success
}

// FailedAuthAggregator aggregates repeated failed auth attempts by subject/IP
// instead of logging each one individually. Under normal load, every event is
// recorded. Under attack conditions, it aggregates counts and flushes
// periodically to keep memory bounded.
type FailedAuthAggregator struct {
	mu            sync.Mutex
	counts        map[string]*aggregatedFailure
	flushInterval time.Duration
	maxEntries    int
	clock         Clock

	// Recent lightweight entries (ring buffer)
	entries  []LightweightAuditEntry
	entryIdx int
	entryCap int
}

// aggregatedFailure tracks failure counts for a single subject/IP key
type aggregatedFailure struct {
	Count     uint32
	FirstSeen time.Time
	LastSeen  time.Time
}

// AggregatedSnapshot is a point-in-time summary of aggregated failures
type AggregatedSnapshot struct {
	Key       string    `json:"key"`
	Count     uint32    `json:"count"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// NewFailedAuthAggregator creates a new aggregator with the given flush interval
func NewFailedAuthAggregator(flushInterval time.Duration, maxEntries int, clock Clock) *FailedAuthAggregator {
	if maxEntries <= 0 {
		maxEntries = 10_000
	}
	entryCap := 1000 // lightweight ring buffer for recent entries
	return &FailedAuthAggregator{
		counts:        make(map[string]*aggregatedFailure),
		flushInterval: flushInterval,
		maxEntries:    maxEntries,
		clock:         clock,
		entries:       make([]LightweightAuditEntry, entryCap),
		entryCap:      entryCap,
	}
}

// RecordFailure records a failed auth attempt, aggregating by key (e.g. "ip:1.2.3.4" or "subject:user-1")
func (a *FailedAuthAggregator) RecordFailure(key, subjectID string) {
	now := a.clock.Now()

	a.mu.Lock()
	defer a.mu.Unlock()

	// Record lightweight entry in ring buffer
	a.entries[a.entryIdx] = LightweightAuditEntry{
		Timestamp: now,
		SubjectID: subjectID,
		Result:    0, // failure
	}
	a.entryIdx = (a.entryIdx + 1) % a.entryCap

	// Aggregate by key
	if existing, ok := a.counts[key]; ok {
		existing.Count++
		existing.LastSeen = now
	} else {
		// Enforce max entries to prevent unbounded growth
		if len(a.counts) >= a.maxEntries {
			a.evictOldest()
		}
		a.counts[key] = &aggregatedFailure{
			Count:     1,
			FirstSeen: now,
			LastSeen:  now,
		}
	}
}

// Flush returns all aggregated failures and resets counters.
// This should be called periodically (e.g. every 30 seconds) to emit summary logs.
func (a *FailedAuthAggregator) Flush() []AggregatedSnapshot {
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(a.counts) == 0 {
		return nil
	}

	snapshots := make([]AggregatedSnapshot, 0, len(a.counts))
	for key, agg := range a.counts {
		snapshots = append(snapshots, AggregatedSnapshot{
			Key:       key,
			Count:     agg.Count,
			FirstSeen: agg.FirstSeen,
			LastSeen:  agg.LastSeen,
		})
	}

	// Reset
	a.counts = make(map[string]*aggregatedFailure)
	return snapshots
}

// Size returns the current number of tracked keys
func (a *FailedAuthAggregator) Size() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.counts)
}

// evictOldest removes the oldest entry to make room. Must be called with lock held.
func (a *FailedAuthAggregator) evictOldest() {
	var oldestKey string
	var oldestTime time.Time

	for key, agg := range a.counts {
		if oldestKey == "" || agg.LastSeen.Before(oldestTime) {
			oldestKey = key
			oldestTime = agg.LastSeen
		}
	}

	if oldestKey != "" {
		delete(a.counts, oldestKey)
	}
}
