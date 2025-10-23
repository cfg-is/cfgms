// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package dna

import (
	"runtime"
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
)

// TestDNACollectionBasic tests core DNA collection functionality quickly
func TestDNACollectionBasic(t *testing.T) {
	if !testing.Short() {
		// In non-short mode, do minimal real collection for validation
		logger := logging.NewLogger("error") // Minimal noise
		collector := NewCollector(logger)

		// Quick validation that collection works
		dna, err := collector.Collect()
		if err != nil {
			t.Fatalf("DNA collection failed: %v", err)
		}

		// Basic validation
		if dna.Id == "" {
			t.Error("DNA ID should not be empty")
		}

		if len(dna.Attributes) < 50 {
			t.Errorf("Expected at least 50 attributes, got %d", len(dna.Attributes))
		}

		t.Logf("✅ DNA collection basic validation passed (%d attributes)", len(dna.Attributes))
		return
	}

	// In short mode, just test the constructor and basic functionality
	logger := logging.NewLogger("error")
	collector := NewCollector(logger)

	// Test that collector was created properly
	if collector == nil {
		t.Fatal("DNA collector should not be nil")
	}

	// Test individual component functions work (without full collection)
	attributes := make(map[string]string)
	collector.collectBasicInfo(attributes)

	// Should have at least hostname and basic info
	if len(attributes) < 3 {
		t.Errorf("Basic info collection should return at least 3 attributes, got %d", len(attributes))
	}

	// Check hostname exists (this is fast to collect)
	if _, exists := attributes["hostname"]; !exists {
		t.Error("Basic info should include hostname")
	}

	t.Logf("✅ DNA collection fast validation passed (%d basic attributes)", len(attributes))
}

// BenchmarkDNACollection benchmarks the DNA collection performance
func BenchmarkDNACollection(b *testing.B) {
	logger := logging.NewLogger("error") // Use error level to reduce noise
	collector := NewCollector(logger)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := collector.Collect()
		if err != nil {
			b.Fatalf("DNA collection failed: %v", err)
		}
	}
}

// TestDNACollectionPerformance tests that DNA collection meets performance requirements
func TestDNACollectionPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping DNA performance test in short mode")
	}

	logger := logging.NewLogger("info")
	collector := NewCollector(logger)

	// Measure CPU usage before collection
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	// Time the collection
	start := time.Now()
	dna, err := collector.Collect()
	duration := time.Since(start)

	// Measure CPU usage after collection
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	if err != nil {
		t.Fatalf("DNA collection failed: %v", err)
	}

	// Check performance requirements
	if duration > 60*time.Second {
		t.Errorf("DNA collection took %v, exceeds 60 second requirement", duration)
	} else {
		t.Logf("DNA collection completed in %v (requirement: <60s) ✅", duration)
	}

	// Check attribute count
	attributeCount := len(dna.Attributes)
	if attributeCount < 100 {
		t.Errorf("DNA collection returned only %d attributes, expected >100", attributeCount)
	} else {
		t.Logf("DNA collection returned %d attributes ✅", attributeCount)
	}

	// Memory usage analysis
	memUsed := after.Alloc - before.Alloc
	t.Logf("Memory used during collection: %d bytes", memUsed)

	// Log timing breakdown (will show in verbose mode)
	t.Logf("Collection timing breakdown:")
	t.Logf("  Total duration: %v", duration)
	t.Logf("  Attributes collected: %d", attributeCount)
	t.Logf("  Average time per attribute: %v", duration/time.Duration(attributeCount))
}

// TestDNACollectionComponents tests individual collection components
func TestDNACollectionComponents(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping DNA component performance test in short mode")
	}

	logger := logging.NewLogger("info")
	collector := NewCollector(logger)

	components := []struct {
		name string
		fn   func(map[string]string)
	}{
		{"Basic Info", collector.collectBasicInfo},
		{"Hardware Info", collector.collectHardwareInfo},
		{"Software Info", collector.collectSoftwareInfo},
		{"Network Info", collector.collectNetworkInfo},
		{"Environment Info", collector.collectEnvironmentInfo},
		{"Security Info", collector.collectSecurityInfo},
	}

	for _, component := range components {
		t.Run(component.name, func(t *testing.T) {
			attributes := make(map[string]string)

			start := time.Now()
			component.fn(attributes)
			duration := time.Since(start)

			t.Logf("%s: %d attributes in %v", component.name, len(attributes), duration)

			if duration > 30*time.Second {
				t.Errorf("%s took %v, may be too slow", component.name, duration)
			}
		})
	}
}

// TestConcurrentDNACollection tests DNA collection under concurrent load
func TestConcurrentDNACollection(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping concurrent DNA collection test in short mode")
	}

	logger := logging.NewLogger("error") // Reduce noise

	// Reduced for faster testing - still validates concurrency
	const goroutines = 3
	const collectionsPerGoroutine = 2

	results := make(chan time.Duration, goroutines*collectionsPerGoroutine)

	start := time.Now()

	for i := 0; i < goroutines; i++ {
		go func() {
			collector := NewCollector(logger)
			for j := 0; j < collectionsPerGoroutine; j++ {
				collectionStart := time.Now()
				_, err := collector.Collect()
				collectionDuration := time.Since(collectionStart)

				if err != nil {
					t.Errorf("Concurrent DNA collection failed: %v", err)
					return
				}

				results <- collectionDuration
			}
		}()
	}

	// Collect all results
	var totalDuration time.Duration
	var maxDuration time.Duration
	minDuration := time.Hour // Start with a large value

	for i := 0; i < goroutines*collectionsPerGoroutine; i++ {
		duration := <-results
		totalDuration += duration

		if duration > maxDuration {
			maxDuration = duration
		}
		if duration < minDuration {
			minDuration = duration
		}
	}

	totalTestDuration := time.Since(start)
	avgDuration := totalDuration / time.Duration(goroutines*collectionsPerGoroutine)

	t.Logf("Concurrent DNA collection results:")
	t.Logf("  Total test time: %v", totalTestDuration)
	t.Logf("  Collections: %d", goroutines*collectionsPerGoroutine)
	t.Logf("  Average duration: %v", avgDuration)
	t.Logf("  Min duration: %v", minDuration)
	t.Logf("  Max duration: %v", maxDuration)

	if maxDuration > 60*time.Second {
		t.Errorf("Slowest concurrent collection took %v, exceeds 60 second requirement", maxDuration)
	}
}
