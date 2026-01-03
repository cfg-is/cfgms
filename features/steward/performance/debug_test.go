// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package performance_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/steward/performance"
)

func TestDebugCollector(t *testing.T) {
	config := performance.DefaultConfig()
	config.Interval = 100 * time.Millisecond

	collector := performance.NewCollector("test-steward-debug", config)

	ctx := context.Background()

	fmt.Println("Starting collector...")
	err := collector.Start(ctx)
	require.NoError(t, err)
	defer func() {
		fmt.Println("Stopping collector...")
		_ = collector.Stop()
	}()

	// Wait a bit
	fmt.Println("Waiting 200ms...")
	time.Sleep(200 * time.Millisecond)

	// Try to get metrics
	fmt.Println("Getting current metrics...")
	metrics, err := collector.GetCurrentMetrics()
	if err != nil {
		fmt.Printf("ERROR getting metrics: %v\n", err)
		t.Fatal(err)
	}

	fmt.Printf("Got metrics: steward=%s hostname=%s cpu=%.2f%% mem=%.2f%%\n",
		metrics.StewardID,
		metrics.Hostname,
		metrics.System.CPUPercent,
		metrics.System.MemoryPercent,
	)
}
