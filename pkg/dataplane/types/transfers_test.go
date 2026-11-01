// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package types

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTransferProgressCalculations(t *testing.T) {
	startTime := time.Now().Add(-2 * time.Minute)
	progress := &TransferProgress{
		BytesTransferred: 524288, // 512 KB
		ChunksCompleted:  8,      // 8 chunks
		StartTime:        startTime,
		LastUpdate:       time.Now(),
	}

	// Verify progress tracking
	assert.Equal(t, int64(524288), progress.BytesTransferred)
	assert.Equal(t, 8, progress.ChunksCompleted)
	assert.True(t, progress.LastUpdate.After(progress.StartTime))

	// Calculate elapsed time
	elapsed := progress.LastUpdate.Sub(progress.StartTime)
	assert.True(t, elapsed >= 2*time.Minute)

	// Calculate average throughput (bytes per second)
	throughput := float64(progress.BytesTransferred) / elapsed.Seconds()
	assert.Greater(t, throughput, 0.0)
}

func TestConfigTransferMinimal(t *testing.T) {
	// Test with minimal required fields
	minimal := &ConfigTransfer{
		ID:        "config-min",
		StewardID: "steward-1",
		TenantID:  "tenant-1",
		Version:   "1.0.0",
		Timestamp: time.Now(),
		Data:      []byte("minimal"),
	}

	data, err := json.Marshal(minimal)
	require.NoError(t, err)

	var deserialized ConfigTransfer
	err = json.Unmarshal(data, &deserialized)
	require.NoError(t, err)

	assert.Equal(t, minimal.ID, deserialized.ID)
	assert.Nil(t, deserialized.Signature) // Optional field should be nil
	assert.Nil(t, deserialized.Metadata)  // Optional field should be nil
}

func TestDNATransferDelta(t *testing.T) {
	// Test delta DNA transfer
	delta := &DNATransfer{
		ID:          "dna-delta",
		StewardID:   "steward-1",
		TenantID:    "tenant-1",
		Timestamp:   time.Now(),
		Attributes:  []byte("changed attrs only"),
		Delta:       true,
		BaseVersion: "1.2.3",
	}

	assert.True(t, delta.Delta)
	assert.Equal(t, "1.2.3", delta.BaseVersion)

	// Test full snapshot
	snapshot := &DNATransfer{
		ID:         "dna-snapshot",
		StewardID:  "steward-1",
		TenantID:   "tenant-1",
		Timestamp:  time.Now(),
		Attributes: []byte("all attrs"),
		Delta:      false,
	}

	assert.False(t, snapshot.Delta)
	assert.Empty(t, snapshot.BaseVersion) // Should be empty for snapshots
}
