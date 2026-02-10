// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package types

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStreamType(t *testing.T) {
	tests := []struct {
		name       string
		streamType StreamType
		expected   string
	}{
		{"Config", StreamConfig, "config"},
		{"DNA", StreamDNA, "dna"},
		{"Bulk", StreamBulk, "bulk"},
		{"Custom", StreamCustom, "custom"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, string(tt.streamType))
		})
	}
}

func TestConfigTransferSerialization(t *testing.T) {
	original := &ConfigTransfer{
		ID:        "config-123",
		StewardID: "steward-1",
		TenantID:  "tenant-1",
		Version:   "1.0.0",
		Timestamp: time.Now().Truncate(time.Second),
		Data:      []byte("test config data"),
		Signature: []byte("test signature"),
		Metadata: map[string]string{
			"compression": "gzip",
			"encoding":    "json",
		},
	}

	// Serialize to JSON
	data, err := json.Marshal(original)
	require.NoError(t, err)

	// Deserialize from JSON
	var deserialized ConfigTransfer
	err = json.Unmarshal(data, &deserialized)
	require.NoError(t, err)

	// Verify fields
	assert.Equal(t, original.ID, deserialized.ID)
	assert.Equal(t, original.StewardID, deserialized.StewardID)
	assert.Equal(t, original.TenantID, deserialized.TenantID)
	assert.Equal(t, original.Version, deserialized.Version)
	assert.Equal(t, original.Timestamp.Unix(), deserialized.Timestamp.Unix())
	assert.Equal(t, original.Data, deserialized.Data)
	assert.Equal(t, original.Signature, deserialized.Signature)
	assert.Equal(t, original.Metadata, deserialized.Metadata)
}

func TestDNATransferSerialization(t *testing.T) {
	original := &DNATransfer{
		ID:          "dna-456",
		StewardID:   "steward-2",
		TenantID:    "tenant-2",
		Timestamp:   time.Now().Truncate(time.Second),
		Attributes:  []byte("test dna attributes"),
		Delta:       true,
		BaseVersion: "0.9.0",
		Metadata: map[string]string{
			"compression":  "zstd",
			"attr_count":   "161",
			"collection_s": "2.5",
		},
	}

	// Serialize to JSON
	data, err := json.Marshal(original)
	require.NoError(t, err)

	// Deserialize from JSON
	var deserialized DNATransfer
	err = json.Unmarshal(data, &deserialized)
	require.NoError(t, err)

	// Verify fields
	assert.Equal(t, original.ID, deserialized.ID)
	assert.Equal(t, original.StewardID, deserialized.StewardID)
	assert.Equal(t, original.TenantID, deserialized.TenantID)
	assert.Equal(t, original.Timestamp.Unix(), deserialized.Timestamp.Unix())
	assert.Equal(t, original.Attributes, deserialized.Attributes)
	assert.Equal(t, original.Delta, deserialized.Delta)
	assert.Equal(t, original.BaseVersion, deserialized.BaseVersion)
	assert.Equal(t, original.Metadata, deserialized.Metadata)
}

func TestBulkTransferSerialization(t *testing.T) {
	original := &BulkTransfer{
		ID:        "bulk-789",
		StewardID: "steward-3",
		TenantID:  "tenant-3",
		Direction: "to_steward",
		Type:      "package",
		TotalSize: 1048576,
		ChunkSize: 65536,
		Timestamp: time.Now().Truncate(time.Second),
		Data:      []byte("test bulk data chunk"),
		Checksum:  "sha256:abc123def456",
		Progress: &TransferProgress{
			BytesTransferred: 524288,
			ChunksCompleted:  8,
			StartTime:        time.Now().Add(-time.Minute).Truncate(time.Second),
			LastUpdate:       time.Now().Truncate(time.Second),
		},
		Metadata: map[string]string{
			"filename":   "package.tar.gz",
			"compressed": "true",
		},
	}

	// Serialize to JSON
	data, err := json.Marshal(original)
	require.NoError(t, err)

	// Deserialize from JSON
	var deserialized BulkTransfer
	err = json.Unmarshal(data, &deserialized)
	require.NoError(t, err)

	// Verify fields
	assert.Equal(t, original.ID, deserialized.ID)
	assert.Equal(t, original.StewardID, deserialized.StewardID)
	assert.Equal(t, original.TenantID, deserialized.TenantID)
	assert.Equal(t, original.Direction, deserialized.Direction)
	assert.Equal(t, original.Type, deserialized.Type)
	assert.Equal(t, original.TotalSize, deserialized.TotalSize)
	assert.Equal(t, original.ChunkSize, deserialized.ChunkSize)
	assert.Equal(t, original.Timestamp.Unix(), deserialized.Timestamp.Unix())
	assert.Equal(t, original.Data, deserialized.Data)
	assert.Equal(t, original.Checksum, deserialized.Checksum)
	assert.Equal(t, original.Metadata, deserialized.Metadata)

	// Verify progress
	require.NotNil(t, deserialized.Progress)
	assert.Equal(t, original.Progress.BytesTransferred, deserialized.Progress.BytesTransferred)
	assert.Equal(t, original.Progress.ChunksCompleted, deserialized.Progress.ChunksCompleted)
	assert.Equal(t, original.Progress.StartTime.Unix(), deserialized.Progress.StartTime.Unix())
	assert.Equal(t, original.Progress.LastUpdate.Unix(), deserialized.Progress.LastUpdate.Unix())
}

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

func TestBulkTransferDirections(t *testing.T) {
	tests := []struct {
		name      string
		direction string
		desc      string
	}{
		{"To Steward", "to_steward", "Controller → Steward deployment"},
		{"To Controller", "to_controller", "Steward → Controller collection"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transfer := &BulkTransfer{
				ID:        "bulk-test",
				StewardID: "steward-1",
				TenantID:  "tenant-1",
				Direction: tt.direction,
				Type:      "file",
				TotalSize: 1024,
				Data:      []byte("test"),
			}

			assert.Equal(t, tt.direction, transfer.Direction)
		})
	}
}

func TestBulkTransferTypes(t *testing.T) {
	types := []string{"file", "package", "logs", "backup", "image"}

	for _, bulkType := range types {
		t.Run(bulkType, func(t *testing.T) {
			transfer := &BulkTransfer{
				ID:        "bulk-" + bulkType,
				StewardID: "steward-1",
				TenantID:  "tenant-1",
				Direction: "to_steward",
				Type:      bulkType,
				TotalSize: 2048,
				Data:      []byte("test"),
			}

			assert.Equal(t, bulkType, transfer.Type)
		})
	}
}
