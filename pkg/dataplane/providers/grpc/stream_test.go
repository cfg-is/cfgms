// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package grpc

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/pkg/dataplane/types"
)

// TestChunksToConfigTransfer_ValidationErrors is a table-driven suite covering all
// chunk integrity validation error paths for config chunk reassembly.
func TestChunksToConfigTransfer_ValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		chunks  []*transportpb.ConfigChunk
		wantErr error
	}{
		{
			name:    "empty_slice",
			chunks:  []*transportpb.ConfigChunk{},
			wantErr: ErrEmptyChunkList,
		},
		{
			name: "total_chunks_mismatch",
			// 2 chunks but TotalChunks=3 — count does not match.
			chunks: []*transportpb.ConfigChunk{
				{Data: []byte("a"), ChunkIndex: 0, TotalChunks: 3},
				{Data: []byte("b"), ChunkIndex: 1, TotalChunks: 3},
			},
			wantErr: ErrChunkCountMismatch,
		},
		{
			name: "sequence_gap",
			// indices 0, 2 with TotalChunks=2 — index 1 is missing.
			chunks: []*transportpb.ConfigChunk{
				{Data: []byte("a"), ChunkIndex: 0, TotalChunks: 2},
				{Data: []byte("c"), ChunkIndex: 2, TotalChunks: 2},
			},
			wantErr: ErrChunkSequenceGap,
		},
		{
			name: "duplicate_sequence",
			// Two chunks both at index 0 — the duplicate causes a gap at index 1.
			chunks: []*transportpb.ConfigChunk{
				{Data: []byte("a"), ChunkIndex: 0, TotalChunks: 2},
				{Data: []byte("b"), ChunkIndex: 0, TotalChunks: 2},
			},
			wantErr: ErrChunkSequenceGap,
		},
		{
			name: "payload_too_large",
			// Two 5 MB chunks → 10 MB assembled payload exceeds maxRecvMsgSize (8 MB).
			chunks: func() []*transportpb.ConfigChunk {
				big := make([]byte, 5*1024*1024)
				return []*transportpb.ConfigChunk{
					{Data: big, ChunkIndex: 0, TotalChunks: 2},
					{Data: big, ChunkIndex: 1, TotalChunks: 2},
				}
			}(),
			wantErr: ErrPayloadTooLarge,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := chunksToConfigTransfer(tc.chunks)
			require.Error(t, err)
			assert.True(t, errors.Is(err, tc.wantErr), "want %v, got %v", tc.wantErr, err)
		})
	}
}

// TestChunksToDNATransfer_ValidationErrors is a table-driven suite covering all
// chunk integrity validation error paths for DNA chunk reassembly.
func TestChunksToDNATransfer_ValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		chunks  []*transportpb.DNAChunk
		wantErr error
	}{
		{
			name:    "empty_slice",
			chunks:  []*transportpb.DNAChunk{},
			wantErr: ErrEmptyChunkList,
		},
		{
			name: "total_chunks_mismatch",
			chunks: []*transportpb.DNAChunk{
				{Data: []byte("a"), ChunkIndex: 0, TotalChunks: 3, StewardId: "s1", TenantId: "t1"},
				{Data: []byte("b"), ChunkIndex: 1, TotalChunks: 3, StewardId: "s1", TenantId: "t1"},
			},
			wantErr: ErrChunkCountMismatch,
		},
		{
			name: "sequence_gap",
			chunks: []*transportpb.DNAChunk{
				{Data: []byte("a"), ChunkIndex: 0, TotalChunks: 2, StewardId: "s1", TenantId: "t1"},
				{Data: []byte("c"), ChunkIndex: 2, TotalChunks: 2, StewardId: "s1", TenantId: "t1"},
			},
			wantErr: ErrChunkSequenceGap,
		},
		{
			name: "duplicate_sequence",
			chunks: []*transportpb.DNAChunk{
				{Data: []byte("a"), ChunkIndex: 0, TotalChunks: 2, StewardId: "s1", TenantId: "t1"},
				{Data: []byte("b"), ChunkIndex: 0, TotalChunks: 2, StewardId: "s1", TenantId: "t1"},
			},
			wantErr: ErrChunkSequenceGap,
		},
		{
			name: "payload_too_large",
			chunks: func() []*transportpb.DNAChunk {
				big := make([]byte, 5*1024*1024)
				return []*transportpb.DNAChunk{
					{Data: big, ChunkIndex: 0, TotalChunks: 2, StewardId: "s1", TenantId: "t1"},
					{Data: big, ChunkIndex: 1, TotalChunks: 2, StewardId: "s1", TenantId: "t1"},
				}
			}(),
			wantErr: ErrPayloadTooLarge,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := chunksToDNATransfer(tc.chunks)
			require.Error(t, err)
			assert.True(t, errors.Is(err, tc.wantErr), "want %v, got %v", tc.wantErr, err)
		})
	}
}

// TestChunksToBulkTransfer_ValidationErrors is a table-driven suite covering all
// chunk integrity validation error paths for bulk chunk reassembly.
func TestChunksToBulkTransfer_ValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		chunks  []*transportpb.BulkChunk
		wantErr error
	}{
		{
			name:    "empty_slice",
			chunks:  []*transportpb.BulkChunk{},
			wantErr: ErrEmptyChunkList,
		},
		{
			name: "offset_gap",
			// chunk[1] starts at offset 10, but chunk[0] ends at offset 5 — 5-byte gap.
			chunks: []*transportpb.BulkChunk{
				{Data: []byte("hello"), Offset: 0, TotalSize: 10},
				{Data: []byte("world"), Offset: 10, TotalSize: 10},
			},
			wantErr: ErrChunkSequenceGap,
		},
		{
			name: "payload_too_large",
			// Two 5 MB chunks → 10 MB assembled payload exceeds maxRecvMsgSize (8 MB).
			chunks: func() []*transportpb.BulkChunk {
				big := make([]byte, 5*1024*1024)
				return []*transportpb.BulkChunk{
					{Data: big, Offset: 0, TotalSize: int64(10 * 1024 * 1024)},
					{Data: big, Offset: int64(5 * 1024 * 1024), TotalSize: int64(10 * 1024 * 1024)},
				}
			}(),
			wantErr: ErrPayloadTooLarge,
		},
		{
			name: "duplicate_offset",
			// Two chunks both at offset 0 — the duplicate causes a mismatch on the second iteration.
			chunks: []*transportpb.BulkChunk{
				{Data: []byte("hello"), Offset: 0, TotalSize: 10},
				{Data: []byte("world"), Offset: 0, TotalSize: 10},
			},
			wantErr: ErrChunkSequenceGap,
		},
		{
			name: "total_size_mismatch",
			// Assembled payload is 13 bytes but TotalSize claims 999.
			chunks: []*transportpb.BulkChunk{
				{Data: []byte(`{"id":"test"}`), Offset: 0, TotalSize: 999},
			},
			wantErr: ErrTotalSizeMismatch,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := chunksToBulkTransfer(tc.chunks)
			require.Error(t, err)
			assert.True(t, errors.Is(err, tc.wantErr), "want %v, got %v", tc.wantErr, err)
		})
	}
}

// TestChunksToBulkTransfer_RoundTrip verifies that bulkTransferToChunks and
// chunksToBulkTransfer are inverse operations for a normal-sized payload.
func TestChunksToBulkTransfer_RoundTrip(t *testing.T) {
	original := &types.BulkTransfer{
		ID:        "bulk-rt-001",
		StewardID: "steward-rt",
		TenantID:  "tenant-rt",
		Direction: "to_steward",
		Type:      "file",
	}
	chunks, err := bulkTransferToChunks(original)
	require.NoError(t, err)
	require.NotEmpty(t, chunks)

	got, err := chunksToBulkTransfer(chunks)
	require.NoError(t, err)
	assert.Equal(t, original.ID, got.ID)
	assert.Equal(t, original.StewardID, got.StewardID)
	assert.Equal(t, original.TenantID, got.TenantID)
}

// TestBulkTransferToChunks_SmallPayload verifies that bulkTransferToChunks produces
// at least one chunk for a small payload and does not error.
func TestBulkTransferToChunks_SmallPayload(t *testing.T) {
	bulk := &types.BulkTransfer{
		ID:   "bulk-small",
		Data: []byte("payload well below any size limit"),
	}
	chunks, err := bulkTransferToChunks(bulk)
	require.NoError(t, err)
	assert.NotEmpty(t, chunks)
}

// TestBulkChecksum_RoundTrip verifies that bulkTransferToChunks computes and stores
// a SHA-256 checksum, and that chunksToBulkTransfer verifies it correctly on reassembly.
func TestBulkChecksum_RoundTrip(t *testing.T) {
	original := &types.BulkTransfer{
		ID:        "bulk-checksum-rt",
		StewardID: "steward-1",
		TenantID:  "tenant-1",
		Data:      []byte("bulk payload data for checksum test"),
	}

	chunks, err := bulkTransferToChunks(original)
	require.NoError(t, err)
	require.NotEmpty(t, chunks)

	// Checksum must be populated on the struct before chunking.
	assert.NotEmpty(t, original.Checksum, "bulkTransferToChunks must populate Checksum")
	assert.True(t, strings.HasPrefix(original.Checksum, "sha256:"), "Checksum must have sha256: prefix")

	got, err := chunksToBulkTransfer(chunks)
	require.NoError(t, err, "valid checksum must pass verification")
	assert.Equal(t, original.Data, got.Data)
	assert.Equal(t, original.Checksum, got.Checksum)
}

// TestBulkChecksum_TamperedData verifies that chunksToBulkTransfer returns
// ErrChecksumMismatch when the assembled BulkTransfer carries a checksum that
// does not match the Data field.
func TestBulkChecksum_TamperedData(t *testing.T) {
	// Build a BulkTransfer where Checksum deliberately does not match Data.
	tampered := &types.BulkTransfer{
		ID:       "bulk-tamper",
		Data:     []byte("actual payload"),
		Checksum: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
	}

	data, err := json.Marshal(tampered)
	require.NoError(t, err)

	chunks := []*transportpb.BulkChunk{{
		TransferId: tampered.ID,
		Data:       data,
		Offset:     0,
		TotalSize:  int64(len(data)),
		IsLast:     true,
	}}

	_, err = chunksToBulkTransfer(chunks)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrChecksumMismatch),
		"tampered checksum must return ErrChecksumMismatch, got: %v", err)
}

// TestDNATransfer_MixedTenantID verifies that chunksToDNATransfer returns
// ErrTenantIDInconsistent when chunks carry different TenantID values.
func TestDNATransfer_MixedTenantID(t *testing.T) {
	chunks := []*transportpb.DNAChunk{
		{StewardId: "s1", TenantId: "tenant-a", Data: []byte("x"), ChunkIndex: 0, TotalChunks: 2},
		{StewardId: "s1", TenantId: "tenant-b", Data: []byte("y"), ChunkIndex: 1, TotalChunks: 2},
	}

	_, err := chunksToDNATransfer(chunks)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrTenantIDInconsistent),
		"mixed TenantIDs must return ErrTenantIDInconsistent, got: %v", err)
}

// TestDNATransfer_ConsistentTenantID verifies that chunksToDNATransfer succeeds
// when all chunks share the same TenantID.
func TestDNATransfer_ConsistentTenantID(t *testing.T) {
	dna := &types.DNATransfer{
		ID:        "dna-tenant-ok",
		StewardID: "s1",
		TenantID:  "tenant-a",
		Delta:     false,
	}
	chunks, err := dnaTransferToChunks(dna)
	require.NoError(t, err)

	got, err := chunksToDNATransfer(chunks)
	require.NoError(t, err, "consistent TenantID must pass validation")
	assert.Equal(t, dna.TenantID, got.TenantID)
}
