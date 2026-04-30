// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package grpc

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/pkg/dataplane/types"
)

// isEOF reports whether err signals end-of-stream from a gRPC Recv call.
func isEOF(err error) bool {
	return err == io.EOF
}

// =============================================================================
// Config transfer conversion
// =============================================================================

// configTransferToChunks serialises cfg to JSON and splits into ≤64 KB chunks.
//
// Each chunk carries the config_id and version fields for correlation.
// An empty payload produces a single chunk with empty data.
func configTransferToChunks(cfg *types.ConfigTransfer) ([]*transportpb.ConfigChunk, error) {
	data, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ConfigTransfer: %w", err)
	}

	if len(data) == 0 {
		return []*transportpb.ConfigChunk{{
			Data:        []byte{},
			ChunkIndex:  0,
			TotalChunks: 1,
			Version:     cfg.Version,
			ConfigId:    cfg.ID,
		}}, nil
	}

	total := (len(data) + types.DefaultChunkSize - 1) / types.DefaultChunkSize
	if total > math.MaxInt32 {
		return nil, fmt.Errorf("config data too large to chunk: %d chunks exceeds int32 limit", total)
	}
	chunks := make([]*transportpb.ConfigChunk, 0, total)
	for i := 0; i < total; i++ {
		start := i * types.DefaultChunkSize
		end := start + types.DefaultChunkSize
		if end > len(data) {
			end = len(data)
		}
		chunks = append(chunks, &transportpb.ConfigChunk{
			Data:        data[start:end],
			ChunkIndex:  int32(i),     //nolint:gosec // G115: bounded by total > math.MaxInt32 check above
			TotalChunks: int32(total), //nolint:gosec // G115: bounded by total > math.MaxInt32 check above
			Version:     cfg.Version,
			ConfigId:    cfg.ID,
		})
	}
	return chunks, nil
}

// chunksToConfigTransfer reassembles chunks into a ConfigTransfer.
//
// Validation: non-empty list, chunk count matches TotalChunks, contiguous
// sequence (0..N-1), assembled payload ≤ maxRecvMsgSize (8 MB).
func chunksToConfigTransfer(chunks []*transportpb.ConfigChunk) (*types.ConfigTransfer, error) {
	if len(chunks) == 0 {
		return nil, ErrEmptyChunkList
	}

	sort.Slice(chunks, func(i, j int) bool {
		return chunks[i].ChunkIndex < chunks[j].ChunkIndex
	})

	if len(chunks) != int(chunks[0].TotalChunks) {
		return nil, fmt.Errorf("got %d chunks, TotalChunks=%d: %w",
			len(chunks), chunks[0].TotalChunks, ErrChunkCountMismatch)
	}

	for i, c := range chunks {
		if c.ChunkIndex != int32(i) { //nolint:gosec // G115: i bounded by TotalChunks check above (≤ math.MaxInt32)
			return nil, fmt.Errorf("position %d has index %d: %w", i, c.ChunkIndex, ErrChunkSequenceGap)
		}
	}

	var data []byte
	for _, c := range chunks {
		data = append(data, c.Data...)
	}

	if len(data) > maxRecvMsgSize {
		return nil, fmt.Errorf("%d bytes: %w", len(data), ErrPayloadTooLarge)
	}

	if len(data) == 0 {
		return &types.ConfigTransfer{
			ID:      chunks[0].ConfigId,
			Version: chunks[0].Version,
		}, nil
	}

	var cfg types.ConfigTransfer
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal ConfigTransfer: %w", err)
	}
	return &cfg, nil
}

// =============================================================================
// DNA transfer conversion
// =============================================================================

// dnaTransferToChunks serialises dna to JSON and splits into ≤64 KB chunks.
func dnaTransferToChunks(dna *types.DNATransfer) ([]*transportpb.DNAChunk, error) {
	data, err := json.Marshal(dna)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal DNATransfer: %w", err)
	}

	if len(data) == 0 {
		return []*transportpb.DNAChunk{{
			StewardId:   dna.StewardID,
			TenantId:    dna.TenantID,
			Data:        []byte{},
			ChunkIndex:  0,
			TotalChunks: 1,
			IsDelta:     dna.Delta,
		}}, nil
	}

	total := (len(data) + types.DefaultChunkSize - 1) / types.DefaultChunkSize
	if total > math.MaxInt32 {
		return nil, fmt.Errorf("DNA data too large to chunk: %d chunks exceeds int32 limit", total)
	}
	chunks := make([]*transportpb.DNAChunk, 0, total)
	for i := 0; i < total; i++ {
		start := i * types.DefaultChunkSize
		end := start + types.DefaultChunkSize
		if end > len(data) {
			end = len(data)
		}
		chunks = append(chunks, &transportpb.DNAChunk{
			StewardId:   dna.StewardID,
			TenantId:    dna.TenantID,
			Data:        data[start:end],
			ChunkIndex:  int32(i),     //nolint:gosec // G115: bounded by total > math.MaxInt32 check above
			TotalChunks: int32(total), //nolint:gosec // G115: bounded by total > math.MaxInt32 check above
			IsDelta:     dna.Delta,
		})
	}
	return chunks, nil
}

// chunksToDNATransfer reassembles DNA chunks into a DNATransfer.
//
// Validation: non-empty list, chunk count matches TotalChunks, contiguous
// sequence (0..N-1), assembled payload ≤ maxRecvMsgSize (8 MB).
func chunksToDNATransfer(chunks []*transportpb.DNAChunk) (*types.DNATransfer, error) {
	if len(chunks) == 0 {
		return nil, ErrEmptyChunkList
	}

	sort.Slice(chunks, func(i, j int) bool {
		return chunks[i].ChunkIndex < chunks[j].ChunkIndex
	})

	if len(chunks) != int(chunks[0].TotalChunks) {
		return nil, fmt.Errorf("got %d chunks, TotalChunks=%d: %w",
			len(chunks), chunks[0].TotalChunks, ErrChunkCountMismatch)
	}

	for i, c := range chunks {
		if c.ChunkIndex != int32(i) { //nolint:gosec // G115: i bounded by TotalChunks check above (≤ math.MaxInt32)
			return nil, fmt.Errorf("position %d has index %d: %w", i, c.ChunkIndex, ErrChunkSequenceGap)
		}
	}

	// All chunks must carry the same TenantID to prevent cross-tenant data confusion.
	firstTenantID := chunks[0].TenantId
	for i, c := range chunks[1:] {
		if c.TenantId != firstTenantID {
			return nil, fmt.Errorf("chunk %d has tenant_id %q, expected %q: %w",
				i+1, c.TenantId, firstTenantID, ErrTenantIDInconsistent)
		}
	}

	var data []byte
	for _, c := range chunks {
		data = append(data, c.Data...)
	}

	if len(data) > maxRecvMsgSize {
		return nil, fmt.Errorf("%d bytes: %w", len(data), ErrPayloadTooLarge)
	}

	if len(data) == 0 {
		return &types.DNATransfer{
			StewardID: chunks[0].StewardId,
			TenantID:  chunks[0].TenantId,
			Delta:     chunks[0].IsDelta,
		}, nil
	}

	var dna types.DNATransfer
	if err := json.Unmarshal(data, &dna); err != nil {
		return nil, fmt.Errorf("failed to unmarshal DNATransfer: %w", err)
	}
	return &dna, nil
}

// =============================================================================
// Bulk transfer conversion
// =============================================================================

// bulkTransferToChunks chunks bulk.Data raw bytes into ≤64 KB BulkChunks.
//
// A SHA-256 checksum of bulk.Data is computed and stored both in bulk.Checksum
// and in the first chunk's metadata under the key "checksum", eliminating the
// 3× memory amplification from JSON-encoding binary data.
func bulkTransferToChunks(bulk *types.BulkTransfer) ([]*transportpb.BulkChunk, error) {
	sum := sha256.Sum256(bulk.Data)
	bulk.Checksum = fmt.Sprintf("sha256:%x", sum)

	// Build first-chunk metadata: carry through caller metadata and add checksum.
	firstMeta := map[string]string{"checksum": bulk.Checksum}
	for k, v := range bulk.Metadata {
		firstMeta[k] = v
	}

	data := bulk.Data
	if len(data) == 0 {
		return []*transportpb.BulkChunk{{
			TransferId: bulk.ID,
			Data:       []byte{},
			TotalSize:  0,
			IsLast:     true,
			Metadata:   firstMeta,
		}}, nil
	}

	if len(data) > math.MaxInt32 {
		return nil, fmt.Errorf("bulk data too large to chunk: %d bytes exceeds int32 limit", len(data))
	}

	total := (len(data) + types.DefaultChunkSize - 1) / types.DefaultChunkSize
	chunks := make([]*transportpb.BulkChunk, 0, total)
	for i := 0; i < total; i++ {
		start := i * types.DefaultChunkSize
		end := start + types.DefaultChunkSize
		if end > len(data) {
			end = len(data)
		}
		isLast := i == total-1
		var meta map[string]string
		if i == 0 {
			meta = firstMeta
		}
		chunks = append(chunks, &transportpb.BulkChunk{
			TransferId: bulk.ID,
			Data:       data[start:end],
			Offset:     int64(start),
			TotalSize:  int64(len(data)),
			IsLast:     isLast,
			Metadata:   meta,
		})
	}
	return chunks, nil
}

// chunksToBulkTransfer reassembles bulk chunks into a BulkTransfer.
//
// Validation: non-empty list, contiguous offsets (no gaps or duplicates),
// assembled payload ≤ maxRecvMsgSize (8 MB), assembled size matches TotalSize.
// Checksum is read from the first chunk's metadata["checksum"] and verified
// against the SHA-256 of the assembled raw bytes.
func chunksToBulkTransfer(chunks []*transportpb.BulkChunk) (*types.BulkTransfer, error) {
	if len(chunks) == 0 {
		return nil, ErrEmptyChunkList
	}

	sort.Slice(chunks, func(i, j int) bool {
		return chunks[i].Offset < chunks[j].Offset
	})

	// Verify offset contiguity: each chunk must start exactly where the previous ended.
	var accumulated int64
	for i, c := range chunks {
		if c.Offset != accumulated {
			return nil, fmt.Errorf("position %d: offset %d, expected %d: %w",
				i, c.Offset, accumulated, ErrChunkSequenceGap)
		}
		accumulated += int64(len(c.Data))
	}

	var data []byte
	for _, c := range chunks {
		data = append(data, c.Data...)
	}

	if len(data) > maxRecvMsgSize {
		return nil, fmt.Errorf("%d bytes: %w", len(data), ErrPayloadTooLarge)
	}

	if int64(len(data)) != chunks[0].TotalSize {
		return nil, fmt.Errorf("assembled %d bytes, TotalSize=%d: %w",
			len(data), chunks[0].TotalSize, ErrTotalSizeMismatch)
	}

	var checksum string
	if chunks[0].Metadata != nil {
		checksum = chunks[0].Metadata["checksum"]
	}
	if checksum != "" {
		sum := sha256.Sum256(data)
		expected := fmt.Sprintf("sha256:%x", sum)
		if checksum != expected {
			return nil, fmt.Errorf("want %s, got %s: %w", expected, checksum, ErrChecksumMismatch)
		}
	}

	return &types.BulkTransfer{
		ID:       chunks[0].TransferId,
		Data:     data,
		Checksum: checksum,
		Metadata: chunks[0].Metadata,
	}, nil
}
