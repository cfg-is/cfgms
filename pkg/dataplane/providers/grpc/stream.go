// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package grpc

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/pkg/dataplane/types"
)

// chunkSize is the maximum bytes per gRPC chunk (64 KB).
const chunkSize = 64 * 1024

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

	total := (len(data) + chunkSize - 1) / chunkSize
	if total > math.MaxInt32 {
		return nil, fmt.Errorf("config data too large to chunk: %d chunks exceeds int32 limit", total)
	}
	chunks := make([]*transportpb.ConfigChunk, 0, total)
	for i := 0; i < total; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunks = append(chunks, &transportpb.ConfigChunk{
			Data:        data[start:end],
			ChunkIndex:  int32(i),   //nolint:gosec // G115: bounded by total > math.MaxInt32 check above
			TotalChunks: int32(total), //nolint:gosec // G115: bounded by total > math.MaxInt32 check above
			Version:     cfg.Version,
			ConfigId:    cfg.ID,
		})
	}
	return chunks, nil
}

// chunksToConfigTransfer reassembles chunks into a ConfigTransfer.
//
// Chunks are sorted by index before reassembly; a nil or empty slice returns
// an error.
func chunksToConfigTransfer(chunks []*transportpb.ConfigChunk) (*types.ConfigTransfer, error) {
	if len(chunks) == 0 {
		return nil, fmt.Errorf("no chunks to reassemble")
	}

	sort.Slice(chunks, func(i, j int) bool {
		return chunks[i].ChunkIndex < chunks[j].ChunkIndex
	})

	var data []byte
	for _, c := range chunks {
		data = append(data, c.Data...)
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

	total := (len(data) + chunkSize - 1) / chunkSize
	if total > math.MaxInt32 {
		return nil, fmt.Errorf("DNA data too large to chunk: %d chunks exceeds int32 limit", total)
	}
	chunks := make([]*transportpb.DNAChunk, 0, total)
	for i := 0; i < total; i++ {
		start := i * chunkSize
		end := start + chunkSize
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
func chunksToDNATransfer(chunks []*transportpb.DNAChunk) (*types.DNATransfer, error) {
	if len(chunks) == 0 {
		return nil, fmt.Errorf("no chunks to reassemble")
	}

	sort.Slice(chunks, func(i, j int) bool {
		return chunks[i].ChunkIndex < chunks[j].ChunkIndex
	})

	var data []byte
	for _, c := range chunks {
		data = append(data, c.Data...)
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

// bulkTransferToChunks serialises bulk to JSON and splits into ≤64 KB chunks.
func bulkTransferToChunks(bulk *types.BulkTransfer) ([]*transportpb.BulkChunk, error) {
	data, err := json.Marshal(bulk)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal BulkTransfer: %w", err)
	}

	if len(data) == 0 {
		return []*transportpb.BulkChunk{{
			TransferId: bulk.ID,
			Data:       []byte{},
			TotalSize:  0,
			IsLast:     true,
		}}, nil
	}

	total := (len(data) + chunkSize - 1) / chunkSize
	chunks := make([]*transportpb.BulkChunk, 0, total)
	for i := 0; i < total; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > len(data) {
			end = len(data)
		}
		isLast := i == total-1
		chunks = append(chunks, &transportpb.BulkChunk{
			TransferId: bulk.ID,
			Data:       data[start:end],
			Offset:     int64(start),
			TotalSize:  int64(len(data)),
			IsLast:     isLast,
			Metadata:   bulk.Metadata,
		})
	}
	return chunks, nil
}

// chunksToBulkTransfer reassembles bulk chunks into a BulkTransfer.
func chunksToBulkTransfer(chunks []*transportpb.BulkChunk) (*types.BulkTransfer, error) {
	if len(chunks) == 0 {
		return nil, fmt.Errorf("no chunks to reassemble")
	}

	sort.Slice(chunks, func(i, j int) bool {
		return chunks[i].Offset < chunks[j].Offset
	})

	var data []byte
	for _, c := range chunks {
		data = append(data, c.Data...)
	}

	if len(data) == 0 {
		return &types.BulkTransfer{
			ID:       chunks[0].TransferId,
			Metadata: chunks[0].Metadata,
		}, nil
	}

	var bulk types.BulkTransfer
	if err := json.Unmarshal(data, &bulk); err != nil {
		return nil, fmt.Errorf("failed to unmarshal BulkTransfer: %w", err)
	}
	return &bulk, nil
}
