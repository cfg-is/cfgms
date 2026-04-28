// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package grpc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/dataplane/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeTestSession creates a minimal session suitable for unit tests.
func makeTestSession(mode string) *Session {
	return &Session{
		id:       "test-session-id",
		peerID:   "test-peer",
		mode:     mode,
		provider: New(),
	}
}

// TestSession_ID verifies the session returns its ID.
func TestSession_ID(t *testing.T) {
	s := makeTestSession("client")
	assert.Equal(t, "test-session-id", s.ID())
}

// TestSession_PeerID verifies the session returns its peer ID.
func TestSession_PeerID(t *testing.T) {
	s := makeTestSession("client")
	assert.Equal(t, "test-peer", s.PeerID())
}

// TestSession_OpenStream_NotSupported verifies a clear error is returned.
func TestSession_OpenStream_NotSupported(t *testing.T) {
	s := makeTestSession("client")
	stream, err := s.OpenStream(context.Background(), types.StreamConfig)
	assert.Nil(t, stream)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "gRPC provider does not support raw streams")
	assert.Contains(t, err.Error(), "SendConfig")
}

// TestSession_AcceptStream_NotSupported verifies a clear error is returned.
func TestSession_AcceptStream_NotSupported(t *testing.T) {
	s := makeTestSession("server")
	stream, streamType, err := s.AcceptStream(context.Background())
	assert.Nil(t, stream)
	assert.Empty(t, streamType)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "gRPC provider does not support raw streams")
	assert.Contains(t, err.Error(), "ReceiveConfig")
}

// TestSession_Close verifies Close marks the session as closed.
func TestSession_Close(t *testing.T) {
	s := makeTestSession("client")
	assert.False(t, s.IsClosed())
	require.NoError(t, s.Close(context.Background()))
	assert.True(t, s.IsClosed())
}

// TestSession_OperationsAfterClose verifies all transfer methods return errors after close.
func TestSession_OperationsAfterClose(t *testing.T) {
	s := makeTestSession("client")
	require.NoError(t, s.Close(context.Background()))

	ctx := context.Background()
	err := s.SendConfig(ctx, &types.ConfigTransfer{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "session closed")

	_, err = s.ReceiveConfig(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "session closed")

	err = s.SendDNA(ctx, &types.DNATransfer{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "session closed")

	_, err = s.ReceiveDNA(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "session closed")

	err = s.SendBulk(ctx, &types.BulkTransfer{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "session closed")

	_, err = s.ReceiveBulk(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "session closed")
}

// =============================================================================
// Conversion tests (13-19)
// =============================================================================

// TestConfigTransferToChunks verifies a 200 KB config splits into 4 chunks (last smaller).
func TestConfigTransferToChunks(t *testing.T) {
	// 200 KB of payload data
	payload := bytes.Repeat([]byte("x"), 200*1024)
	cfg := &types.ConfigTransfer{
		ID:        "cfg-test",
		StewardID: "steward-1",
		TenantID:  "tenant-1",
		Version:   "2.0.0",
		Data:      payload,
	}

	chunks, err := configTransferToChunks(cfg)
	require.NoError(t, err)
	require.NotEmpty(t, chunks)

	// The JSON of a 200 KB payload will be slightly larger than 200 KB.
	// Each chunk ≤ 64 KB, so we expect ≥ 4 chunks.
	assert.GreaterOrEqual(t, len(chunks), 4)

	for i, c := range chunks {
		assert.Equal(t, int32(i), c.ChunkIndex, "chunk index mismatch at position %d", i)
		assert.Equal(t, int32(len(chunks)), c.TotalChunks)
		assert.Equal(t, "cfg-test", c.ConfigId)
		assert.Equal(t, "2.0.0", c.Version)
		assert.LessOrEqual(t, len(c.Data), chunkSize, "chunk %d exceeds max size", i)
	}
	// Last chunk must be smaller or equal to chunkSize
	lastChunk := chunks[len(chunks)-1]
	assert.LessOrEqual(t, len(lastChunk.Data), chunkSize)
}

// TestChunksToConfigTransfer verifies chunks reassemble to the original config.
func TestChunksToConfigTransfer(t *testing.T) {
	payload := bytes.Repeat([]byte("y"), 200*1024)
	original := &types.ConfigTransfer{
		ID:        "cfg-roundtrip",
		StewardID: "steward-2",
		TenantID:  "tenant-2",
		Version:   "3.0.0",
		Data:      payload,
	}

	chunks, err := configTransferToChunks(original)
	require.NoError(t, err)

	reassembled, err := chunksToConfigTransfer(chunks)
	require.NoError(t, err)
	require.NotNil(t, reassembled)

	assert.Equal(t, original.ID, reassembled.ID)
	assert.Equal(t, original.StewardID, reassembled.StewardID)
	assert.Equal(t, original.Version, reassembled.Version)
	assert.Equal(t, payload, reassembled.Data)
}

// TestDNATransferToChunks verifies DNA data splits correctly.
func TestDNATransferToChunks(t *testing.T) {
	attrs := bytes.Repeat([]byte("a"), 100*1024)
	dna := &types.DNATransfer{
		ID:         "dna-test",
		StewardID:  "steward-3",
		TenantID:   "tenant-3",
		Attributes: attrs,
		Delta:      true,
	}

	chunks, err := dnaTransferToChunks(dna)
	require.NoError(t, err)
	require.NotEmpty(t, chunks)

	for i, c := range chunks {
		assert.Equal(t, int32(i), c.ChunkIndex)
		assert.Equal(t, "steward-3", c.StewardId)
		assert.Equal(t, "tenant-3", c.TenantId)
		assert.LessOrEqual(t, len(c.Data), chunkSize)
	}
}

// TestBulkTransferToChunks verifies bulk data splits correctly and metadata is preserved.
func TestBulkTransferToChunks(t *testing.T) {
	data := bytes.Repeat([]byte("b"), 130*1024)
	bulk := &types.BulkTransfer{
		ID:        "bulk-test",
		StewardID: "steward-4",
		TenantID:  "tenant-4",
		Direction: "to_steward",
		Type:      "file",
		TotalSize: int64(len(data)),
		Data:      data,
		Metadata:  map[string]string{"filename": "deploy.sh"},
	}

	chunks, err := bulkTransferToChunks(bulk)
	require.NoError(t, err)
	require.NotEmpty(t, chunks)

	for i, c := range chunks {
		assert.Equal(t, "bulk-test", c.TransferId)
		assert.LessOrEqual(t, len(c.Data), chunkSize, "chunk %d too large", i)
	}
	// Last chunk must have is_last = true
	assert.True(t, chunks[len(chunks)-1].IsLast)
}

// TestChunkRoundTrip_Config verifies marshal → chunks → unmarshal preserves data exactly.
func TestChunkRoundTrip_Config(t *testing.T) {
	ts := time.Date(2026, 3, 23, 0, 0, 0, 0, time.UTC)
	original := &types.ConfigTransfer{
		ID:        "rt-cfg-1",
		StewardID: "steward-rt",
		TenantID:  "tenant-rt",
		Version:   "5.1.2",
		Timestamp: ts,
		Data:      []byte(`{"modules":["file","firewall"]}`),
		Signature: []byte("sig-bytes"),
		Metadata:  map[string]string{"encoding": "json"},
	}

	chunks, err := configTransferToChunks(original)
	require.NoError(t, err)

	got, err := chunksToConfigTransfer(chunks)
	require.NoError(t, err)

	assert.Equal(t, original.ID, got.ID)
	assert.Equal(t, original.StewardID, got.StewardID)
	assert.Equal(t, original.TenantID, got.TenantID)
	assert.Equal(t, original.Version, got.Version)
	assert.Equal(t, original.Data, got.Data)
	assert.Equal(t, original.Signature, got.Signature)
	assert.Equal(t, original.Metadata, got.Metadata)
}

// TestChunkRoundTrip_DNA verifies marshal → chunks → unmarshal preserves DNA data exactly.
func TestChunkRoundTrip_DNA(t *testing.T) {
	original := &types.DNATransfer{
		ID:          "rt-dna-1",
		StewardID:   "steward-rt",
		TenantID:    "tenant-rt",
		Attributes:  []byte(`{"os":"linux","cpu":"arm64"}`),
		Delta:       true,
		BaseVersion: "v4",
		Metadata:    map[string]string{"collector": "v2"},
	}

	chunks, err := dnaTransferToChunks(original)
	require.NoError(t, err)

	got, err := chunksToDNATransfer(chunks)
	require.NoError(t, err)

	assert.Equal(t, original.ID, got.ID)
	assert.Equal(t, original.StewardID, got.StewardID)
	assert.Equal(t, original.Attributes, got.Attributes)
	assert.Equal(t, original.Delta, got.Delta)
	assert.Equal(t, original.BaseVersion, got.BaseVersion)
}

// TestChunkRoundTrip_EmptyData verifies empty transfer produces 1 chunk with empty data.
func TestChunkRoundTrip_EmptyData(t *testing.T) {
	// Empty ConfigTransfer data
	cfg := &types.ConfigTransfer{
		ID:      "empty-cfg",
		Version: "0.0.1",
		Data:    []byte{},
	}

	// Marshal empty cfg → JSON has other fields but Data is empty
	data, err := json.Marshal(cfg)
	require.NoError(t, err)
	// The JSON will be non-empty because the struct has other fields.
	// configTransferToChunks will produce at least 1 chunk.
	_ = data

	chunks, err := configTransferToChunks(cfg)
	require.NoError(t, err)
	require.NotEmpty(t, chunks)

	got, err := chunksToConfigTransfer(chunks)
	require.NoError(t, err)
	assert.Equal(t, "empty-cfg", got.ID)
	assert.Equal(t, "0.0.1", got.Version)
}

// TestChunksToConfigTransfer_EmptyChunks verifies an error on empty chunk slice.
func TestChunksToConfigTransfer_EmptyChunks(t *testing.T) {
	_, err := chunksToConfigTransfer(nil)
	require.Error(t, err)
}

// TestChunksToDNATransfer_EmptyChunks verifies an error on empty chunk slice.
func TestChunksToDNATransfer_EmptyChunks(t *testing.T) {
	_, err := chunksToDNATransfer(nil)
	require.Error(t, err)
}

// TestChunksToBulkTransfer_EmptyChunks verifies an error on empty chunk slice.
func TestChunksToBulkTransfer_EmptyChunks(t *testing.T) {
	_, err := chunksToBulkTransfer(nil)
	require.Error(t, err)
}

// TestSession_Close_RemovesFromProviderMap verifies that Close removes the session
// from the provider's sessions map, preventing unbounded map growth.
func TestSession_Close_RemovesFromProviderMap(t *testing.T) {
	p := New()

	const n = 5
	sessions := make([]*Session, n)
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("session-%d", i)
		s := &Session{
			id:       id,
			mode:     "client",
			provider: p,
		}
		p.mu.Lock()
		p.sessions[id] = s
		p.mu.Unlock()
		sessions[i] = s
	}

	p.mu.RLock()
	assert.Equal(t, n, len(p.sessions), "sessions should be in map before close")
	p.mu.RUnlock()

	for _, s := range sessions {
		require.NoError(t, s.Close(context.Background()))
	}

	p.mu.RLock()
	assert.Equal(t, 0, len(p.sessions), "sessions map should be empty after all closed")
	p.mu.RUnlock()
}

// TestSession_Close_Twice_NoPanic verifies that calling Close twice does not panic.
func TestSession_Close_Twice_NoPanic(t *testing.T) {
	p := New()
	s := &Session{
		id:       "double-close-session",
		mode:     "client",
		provider: p,
	}
	p.mu.Lock()
	p.sessions[s.id] = s
	p.mu.Unlock()

	require.NoError(t, s.Close(context.Background()))
	require.NoError(t, s.Close(context.Background()))

	p.mu.RLock()
	assert.Equal(t, 0, len(p.sessions))
	p.mu.RUnlock()
}

// TestSession_Close_Concurrent verifies that concurrent Close calls do not data-race.
// Runs N goroutines each calling Close() on a distinct session that shares a single
// provider — exercises the mutex in Close() under go test -race.
func TestSession_Close_Concurrent(t *testing.T) {
	p := New()

	const n = 20
	sessions := make([]*Session, n)
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("concurrent-session-%d", i)
		s := &Session{
			id:       id,
			mode:     "client",
			provider: p,
		}
		p.mu.Lock()
		p.sessions[id] = s
		p.mu.Unlock()
		sessions[i] = s
	}

	errCh := make(chan error, n)
	var wg sync.WaitGroup
	for _, s := range sessions {
		wg.Add(1)
		go func(s *Session) {
			defer wg.Done()
			errCh <- s.Close(context.Background())
		}(s)
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		require.NoError(t, err)
	}

	p.mu.RLock()
	assert.Equal(t, 0, len(p.sessions), "all sessions must be removed from map after concurrent closes")
	p.mu.RUnlock()
}
