// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package storage provides tests for DNA compression.

package storage

import (
	"bytes"
	"compress/gzip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
)

// buildRealisticDNA returns a DNA with non-attribute metadata fields and non-zero timestamps.
// Attribute dict encoding was retired (Issue #3329); attributes do not survive a
// compress+decompress cycle through OptimizedDNACompressor.
func buildRealisticDNA() *commonpb.DNA {
	return &commonpb.DNA{
		Id:              "device-12345",
		ConfigHash:      "abc123def456",
		AttributeCount:  15,
		SyncFingerprint: "fp-xyz789",
		LastUpdated:     &timestamppb.Timestamp{Seconds: 1700000000, Nanos: 123456789},
		LastSyncTime:    &timestamppb.Timestamp{Seconds: 1700000100, Nanos: 987654321},
	}
}

func TestOptimizedDNACompressor_RoundTrip(t *testing.T) {
	dna := buildRealisticDNA()

	compressor, err := NewOptimizedDNACompressor("gzip", 6)
	require.NoError(t, err)
	defer func() { _ = compressor.Close() }()

	compressed, originalSize, err := compressor.Compress(dna)
	require.NoError(t, err)
	assert.Positive(t, originalSize)
	assert.NotEmpty(t, compressed)

	decompressed, err := compressor.Decompress(compressed)
	require.NoError(t, err)
	require.NotNil(t, decompressed)

	// proto.Equal covers all retained metadata fields. Attributes are not stored in
	// the optimized payload (retired, Issue #3329) so the input DNA must not carry them.
	assert.True(t, proto.Equal(dna, decompressed),
		"round-trip must return semantically identical DNA\nwant: %v\ngot:  %v", dna, decompressed)
}

func TestOptimizedDNACompressor_RoundTrip_EmptyDNA(t *testing.T) {
	dna := &commonpb.DNA{
		Id:         "empty-device",
		ConfigHash: "hash-empty",
	}

	compressor, err := NewOptimizedDNACompressor("gzip", 6)
	require.NoError(t, err)
	defer func() { _ = compressor.Close() }()

	compressed, _, err := compressor.Compress(dna)
	require.NoError(t, err)

	decompressed, err := compressor.Decompress(compressed)
	require.NoError(t, err)
	assert.True(t, proto.Equal(dna, decompressed))
}

func TestOptimizedDNACompressor_RoundTrip_NilTimestamps(t *testing.T) {
	dna := &commonpb.DNA{
		Id:              "no-timestamps",
		ConfigHash:      "cfg",
		SyncFingerprint: "fp",
		AttributeCount:  2,
	}

	compressor, err := NewOptimizedDNACompressor("gzip", 6)
	require.NoError(t, err)
	defer func() { _ = compressor.Close() }()

	compressed, _, err := compressor.Compress(dna)
	require.NoError(t, err)

	decompressed, err := compressor.Decompress(compressed)
	require.NoError(t, err)
	assert.True(t, proto.Equal(dna, decompressed))
	assert.Nil(t, decompressed.LastUpdated)
	assert.Nil(t, decompressed.LastSyncTime)
}

func TestNewCompressor_DNAOptimized(t *testing.T) {
	compressor, err := NewCompressor("dna-optimized", 6)
	require.NoError(t, err)
	require.NotNil(t, compressor)

	_, ok := compressor.(*OptimizedDNACompressor)
	assert.True(t, ok, "NewCompressor(\"dna-optimized\") must return *OptimizedDNACompressor")

	defer func() { _ = compressor.Close() }()

	// Verify it is fully functional end-to-end via the factory.
	dna := buildRealisticDNA()
	compressed, _, err := compressor.Compress(dna)
	require.NoError(t, err)

	decompressed, err := compressor.Decompress(compressed)
	require.NoError(t, err)
	assert.True(t, proto.Equal(dna, decompressed))
}

func TestOptimizedDNACompressor_Decompress_CorruptGzip(t *testing.T) {
	compressor, err := NewOptimizedDNACompressor("gzip", 6)
	require.NoError(t, err)
	defer func() { _ = compressor.Close() }()

	_, err = compressor.Decompress([]byte("not valid gzip data"))
	assert.Error(t, err)
}

func TestOptimizedDNACompressor_Decompress_ValidGzipBadJSON(t *testing.T) {
	compressor, err := NewOptimizedDNACompressor("gzip", 6)
	require.NoError(t, err)
	defer func() { _ = compressor.Close() }()

	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, _ = w.Write([]byte("{ not valid json !!!"))
	_ = w.Close()

	_, err = compressor.Decompress(buf.Bytes())
	assert.Error(t, err)
}

func TestOptimizedDNACompressor_Stats(t *testing.T) {
	compressor, err := NewOptimizedDNACompressor("gzip", 6)
	require.NoError(t, err)
	defer func() { _ = compressor.Close() }()

	dna := buildRealisticDNA()
	_, _, err = compressor.Compress(dna)
	require.NoError(t, err)

	stats := compressor.GetStats()
	assert.Positive(t, stats.TotalOperations)
	assert.Positive(t, stats.TotalBytesIn)
	assert.Positive(t, stats.TotalBytesOut)
	assert.Positive(t, compressor.GetCompressionRatio())
}
