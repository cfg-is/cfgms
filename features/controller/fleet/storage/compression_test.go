// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package storage provides tests for DNA compression.

package storage

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
)

// buildRealisticDNA returns a DNA with multiple attributes, nested keys, and non-zero timestamps
// to catch index-boundary bugs and nanos-loss bugs.
func buildRealisticDNA() *commonpb.DNA {
	return &commonpb.DNA{
		Id:              "device-12345",
		ConfigHash:      "abc123def456",
		AttributeCount:  15,
		SyncFingerprint: "fp-xyz789",
		LastUpdated:     &timestamppb.Timestamp{Seconds: 1700000000, Nanos: 123456789},
		LastSyncTime:    &timestamppb.Timestamp{Seconds: 1700000100, Nanos: 987654321},
		Attributes: map[string]string{
			"os.name":          "Ubuntu",
			"os.version":       "22.04",
			"os.arch":          "amd64",
			"software.nginx":   "1.24.0",
			"software.docker":  "24.0.7",
			"config.hostname":  "web-server-01",
			"config.domain":    "example.com",
			"network.ipv4":     "192.168.1.100",
			"network.ipv6":     "::1",
			"hardware.cpu":     "AMD EPYC 7543",
			"hardware.memory":  "64GB",
			"hardware.disk":    "1TB NVMe",
			"security.fw":      "active",
			"security.selinux": "enforcing",
			"monitoring.agent": "prometheus-2.45",
		},
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

	// Use proto.Equal for a complete semantic comparison including all fields.
	assert.True(t, proto.Equal(dna, decompressed),
		"round-trip must return semantically identical DNA\nwant: %v\ngot:  %v", dna, decompressed)
}

func TestOptimizedDNACompressor_RoundTrip_EmptyAttributes(t *testing.T) {
	dna := &commonpb.DNA{
		Id:         "empty-device",
		ConfigHash: "hash-empty",
		Attributes: map[string]string{},
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
		Attributes: map[string]string{
			"key1": "val1",
			"key2": "val2",
		},
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

func TestOptimizedDNACompressor_Decompress_IndexOutOfRange(t *testing.T) {
	compressor, err := NewOptimizedDNACompressor("gzip", 6)
	require.NoError(t, err)
	defer func() { _ = compressor.Close() }()

	// Craft a payload with an attribute key index that exceeds the dict.
	payload := serializedOptimizedPayload{
		Data: &OptimizedDNAData{
			ID:              "bad-device",
			AttributeKeys:   []int{99}, // out of range
			AttributeValues: []int{0},
		},
		AttributeDict: []string{"only-one-key"},
		ValueDict:     []string{"only-one-value"},
	}
	raw, err := json.Marshal(payload)
	require.NoError(t, err)

	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, _ = w.Write(raw)
	_ = w.Close()

	_, err = compressor.Decompress(buf.Bytes())
	assert.Error(t, err)
}

func TestOptimizedDNACompressor_Decompress_KeyValueLengthMismatch(t *testing.T) {
	compressor, err := NewOptimizedDNACompressor("gzip", 6)
	require.NoError(t, err)
	defer func() { _ = compressor.Close() }()

	payload := serializedOptimizedPayload{
		Data: &OptimizedDNAData{
			ID:              "mismatch-device",
			AttributeKeys:   []int{0, 1},
			AttributeValues: []int{0}, // one fewer value than keys
		},
		AttributeDict: []string{"key-a", "key-b"},
		ValueDict:     []string{"val-a"},
	}
	raw, err := json.Marshal(payload)
	require.NoError(t, err)

	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, _ = w.Write(raw)
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
