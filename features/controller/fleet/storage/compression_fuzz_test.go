// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package storage

import (
	"testing"

	"google.golang.org/protobuf/types/known/timestamppb"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
)

// FuzzGzipDecompress fuzzes (*GzipCompressor).Decompress at the storage
// read-back boundary (compression.go:111). The decompression-bomb surface:
// an attacker who can write to the config store's compressed blob could trigger
// unbounded memory growth on decompress without this check. Seed corpus is
// real compressed DNA so the fuzzer starts from a structurally valid input.
func FuzzGzipDecompress(f *testing.F) {
	c, err := NewGzipCompressor(6)
	if err != nil {
		f.Fatal(err)
	}

	seeds := []*commonpb.DNA{
		{
			Id:              "device-seed-1",
			ConfigHash:      "abc123",
			AttributeCount:  3,
			SyncFingerprint: "fp-seed-1",
			LastUpdated:     &timestamppb.Timestamp{Seconds: 1700000000, Nanos: 123456789},
			LastSyncTime:    &timestamppb.Timestamp{Seconds: 1700000100, Nanos: 987654321},
			Attributes: map[string]string{
				"os.name":    "Ubuntu",
				"os.version": "22.04",
				"os.arch":    "amd64",
			},
		},
		{
			Id:         "device-seed-2",
			ConfigHash: "def456",
			Attributes: map[string]string{},
		},
		{
			Id:              "device-seed-3",
			ConfigHash:      "ghi789",
			AttributeCount:  1,
			SyncFingerprint: "fp-seed-3",
			Attributes: map[string]string{
				"hardware.cpu": "AMD EPYC 7543",
			},
		},
	}

	for _, dna := range seeds {
		compressed, _, err := c.Compress(dna)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(compressed)
	}

	// Seed with trivially invalid inputs so the fuzzer explores the error path.
	f.Add([]byte{})
	f.Add([]byte("not gzip"))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Any panic is a bug. Errors from malformed input are expected and safe.
		_, _ = c.Decompress(data)
	})
}

// FuzzOptimizedDNADecompress fuzzes (*OptimizedDNACompressor).Decompress
// (compression.go:468) — a distinct decode boundary from FuzzGzipDecompress:
// gzip-decompress then json.Unmarshal into serializedOptimizedPayload, then
// manual field-by-field reconstruction. Reachable via NewCompressor("dna-optimized",
// level) called from storage.go with config.CompressionType. Zstd/LZ4 are
// intentionally not separately fuzzed: their Decompress methods are one-line
// delegates to GzipCompressor.Decompress (compression.go:225, :308) and would
// exercise the exact same code path as FuzzGzipDecompress above.
func FuzzOptimizedDNADecompress(f *testing.F) {
	c, err := NewOptimizedDNACompressor("gzip", 6)
	if err != nil {
		f.Fatal(err)
	}

	seeds := []*commonpb.DNA{
		buildRealisticDNA(),
		{
			Id:         "empty-device",
			ConfigHash: "hash-empty",
			Attributes: map[string]string{},
		},
		{
			Id:              "no-timestamps",
			ConfigHash:      "cfg",
			SyncFingerprint: "fp",
			AttributeCount:  2,
			Attributes: map[string]string{
				"key1": "val1",
				"key2": "val2",
			},
		},
	}

	for _, dna := range seeds {
		compressed, _, err := c.Compress(dna)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(compressed)
	}

	f.Add([]byte{})
	f.Add([]byte("not gzip"))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Any panic is a bug. Errors from malformed input are expected and safe.
		_, _ = c.Decompress(data)
	})
}
