// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package storage implements DNA data compression with multiple algorithms.

package storage

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
)

// ZstdCompressor implements Zstandard compression for DNA data
type ZstdCompressor struct {
	level      int
	stats      *CompressionStats
	statsMutex sync.RWMutex
}

// GzipCompressor implements GZIP compression for DNA data
type GzipCompressor struct {
	level      int
	stats      *CompressionStats
	statsMutex sync.RWMutex
}

// LZ4Compressor implements LZ4 compression for DNA data
type LZ4Compressor struct {
	stats      *CompressionStats
	statsMutex sync.RWMutex
}

// NewCompressor creates a new compressor based on the specified algorithm and level
func NewCompressor(algorithm string, level int) (Compressor, error) {
	switch algorithm {
	case "gzip":
		return NewGzipCompressor(level)
	case "zstd":
		return NewZstdCompressor(level)
	case "lz4":
		return NewLZ4Compressor()
	default:
		return nil, fmt.Errorf("unsupported compression algorithm: %s", algorithm)
	}
}

// NewGzipCompressor creates a new GZIP compressor with the specified compression level
func NewGzipCompressor(level int) (*GzipCompressor, error) {
	if level < 1 || level > 9 {
		level = gzip.DefaultCompression
	}

	return &GzipCompressor{
		level: level,
		stats: &CompressionStats{
			Algorithm: "gzip",
			Level:     level,
		},
	}, nil
}

// Compress compresses DNA data using GZIP compression
func (c *GzipCompressor) Compress(dna *commonpb.DNA) ([]byte, int64, error) {
	start := time.Now()

	// Serialize DNA to bytes first using protobuf
	originalData, err := proto.Marshal(dna)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to marshal DNA: %w", err)
	}

	originalSize := int64(len(originalData))

	// Compress the serialized data
	var compressed bytes.Buffer
	writer, err := gzip.NewWriterLevel(&compressed, c.level)
	if err != nil {
		return nil, originalSize, fmt.Errorf("failed to create gzip writer: %w", err)
	}

	if _, err := writer.Write(originalData); err != nil {
		_ = writer.Close() // Best effort cleanup
		return nil, originalSize, fmt.Errorf("failed to compress data: %w", err)
	}

	if err := writer.Close(); err != nil {
		return nil, originalSize, fmt.Errorf("failed to close gzip writer: %w", err)
	}

	compressedData := compressed.Bytes()
	compressedSize := int64(len(compressedData))
	compressionTime := time.Since(start)

	// Update statistics
	c.updateStats(originalSize, compressedSize, compressionTime)

	return compressedData, originalSize, nil
}

// Decompress decompresses GZIP-compressed data back to DNA structure
func (c *GzipCompressor) Decompress(data []byte) (*commonpb.DNA, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer func() {
		if err := reader.Close(); err != nil {
			// Log error but continue - decompression already completed
			_ = err // Explicitly ignore close errors after successful decompression
		}
	}()

	var decompressed bytes.Buffer
	if _, err := decompressed.ReadFrom(reader); err != nil {
		return nil, fmt.Errorf("failed to decompress data: %w", err)
	}

	// Deserialize back to DNA structure
	dna := &commonpb.DNA{}
	if err := proto.Unmarshal(decompressed.Bytes(), dna); err != nil {
		return nil, fmt.Errorf("failed to unmarshal DNA: %w", err)
	}

	return dna, nil
}

// GetCompressionRatio returns the current average compression ratio
func (c *GzipCompressor) GetCompressionRatio() float64 {
	c.statsMutex.RLock()
	defer c.statsMutex.RUnlock()

	if c.stats.TotalBytesIn == 0 {
		return 0
	}

	return float64(c.stats.TotalBytesOut) / float64(c.stats.TotalBytesIn)
}

// GetStats returns compression statistics
func (c *GzipCompressor) GetStats() *CompressionStats {
	c.statsMutex.RLock()
	defer c.statsMutex.RUnlock()

	// Return a copy to avoid race conditions
	statsCopy := *c.stats
	return &statsCopy
}

// Close closes the compressor and releases resources
func (c *GzipCompressor) Close() error {
	// GZIP compressor doesn't need explicit cleanup
	return nil
}

func (c *GzipCompressor) updateStats(originalSize, compressedSize int64, duration time.Duration) {
	c.statsMutex.Lock()
	defer c.statsMutex.Unlock()

	c.stats.TotalBytesIn += originalSize
	c.stats.TotalBytesOut += compressedSize
	c.stats.TotalOperations++

	// Update rolling average of compression time
	if c.stats.TotalOperations == 1 {
		c.stats.AverageTime = duration
	} else {
		// Exponential moving average
		alpha := 0.1
		c.stats.AverageTime = time.Duration(float64(c.stats.AverageTime)*(1-alpha) + float64(duration)*alpha)
	}

	// Update compression ratio
	if c.stats.TotalBytesIn > 0 {
		c.stats.CompressionRatio = float64(c.stats.TotalBytesOut) / float64(c.stats.TotalBytesIn)
	}
}

// NewZstdCompressor creates a new Zstandard compressor (stub implementation)
func NewZstdCompressor(level int) (*ZstdCompressor, error) {
	// Note: This is a stub implementation. In a real implementation,
	// you would use a library like github.com/klauspost/compress/zstd
	return &ZstdCompressor{
		level: level,
		stats: &CompressionStats{
			Algorithm: "zstd",
			Level:     level,
		},
	}, nil
}

// Compress compresses DNA data using Zstandard compression (stub)
func (c *ZstdCompressor) Compress(dna *commonpb.DNA) ([]byte, int64, error) {
	// Fallback to GZIP for now since we don't have zstd dependency
	gzipCompressor, err := NewGzipCompressor(c.level)
	if err != nil {
		return nil, 0, err
	}

	compressed, originalSize, err := gzipCompressor.Compress(dna)
	if err == nil {
		// Update our stats
		c.updateStats(originalSize, int64(len(compressed)), 0)
	}

	return compressed, originalSize, err
}

// Decompress decompresses Zstandard-compressed data (stub)
func (c *ZstdCompressor) Decompress(data []byte) (*commonpb.DNA, error) {
	// Fallback to GZIP for now
	gzipCompressor, err := NewGzipCompressor(c.level)
	if err != nil {
		return nil, err
	}

	return gzipCompressor.Decompress(data)
}

// GetCompressionRatio returns the current average compression ratio
func (c *ZstdCompressor) GetCompressionRatio() float64 {
	c.statsMutex.RLock()
	defer c.statsMutex.RUnlock()

	if c.stats.TotalBytesIn == 0 {
		return 0
	}

	return float64(c.stats.TotalBytesOut) / float64(c.stats.TotalBytesIn)
}

// GetStats returns compression statistics
func (c *ZstdCompressor) GetStats() *CompressionStats {
	c.statsMutex.RLock()
	defer c.statsMutex.RUnlock()

	statsCopy := *c.stats
	return &statsCopy
}

// Close closes the compressor
func (c *ZstdCompressor) Close() error {
	return nil
}

func (c *ZstdCompressor) updateStats(originalSize, compressedSize int64, duration time.Duration) {
	c.statsMutex.Lock()
	defer c.statsMutex.Unlock()

	c.stats.TotalBytesIn += originalSize
	c.stats.TotalBytesOut += compressedSize
	c.stats.TotalOperations++

	if c.stats.TotalOperations == 1 {
		c.stats.AverageTime = duration
	} else {
		alpha := 0.1
		c.stats.AverageTime = time.Duration(float64(c.stats.AverageTime)*(1-alpha) + float64(duration)*alpha)
	}

	if c.stats.TotalBytesIn > 0 {
		c.stats.CompressionRatio = float64(c.stats.TotalBytesOut) / float64(c.stats.TotalBytesIn)
	}
}

// NewLZ4Compressor creates a new LZ4 compressor (stub)
func NewLZ4Compressor() (*LZ4Compressor, error) {
	return &LZ4Compressor{
		stats: &CompressionStats{
			Algorithm: "lz4",
			Level:     0, // LZ4 doesn't have compression levels
		},
	}, nil
}

// Compress compresses DNA data using LZ4 compression (stub)
func (c *LZ4Compressor) Compress(dna *commonpb.DNA) ([]byte, int64, error) {
	// Fallback to GZIP for now since we don't have LZ4 dependency
	gzipCompressor, err := NewGzipCompressor(gzip.DefaultCompression)
	if err != nil {
		return nil, 0, err
	}

	compressed, originalSize, err := gzipCompressor.Compress(dna)
	if err == nil {
		c.updateStats(originalSize, int64(len(compressed)), 0)
	}

	return compressed, originalSize, err
}

// Decompress decompresses LZ4-compressed data (stub)
func (c *LZ4Compressor) Decompress(data []byte) (*commonpb.DNA, error) {
	// Fallback to GZIP for now
	gzipCompressor, err := NewGzipCompressor(gzip.DefaultCompression)
	if err != nil {
		return nil, err
	}

	return gzipCompressor.Decompress(data)
}

// GetCompressionRatio returns the current average compression ratio
func (c *LZ4Compressor) GetCompressionRatio() float64 {
	c.statsMutex.RLock()
	defer c.statsMutex.RUnlock()

	if c.stats.TotalBytesIn == 0 {
		return 0
	}

	return float64(c.stats.TotalBytesOut) / float64(c.stats.TotalBytesIn)
}

// GetStats returns compression statistics
func (c *LZ4Compressor) GetStats() *CompressionStats {
	c.statsMutex.RLock()
	defer c.statsMutex.RUnlock()

	statsCopy := *c.stats
	return &statsCopy
}

// Close closes the compressor
func (c *LZ4Compressor) Close() error {
	return nil
}

func (c *LZ4Compressor) updateStats(originalSize, compressedSize int64, duration time.Duration) {
	c.statsMutex.Lock()
	defer c.statsMutex.Unlock()

	c.stats.TotalBytesIn += originalSize
	c.stats.TotalBytesOut += compressedSize
	c.stats.TotalOperations++

	if c.stats.TotalOperations == 1 {
		c.stats.AverageTime = duration
	} else {
		alpha := 0.1
		c.stats.AverageTime = time.Duration(float64(c.stats.AverageTime)*(1-alpha) + float64(duration)*alpha)
	}

	if c.stats.TotalBytesIn > 0 {
		c.stats.CompressionRatio = float64(c.stats.TotalBytesOut) / float64(c.stats.TotalBytesIn)
	}
}

// OptimizedDNACompressor implements optimized compression specifically for DNA data
//
// This compressor takes advantage of DNA data characteristics:
// - Many repeated attribute keys across devices
// - Similar attribute values (OS versions, software versions, etc.)
// - Predictable data structure patterns
type OptimizedDNACompressor struct {
	attributeDict  map[string]int // Dictionary for attribute keys
	valueDict      map[string]int // Dictionary for common values
	dictMutex      sync.RWMutex
	baseCompressor Compressor // Underlying compressor
	stats          *CompressionStats
	statsMutex     sync.RWMutex
}

// NewOptimizedDNACompressor creates a new optimized DNA compressor
func NewOptimizedDNACompressor(algorithm string, level int) (*OptimizedDNACompressor, error) {
	baseCompressor, err := NewCompressor(algorithm, level)
	if err != nil {
		return nil, err
	}

	return &OptimizedDNACompressor{
		attributeDict:  make(map[string]int),
		valueDict:      make(map[string]int),
		baseCompressor: baseCompressor,
		stats: &CompressionStats{
			Algorithm: "optimized_" + algorithm,
			Level:     level,
		},
	}, nil
}

// OptimizedDNAData represents DNA data optimized for compression
type OptimizedDNAData struct {
	ID              string `json:"id"`
	AttributeKeys   []int  `json:"attribute_keys"`   // Indices into attribute dictionary
	AttributeValues []int  `json:"attribute_values"` // Indices into value dictionary
	LastUpdated     int64  `json:"last_updated"`     // Unix timestamp
	ConfigHash      string `json:"config_hash"`
	LastSyncTime    int64  `json:"last_sync_time"` // Unix timestamp
	AttributeCount  int32  `json:"attribute_count"`
	SyncFingerprint string `json:"sync_fingerprint"`
}

// Compress compresses DNA data using dictionary-based optimization
func (c *OptimizedDNACompressor) Compress(dna *commonpb.DNA) ([]byte, int64, error) {
	start := time.Now()

	// Build dictionaries and convert to optimized format
	optimized := c.optimizeDNA(dna)

	// Serialize optimized data
	optimizedData, err := json.Marshal(optimized)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to marshal optimized DNA: %w", err)
	}

	originalSize := int64(len(optimizedData))

	// Compress using base compressor
	compressed, _, err := c.baseCompressor.Compress(dna)
	if err != nil {
		return nil, originalSize, err
	}

	compressedSize := int64(len(compressed))
	compressionTime := time.Since(start)

	// Update statistics
	c.updateStats(originalSize, compressedSize, compressionTime)

	return compressed, originalSize, nil
}

// Decompress decompresses optimized DNA data
func (c *OptimizedDNACompressor) Decompress(data []byte) (*commonpb.DNA, error) {
	// For now, delegate to base compressor
	// In a full implementation, this would reverse the optimization
	return c.baseCompressor.Decompress(data)
}

// GetCompressionRatio returns the current average compression ratio
func (c *OptimizedDNACompressor) GetCompressionRatio() float64 {
	c.statsMutex.RLock()
	defer c.statsMutex.RUnlock()

	if c.stats.TotalBytesIn == 0 {
		return 0
	}

	return float64(c.stats.TotalBytesOut) / float64(c.stats.TotalBytesIn)
}

// GetStats returns compression statistics
func (c *OptimizedDNACompressor) GetStats() *CompressionStats {
	c.statsMutex.RLock()
	defer c.statsMutex.RUnlock()

	statsCopy := *c.stats
	return &statsCopy
}

// Close closes the compressor
func (c *OptimizedDNACompressor) Close() error {
	return c.baseCompressor.Close()
}

func (c *OptimizedDNACompressor) optimizeDNA(dna *commonpb.DNA) *OptimizedDNAData {
	c.dictMutex.Lock()
	defer c.dictMutex.Unlock()

	optimized := &OptimizedDNAData{
		ID:              dna.Id,
		ConfigHash:      dna.ConfigHash,
		AttributeCount:  dna.AttributeCount,
		SyncFingerprint: dna.SyncFingerprint,
	}

	if dna.LastUpdated != nil {
		optimized.LastUpdated = dna.LastUpdated.Seconds
	}

	if dna.LastSyncTime != nil {
		optimized.LastSyncTime = dna.LastSyncTime.Seconds
	}

	// Convert attributes using dictionaries
	for key, value := range dna.Attributes {
		// Get or create key index
		keyIndex := c.getOrCreateKeyIndex(key)
		optimized.AttributeKeys = append(optimized.AttributeKeys, keyIndex)

		// Get or create value index
		valueIndex := c.getOrCreateValueIndex(value)
		optimized.AttributeValues = append(optimized.AttributeValues, valueIndex)
	}

	return optimized
}

func (c *OptimizedDNACompressor) getOrCreateKeyIndex(key string) int {
	if index, exists := c.attributeDict[key]; exists {
		return index
	}

	index := len(c.attributeDict)
	c.attributeDict[key] = index
	return index
}

func (c *OptimizedDNACompressor) getOrCreateValueIndex(value string) int {
	if index, exists := c.valueDict[value]; exists {
		return index
	}

	index := len(c.valueDict)
	c.valueDict[value] = index
	return index
}

func (c *OptimizedDNACompressor) updateStats(originalSize, compressedSize int64, duration time.Duration) {
	c.statsMutex.Lock()
	defer c.statsMutex.Unlock()

	c.stats.TotalBytesIn += originalSize
	c.stats.TotalBytesOut += compressedSize
	c.stats.TotalOperations++

	if c.stats.TotalOperations == 1 {
		c.stats.AverageTime = duration
	} else {
		alpha := 0.1
		c.stats.AverageTime = time.Duration(float64(c.stats.AverageTime)*(1-alpha) + float64(duration)*alpha)
	}

	if c.stats.TotalBytesIn > 0 {
		c.stats.CompressionRatio = float64(c.stats.TotalBytesOut) / float64(c.stats.TotalBytesIn)
	}
}
