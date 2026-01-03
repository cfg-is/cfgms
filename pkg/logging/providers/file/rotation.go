// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
// Package file - Log rotation and file management for the file-based logging provider
package file

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/cfgis/cfgms/pkg/logging/interfaces"
)

// needsRotation checks if the current log file needs to be rotated
func (p *FileProvider) needsRotation() bool {
	if p.currentFile == nil {
		return true
	}

	// Check file size
	if info, err := p.currentFile.Stat(); err == nil {
		if info.Size() >= p.config.MaxFileSize {
			return true
		}
	}

	return false
}

// rotateLogFile rotates the current log file and creates a new one
// Note: This function expects the caller to hold p.mutex
func (p *FileProvider) rotateLogFile() error {
	// Flush and close current file
	if p.writer != nil {
		_ = p.writer.Flush() // Ignore flush error during rotation
		p.writer = nil
	}

	if p.currentFile != nil {
		_ = p.currentFile.Close() // Ignore close error during rotation
		p.currentFile = nil
	}

	// Create new log file with timestamp
	timestamp := time.Now().Format("2006-01-02-15-04-05")
	filename := fmt.Sprintf("%s-%s.log", p.config.FilePrefix, timestamp)

	// Build secure file path
	filepath, err := p.buildSecureFilePath(filename)
	if err != nil {
		return fmt.Errorf("failed to build secure file path: %w", err)
	}

	// Open new file
	// #nosec G304 - filepath is validated via buildSecureFilePath above
	file, err := os.OpenFile(filepath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, p.config.FileMode)
	if err != nil {
		return fmt.Errorf("failed to open log file %s: %w", filepath, err)
	}

	p.currentFile = file
	p.writer = bufio.NewWriterSize(file, p.config.BufferSize)

	// Start compression of old files in background (pass needed config to avoid race)
	go p.compressOldFiles(p.config.CompressRotated, p.config.Directory, p.config.FilePrefix)

	return nil
}

// compressOldFiles compresses rotated log files to save space
func (p *FileProvider) compressOldFiles(compressRotated bool, directory, filePrefix string) {
	if !compressRotated {
		return
	}

	pattern := filepath.Join(directory, filePrefix+"*.log")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return
	}

	// Get current file name safely
	p.mutex.RLock()
	var currentFileName string
	if p.currentFile != nil {
		currentFileName = p.currentFile.Name()
	}
	p.mutex.RUnlock()

	for _, filename := range files {
		// Skip current log file
		if currentFileName != "" && filename == currentFileName {
			continue
		}

		// Skip already compressed files
		if strings.HasSuffix(filename, ".gz") {
			continue
		}

		// Check if file is old enough to compress (e.g., more than 1 hour old)
		if info, err := os.Stat(filename); err == nil {
			if time.Since(info.ModTime()) < time.Hour {
				continue
			}
		}

		if err := p.compressFile(filename); err != nil {
			fmt.Printf("Warning: failed to compress log file %s: %v\n", filename, err)
		}
	}
}

// compressFile compresses a single log file using GZIP
// #nosec G304 - Filename parameter is from controlled directory scan
func (p *FileProvider) compressFile(filename string) error {
	// Get config values with proper synchronization
	p.mutex.RLock()
	directory := p.config.Directory
	compressionLevel := p.config.CompressionLevel
	p.mutex.RUnlock()

	// Validate the file path is within our directory
	if err := validateFilePath(directory, filename); err != nil {
		return fmt.Errorf("invalid file path for compression: %w", err)
	}

	// Open source file
	src, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer func() { _ = src.Close() }()

	// Create compressed file
	compressedFilename := filename + ".gz"
	dst, err := os.Create(compressedFilename)
	if err != nil {
		return fmt.Errorf("failed to create compressed file: %w", err)
	}
	defer func() { _ = dst.Close() }()

	// Create GZIP writer
	gzWriter, err := gzip.NewWriterLevel(dst, compressionLevel)
	if err != nil {
		return fmt.Errorf("failed to create gzip writer: %w", err)
	}
	defer func() { _ = gzWriter.Close() }()

	// Copy data
	if _, err := io.Copy(gzWriter, src); err != nil {
		return fmt.Errorf("failed to compress data: %w", err)
	}

	if err := gzWriter.Close(); err != nil {
		return fmt.Errorf("failed to close gzip writer: %w", err)
	}

	if err := dst.Close(); err != nil {
		return fmt.Errorf("failed to close compressed file: %w", err)
	}

	// Remove original file after successful compression
	if err := os.Remove(filename); err != nil {
		fmt.Printf("Warning: failed to remove original file %s after compression: %v\n", filename, err)
	} else {
		fmt.Printf("Compressed log file: %s -> %s\n", filename, compressedFilename)
	}

	return nil
}

// findRelevantLogFiles finds log files that might contain entries within the time range
func (p *FileProvider) findRelevantLogFiles(startTime, endTime time.Time) ([]string, error) {
	pattern := filepath.Join(p.config.Directory, p.config.FilePrefix+"*")
	allFiles, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to find log files: %w", err)
	}

	var relevantFiles []string

	for _, filename := range allFiles {
		// Get file modification time as a proxy for content time range
		info, err := os.Stat(filename)
		if err != nil {
			continue
		}

		// Include file if it was modified during or after the start time
		// This is a conservative approach - we may include some files that don't contain relevant entries
		if info.ModTime().After(startTime.Add(-24 * time.Hour)) { // Include files from 24h before start time
			relevantFiles = append(relevantFiles, filename)
		}
	}

	// Sort files by modification time (newest first for better performance on recent queries)
	sort.Slice(relevantFiles, func(i, j int) bool {
		infoI, errI := os.Stat(relevantFiles[i])
		infoJ, errJ := os.Stat(relevantFiles[j])
		if errI != nil || errJ != nil {
			return false
		}
		return infoI.ModTime().After(infoJ.ModTime())
	})

	return relevantFiles, nil
}

// parseLogFile parses a log file and returns entries matching the query
// #nosec G304 - Filename parameter is from controlled directory scan
func (p *FileProvider) parseLogFile(filename string, query interfaces.TimeRangeQuery) ([]interfaces.LogEntry, error) {
	// Validate the file path is within our directory
	if err := validateFilePath(p.config.Directory, filename); err != nil {
		return nil, fmt.Errorf("invalid file path for parsing: %w", err)
	}

	var reader io.Reader

	// Open file (handle compressed files)
	if strings.HasSuffix(filename, ".gz") {
		file, err := os.Open(filename)
		if err != nil {
			return nil, fmt.Errorf("failed to open compressed file: %w", err)
		}
		defer func() { _ = file.Close() }()

		gzReader, err := gzip.NewReader(file)
		if err != nil {
			return nil, fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer func() { _ = gzReader.Close() }()

		reader = gzReader
	} else {
		file, err := os.Open(filename)
		if err != nil {
			return nil, fmt.Errorf("failed to open file: %w", err)
		}
		defer func() { _ = file.Close() }()

		reader = file
	}

	var entries []interfaces.LogEntry
	scanner := bufio.NewScanner(reader)

	// Increase scanner buffer size for large log entries
	const maxCapacity = 512 * 1024 // 512KB max line size
	buf := make([]byte, maxCapacity)
	scanner.Buffer(buf, maxCapacity)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var entry interfaces.LogEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			// Skip malformed entries rather than failing the entire query
			continue
		}

		// Apply time filter
		if entry.Timestamp.Before(query.StartTime) || entry.Timestamp.After(query.EndTime) {
			continue
		}

		// Apply field filters
		if !p.matchesFilters(entry, query.Filters) {
			continue
		}

		entries = append(entries, entry)

		// Check limit
		if query.Limit > 0 && len(entries) >= query.Limit {
			break
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error scanning file: %w", err)
	}

	return entries, nil
}

// matchesFilters checks if a log entry matches the given filters
func (p *FileProvider) matchesFilters(entry interfaces.LogEntry, filters map[string]interface{}) bool {
	if len(filters) == 0 {
		return true
	}

	for key, expectedValue := range filters {
		var actualValue interface{}

		// Map filter keys to log entry fields
		switch key {
		case "level":
			actualValue = entry.Level
		case "service_name":
			actualValue = entry.ServiceName
		case "component":
			actualValue = entry.Component
		case "tenant_id":
			actualValue = entry.TenantID
		case "session_id":
			actualValue = entry.SessionID
		case "correlation_id":
			actualValue = entry.CorrelationID
		case "trace_id":
			actualValue = entry.TraceID
		case "span_id":
			actualValue = entry.SpanID
		case "message":
			actualValue = entry.Message
		default:
			// Check in Fields map
			if entry.Fields != nil {
				actualValue = entry.Fields[key]
			}
		}

		// Handle different filter types
		switch expected := expectedValue.(type) {
		case string:
			if actualStr, ok := actualValue.(string); !ok || actualStr != expected {
				return false
			}
		case []string:
			// For multiple values (e.g., levels), check if actual value is in the list
			actualStr, ok := actualValue.(string)
			if !ok {
				return false
			}
			found := false
			for _, val := range expected {
				if actualStr == val {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		case []interface{}:
			// Handle generic slice of interfaces
			actualStr, ok := actualValue.(string)
			if !ok {
				return false
			}
			found := false
			for _, val := range expected {
				if valStr, ok := val.(string); ok && actualStr == valStr {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		default:
			// Direct comparison for other types
			if actualValue != expectedValue {
				return false
			}
		}
	}

	return true
}

// backgroundMaintenance runs periodic maintenance tasks
func (p *FileProvider) backgroundMaintenance(flushInterval time.Duration) {
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	for {
		// Check if still initialized and get stop channel safely
		p.mutex.RLock()
		initialized := p.initialized
		stopChan := p.stopRotation
		p.mutex.RUnlock()

		if !initialized || stopChan == nil {
			return
		}

		select {
		case <-ticker.C:
			// Check again if still initialized before doing work
			p.mutex.RLock()
			stillInitialized := p.initialized
			compressRotated := p.config.CompressRotated
			directory := p.config.Directory
			filePrefix := p.config.FilePrefix
			p.mutex.RUnlock()

			if !stillInitialized {
				return
			}

			// Periodic flush
			if err := p.Flush(context.TODO()); err != nil {
				fmt.Printf("Warning: periodic flush failed: %v\n", err)
			}

			// Compress old files
			p.compressOldFiles(compressRotated, directory, filePrefix)

			// Clean up old files based on max files limit
			p.cleanupOldFiles()

		case <-stopChan:
			return
		}
	}
}

// cleanupOldFiles removes excess log files beyond MaxFiles limit
func (p *FileProvider) cleanupOldFiles() {
	if p.config.MaxFiles <= 0 {
		return
	}

	pattern := filepath.Join(p.config.Directory, p.config.FilePrefix+"*")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return
	}

	// Sort files by modification time (oldest first)
	sort.Slice(files, func(i, j int) bool {
		infoI, errI := os.Stat(files[i])
		infoJ, errJ := os.Stat(files[j])
		if errI != nil || errJ != nil {
			return false
		}
		return infoI.ModTime().Before(infoJ.ModTime())
	})

	// Remove excess files
	if len(files) > p.config.MaxFiles {
		// Get current file name safely
		p.mutex.RLock()
		var currentFileName string
		if p.currentFile != nil {
			currentFileName = p.currentFile.Name()
		}
		p.mutex.RUnlock()

		excessFiles := files[:len(files)-p.config.MaxFiles]
		for _, filename := range excessFiles {
			// Skip current log file
			if currentFileName != "" && filename == currentFileName {
				continue
			}

			if err := os.Remove(filename); err != nil {
				fmt.Printf("Warning: failed to remove excess log file %s: %v\n", filename, err)
			} else {
				fmt.Printf("Removed excess log file: %s\n", filename)
			}
		}
	}
}

// calculateTotalStorageSize calculates total storage used by log files
func (p *FileProvider) calculateTotalStorageSize() (int64, error) {
	pattern := filepath.Join(p.config.Directory, p.config.FilePrefix+"*")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return 0, fmt.Errorf("failed to find log files: %w", err)
	}

	var totalSize int64
	for _, filename := range files {
		info, err := os.Stat(filename)
		if err != nil {
			continue
		}
		totalSize += info.Size()
	}

	return totalSize, nil
}

// calculateDiskUsage is implemented in platform-specific files:
// - rotation_unix.go for Linux/macOS/BSD
// - rotation_windows.go for Windows

// updateStats updates provider statistics
func (p *FileProvider) updateStats(entriesWritten int, latency time.Duration) {
	// Lock to prevent concurrent access to stats
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.stats.TotalEntries += int64(entriesWritten)
	p.stats.LatestEntry = time.Now()

	// Update rolling average for write latency
	newLatencyMs := float64(latency.Milliseconds())
	p.stats.WriteLatencyMs = (p.stats.WriteLatencyMs * 0.9) + (newLatencyMs * 0.1)

	// Update hourly/daily counters (simplified - would need proper time window tracking in production)
	now := time.Now()
	if now.Sub(p.stats.LatestEntry) < time.Hour {
		p.stats.EntriesLastHour += int64(entriesWritten)
	}
	if now.Sub(p.stats.LatestEntry) < 24*time.Hour {
		p.stats.EntriesLastDay += int64(entriesWritten)
	}
}
