// Package file implements a file-based logging provider for CFGMS time-series logging.
// This provider writes logs to rotating files with compression and retention policies,
// providing zero-dependency time-series logging suitable for most deployments.
package file

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/logging/interfaces"
)

// FileProvider implements the LoggingProvider interface using file-based storage
type FileProvider struct {
	config       *FileConfig
	currentFile  *os.File
	writer       *bufio.Writer
	mutex        sync.RWMutex
	stats        interfaces.ProviderStats
	initialized  bool
	stopRotation chan struct{}
	closeOnce    sync.Once
}

// FileConfig holds configuration for the file-based logging provider
type FileConfig struct {
	// Basic settings
	Directory     string `json:"directory"`      // Log directory path
	FilePrefix    string `json:"file_prefix"`    // Log file prefix (default: "cfgms")
	MaxFileSize   int64  `json:"max_file_size"`  // Max size before rotation (bytes)
	MaxFiles      int    `json:"max_files"`      // Max number of rotated files to keep
	RetentionDays int    `json:"retention_days"` // Days to keep log files
	
	// Performance settings
	BufferSize    int           `json:"buffer_size"`     // Write buffer size
	FlushInterval time.Duration `json:"flush_interval"`  // Auto-flush interval
	
	// Compression settings
	CompressRotated bool   `json:"compress_rotated"` // Compress rotated files
	CompressionLevel int   `json:"compression_level"` // GZIP compression level (1-9)
	
	// File permissions
	FileMode os.FileMode `json:"file_mode"` // File permission mode
	DirMode  os.FileMode `json:"dir_mode"`  // Directory permission mode
}

// DefaultFileConfig returns a sensible default configuration
func DefaultFileConfig() *FileConfig {
	return &FileConfig{
		Directory:        "/var/log/cfgms",
		FilePrefix:       "cfgms",
		MaxFileSize:      100 * 1024 * 1024, // 100MB
		MaxFiles:         10,
		RetentionDays:    30,
		BufferSize:       64 * 1024, // 64KB buffer
		FlushInterval:    5 * time.Second,
		CompressRotated:  true,
		CompressionLevel: 6, // Balanced compression
		FileMode:         0644,
		DirMode:          0755,
	}
}

// Name returns the provider name
func (p *FileProvider) Name() string {
	return "file"
}

// Description returns a human-readable description
func (p *FileProvider) Description() string {
	return "File-based time-series logging with rotation, compression, and retention policies"
}

// GetVersion returns the provider version
func (p *FileProvider) GetVersion() string {
	return "1.0.0"
}

// GetCapabilities returns the provider's capabilities
func (p *FileProvider) GetCapabilities() interfaces.LoggingCapabilities {
	return interfaces.LoggingCapabilities{
		SupportsCompression:       true,  // GZIP compression on rotated files
		SupportsRetentionPolicies: true,  // File-based retention
		SupportsRealTimeQueries:   false, // Files need parsing for queries
		SupportsBatchWrites:       true,  // Batched writes to buffer
		SupportsTimeRangeQueries:  true,  // Can parse files for time ranges
		SupportsFullTextSearch:    true,  // Text-based searching
		MaxEntriesPerSecond:       50000, // Estimated throughput
		MaxBatchSize:              1000,  // Reasonable batch size
		DefaultRetentionDays:      30,    // Default retention
		CompressionRatio:          0.1,   // ~10:1 compression for text logs
		RequiresFlush:             true,  // Buffered writes need flushing
		SupportsTransactions:      false, // File-based, no transactions
		SupportsPartitioning:      true,  // Time-based file rotation
		SupportsIndexing:          false, // No built-in indexing
	}
}

// Available checks if file system is accessible and writable
func (p *FileProvider) Available() (bool, error) {
	if p.config == nil {
		return false, fmt.Errorf("provider not configured")
	}
	
	// Check if directory exists or can be created
	if err := os.MkdirAll(p.config.Directory, p.config.DirMode); err != nil {
		return false, fmt.Errorf("cannot create log directory: %w", err)
	}
	
	// Check write permissions
	testFile, err := p.buildSecureFilePath(".cfgms-write-test")
	if err != nil {
		return false, fmt.Errorf("cannot build test file path: %w", err)
	}
	// #nosec G304 - testFile is validated via buildSecureFilePath above
	if f, err := os.OpenFile(testFile, os.O_CREATE|os.O_WRONLY, p.config.FileMode); err != nil {
		return false, fmt.Errorf("cannot write to log directory: %w", err)
	} else {
		_ = f.Close()       // Ignore close error on test file
		_ = os.Remove(testFile) // Ignore remove error on test file
	}
	
	return true, nil
}

// Initialize sets up the file provider with the given configuration
func (p *FileProvider) Initialize(config map[string]interface{}) error {
	// Parse configuration with proper synchronization
	p.mutex.Lock()
	p.config = DefaultFileConfig()
	if err := p.parseConfig(config); err != nil {
		p.mutex.Unlock()
		return fmt.Errorf("invalid configuration: %w", err)
	}
	
	// Create directory if it doesn't exist
	if err := os.MkdirAll(p.config.Directory, p.config.DirMode); err != nil {
		p.mutex.Unlock()
		return fmt.Errorf("failed to create log directory: %w", err)
	}
	
	// Open initial log file (rotateLogFile expects mutex to be held)
	if err := p.rotateLogFile(); err != nil {
		p.mutex.Unlock()
		return fmt.Errorf("failed to create initial log file: %w", err)
	}
	p.stopRotation = make(chan struct{})
	p.initialized = true
	flushInterval := p.config.FlushInterval
	p.mutex.Unlock()
	
	go p.backgroundMaintenance(flushInterval)
	p.stats = interfaces.ProviderStats{
		OldestEntry:    time.Now(),
		LatestEntry:    time.Now(),
		WriteLatencyMs: 1.0, // Initial estimate
		QueryLatencyMs: 100.0, // File parsing is slower
	}
	
	return nil
}

// Close shuts down the provider and closes files
func (p *FileProvider) Close() error {
	var err error
	p.closeOnce.Do(func() {
		// Stop background tasks first, then mark as closing
		p.mutex.Lock()
		if !p.initialized {
			p.mutex.Unlock()
			return
		}
		
		// Mark as closing and get the stop channel
		p.initialized = false
		stopChan := p.stopRotation
		p.stopRotation = nil // Prevent further usage
		p.mutex.Unlock()
		
		// Stop background tasks if they were started
		if stopChan != nil {
			close(stopChan)
			// Give background goroutines time to finish cleanly
			time.Sleep(200 * time.Millisecond)
		}
		
		// Now safely close resources
		p.mutex.Lock()
		defer p.mutex.Unlock()
		
		// Close resources
		if p.writer != nil {
			_ = p.writer.Flush() // Ignore flush error during cleanup
			p.writer = nil
		}
		
		if p.currentFile != nil {
			_ = p.currentFile.Close() // Ignore close error during cleanup
			p.currentFile = nil
		}
	})
	
	return err
}

// WriteEntry writes a single log entry to the file
func (p *FileProvider) WriteEntry(ctx context.Context, entry interfaces.LogEntry) error {
	if !p.initialized {
		return fmt.Errorf("provider not initialized")
	}
	
	start := time.Now()
	defer func() {
		p.updateStats(1, time.Since(start))
	}()
	
	// Serialize entry to JSON
	jsonBytes, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal log entry: %w", err)
	}
	
	p.mutex.Lock()
	defer p.mutex.Unlock()
	
	// Check if rotation is needed before writing
	if p.needsRotation() {
		if err := p.rotateLogFile(); err != nil {
			return fmt.Errorf("failed to rotate log file: %w", err)
		}
	}
	
	// Write entry with newline
	if _, err := p.writer.Write(jsonBytes); err != nil {
		return fmt.Errorf("failed to write log entry: %w", err)
	}
	
	if _, err := p.writer.WriteString("\n"); err != nil {
		return fmt.Errorf("failed to write newline: %w", err)
	}
	
	return nil
}

// WriteBatch writes multiple log entries efficiently
func (p *FileProvider) WriteBatch(ctx context.Context, entries []interfaces.LogEntry) error {
	if !p.initialized {
		return fmt.Errorf("provider not initialized")
	}
	
	if len(entries) == 0 {
		return nil
	}
	
	start := time.Now()
	defer func() {
		p.updateStats(len(entries), time.Since(start))
	}()
	
	p.mutex.Lock()
	defer p.mutex.Unlock()
	
	// Check if rotation is needed before batch write
	if p.needsRotation() {
		if err := p.rotateLogFile(); err != nil {
			return fmt.Errorf("failed to rotate log file: %w", err)
		}
	}
	
	// Write all entries in the batch
	for _, entry := range entries {
		jsonBytes, err := json.Marshal(entry)
		if err != nil {
			return fmt.Errorf("failed to marshal log entry: %w", err)
		}
		
		if _, err := p.writer.Write(jsonBytes); err != nil {
			return fmt.Errorf("failed to write log entry: %w", err)
		}
		
		if _, err := p.writer.WriteString("\n"); err != nil {
			return fmt.Errorf("failed to write newline: %w", err)
		}
	}
	
	return nil
}

// QueryTimeRange queries log entries within a time range
func (p *FileProvider) QueryTimeRange(ctx context.Context, query interfaces.TimeRangeQuery) ([]interfaces.LogEntry, error) {
	if !p.initialized {
		return nil, fmt.Errorf("provider not initialized")
	}
	
	start := time.Now()
	defer func() {
		// Lock to prevent concurrent access to stats
		p.mutex.Lock()
		p.stats.QueryLatencyMs = float64(time.Since(start).Milliseconds())
		p.mutex.Unlock()
	}()
	
	// Find relevant log files based on time range
	files, err := p.findRelevantLogFiles(query.StartTime, query.EndTime)
	if err != nil {
		return nil, fmt.Errorf("failed to find relevant log files: %w", err)
	}
	
	var results []interfaces.LogEntry
	
	// Parse each relevant file
	for _, filename := range files {
		entries, err := p.parseLogFile(filename, query)
		if err != nil {
			// Log error but continue with other files
			fmt.Printf("Warning: failed to parse log file %s: %v\n", filename, err)
			continue
		}
		
		results = append(results, entries...)
		
		// Check limit
		if query.Limit > 0 && len(results) >= query.Limit {
			results = results[:query.Limit]
			break
		}
	}
	
	// Sort results by timestamp if needed
	if query.OrderBy == "" || query.OrderBy == "timestamp" {
		sort.Slice(results, func(i, j int) bool {
			if query.SortDesc {
				return results[i].Timestamp.After(results[j].Timestamp)
			}
			return results[i].Timestamp.Before(results[j].Timestamp)
		})
	}
	
	return results, nil
}

// QueryCount returns count of log entries matching criteria
func (p *FileProvider) QueryCount(ctx context.Context, query interfaces.CountQuery) (int64, error) {
	// For file provider, we need to parse files to count
	timeQuery := interfaces.TimeRangeQuery{
		StartTime: query.StartTime,
		EndTime:   query.EndTime,
		Filters:   query.Filters,
	}
	
	entries, err := p.QueryTimeRange(ctx, timeQuery)
	if err != nil {
		return 0, err
	}
	
	return int64(len(entries)), nil
}

// QueryLevels queries log entries by log levels
func (p *FileProvider) QueryLevels(ctx context.Context, query interfaces.LevelQuery) ([]interfaces.LogEntry, error) {
	// Add level filter to the base query
	if query.Filters == nil {
		query.Filters = make(map[string]interface{})
	}
	
	// Convert levels to filter
	if len(query.Levels) > 0 {
		query.Filters["level"] = query.Levels
	}
	
	return p.QueryTimeRange(ctx, query.TimeRangeQuery)
}

// ApplyRetentionPolicy removes old log files based on retention policy
func (p *FileProvider) ApplyRetentionPolicy(ctx context.Context, policy interfaces.RetentionPolicy) error {
	if !p.initialized {
		return fmt.Errorf("provider not initialized")
	}
	
	cutoffTime := time.Now().AddDate(0, 0, -policy.RetentionDays)
	
	// Get all log files
	pattern := filepath.Join(p.config.Directory, p.config.FilePrefix+"*")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("failed to find log files: %w", err)
	}
	
	var deletedFiles int
	for _, filename := range files {
		// Skip current log file
		if p.currentFile != nil && filename == p.currentFile.Name() {
			continue
		}
		
		info, err := os.Stat(filename)
		if err != nil {
			continue
		}
		
		if info.ModTime().Before(cutoffTime) {
			if err := os.Remove(filename); err != nil {
				fmt.Printf("Warning: failed to remove old log file %s: %v\n", filename, err)
			} else {
				deletedFiles++
			}
		}
	}
	
	fmt.Printf("Applied retention policy: removed %d old log files\n", deletedFiles)
	return nil
}

// GetStats returns operational statistics
func (p *FileProvider) GetStats(ctx context.Context) (interfaces.ProviderStats, error) {
	if !p.initialized {
		return interfaces.ProviderStats{}, fmt.Errorf("provider not initialized")
	}
	
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	
	// Update storage size
	totalSize, err := p.calculateTotalStorageSize()
	if err != nil {
		fmt.Printf("Warning: failed to calculate storage size: %v\n", err)
	}
	
	stats := p.stats
	stats.StorageSize = totalSize
	
	// Calculate disk usage if possible
	if p.config != nil {
		if usage, err := p.calculateDiskUsage(); err == nil {
			stats.DiskUsagePercent = usage
		}
	}
	
	return stats, nil
}

// Flush forces buffered writes to disk
func (p *FileProvider) Flush(ctx context.Context) error {
	if !p.initialized {
		return fmt.Errorf("provider not initialized")
	}
	
	p.mutex.Lock()
	defer p.mutex.Unlock()
	
	if p.writer != nil {
		if err := p.writer.Flush(); err != nil {
			return fmt.Errorf("failed to flush buffer: %w", err)
		}
	}
	
	if p.currentFile != nil {
		if err := p.currentFile.Sync(); err != nil {
			return fmt.Errorf("failed to sync file: %w", err)
		}
	}
	
	return nil
}

// parseConfig parses the configuration map into FileConfig
func (p *FileProvider) parseConfig(config map[string]interface{}) error {
	if directory, ok := config["directory"].(string); ok {
		p.config.Directory = directory
	}
	
	if prefix, ok := config["file_prefix"].(string); ok {
		p.config.FilePrefix = prefix
	}
	
	if maxSize, ok := config["max_file_size"].(int64); ok {
		p.config.MaxFileSize = maxSize
	} else if maxSize, ok := config["max_file_size"].(float64); ok {
		p.config.MaxFileSize = int64(maxSize)
	}
	
	if maxFiles, ok := config["max_files"].(int); ok {
		p.config.MaxFiles = maxFiles
	} else if maxFiles, ok := config["max_files"].(float64); ok {
		p.config.MaxFiles = int(maxFiles)
	}
	
	if retentionDays, ok := config["retention_days"].(int); ok {
		p.config.RetentionDays = retentionDays
	} else if retentionDays, ok := config["retention_days"].(float64); ok {
		p.config.RetentionDays = int(retentionDays)
	}
	
	if bufferSize, ok := config["buffer_size"].(int); ok {
		p.config.BufferSize = bufferSize
	} else if bufferSize, ok := config["buffer_size"].(float64); ok {
		p.config.BufferSize = int(bufferSize)
	}
	
	if flushInterval, ok := config["flush_interval"].(string); ok {
		if duration, err := time.ParseDuration(flushInterval); err == nil {
			p.config.FlushInterval = duration
		}
	}
	
	if compress, ok := config["compress_rotated"].(bool); ok {
		p.config.CompressRotated = compress
	}
	
	if level, ok := config["compression_level"].(int); ok {
		if level >= 1 && level <= 9 {
			p.config.CompressionLevel = level
		}
	} else if level, ok := config["compression_level"].(float64); ok {
		if level >= 1 && level <= 9 {
			p.config.CompressionLevel = int(level)
		}
	}
	
	return nil
}

// validateFilePath validates file paths to prevent directory traversal attacks
// #nosec G304 - This function prevents directory traversal by validating paths
func validateFilePath(basePath, filePath string) error {
	if basePath == "" {
		return fmt.Errorf("base path cannot be empty")
	}
	
	if filePath == "" {
		return fmt.Errorf("file path cannot be empty")
	}
	
	// Clean the paths to resolve . and .. components
	cleanBase := filepath.Clean(basePath)
	cleanFile := filepath.Clean(filePath)
	
	// Convert to absolute paths for comparison
	absBase, err := filepath.Abs(cleanBase)
	if err != nil {
		return fmt.Errorf("failed to get absolute base path: %w", err)
	}
	
	absFile, err := filepath.Abs(cleanFile)
	if err != nil {
		return fmt.Errorf("failed to get absolute file path: %w", err)
	}
	
	// Check if the file path is within the base directory
	relPath, err := filepath.Rel(absBase, absFile)
	if err != nil {
		return fmt.Errorf("failed to get relative path: %w", err)
	}
	
	// If the relative path starts with "..", it's outside the base directory
	if len(relPath) >= 2 && relPath[:2] == ".." {
		return fmt.Errorf("file path is outside base directory: %s", filePath)
	}
	
	// Check for suspicious patterns
	if filepath.IsAbs(relPath) {
		return fmt.Errorf("relative path should not be absolute: %s", relPath)
	}
	
	return nil
}

// buildSecureFilePath builds a file path and validates it for security
// #nosec G304 - File paths are validated before use
func (p *FileProvider) buildSecureFilePath(filename string) (string, error) {
	// Build the full file path
	fullPath := filepath.Join(p.config.Directory, filename)
	
	// Validate the path
	if err := validateFilePath(p.config.Directory, fullPath); err != nil {
		return "", fmt.Errorf("invalid file path: %w", err)
	}
	
	return fullPath, nil
}

// init registers the file provider
func init() {
	interfaces.RegisterLoggingProvider(&FileProvider{})
}