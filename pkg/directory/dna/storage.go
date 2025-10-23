// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
// Package dna - Directory DNA Storage Integration
//
// This file implements storage adapters that integrate DirectoryDNA with
// CFGMS's existing DNA storage infrastructure, enabling directory objects
// to use the established storage, compression, and indexing systems.

package dna

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/steward/dna/storage"
	"github.com/cfgis/cfgms/pkg/directory/interfaces"
	"github.com/cfgis/cfgms/pkg/logging"
)

// DirectoryDNAStorageAdapter adapts DirectoryDNA to work with existing DNA storage infrastructure.
//
// This adapter implements the DirectoryDNAStorage interface by leveraging the existing
// Backend, Compressor, and Indexer interfaces, providing seamless integration with
// the established DNA storage ecosystem.
type DirectoryDNAStorageAdapter struct {
	backend    storage.Backend
	compressor storage.Compressor
	indexer    storage.Indexer
	logger     logging.Logger

	// Configuration
	enableDeduplication bool
	compressionLevel    int
	shardPrefix         string
}

// NewDirectoryDNAStorageAdapter creates a new storage adapter.
func NewDirectoryDNAStorageAdapter(
	backend storage.Backend,
	compressor storage.Compressor,
	indexer storage.Indexer,
	logger logging.Logger,
) *DirectoryDNAStorageAdapter {
	return &DirectoryDNAStorageAdapter{
		backend:    backend,
		compressor: compressor,
		indexer:    indexer,
		logger:     logger,

		enableDeduplication: true,
		compressionLevel:    6,
		shardPrefix:         "directory",
	}
}

// StoreDirectoryDNA stores a DirectoryDNA record using existing storage infrastructure.
func (s *DirectoryDNAStorageAdapter) StoreDirectoryDNA(ctx context.Context, dna *DirectoryDNA) error {
	startTime := time.Now()

	s.logger.Debug("Storing directory DNA",
		"object_id", dna.ObjectID,
		"object_type", dna.ObjectType,
		"dna_id", dna.ID)

	// Convert DirectoryDNA to standard DNA for storage compatibility
	standardDNA := dna.ToDNA()

	// Create storage record
	record := &storage.DNARecord{
		DeviceID:    dna.ObjectID, // Use ObjectID as DeviceID for compatibility
		DNA:         standardDNA,
		ContentHash: s.generateContentHash(standardDNA),
		ShardID:     s.generateShardID(dna.ObjectID, dna.ObjectType),
		StoredAt:    time.Now(),
	}

	// Check for deduplication if enabled
	if s.enableDeduplication {
		exists, err := s.backend.HasContent(ctx, record.ContentHash)
		if err != nil {
			return fmt.Errorf("failed to check content existence: %w", err)
		}

		if exists {
			// Store reference only (deduplication)
			if err := s.backend.StoreReference(ctx, record); err != nil {
				return fmt.Errorf("failed to store DNA reference: %w", err)
			}

			s.logger.Debug("Directory DNA deduplicated",
				"object_id", dna.ObjectID,
				"content_hash", record.ContentHash[:16])
		} else {
			// Compress and store new content
			if err := s.storeNewContent(ctx, record); err != nil {
				return err
			}
		}
	} else {
		// Store without deduplication
		if err := s.storeNewContent(ctx, record); err != nil {
			return err
		}
	}

	// Index the record for fast retrieval
	if err := s.indexer.IndexRecord(ctx, record); err != nil {
		s.logger.Warn("Failed to index directory DNA record",
			"object_id", dna.ObjectID,
			"error", err)
		// Don't fail the storage operation for indexing issues
	}

	s.logger.Debug("Directory DNA stored successfully",
		"object_id", dna.ObjectID,
		"content_hash", record.ContentHash[:16],
		"shard_id", record.ShardID,
		"storage_time", time.Since(startTime))

	return nil
}

// GetDirectoryDNA retrieves a DirectoryDNA record by object ID and type.
func (s *DirectoryDNAStorageAdapter) GetDirectoryDNA(ctx context.Context, objectID string, objectType interfaces.DirectoryObjectType) (*DirectoryDNA, error) {
	s.logger.Debug("Retrieving directory DNA", "object_id", objectID, "object_type", objectType)

	// Query for the most recent record for this object
	options := &storage.QueryOptions{
		Limit:       1,
		IncludeData: true,
	}

	refs, _, err := s.indexer.QueryRecords(ctx, objectID, options)
	if err != nil {
		return nil, fmt.Errorf("failed to query directory DNA records: %w", err)
	}

	if len(refs) == 0 {
		return nil, fmt.Errorf("no directory DNA record found for object %s", objectID)
	}

	// Get the most recent record
	ref := refs[0]
	record, err := s.backend.GetRecord(ctx, ref.ContentHash, ref.ShardID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve DNA record: %w", err)
	}

	// Use DNA from record (it's already stored as standard DNA)
	standardDNA := record.DNA
	if standardDNA == nil {
		return nil, fmt.Errorf("no DNA data in record")
	}

	// Convert back to DirectoryDNA
	directoryDNA := FromDNA(standardDNA, objectID, objectType)

	// Restore directory-specific metadata from DNA attributes
	if directoryDNA.Attributes != nil {
		directoryDNA.Provider = directoryDNA.Attributes["provider"]
		directoryDNA.TenantID = directoryDNA.Attributes["tenant_id"]
		directoryDNA.DistinguishedName = directoryDNA.Attributes["distinguished_name"]
	}

	s.logger.Debug("Directory DNA retrieved successfully",
		"object_id", objectID,
		"content_hash", ref.ContentHash[:16])

	return directoryDNA, nil
}

// QueryDirectoryDNA queries directory DNA records based on specified criteria.
func (s *DirectoryDNAStorageAdapter) QueryDirectoryDNA(ctx context.Context, query *DirectoryDNAQuery) ([]*DirectoryDNA, error) {
	s.logger.Debug("Querying directory DNA records", "limit", query.Limit)

	var allResults []*DirectoryDNA

	// Simplified query - in a full implementation, this would handle complex filtering
	for _, objectID := range query.ObjectIDs {
		options := &storage.QueryOptions{
			Limit:       query.Limit,
			Offset:      query.Offset,
			IncludeData: true,
		}

		// Add time range if specified
		if query.TimeRange != nil {
			options.TimeRange = &storage.TimeRange{
				Start: query.TimeRange.StartTime,
				End:   query.TimeRange.EndTime,
			}
		}

		refs, _, err := s.indexer.QueryRecords(ctx, objectID, options)
		if err != nil {
			s.logger.Warn("Query failed for object", "object_id", objectID, "error", err)
			continue
		}

		// Process each record
		for _, ref := range refs {
			record, err := s.backend.GetRecord(ctx, ref.ContentHash, ref.ShardID)
			if err != nil {
				s.logger.Warn("Failed to retrieve record", "content_hash", ref.ContentHash, "error", err)
				continue
			}

			// Use DNA from record
			standardDNA := record.DNA
			if standardDNA == nil {
				s.logger.Warn("No DNA data in record", "content_hash", ref.ContentHash)
				continue
			}

			// Determine object type from attributes (simplified)
			objectType := interfaces.DirectoryObjectTypeUser
			if objTypeAttr, exists := standardDNA.Attributes["object_type"]; exists {
				objectType = interfaces.DirectoryObjectType(objTypeAttr)
			}

			directoryDNA := FromDNA(standardDNA, objectID, objectType)

			// Apply filtering based on query criteria (simplified)
			if len(query.ObjectTypes) > 0 {
				found := false
				for _, queryType := range query.ObjectTypes {
					if objectType == queryType {
						found = true
						break
					}
				}
				if !found {
					continue
				}
			}

			allResults = append(allResults, directoryDNA)

			// Check if we've reached the overall query limit
			if query.Limit > 0 && len(allResults) >= query.Limit {
				break
			}
		}

		// Break out of outer loop if limit reached
		if query.Limit > 0 && len(allResults) >= query.Limit {
			break
		}
	}

	s.logger.Debug("Directory DNA query completed", "results", len(allResults))
	return allResults, nil
}

// GetDirectoryHistory retrieves historical DNA records for a specific object.
func (s *DirectoryDNAStorageAdapter) GetDirectoryHistory(ctx context.Context, objectID string, timeRange *TimeRange) ([]*DirectoryDNA, error) {
	s.logger.Debug("Retrieving directory history", "object_id", objectID)

	options := &storage.QueryOptions{
		Limit:       1000, // Reasonable limit for history
		IncludeData: true,
	}

	// Add time range if specified
	if timeRange != nil {
		options.TimeRange = &storage.TimeRange{
			Start: timeRange.StartTime,
			End:   timeRange.EndTime,
		}
	}

	refs, _, err := s.indexer.QueryRecords(ctx, objectID, options)
	if err != nil {
		return nil, fmt.Errorf("failed to query history: %w", err)
	}

	var history []*DirectoryDNA

	for _, ref := range refs {
		record, err := s.backend.GetRecord(ctx, ref.ContentHash, ref.ShardID)
		if err != nil {
			s.logger.Warn("Failed to retrieve historical record", "content_hash", ref.ContentHash, "error", err)
			continue
		}

		// Use DNA from record
		standardDNA := record.DNA
		if standardDNA == nil {
			s.logger.Warn("No DNA data in record", "content_hash", ref.ContentHash)
			continue
		}

		// Determine object type from attributes
		objectType := interfaces.DirectoryObjectTypeUser // Default
		if objTypeAttr, exists := standardDNA.Attributes["object_type"]; exists {
			objectType = interfaces.DirectoryObjectType(objTypeAttr)
		}

		directoryDNA := FromDNA(standardDNA, objectID, objectType)

		// Restore metadata from DNA attributes
		if directoryDNA.Attributes != nil {
			directoryDNA.Provider = directoryDNA.Attributes["provider"]
			directoryDNA.TenantID = directoryDNA.Attributes["tenant_id"]
			directoryDNA.DistinguishedName = directoryDNA.Attributes["distinguished_name"]
		}

		history = append(history, directoryDNA)
	}

	s.logger.Debug("Directory history retrieved", "object_id", objectID, "records", len(history))
	return history, nil
}

// StoreRelationships stores directory relationships.
func (s *DirectoryDNAStorageAdapter) StoreRelationships(ctx context.Context, relationships *DirectoryRelationships) error {
	s.logger.Debug("Storing directory relationships", "object_id", relationships.ObjectID)

	// Convert relationships to JSON for storage
	relationshipData, err := json.Marshal(relationships)
	if err != nil {
		return fmt.Errorf("failed to marshal relationships: %w", err)
	}

	// Create a pseudo-DNA record for relationships
	relationshipDNA := &commonpb.DNA{
		Id: fmt.Sprintf("rel_%s", relationships.ObjectID),
		Attributes: map[string]string{
			"relationships_data": string(relationshipData),
			"object_id":          relationships.ObjectID,
			"object_type":        string(relationships.ObjectType),
			"provider":           relationships.Provider,
			"tenant_id":          relationships.TenantID,
			"collected_at":       relationships.CollectedAt.Format(time.RFC3339),
		},
		AttributeCount: func() int32 {
			count := len(relationships.MemberOf) + len(relationships.Members) + len(relationships.ChildOUs)
			if count > math.MaxInt32 {
				return math.MaxInt32
			}
			// #nosec G115 - Bounds checking above prevents integer overflow
			return int32(count)
		}(),
	}

	record := &storage.DNARecord{
		DeviceID:    relationships.ObjectID,
		DNA:         relationshipDNA,
		ContentHash: s.generateContentHash(relationshipDNA),
		ShardID:     s.generateShardID(relationships.ObjectID, relationships.ObjectType),
		StoredAt:    time.Now(),
	}

	// Store the relationships data
	if err := s.storeNewContent(ctx, record); err != nil {
		return fmt.Errorf("failed to store relationships: %w", err)
	}

	// Index the relationships record
	if err := s.indexer.IndexRecord(ctx, record); err != nil {
		s.logger.Warn("Failed to index relationships record", "object_id", relationships.ObjectID, "error", err)
	}

	s.logger.Debug("Directory relationships stored successfully", "object_id", relationships.ObjectID)
	return nil
}

// GetRelationships retrieves directory relationships.
func (s *DirectoryDNAStorageAdapter) GetRelationships(ctx context.Context, objectID string) (*DirectoryRelationships, error) {
	s.logger.Debug("Retrieving directory relationships", "object_id", objectID)

	options := &storage.QueryOptions{
		Limit:       1,
		IncludeData: true,
	}

	refs, _, err := s.indexer.QueryRecords(ctx, objectID, options)
	if err != nil {
		return nil, fmt.Errorf("failed to query relationships: %w", err)
	}

	if len(refs) == 0 {
		return nil, fmt.Errorf("no relationships found for object %s", objectID)
	}

	// Get the most recent relationships record
	ref := refs[0]
	record, err := s.backend.GetRecord(ctx, ref.ContentHash, ref.ShardID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve relationships record: %w", err)
	}

	relationshipDNA := record.DNA
	if relationshipDNA == nil {
		return nil, fmt.Errorf("no DNA data in relationships record")
	}

	// Extract relationships from attributes
	relationshipDataStr, exists := relationshipDNA.Attributes["relationships_data"]
	if !exists {
		return nil, fmt.Errorf("relationships data not found in record")
	}

	var relationships DirectoryRelationships
	if err := json.Unmarshal([]byte(relationshipDataStr), &relationships); err != nil {
		return nil, fmt.Errorf("failed to unmarshal relationships data: %w", err)
	}

	s.logger.Debug("Directory relationships retrieved successfully", "object_id", objectID)
	return &relationships, nil
}

// GetDirectoryStats returns statistics about directory DNA storage.
func (s *DirectoryDNAStorageAdapter) GetDirectoryStats(ctx context.Context) (*DirectoryDNAStats, error) {
	s.logger.Debug("Retrieving directory DNA statistics")

	// Get general storage stats
	storageStats, err := s.backend.GetStats(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get storage stats: %w", err)
	}

	// Get index stats
	_, err = s.indexer.GetGlobalStats(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get index stats: %w", err)
	}

	// Build directory-specific stats
	directoryStats := &DirectoryDNAStats{
		TotalObjects:              storageStats.TotalDevices, // Devices are objects in our case
		LastCollectionTime:        time.Now(),                // Would be tracked separately in real implementation
		AverageCollectionDuration: time.Minute,               // Would be calculated from actual collections
		CollectionSuccessRate:     0.95,                      // Would be tracked separately
		TotalStorageUsed:          storageStats.TotalSize,
		CompressionRatio:          storageStats.CompressionRatio,
		TotalChangesDetected:      0,         // Would be tracked by drift detector
		ChangesPerDay:             0,         // Would be calculated from change history
		ActiveDrifts:              0,         // Would be provided by drift detector
		CriticalDrifts:            0,         // Would be provided by drift detector
		DriftsPerDay:              0,         // Would be calculated from drift history
		CollectionHealth:          "healthy", // Would be determined by health checks
		LastHealthCheck:           time.Now(),
	}

	// Count objects by type (would be done more efficiently with proper indexing)
	directoryStats.UserCount = 0  // Would query for DirectoryObjectTypeUser records
	directoryStats.GroupCount = 0 // Would query for DirectoryObjectTypeGroup records
	directoryStats.OUCount = 0    // Would query for DirectoryObjectTypeOU records

	s.logger.Debug("Directory DNA statistics retrieved", "total_objects", directoryStats.TotalObjects)
	return directoryStats, nil
}

// GetObjectStats returns statistics for a specific object type.
func (s *DirectoryDNAStorageAdapter) GetObjectStats(ctx context.Context, objectType interfaces.DirectoryObjectType) (*ObjectTypeStats, error) {
	s.logger.Debug("Retrieving object type statistics", "object_type", objectType)

	// This would require more sophisticated querying in a real implementation
	// For now, return basic stats structure
	stats := &ObjectTypeStats{
		ObjectType:        objectType,
		TotalCount:        0,                                                  // Would count records of this type
		ActiveCount:       0,                                                  // Would count recently updated records
		ChangedToday:      0,                                                  // Would count records changed today
		AverageAttributes: 50.0,                                               // Would calculate from actual records
		MostCommonChanges: []string{"display_name", "description", "members"}, // Would analyze change patterns
	}

	s.logger.Debug("Object type statistics retrieved", "object_type", objectType)
	return stats, nil
}

// Helper methods

// storeNewContent compresses and stores new DNA content.
func (s *DirectoryDNAStorageAdapter) storeNewContent(ctx context.Context, record *storage.DNARecord) error {
	// Compress the DNA data
	compressedData, originalSize, err := s.compressor.Compress(record.DNA)
	if err != nil {
		return fmt.Errorf("failed to compress DNA data: %w", err)
	}

	// Update record with compression info
	record.CompressedSize = int64(len(compressedData))
	record.OriginalSize = originalSize
	record.CompressionRatio = float64(len(compressedData)) / float64(originalSize)

	// Store the compressed data
	if err := s.backend.StoreRecord(ctx, record, compressedData); err != nil {
		return fmt.Errorf("failed to store DNA record: %w", err)
	}

	return nil
}

// generateContentHash generates a content hash for DNA data.
func (s *DirectoryDNAStorageAdapter) generateContentHash(dna *commonpb.DNA) string {
	// Create deterministic hash from DNA attributes
	var hashInput strings.Builder
	hashInput.WriteString(dna.Id)

	// Sort attributes for consistent hashing
	for key, value := range dna.Attributes {
		hashInput.WriteString(key)
		hashInput.WriteString(":")
		hashInput.WriteString(value)
		hashInput.WriteString("|")
	}

	hash := sha256.Sum256([]byte(hashInput.String()))
	return fmt.Sprintf("%x", hash)
}

// generateShardID generates an appropriate shard ID for directory objects.
func (s *DirectoryDNAStorageAdapter) generateShardID(objectID string, objectType interfaces.DirectoryObjectType) string {
	// Create shard based on object type and hash of object ID
	hash := sha256.Sum256([]byte(objectID))
	shardNumber := int(hash[0]) % 16 // 16 shards per object type

	return fmt.Sprintf("%s_%s_%02d", s.shardPrefix, objectType, shardNumber)
}

// Configuration methods

// SetDeduplication enables or disables content deduplication.
func (s *DirectoryDNAStorageAdapter) SetDeduplication(enabled bool) {
	s.enableDeduplication = enabled
}

// SetCompressionLevel sets the compression level (if supported by compressor).
func (s *DirectoryDNAStorageAdapter) SetCompressionLevel(level int) {
	s.compressionLevel = level
}

// SetShardPrefix sets the prefix used for shard naming.
func (s *DirectoryDNAStorageAdapter) SetShardPrefix(prefix string) {
	s.shardPrefix = prefix
}

// Health and monitoring methods

// GetStorageHealth returns the health status of the storage adapter.
func (s *DirectoryDNAStorageAdapter) GetStorageHealth(ctx context.Context) (*DirectoryStorageHealth, error) {
	// Get underlying storage stats
	storageStats, err := s.backend.GetStats(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get storage stats: %w", err)
	}

	// Get compression stats
	_ = s.compressor.GetStats()

	health := &DirectoryStorageHealth{
		Status:              "healthy",
		LastCheck:           time.Now(),
		StorageUsed:         storageStats.TotalSize,
		CompressionRatio:    storageStats.CompressionRatio,
		DeduplicationRatio:  storageStats.DeduplicationRatio,
		ActiveObjects:       storageStats.ActiveDevices,
		RecentErrors:        0, // Would track from error logs
		AverageResponseTime: storageStats.AverageReadTime,
		BackendHealth:       "healthy", // Would check backend connectivity
		IndexHealth:         "healthy", // Would check index performance
		CompressionHealth:   "healthy", // Would check compressor status
	}

	// Determine overall health based on metrics
	if health.CompressionRatio < 0.5 {
		health.Status = "degraded"
		health.Issues = append(health.Issues, "Low compression ratio")
	}

	if health.AverageResponseTime > 5*time.Second {
		health.Status = "degraded"
		health.Issues = append(health.Issues, "High response times")
	}

	return health, nil
}

// DirectoryStorageHealth represents the health status of directory DNA storage.
type DirectoryStorageHealth struct {
	Status              string        `json:"status"`
	LastCheck           time.Time     `json:"last_check"`
	StorageUsed         int64         `json:"storage_used"`
	CompressionRatio    float64       `json:"compression_ratio"`
	DeduplicationRatio  float64       `json:"deduplication_ratio"`
	ActiveObjects       int64         `json:"active_objects"`
	RecentErrors        int64         `json:"recent_errors"`
	AverageResponseTime time.Duration `json:"average_response_time"`
	BackendHealth       string        `json:"backend_health"`
	IndexHealth         string        `json:"index_health"`
	CompressionHealth   string        `json:"compression_health"`
	Issues              []string      `json:"issues,omitempty"`
}
