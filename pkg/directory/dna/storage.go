// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
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
	"sync"
	"time"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/controller/fleet/storage"
	"github.com/cfgis/cfgms/pkg/directory/interfaces"
	"github.com/cfgis/cfgms/pkg/logging"
)

// Fragment IDs for the directory DNA adapter's local serialization format.
// Each constant selects the specific Fragment within a commonpb.DNA envelope
// that carries the JSON payload, replacing the old Attributes-as-KV-bag pattern.
const (
	directoryDNAFragmentID = "directory_dna:v1"
	directoryRelFragmentID = "directory_rel:v1"
	directoryAuthority     = "directory"
)

// marshalToProto marshals a DirectoryDNA into a commonpb.DNA envelope.
// The full DirectoryDNA is JSON-encoded into a Fragment's canonical_bytes;
// commonpb.DNA.Attributes is not populated.
func marshalToProto(dna *DirectoryDNA) (*commonpb.DNA, error) {
	payload, err := json.Marshal(dna)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal directory DNA: %w", err)
	}
	return &commonpb.DNA{
		Id: dna.ID,
		Fragments: []*commonpb.Fragment{{
			FragmentId:     directoryDNAFragmentID,
			Authority:      directoryAuthority,
			CanonicalBytes: payload,
		}},
	}, nil
}

// unmarshalFromProto extracts a DirectoryDNA from the Fragment stored by marshalToProto.
func unmarshalFromProto(proto *commonpb.DNA) (*DirectoryDNA, error) {
	for _, frag := range proto.Fragments {
		if frag.FragmentId == directoryDNAFragmentID {
			var dna DirectoryDNA
			if err := json.Unmarshal(frag.CanonicalBytes, &dna); err != nil {
				return nil, fmt.Errorf("failed to unmarshal directory DNA: %w", err)
			}
			return &dna, nil
		}
	}
	return nil, fmt.Errorf("directory DNA fragment not found in stored record")
}

// marshalRelToProto marshals DirectoryRelationships into a commonpb.DNA envelope.
func marshalRelToProto(rel *DirectoryRelationships) (*commonpb.DNA, error) {
	payload, err := json.Marshal(rel)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal directory relationships: %w", err)
	}
	return &commonpb.DNA{
		Id: fmt.Sprintf("rel_%s", rel.ObjectID),
		Fragments: []*commonpb.Fragment{{
			FragmentId:     directoryRelFragmentID,
			Authority:      directoryAuthority,
			CanonicalBytes: payload,
		}},
	}, nil
}

// unmarshalRelFromProto extracts DirectoryRelationships from the Fragment stored by marshalRelToProto.
func unmarshalRelFromProto(proto *commonpb.DNA) (*DirectoryRelationships, error) {
	for _, frag := range proto.Fragments {
		if frag.FragmentId == directoryRelFragmentID {
			var rel DirectoryRelationships
			if err := json.Unmarshal(frag.CanonicalBytes, &rel); err != nil {
				return nil, fmt.Errorf("failed to unmarshal directory relationships: %w", err)
			}
			return &rel, nil
		}
	}
	return nil, fmt.Errorf("directory relationships fragment not found in stored record")
}

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

	// Per-type object tracking for aggregation queries.
	// Maps each object type to a set of unique object IDs and their latest write timestamp.
	typeStatsMu sync.RWMutex
	typeObjects map[interfaces.DirectoryObjectType]map[string]time.Time
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

		typeObjects: make(map[interfaces.DirectoryObjectType]map[string]time.Time),
	}
}

// StoreDirectoryDNA stores a DirectoryDNA record using existing storage infrastructure.
func (s *DirectoryDNAStorageAdapter) StoreDirectoryDNA(ctx context.Context, dna *DirectoryDNA) error {
	startTime := time.Now()

	s.logger.Debug("Storing directory DNA",
		"object_id", dna.ObjectID,
		"object_type", dna.ObjectType,
		"dna_id", dna.ID)

	// Encode DirectoryDNA into a Fragment-based commonpb.DNA envelope.
	dnaProto, err := marshalToProto(dna)
	if err != nil {
		return fmt.Errorf("failed to marshal directory DNA for storage: %w", err)
	}

	// Assign the next version for this object. Durable backends key records by
	// (device_id, version); leaving the version unset makes every write collide
	// with the previous one, so history is silently overwritten instead of appended.
	version, err := s.nextVersion(ctx, dna.ObjectID)
	if err != nil {
		return fmt.Errorf("failed to determine next directory DNA version: %w", err)
	}

	record := &storage.DNARecord{
		DeviceID:    dna.ObjectID,
		DNA:         dnaProto,
		ContentHash: s.generateContentHash(dnaProto),
		ShardID:     s.generateShardID(dna.ObjectID, dna.ObjectType),
		StoredAt:    time.Now(),
		Version:     version,
		TenantID:    dna.TenantID,
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

	// Update per-type aggregation counters
	s.trackObjectType(dna)

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

	if record.DNA == nil {
		return nil, fmt.Errorf("no DNA data in record")
	}

	directoryDNA, err := unmarshalFromProto(record.DNA)
	if err != nil {
		return nil, fmt.Errorf("failed to decode directory DNA: %w", err)
	}

	// Caller-provided identity takes precedence for correctness under re-key scenarios.
	directoryDNA.ObjectID = objectID
	directoryDNA.ObjectType = objectType

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

			if record.DNA == nil {
				s.logger.Warn("No DNA data in record", "content_hash", ref.ContentHash)
				continue
			}

			directoryDNA, err := unmarshalFromProto(record.DNA)
			if err != nil {
				s.logger.Warn("Failed to decode directory DNA", "content_hash", ref.ContentHash, "error", err)
				continue
			}

			// Apply filtering based on query criteria (simplified)
			if len(query.ObjectTypes) > 0 {
				found := false
				for _, queryType := range query.ObjectTypes {
					if directoryDNA.ObjectType == queryType {
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

		if record.DNA == nil {
			s.logger.Warn("No DNA data in record", "content_hash", ref.ContentHash)
			continue
		}

		directoryDNA, err := unmarshalFromProto(record.DNA)
		if err != nil {
			s.logger.Warn("Failed to decode historical DNA record", "content_hash", ref.ContentHash, "error", err)
			continue
		}

		history = append(history, directoryDNA)
	}

	s.logger.Debug("Directory history retrieved", "object_id", objectID, "records", len(history))
	return history, nil
}

// StoreRelationships stores directory relationships.
func (s *DirectoryDNAStorageAdapter) StoreRelationships(ctx context.Context, relationships *DirectoryRelationships) error {
	s.logger.Debug("Storing directory relationships", "object_id", relationships.ObjectID)

	// Encode relationships into a Fragment-based commonpb.DNA envelope.
	relProto, err := marshalRelToProto(relationships)
	if err != nil {
		return fmt.Errorf("failed to marshal relationships for storage: %w", err)
	}

	version, err := s.nextVersion(ctx, relationships.ObjectID)
	if err != nil {
		return fmt.Errorf("failed to determine next relationships version: %w", err)
	}

	record := &storage.DNARecord{
		DeviceID:    relationships.ObjectID,
		DNA:         relProto,
		ContentHash: s.generateContentHash(relProto),
		ShardID:     s.generateShardID(relationships.ObjectID, relationships.ObjectType),
		StoredAt:    time.Now(),
		Version:     version,
		TenantID:    relationships.TenantID,
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

	if record.DNA == nil {
		return nil, fmt.Errorf("no DNA data in relationships record")
	}

	relationships, err := unmarshalRelFromProto(record.DNA)
	if err != nil {
		return nil, fmt.Errorf("failed to decode relationships: %w", err)
	}

	s.logger.Debug("Directory relationships retrieved successfully", "object_id", objectID)
	return relationships, nil
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

	// Aggregate per-type counts and find the most recent write timestamp
	s.typeStatsMu.RLock()
	userCount := int64(len(s.typeObjects[interfaces.DirectoryObjectTypeUser]))
	groupCount := int64(len(s.typeObjects[interfaces.DirectoryObjectTypeGroup]))
	ouCount := int64(len(s.typeObjects[interfaces.DirectoryObjectTypeOU]))
	var lastWrite time.Time
	for _, objects := range s.typeObjects {
		for _, t := range objects {
			if t.After(lastWrite) {
				lastWrite = t
			}
		}
	}
	s.typeStatsMu.RUnlock()

	// Use last write time if any objects have been stored; fall back to now for empty stores
	lastCollectionTime := lastWrite
	if lastCollectionTime.IsZero() {
		lastCollectionTime = time.Now()
	}

	totalObjects := userCount + groupCount + ouCount

	// Build directory-specific stats
	directoryStats := &DirectoryDNAStats{
		TotalObjects:              totalObjects,
		LastCollectionTime:        lastCollectionTime,
		AverageCollectionDuration: time.Minute, // Would be calculated from actual collections
		CollectionSuccessRate:     0.95,        // Would be tracked separately
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

	directoryStats.UserCount = userCount
	directoryStats.GroupCount = groupCount
	directoryStats.OUCount = ouCount

	s.logger.Debug("Directory DNA statistics retrieved", "total_objects", directoryStats.TotalObjects)
	return directoryStats, nil
}

// GetObjectStats returns statistics for a specific object type.
func (s *DirectoryDNAStorageAdapter) GetObjectStats(ctx context.Context, objectType interfaces.DirectoryObjectType) (*ObjectTypeStats, error) {
	s.logger.Debug("Retrieving object type statistics", "object_type", objectType)

	s.typeStatsMu.RLock()
	objects := s.typeObjects[objectType]
	count := int64(len(objects))
	var lastUpdated time.Time
	for _, t := range objects {
		if t.After(lastUpdated) {
			lastUpdated = t
		}
	}
	s.typeStatsMu.RUnlock()

	stats := &ObjectTypeStats{
		ObjectType:        objectType,
		TotalCount:        count,
		ActiveCount:       count,
		ChangedToday:      0,
		AverageAttributes: 50.0,
		MostCommonChanges: []string{"display_name", "description", "members"},
		LastUpdated:       lastUpdated,
	}

	s.logger.Debug("Object type statistics retrieved", "object_type", objectType, "count", count)
	return stats, nil
}

// Helper methods

// versionedBackend is implemented by durable backends that derive the next
// version from stored data (SQLite reads MAX(version)+1).
type versionedBackend interface {
	GetNextVersion(ctx context.Context, deviceID string) (int64, error)
}

// nextVersion returns the next version number for an object.
//
// The durable backend is preferred over the indexer: the in-memory indexer
// restarts its counters with the process, which would reuse (device_id, version)
// pairs already written by a previous controller run.
func (s *DirectoryDNAStorageAdapter) nextVersion(ctx context.Context, objectID string) (int64, error) {
	if backend, ok := s.backend.(versionedBackend); ok {
		return backend.GetNextVersion(ctx, objectID)
	}
	return s.indexer.GetNextVersion(ctx, objectID)
}

// trackObjectType records the objectID and write timestamp for aggregation queries.
func (s *DirectoryDNAStorageAdapter) trackObjectType(dna *DirectoryDNA) {
	var writeTime time.Time
	if dna.LastUpdated != nil {
		writeTime = *dna.LastUpdated
	} else {
		writeTime = time.Now()
	}

	s.typeStatsMu.Lock()
	defer s.typeStatsMu.Unlock()

	if s.typeObjects[dna.ObjectType] == nil {
		s.typeObjects[dna.ObjectType] = make(map[string]time.Time)
	}
	existing, exists := s.typeObjects[dna.ObjectType][dna.ObjectID]
	if !exists || writeTime.After(existing) {
		s.typeObjects[dna.ObjectType][dna.ObjectID] = writeTime
	}
}

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

// generateContentHash generates a deterministic content hash from a commonpb.DNA envelope.
// It hashes the DNA ID and the canonical_bytes of each Fragment in declaration order,
// matching the order produced by marshalToProto and marshalRelToProto.
func (s *DirectoryDNAStorageAdapter) generateContentHash(dna *commonpb.DNA) string {
	h := sha256.New()
	h.Write([]byte(dna.Id))
	for _, frag := range dna.Fragments {
		h.Write([]byte(frag.FragmentId))
		h.Write([]byte(":"))
		h.Write(frag.CanonicalBytes)
		h.Write([]byte("|"))
	}
	return fmt.Sprintf("%x", h.Sum(nil))
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
