// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package flatfile

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// FlatFileAuditStore implements interfaces.AuditStore using append-only JSONL files.
//
// File layout: <root>/<tenantID>/audit/<YYYY-MM-DD>.jsonl
//
// Each line in a JSONL file is a JSON-encoded AuditEntry. Files are append-only;
// entries are immutable. Methods that would mutate existing entries return ErrImmutable.
//
// StoreAuditEntry returns ErrImmutable when the entry's timestamp predates the
// configured retention period — those time slots are considered sealed.
type FlatFileAuditStore struct {
	root             string
	maxRetentionDays int
	mutex            sync.Mutex // serialises appends across goroutines
}

// NewFlatFileAuditStore creates a new FlatFileAuditStore rooted at root.
// maxRetentionDays controls how far back new entries may be stored; defaults to 90.
func NewFlatFileAuditStore(root string, maxRetentionDays int) (*FlatFileAuditStore, error) {
	if err := os.MkdirAll(root, 0750); err != nil {
		return nil, fmt.Errorf("failed to create audit root: %w", err)
	}
	if maxRetentionDays <= 0 {
		maxRetentionDays = 90
	}
	return &FlatFileAuditStore{
		root:             root,
		maxRetentionDays: maxRetentionDays,
	}, nil
}

// retentionCutoff returns the oldest timestamp that may be stored.
func (s *FlatFileAuditStore) retentionCutoff() time.Time {
	return time.Now().UTC().AddDate(0, 0, -s.maxRetentionDays)
}

// auditDir returns the audit directory for tenantID (validated against traversal).
func (s *FlatFileAuditStore) auditDir(tenantID string) (string, error) {
	return safeJoin(s.root, tenantID, "audit")
}

// dailyFilePath returns the path to the JSONL file for tenantID on date t.
func (s *FlatFileAuditStore) dailyFilePath(tenantID string, t time.Time) (string, error) {
	dir, err := s.auditDir(tenantID)
	if err != nil {
		return "", err
	}
	filename := t.UTC().Format("2006-01-02") + ".jsonl"
	return filepath.Join(dir, filename), nil
}

// StoreAuditEntry appends an immutable audit entry to the daily JSONL file.
// Returns ErrImmutable if the entry's timestamp predates the retention period.
func (s *FlatFileAuditStore) StoreAuditEntry(ctx context.Context, entry *interfaces.AuditEntry) error {
	if entry.TenantID == "" {
		return interfaces.ErrTenantIDRequired
	}
	if entry.UserID == "" {
		return interfaces.ErrUserIDRequired
	}
	if entry.Action == "" {
		return interfaces.ErrActionRequired
	}
	if entry.ResourceType == "" {
		return interfaces.ErrResourceTypeRequired
	}
	if entry.ResourceID == "" {
		return interfaces.ErrResourceIDRequired
	}

	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}

	// Entries older than maxRetentionDays are considered sealed/immutable.
	if entry.Timestamp.Before(s.retentionCutoff()) {
		return ErrImmutable
	}

	path, err := s.dailyFilePath(entry.TenantID, entry.Timestamp)
	if err != nil {
		return fmt.Errorf("invalid tenant ID: %w", err)
	}

	raw, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal audit entry: %w", err)
	}
	raw = append(raw, '\n')

	s.mutex.Lock()
	defer s.mutex.Unlock()

	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return fmt.Errorf("failed to create audit dir: %w", err)
	}

	// #nosec G304 — path validated by safeJoin inside dailyFilePath
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return fmt.Errorf("failed to open audit file: %w", err)
	}
	defer func() { _ = f.Close() }()

	if _, err := f.Write(raw); err != nil {
		return fmt.Errorf("failed to append audit entry: %w", err)
	}
	return nil
}

// StoreAuditBatch stores multiple audit entries, stopping on first error.
func (s *FlatFileAuditStore) StoreAuditBatch(ctx context.Context, entries []*interfaces.AuditEntry) error {
	for _, entry := range entries {
		if err := s.StoreAuditEntry(ctx, entry); err != nil {
			return fmt.Errorf("batch store failed for entry %q: %w", entry.ID, err)
		}
	}
	return nil
}

// GetAuditEntry retrieves an audit entry by ID, scanning daily JSONL files newest-first.
func (s *FlatFileAuditStore) GetAuditEntry(ctx context.Context, id string) (*interfaces.AuditEntry, error) {
	tenantDirs, err := os.ReadDir(s.root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, interfaces.ErrAuditNotFound
		}
		return nil, fmt.Errorf("failed to read audit root: %w", err)
	}

	for _, tenantDir := range tenantDirs {
		if !tenantDir.IsDir() {
			continue
		}
		auditDir := filepath.Join(s.root, tenantDir.Name(), "audit")
		entry, err := s.scanDirForID(auditDir, id)
		if err == nil {
			return entry, nil
		}
	}
	return nil, interfaces.ErrAuditNotFound
}

// scanDirForID scans all JSONL files in auditDir for an entry matching id.
func (s *FlatFileAuditStore) scanDirForID(auditDir, id string) (*interfaces.AuditEntry, error) {
	files, err := os.ReadDir(auditDir)
	if err != nil {
		return nil, fmt.Errorf("cannot read dir: %w", err)
	}

	// Newest first for faster lookup of recent entries
	sort.Slice(files, func(i, j int) bool {
		return files[i].Name() > files[j].Name()
	})

	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".jsonl") {
			continue
		}
		entry, err := s.scanFileForID(filepath.Join(auditDir, f.Name()), id)
		if err == nil {
			return entry, nil
		}
	}
	return nil, interfaces.ErrAuditNotFound
}

// scanFileForID scans a single JSONL file for an entry matching id.
func (s *FlatFileAuditStore) scanFileForID(path, id string) (*interfaces.AuditEntry, error) {
	// #nosec G304 — path from trusted os.ReadDir rooted at s.root
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var entry interfaces.AuditEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			continue
		}
		if entry.ID == id {
			return &entry, nil
		}
	}
	return nil, interfaces.ErrAuditNotFound
}

// ListAuditEntries returns audit entries matching the filter.
func (s *FlatFileAuditStore) ListAuditEntries(ctx context.Context, filter *interfaces.AuditFilter) ([]*interfaces.AuditEntry, error) {
	tenantIDs, err := s.tenantIDsForFilter(filter)
	if err != nil {
		return nil, err
	}

	var results []*interfaces.AuditEntry
	for _, tenantID := range tenantIDs {
		auditDir, err := s.auditDir(tenantID)
		if err != nil {
			continue
		}
		entries, err := s.scanDirForEntries(auditDir, filter)
		if err != nil {
			continue
		}
		results = append(results, entries...)
	}

	// Sort by timestamp (default: descending)
	sortOrder := "desc"
	if filter != nil && filter.Order == "asc" {
		sortOrder = "asc"
	}
	sort.Slice(results, func(i, j int) bool {
		if sortOrder == "asc" {
			return results[i].Timestamp.Before(results[j].Timestamp)
		}
		return results[i].Timestamp.After(results[j].Timestamp)
	})

	return paginateAudit(results, filter), nil
}

// tenantIDsForFilter returns the list of tenant IDs to scan, based on the filter.
func (s *FlatFileAuditStore) tenantIDsForFilter(filter *interfaces.AuditFilter) ([]string, error) {
	if filter != nil && filter.TenantID != "" {
		return []string{filter.TenantID}, nil
	}
	dirs, err := os.ReadDir(s.root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to list tenants: %w", err)
	}
	var ids []string
	for _, d := range dirs {
		if d.IsDir() {
			ids = append(ids, d.Name())
		}
	}
	return ids, nil
}

// scanDirForEntries scans all JSONL files in auditDir matching the filter.
func (s *FlatFileAuditStore) scanDirForEntries(auditDir string, filter *interfaces.AuditFilter) ([]*interfaces.AuditEntry, error) {
	files, err := os.ReadDir(auditDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var results []*interfaces.AuditEntry
	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".jsonl") {
			continue
		}
		if filter != nil && filter.TimeRange != nil {
			if !fileInTimeRange(f.Name(), filter.TimeRange) {
				continue
			}
		}
		entries, err := s.readJSONLFile(filepath.Join(auditDir, f.Name()), filter)
		if err != nil {
			continue
		}
		results = append(results, entries...)
	}
	return results, nil
}

// fileInTimeRange checks whether a YYYY-MM-DD.jsonl file may contain entries in tr.
func fileInTimeRange(filename string, tr *interfaces.TimeRange) bool {
	dateStr := strings.TrimSuffix(filename, ".jsonl")
	fileDate, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		return true // include unparseable filenames
	}
	fileEnd := fileDate.AddDate(0, 0, 1)
	if tr.Start != nil && fileEnd.Before(*tr.Start) {
		return false
	}
	if tr.End != nil && fileDate.After(*tr.End) {
		return false
	}
	return true
}

// readJSONLFile reads all entries from a JSONL file, applying the filter.
func (s *FlatFileAuditStore) readJSONLFile(path string, filter *interfaces.AuditFilter) ([]*interfaces.AuditEntry, error) {
	// #nosec G304 — path from trusted os.ReadDir rooted at s.root
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	var results []*interfaces.AuditEntry
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var entry interfaces.AuditEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			continue
		}
		if applyAuditFilter(&entry, filter) {
			results = append(results, &entry)
		}
	}
	return results, scanner.Err()
}

// applyAuditFilter returns true if the entry matches all filter criteria.
func applyAuditFilter(entry *interfaces.AuditEntry, filter *interfaces.AuditFilter) bool {
	if filter == nil {
		return true
	}
	if filter.TenantID != "" && entry.TenantID != filter.TenantID {
		return false
	}
	if len(filter.EventTypes) > 0 && !containsEventType(filter.EventTypes, entry.EventType) {
		return false
	}
	if len(filter.Actions) > 0 && !containsString(filter.Actions, entry.Action) {
		return false
	}
	if len(filter.UserIDs) > 0 && !containsString(filter.UserIDs, entry.UserID) {
		return false
	}
	if len(filter.UserTypes) > 0 && !containsUserType(filter.UserTypes, entry.UserType) {
		return false
	}
	if len(filter.Results) > 0 && !containsResult(filter.Results, entry.Result) {
		return false
	}
	if len(filter.Severities) > 0 && !containsSeverity(filter.Severities, entry.Severity) {
		return false
	}
	if len(filter.ResourceTypes) > 0 && !containsString(filter.ResourceTypes, entry.ResourceType) {
		return false
	}
	if len(filter.ResourceIDs) > 0 && !containsString(filter.ResourceIDs, entry.ResourceID) {
		return false
	}
	if filter.TimeRange != nil {
		if filter.TimeRange.Start != nil && entry.Timestamp.Before(*filter.TimeRange.Start) {
			return false
		}
		if filter.TimeRange.End != nil && entry.Timestamp.After(*filter.TimeRange.End) {
			return false
		}
	}
	for _, tag := range filter.Tags {
		if !containsString(entry.Tags, tag) {
			return false
		}
	}
	return true
}

// paginateAudit applies offset and limit from the filter.
func paginateAudit(results []*interfaces.AuditEntry, filter *interfaces.AuditFilter) []*interfaces.AuditEntry {
	if filter == nil {
		return results
	}
	if filter.Offset > 0 {
		if filter.Offset >= len(results) {
			return nil
		}
		results = results[filter.Offset:]
	}
	if filter.Limit > 0 && filter.Limit < len(results) {
		results = results[:filter.Limit]
	}
	return results
}

// GetAuditsByUser retrieves audit entries for a specific user in the given time range.
func (s *FlatFileAuditStore) GetAuditsByUser(ctx context.Context, userID string, timeRange *interfaces.TimeRange) ([]*interfaces.AuditEntry, error) {
	return s.ListAuditEntries(ctx, &interfaces.AuditFilter{
		UserIDs:   []string{userID},
		TimeRange: timeRange,
	})
}

// GetAuditsByResource retrieves audit entries for a specific resource.
func (s *FlatFileAuditStore) GetAuditsByResource(ctx context.Context, resourceType, resourceID string, timeRange *interfaces.TimeRange) ([]*interfaces.AuditEntry, error) {
	return s.ListAuditEntries(ctx, &interfaces.AuditFilter{
		ResourceTypes: []string{resourceType},
		ResourceIDs:   []string{resourceID},
		TimeRange:     timeRange,
	})
}

// GetAuditsByAction retrieves audit entries for a specific action.
func (s *FlatFileAuditStore) GetAuditsByAction(ctx context.Context, action string, timeRange *interfaces.TimeRange) ([]*interfaces.AuditEntry, error) {
	return s.ListAuditEntries(ctx, &interfaces.AuditFilter{
		Actions:   []string{action},
		TimeRange: timeRange,
	})
}

// GetFailedActions retrieves audit entries with failure, error, or denied results.
func (s *FlatFileAuditStore) GetFailedActions(ctx context.Context, timeRange *interfaces.TimeRange, limit int) ([]*interfaces.AuditEntry, error) {
	return s.ListAuditEntries(ctx, &interfaces.AuditFilter{
		Results: []interfaces.AuditResult{
			interfaces.AuditResultFailure,
			interfaces.AuditResultError,
			interfaces.AuditResultDenied,
		},
		TimeRange: timeRange,
		Limit:     limit,
	})
}

// GetSuspiciousActivity retrieves high and critical severity entries for a tenant.
func (s *FlatFileAuditStore) GetSuspiciousActivity(ctx context.Context, tenantID string, timeRange *interfaces.TimeRange) ([]*interfaces.AuditEntry, error) {
	return s.ListAuditEntries(ctx, &interfaces.AuditFilter{
		TenantID: tenantID,
		Severities: []interfaces.AuditSeverity{
			interfaces.AuditSeverityHigh,
			interfaces.AuditSeverityCritical,
		},
		TimeRange: timeRange,
	})
}

// GetAuditStats scans all JSONL files and returns aggregate statistics.
func (s *FlatFileAuditStore) GetAuditStats(ctx context.Context) (*interfaces.AuditStats, error) {
	stats := &interfaces.AuditStats{
		EntriesByTenant:   make(map[string]int64),
		EntriesByType:     make(map[string]int64),
		EntriesByResult:   make(map[string]int64),
		EntriesBySeverity: make(map[string]int64),
		LastUpdated:       time.Now().UTC(),
	}

	now := time.Now().UTC()
	last24h := now.Add(-24 * time.Hour)
	last7d := now.AddDate(0, 0, -7)
	last30d := now.AddDate(0, 0, -30)

	var oldest, newest *time.Time

	walkErr := filepath.WalkDir(s.root, func(path string, d os.DirEntry, ferr error) error {
		if ferr != nil || d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".jsonl") {
			return nil
		}

		// #nosec G304 — path from WalkDir rooted at s.root
		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer func() { _ = f.Close() }()

		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

		for scanner.Scan() {
			line := scanner.Bytes()
			if len(line) == 0 {
				continue
			}
			var entry interfaces.AuditEntry
			if err := json.Unmarshal(line, &entry); err != nil {
				continue
			}

			stats.TotalEntries++
			stats.TotalSize += int64(len(line))
			stats.EntriesByTenant[entry.TenantID]++
			stats.EntriesByType[string(entry.EventType)]++
			stats.EntriesByResult[string(entry.Result)]++
			stats.EntriesBySeverity[string(entry.Severity)]++

			if entry.Timestamp.After(last24h) {
				stats.EntriesLast24h++
			}
			if entry.Timestamp.After(last7d) {
				stats.EntriesLast7d++
			}
			if entry.Timestamp.After(last30d) {
				stats.EntriesLast30d++
			}
			if entry.Result == interfaces.AuditResultFailure ||
				entry.Result == interfaces.AuditResultError ||
				entry.Result == interfaces.AuditResultDenied {
				if entry.Timestamp.After(last24h) {
					stats.FailedActionsLast24h++
				}
			}
			if entry.Severity == interfaces.AuditSeverityHigh ||
				entry.Severity == interfaces.AuditSeverityCritical {
				stats.SuspiciousActivityCount++
				if stats.LastSecurityIncident == nil || entry.Timestamp.After(*stats.LastSecurityIncident) {
					t := entry.Timestamp
					stats.LastSecurityIncident = &t
				}
			}

			if oldest == nil || entry.Timestamp.Before(*oldest) {
				t := entry.Timestamp
				oldest = &t
			}
			if newest == nil || entry.Timestamp.After(*newest) {
				t := entry.Timestamp
				newest = &t
			}
		}
		return nil
	})
	if walkErr != nil && !os.IsNotExist(walkErr) {
		return nil, fmt.Errorf("failed to compute audit stats: %w", walkErr)
	}

	stats.OldestEntry = oldest
	stats.NewestEntry = newest
	if stats.TotalEntries > 0 {
		stats.AverageSize = stats.TotalSize / stats.TotalEntries
	}
	return stats, nil
}

// ArchiveAuditEntries moves daily JSONL files older than beforeDate into an archive
// subdirectory under each tenant's audit directory.
func (s *FlatFileAuditStore) ArchiveAuditEntries(ctx context.Context, beforeDate time.Time) (int64, error) {
	var count int64

	walkErr := filepath.WalkDir(s.root, func(path string, d os.DirEntry, ferr error) error {
		if ferr != nil || d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".jsonl") {
			return nil
		}
		dateStr := strings.TrimSuffix(filepath.Base(path), ".jsonl")
		fileDate, err := time.Parse("2006-01-02", dateStr)
		if err != nil || !fileDate.Before(beforeDate) {
			return nil
		}

		archiveDir := filepath.Join(filepath.Dir(path), "archive")
		if err := os.MkdirAll(archiveDir, 0750); err != nil {
			return nil
		}
		archivePath := filepath.Join(archiveDir, filepath.Base(path))
		if err := os.Rename(path, archivePath); err != nil {
			return nil
		}

		// Count entries in the archived file
		// #nosec G304 — archivePath constructed from controlled path
		raw, err := os.ReadFile(archivePath)
		if err == nil {
			for _, line := range strings.Split(string(raw), "\n") {
				if strings.TrimSpace(line) != "" {
					count++
				}
			}
		}
		return nil
	})
	if walkErr != nil {
		return count, fmt.Errorf("archive walk failed: %w", walkErr)
	}
	return count, nil
}

// PurgeAuditEntries deletes daily JSONL files older than beforeDate.
func (s *FlatFileAuditStore) PurgeAuditEntries(ctx context.Context, beforeDate time.Time) (int64, error) {
	var count int64

	walkErr := filepath.WalkDir(s.root, func(path string, d os.DirEntry, ferr error) error {
		if ferr != nil || d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".jsonl") {
			return nil
		}
		dateStr := strings.TrimSuffix(filepath.Base(path), ".jsonl")
		fileDate, err := time.Parse("2006-01-02", dateStr)
		if err != nil || !fileDate.Before(beforeDate) {
			return nil
		}

		// Count entries before deleting
		// #nosec G304 — path from trusted WalkDir rooted at s.root
		raw, err := os.ReadFile(path)
		if err == nil {
			for _, line := range strings.Split(string(raw), "\n") {
				if strings.TrimSpace(line) != "" {
					count++
				}
			}
		}
		_ = os.Remove(path)
		return nil
	})
	if walkErr != nil {
		return count, fmt.Errorf("purge walk failed: %w", walkErr)
	}
	return count, nil
}

// Helper functions for slice membership checks.

func containsEventType(slice []interfaces.AuditEventType, v interfaces.AuditEventType) bool {
	for _, s := range slice {
		if s == v {
			return true
		}
	}
	return false
}

func containsUserType(slice []interfaces.AuditUserType, v interfaces.AuditUserType) bool {
	for _, s := range slice {
		if s == v {
			return true
		}
	}
	return false
}

func containsResult(slice []interfaces.AuditResult, v interfaces.AuditResult) bool {
	for _, s := range slice {
		if s == v {
			return true
		}
	}
	return false
}

func containsSeverity(slice []interfaces.AuditSeverity, v interfaces.AuditSeverity) bool {
	for _, s := range slice {
		if s == v {
			return true
		}
	}
	return false
}

func containsString(slice []string, v string) bool {
	for _, s := range slice {
		if s == v {
			return true
		}
	}
	return false
}
