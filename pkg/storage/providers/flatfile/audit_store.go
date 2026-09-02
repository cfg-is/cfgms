// SPDX-License-Identifier: AGPL-3.0-only
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

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// FlatFileAuditStore implements business.AuditStore using append-only JSONL files.
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

	// chainHeads caches the last chained entry this store appended per tenant,
	// guarded by mutex. Without it AppendChainedEntry re-reads and JSON-decodes
	// every entry in the tenant's audit files on every single append, making a
	// run of N appends O(N^2) decodes — 1100 entries cost ~600k decodes, enough
	// to stall the audit drain goroutine past a 60s Flush deadline under
	// parallel test load (Issue #3797). The type is a single-process,
	// single-writer store (see the doc comment above), so the head this process
	// last wrote is authoritative; any path that writes or removes entries
	// outside AppendChainedEntry invalidates the affected cache entries so the
	// next append re-reads from disk.
	chainHeads map[string]chainHead
}

// chainHead is the cached tail of one tenant's audit chain: the sequence number
// and checksum the next appended entry must link to.
type chainHead struct {
	sequenceNumber uint64
	checksum       string
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
		chainHeads:       make(map[string]chainHead),
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

// validateFlatFileAuditEntry checks the required fields shared by every write path
// (StoreAuditEntry, AppendChainedEntry).
func validateFlatFileAuditEntry(entry *business.AuditEntry) error {
	if entry.TenantID == "" {
		return business.ErrTenantIDRequired
	}
	if entry.UserID == "" {
		return business.ErrUserIDRequired
	}
	if entry.Action == "" {
		return business.ErrActionRequired
	}
	if entry.ResourceType == "" {
		return business.ErrResourceTypeRequired
	}
	if entry.ResourceID == "" {
		return business.ErrResourceIDRequired
	}
	return nil
}

// StoreAuditEntry appends an immutable audit entry to the daily JSONL file.
// Returns ErrImmutable if the entry's timestamp predates the retention period.
func (s *FlatFileAuditStore) StoreAuditEntry(ctx context.Context, entry *business.AuditEntry) error {
	if err := validateFlatFileAuditEntry(entry); err != nil {
		return err
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

	// This path writes a caller-supplied SequenceNumber straight to disk, so the
	// tenant's durable chain head may move without AppendChainedEntry seeing it.
	// Drop the cached head; the next chained append re-reads it from disk.
	s.forgetChainHead(entry.TenantID)

	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return fmt.Errorf("failed to create audit dir: %w", err)
	}

	// #nosec G304 — path validated by safeJoin inside dailyFilePath
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
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
func (s *FlatFileAuditStore) StoreAuditBatch(ctx context.Context, entries []*business.AuditEntry) error {
	for _, entry := range entries {
		if err := s.StoreAuditEntry(ctx, entry); err != nil {
			return fmt.Errorf("batch store failed for entry %q: %w", entry.ID, err)
		}
	}
	return nil
}

// AppendChainedEntry implements business.AuditStore.AppendChainedEntry. It holds
// s.mutex for the read-then-append critical section — the same mutex StoreAuditEntry
// uses to serialize appends — so the chain-head read and the write land atomically
// with respect to every other writer in this process. FlatFileAuditStore is a
// single-process, single-writer store (documented on the type); there is no
// cross-process deployment of the flatfile provider to defend against
// (ADR-004 amendment, ADR-031 Decision 1, Issue #3754).
//
// The chain head comes from s.chainHeads when this store has already appended
// for the tenant, and is read from disk once otherwise, so an append costs one
// file write rather than a full re-scan of the tenant's audit files (Issue
// #3797). Writes that bypass this method (StoreAuditEntry) and file removals
// (ArchiveAuditEntries, PurgeAuditEntries) invalidate the cache.
func (s *FlatFileAuditStore) AppendChainedEntry(ctx context.Context, tenantID string, entry *business.AuditEntry, computeChecksum func(entry *business.AuditEntry) string) error {
	if entry == nil {
		return fmt.Errorf("audit entry cannot be nil")
	}
	if computeChecksum == nil {
		return fmt.Errorf("computeChecksum function is required")
	}
	entry.TenantID = tenantID
	if err := validateFlatFileAuditEntry(entry); err != nil {
		return err
	}

	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}
	if entry.Timestamp.Before(s.retentionCutoff()) {
		return ErrImmutable
	}

	path, err := s.dailyFilePath(entry.TenantID, entry.Timestamp)
	if err != nil {
		return fmt.Errorf("invalid tenant ID: %w", err)
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	head, cached := s.chainHeads[tenantID]
	if !cached {
		last, err := s.GetLastAuditEntry(ctx, tenantID)
		if err != nil {
			return fmt.Errorf("failed to read chain head: %w", err)
		}
		if last != nil {
			head = chainHead{sequenceNumber: last.SequenceNumber, checksum: last.Checksum}
		}
	}
	entry.SequenceNumber = head.sequenceNumber + 1
	entry.PreviousChecksum = head.checksum
	entry.Checksum = computeChecksum(entry)

	raw, err := json.Marshal(entry)
	if err != nil {
		s.forgetChainHead(tenantID)
		return fmt.Errorf("failed to marshal audit entry: %w", err)
	}
	raw = append(raw, '\n')

	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		s.forgetChainHead(tenantID)
		return fmt.Errorf("failed to create audit dir: %w", err)
	}

	// #nosec G304 -- path validated by safeJoin inside dailyFilePath
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		s.forgetChainHead(tenantID)
		return fmt.Errorf("failed to open audit file: %w", err)
	}
	defer func() { _ = f.Close() }()

	if _, err := f.Write(raw); err != nil {
		// The write may have landed partially, so the durable head is unknown:
		// drop the cached head and let the next append re-read it from disk.
		s.forgetChainHead(tenantID)
		return fmt.Errorf("failed to append audit entry: %w", err)
	}

	s.rememberChainHead(tenantID, entry.SequenceNumber, entry.Checksum)
	return nil
}

// rememberChainHead records the entry this store just appended as tenantID's
// chain head. Callers must hold s.mutex.
func (s *FlatFileAuditStore) rememberChainHead(tenantID string, sequenceNumber uint64, checksum string) {
	if s.chainHeads == nil {
		s.chainHeads = make(map[string]chainHead)
	}
	s.chainHeads[tenantID] = chainHead{sequenceNumber: sequenceNumber, checksum: checksum}
}

// forgetChainHead drops tenantID's cached chain head so the next
// AppendChainedEntry re-reads it from disk. Callers must hold s.mutex.
func (s *FlatFileAuditStore) forgetChainHead(tenantID string) {
	delete(s.chainHeads, tenantID)
}

// forgetAllChainHeads drops every cached chain head. Callers must hold s.mutex.
func (s *FlatFileAuditStore) forgetAllChainHeads() {
	clear(s.chainHeads)
}

// GetAuditEntry retrieves an audit entry by ID, walking the full directory tree.
// Hierarchical tenant IDs (e.g. "fleet-root/fleet-child-a") store their audit files
// under nested subdirectories, so a single-level ReadDir(root) would miss them.
func (s *FlatFileAuditStore) GetAuditEntry(ctx context.Context, id string) (*business.AuditEntry, error) {
	var found *business.AuditEntry
	walkErr := filepath.WalkDir(s.root, func(path string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() || d.Name() != "audit" {
			return nil
		}
		entry, scanErr := s.scanDirForID(path, id)
		if scanErr == nil {
			found = entry
		}
		return nil
	})
	if found != nil {
		return found, nil
	}
	if walkErr != nil && !os.IsNotExist(walkErr) {
		return nil, fmt.Errorf("failed to read audit root: %w", walkErr)
	}
	return nil, business.ErrAuditNotFound
}

// scanDirForID scans all JSONL files in auditDir for an entry matching id.
func (s *FlatFileAuditStore) scanDirForID(auditDir, id string) (*business.AuditEntry, error) {
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
	return nil, business.ErrAuditNotFound
}

// scanFileForID scans a single JSONL file for an entry matching id.
func (s *FlatFileAuditStore) scanFileForID(path, id string) (*business.AuditEntry, error) {
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
		var entry business.AuditEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			continue
		}
		if entry.ID == id {
			return &entry, nil
		}
	}
	return nil, business.ErrAuditNotFound
}

// ListAuditEntries returns audit entries matching the filter.
func (s *FlatFileAuditStore) ListAuditEntries(ctx context.Context, filter *business.AuditFilter) ([]*business.AuditEntry, error) {
	tenantIDs, err := s.tenantIDsForFilter(filter)
	if err != nil {
		return nil, err
	}

	var results []*business.AuditEntry
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
// When no specific tenant is requested, it walks the root directory tree to find
// every directory that contains an "audit" subdirectory. This supports hierarchical
// tenant IDs (e.g. "fleet-root/fleet-child-a") whose audit files are stored under
// nested subdirectories rather than directly under root.
func (s *FlatFileAuditStore) tenantIDsForFilter(filter *business.AuditFilter) ([]string, error) {
	if filter != nil && filter.TenantID != "" {
		return []string{filter.TenantID}, nil
	}
	var ids []string
	walkErr := filepath.WalkDir(s.root, func(path string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		// Check if this directory has an "audit" subdirectory with JSONL files.
		auditSub := filepath.Join(path, "audit")
		entries, readErr := os.ReadDir(auditSub)
		if readErr != nil {
			return nil // no audit subdir — keep walking
		}
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".jsonl") {
				// This directory is a tenant leaf: compute its ID relative to root.
				rel, relErr := filepath.Rel(s.root, path)
				if relErr != nil {
					return nil
				}
				// Convert OS path separator to '/' for tenant ID consistency.
				ids = append(ids, filepath.ToSlash(rel))
				return nil
			}
		}
		return nil
	})
	if walkErr != nil && !os.IsNotExist(walkErr) {
		return nil, fmt.Errorf("failed to walk tenant dirs: %w", walkErr)
	}
	return ids, nil
}

// scanDirForEntries scans all JSONL files in auditDir matching the filter.
func (s *FlatFileAuditStore) scanDirForEntries(auditDir string, filter *business.AuditFilter) ([]*business.AuditEntry, error) {
	files, err := os.ReadDir(auditDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var results []*business.AuditEntry
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
func fileInTimeRange(filename string, tr *business.TimeRange) bool {
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
func (s *FlatFileAuditStore) readJSONLFile(path string, filter *business.AuditFilter) ([]*business.AuditEntry, error) {
	// #nosec G304 — path from trusted os.ReadDir rooted at s.root
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	var results []*business.AuditEntry
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var entry business.AuditEntry
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
func applyAuditFilter(entry *business.AuditEntry, filter *business.AuditFilter) bool {
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
func paginateAudit(results []*business.AuditEntry, filter *business.AuditFilter) []*business.AuditEntry {
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

// GetLastAuditEntry returns the entry with the highest SequenceNumber for tenantID,
// or nil if no entries exist for that tenant. This is O(N) across the tenant's audit
// files, which is acceptable for the OSS/testing use case.
func (s *FlatFileAuditStore) GetLastAuditEntry(ctx context.Context, tenantID string) (*business.AuditEntry, error) {
	auditDir, err := s.auditDir(tenantID)
	if err != nil {
		return nil, fmt.Errorf("invalid tenant ID: %w", err)
	}

	files, err := os.ReadDir(auditDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read audit dir: %w", err)
	}

	// Scan newest files first — most likely to contain the highest sequence number.
	sort.Slice(files, func(i, j int) bool {
		return files[i].Name() > files[j].Name()
	})

	var last *business.AuditEntry
	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".jsonl") {
			continue
		}
		entries, err := s.readJSONLFile(filepath.Join(auditDir, f.Name()), nil)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if last == nil || e.SequenceNumber > last.SequenceNumber {
				last = e
			}
		}
	}
	return last, nil
}

// GetAuditsByUser retrieves audit entries for a specific user in the given time range.
func (s *FlatFileAuditStore) GetAuditsByUser(ctx context.Context, userID string, timeRange *business.TimeRange) ([]*business.AuditEntry, error) {
	return s.ListAuditEntries(ctx, &business.AuditFilter{
		UserIDs:   []string{userID},
		TimeRange: timeRange,
	})
}

// GetAuditsByResource retrieves audit entries for a specific resource.
func (s *FlatFileAuditStore) GetAuditsByResource(ctx context.Context, resourceType, resourceID string, timeRange *business.TimeRange) ([]*business.AuditEntry, error) {
	return s.ListAuditEntries(ctx, &business.AuditFilter{
		ResourceTypes: []string{resourceType},
		ResourceIDs:   []string{resourceID},
		TimeRange:     timeRange,
	})
}

// GetAuditsByAction retrieves audit entries for a specific action.
func (s *FlatFileAuditStore) GetAuditsByAction(ctx context.Context, action string, timeRange *business.TimeRange) ([]*business.AuditEntry, error) {
	return s.ListAuditEntries(ctx, &business.AuditFilter{
		Actions:   []string{action},
		TimeRange: timeRange,
	})
}

// GetFailedActions retrieves audit entries with failure, error, or denied results.
func (s *FlatFileAuditStore) GetFailedActions(ctx context.Context, timeRange *business.TimeRange, limit int) ([]*business.AuditEntry, error) {
	return s.ListAuditEntries(ctx, &business.AuditFilter{
		Results: []business.AuditResult{
			business.AuditResultFailure,
			business.AuditResultError,
			business.AuditResultDenied,
		},
		TimeRange: timeRange,
		Limit:     limit,
	})
}

// GetSuspiciousActivity retrieves high and critical severity entries for a tenant.
func (s *FlatFileAuditStore) GetSuspiciousActivity(ctx context.Context, tenantID string, timeRange *business.TimeRange) ([]*business.AuditEntry, error) {
	return s.ListAuditEntries(ctx, &business.AuditFilter{
		TenantID: tenantID,
		Severities: []business.AuditSeverity{
			business.AuditSeverityHigh,
			business.AuditSeverityCritical,
		},
		TimeRange: timeRange,
	})
}

// GetAuditStats scans all JSONL files and returns aggregate statistics.
func (s *FlatFileAuditStore) GetAuditStats(ctx context.Context) (*business.AuditStats, error) {
	stats := &business.AuditStats{
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

	auditRoot, err := os.OpenRoot(s.root)
	if err != nil {
		return nil, fmt.Errorf("open audit root: %w", err)
	}
	defer func() { _ = auditRoot.Close() }()

	walkErr := filepath.WalkDir(s.root, func(path string, d os.DirEntry, ferr error) error {
		if ferr != nil || d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".jsonl") {
			return nil
		}

		relativePath, err := filepath.Rel(s.root, path)
		if err != nil {
			return nil
		}
		f, err := auditRoot.Open(relativePath)
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
			var entry business.AuditEntry
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
			if entry.Result == business.AuditResultFailure ||
				entry.Result == business.AuditResultError ||
				entry.Result == business.AuditResultDenied {
				if entry.Timestamp.After(last24h) {
					stats.FailedActionsLast24h++
				}
			}
			if entry.Severity == business.AuditSeverityHigh ||
				entry.Severity == business.AuditSeverityCritical {
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

	// Archiving moves daily files out of the tenants' audit directories, which
	// changes what GetLastAuditEntry reports. Drop every cached chain head once
	// the walk has settled so the next append re-derives it from what remains
	// on disk.
	defer func() {
		s.mutex.Lock()
		s.forgetAllChainHeads()
		s.mutex.Unlock()
	}()

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
		// atomicRename retries Windows ERROR_SHARING_VIOLATION from
		// concurrent readers (blue/green substrate, Issue #1919).
		if err := atomicRename(path, archivePath); err != nil {
			return nil
		}

		// Count entries in the archived file. readFile retries Windows
		// sharing violations from concurrent writers.
		raw, err := readFile(archivePath)
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

	auditRoot, err := os.OpenRoot(s.root)
	if err != nil {
		return 0, fmt.Errorf("open audit root: %w", err)
	}
	defer func() { _ = auditRoot.Close() }()

	// Purging deletes daily files, which changes what GetLastAuditEntry reports.
	// Drop every cached chain head once the walk has settled so the next append
	// re-derives it from what remains on disk.
	defer func() {
		s.mutex.Lock()
		s.forgetAllChainHeads()
		s.mutex.Unlock()
	}()

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

		relativePath, err := filepath.Rel(s.root, path)
		if err != nil {
			return nil
		}
		// Files selected for purge predate the current audit file, so no writer
		// should hold them; Root keeps both the count and removal beneath s.root.
		raw, err := auditRoot.ReadFile(relativePath)
		if err == nil {
			for _, line := range strings.Split(string(raw), "\n") {
				if strings.TrimSpace(line) != "" {
					count++
				}
			}
		}
		_ = auditRoot.Remove(relativePath)
		return nil
	})
	if walkErr != nil {
		return count, fmt.Errorf("purge walk failed: %w", walkErr)
	}
	return count, nil
}

// Close satisfies business.AuditStore. FlatFileAuditStore opens files
// per-write, so there is no persistent handle to release.
func (s *FlatFileAuditStore) Close() error {
	return nil
}

// Helper functions for slice membership checks.

func containsEventType(slice []business.AuditEventType, v business.AuditEventType) bool {
	for _, s := range slice {
		if s == v {
			return true
		}
	}
	return false
}

func containsUserType(slice []business.AuditUserType, v business.AuditUserType) bool {
	for _, s := range slice {
		if s == v {
			return true
		}
	}
	return false
}

func containsResult(slice []business.AuditResult, v business.AuditResult) bool {
	for _, s := range slice {
		if s == v {
			return true
		}
	}
	return false
}

func containsSeverity(slice []business.AuditSeverity, v business.AuditSeverity) bool {
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
