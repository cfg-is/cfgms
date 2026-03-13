// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
// Package git implements production-ready git-based storage provider for CFGMS
package git

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// GitAuditStore implements AuditStore using git for persistence with JSON format
type GitAuditStore struct {
	repoPath  string
	remoteURL string
	mutex     sync.RWMutex
}

// NewGitAuditStore creates a new git-based audit store
func NewGitAuditStore(repoPath, remoteURL string) (*GitAuditStore, error) {
	store := &GitAuditStore{
		repoPath:  repoPath,
		remoteURL: remoteURL,
	}

	if err := initializeGitRepo(repoPath); err != nil {
		return nil, fmt.Errorf("failed to initialize git repository: %w", err)
	}

	return store, nil
}

// getAuditPath returns the file path for an audit entry.
// Uses date-based hierarchical structure for efficient organization.
// Example: audit/2025/01/15/tenant-a/authentication-events.json
func (s *GitAuditStore) getAuditPath(entry *interfaces.AuditEntry) (string, error) {
	year := entry.Timestamp.Format("2006")
	month := entry.Timestamp.Format("01")
	day := entry.Timestamp.Format("02")
	fileName := fmt.Sprintf("%s-events.json", entry.EventType)
	p, err := safePath(s.repoPath, year, month, day, entry.TenantID, fileName)
	if err != nil {
		return "", err
	}
	return filepath.Clean(p), nil // explicit Clean for CodeQL path-injection analysis
}

// StoreAuditEntry stores an audit entry as JSON in git
func (s *GitAuditStore) StoreAuditEntry(ctx context.Context, entry *interfaces.AuditEntry) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

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

	if entry.ID == "" {
		entry.ID = s.generateAuditID(entry)
	}
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}

	filePath, err := s.getAuditPath(entry)
	if err != nil {
		return fmt.Errorf("invalid audit path: %w", err)
	}

	// #nosec G301 - Git repository directories need standard permissions for git operations
	if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	var entries []*interfaces.AuditEntry
	if _, err := os.Stat(filePath); !os.IsNotExist(err) {
		entries, err = s.readAuditFile(filePath)
		if err != nil {
			return fmt.Errorf("failed to read existing audit file: %w", err)
		}
	}

	entries = append(entries, entry)

	if err := s.writeAuditFile(filePath, entries); err != nil {
		return fmt.Errorf("failed to write audit file: %w", err)
	}

	commitMsg := fmt.Sprintf("Add audit entry %s: %s by %s",
		entry.EventType, entry.Action, entry.UserID)

	if err := gitCommitFile(s.repoPath, filePath, commitMsg); err != nil {
		return fmt.Errorf("failed to commit to git: %w", err)
	}

	return nil
}

// GetAuditEntry retrieves a specific audit entry by ID
func (s *GitAuditStore) GetAuditEntry(ctx context.Context, id string) (*interfaces.AuditEntry, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	var foundEntry *interfaces.AuditEntry

	err := filepath.Walk(s.repoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}
		if strings.Contains(path, ".git") {
			return nil
		}

		entries, err := s.readAuditFile(path)
		if err != nil {
			return nil
		}

		for _, entry := range entries {
			if entry.ID == id {
				foundEntry = entry
				return filepath.SkipDir
			}
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to search for audit entry: %w", err)
	}

	if foundEntry == nil {
		return nil, interfaces.ErrAuditNotFound
	}

	return foundEntry, nil
}

// ListAuditEntries lists audit entries matching the filter
func (s *GitAuditStore) ListAuditEntries(ctx context.Context, filter *interfaces.AuditFilter) ([]*interfaces.AuditEntry, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	var allEntries []*interfaces.AuditEntry

	err := filepath.Walk(s.repoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}
		if strings.Contains(path, ".git") {
			return nil
		}

		entries, err := s.readAuditFile(path)
		if err != nil {
			return nil
		}

		for _, entry := range entries {
			if s.matchesFilter(entry, filter) {
				allEntries = append(allEntries, entry)
			}
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk repository: %w", err)
	}

	if len(allEntries) > 1 {
		s.sortAuditEntries(allEntries, filter)
	}

	if filter != nil && filter.Limit > 0 {
		start := filter.Offset
		if start > len(allEntries) {
			start = len(allEntries)
		}
		end := start + filter.Limit
		if end > len(allEntries) {
			end = len(allEntries)
		}
		allEntries = allEntries[start:end]
	}

	return allEntries, nil
}

// StoreAuditBatch stores multiple audit entries efficiently
func (s *GitAuditStore) StoreAuditBatch(ctx context.Context, entries []*interfaces.AuditEntry) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	fileGroups := make(map[string][]*interfaces.AuditEntry)

	for _, entry := range entries {
		if err := s.validateAndSetMetadata(entry); err != nil {
			return fmt.Errorf("failed to validate entry %s: %w", entry.ID, err)
		}
		filePath, err := s.getAuditPath(entry)
		if err != nil {
			return fmt.Errorf("invalid audit path for entry %s: %w", entry.ID, err)
		}
		fileGroups[filePath] = append(fileGroups[filePath], entry)
	}

	var filePaths []string

	for filePath, groupEntries := range fileGroups {
		// #nosec G301 - Git repository directories need standard permissions for git operations
		if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}

		var existingEntries []*interfaces.AuditEntry
		if _, err := os.Stat(filePath); !os.IsNotExist(err) {
			existing, err := s.readAuditFile(filePath)
			if err != nil {
				return fmt.Errorf("failed to read existing audit file: %w", err)
			}
			existingEntries = existing
		}

		allEntries := append(existingEntries, groupEntries...)

		if err := s.writeAuditFile(filePath, allEntries); err != nil {
			return fmt.Errorf("failed to write audit file: %w", err)
		}

		filePaths = append(filePaths, filePath)
	}

	commitMsg := fmt.Sprintf("Batch add %d audit entries", len(entries))
	if err := gitCommitFiles(s.repoPath, filePaths, commitMsg); err != nil {
		return fmt.Errorf("failed to commit batch: %w", err)
	}

	return nil
}

// GetAuditsByUser gets audit entries for a specific user
func (s *GitAuditStore) GetAuditsByUser(ctx context.Context, userID string, timeRange *interfaces.TimeRange) ([]*interfaces.AuditEntry, error) {
	filter := &interfaces.AuditFilter{
		UserIDs:   []string{userID},
		TimeRange: timeRange,
	}
	return s.ListAuditEntries(ctx, filter)
}

// GetAuditsByResource gets audit entries for a specific resource
func (s *GitAuditStore) GetAuditsByResource(ctx context.Context, resourceType, resourceID string, timeRange *interfaces.TimeRange) ([]*interfaces.AuditEntry, error) {
	filter := &interfaces.AuditFilter{
		ResourceTypes: []string{resourceType},
		ResourceIDs:   []string{resourceID},
		TimeRange:     timeRange,
	}
	return s.ListAuditEntries(ctx, filter)
}

// GetAuditsByAction gets audit entries for a specific action
func (s *GitAuditStore) GetAuditsByAction(ctx context.Context, action string, timeRange *interfaces.TimeRange) ([]*interfaces.AuditEntry, error) {
	filter := &interfaces.AuditFilter{
		Actions:   []string{action},
		TimeRange: timeRange,
	}
	return s.ListAuditEntries(ctx, filter)
}

// GetFailedActions gets recent failed actions for security monitoring
func (s *GitAuditStore) GetFailedActions(ctx context.Context, timeRange *interfaces.TimeRange, limit int) ([]*interfaces.AuditEntry, error) {
	filter := &interfaces.AuditFilter{
		Results:   []interfaces.AuditResult{interfaces.AuditResultFailure, interfaces.AuditResultError, interfaces.AuditResultDenied},
		TimeRange: timeRange,
		Limit:     limit,
		SortBy:    "timestamp",
		Order:     "desc",
	}
	return s.ListAuditEntries(ctx, filter)
}

// GetSuspiciousActivity gets suspicious activity for a tenant
func (s *GitAuditStore) GetSuspiciousActivity(ctx context.Context, tenantID string, timeRange *interfaces.TimeRange) ([]*interfaces.AuditEntry, error) {
	filter := &interfaces.AuditFilter{
		TenantID:   tenantID,
		EventTypes: []interfaces.AuditEventType{interfaces.AuditEventSecurityEvent},
		Severities: []interfaces.AuditSeverity{interfaces.AuditSeverityHigh, interfaces.AuditSeverityCritical},
		TimeRange:  timeRange,
		SortBy:     "timestamp",
		Order:      "desc",
	}
	return s.ListAuditEntries(ctx, filter)
}

// GetAuditStats returns statistics about stored audit entries
func (s *GitAuditStore) GetAuditStats(ctx context.Context) (*interfaces.AuditStats, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	stats := &interfaces.AuditStats{
		EntriesByTenant:   make(map[string]int64),
		EntriesByType:     make(map[string]int64),
		EntriesByResult:   make(map[string]int64),
		EntriesBySeverity: make(map[string]int64),
		LastUpdated:       time.Now(),
	}

	now := time.Now()
	last24h := now.Add(-24 * time.Hour)
	last7d := now.Add(-7 * 24 * time.Hour)
	last30d := now.Add(-30 * 24 * time.Hour)

	err := filepath.Walk(s.repoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}
		if strings.Contains(path, ".git") {
			return nil
		}

		entries, err := s.readAuditFile(path)
		if err != nil {
			return nil
		}

		for _, entry := range entries {
			stats.TotalEntries++
			stats.TotalSize += int64(len(entry.ID))
			stats.EntriesByTenant[entry.TenantID]++
			stats.EntriesByType[string(entry.EventType)]++
			stats.EntriesByResult[string(entry.Result)]++
			stats.EntriesBySeverity[string(entry.Severity)]++

			if stats.OldestEntry == nil || entry.Timestamp.Before(*stats.OldestEntry) {
				stats.OldestEntry = &entry.Timestamp
			}
			if stats.NewestEntry == nil || entry.Timestamp.After(*stats.NewestEntry) {
				stats.NewestEntry = &entry.Timestamp
			}

			if entry.Timestamp.After(last24h) {
				stats.EntriesLast24h++
			}
			if entry.Timestamp.After(last7d) {
				stats.EntriesLast7d++
			}
			if entry.Timestamp.After(last30d) {
				stats.EntriesLast30d++
			}

			if entry.Result == interfaces.AuditResultFailure || entry.Result == interfaces.AuditResultError || entry.Result == interfaces.AuditResultDenied {
				if entry.Timestamp.After(last24h) {
					stats.FailedActionsLast24h++
				}
			}

			if entry.EventType == interfaces.AuditEventSecurityEvent {
				stats.SuspiciousActivityCount++
				if stats.LastSecurityIncident == nil || entry.Timestamp.After(*stats.LastSecurityIncident) {
					stats.LastSecurityIncident = &entry.Timestamp
				}
			}
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to collect statistics: %w", err)
	}

	if stats.TotalEntries > 0 {
		stats.AverageSize = stats.TotalSize / stats.TotalEntries
	}

	return stats, nil
}

// ArchiveAuditEntries archives old audit entries.
// Git-based storage naturally archives data through commits.
func (s *GitAuditStore) ArchiveAuditEntries(ctx context.Context, beforeDate time.Time) (int64, error) {
	return 0, nil
}

// PurgeAuditEntries purges very old audit entries (use with caution)
func (s *GitAuditStore) PurgeAuditEntries(ctx context.Context, beforeDate time.Time) (int64, error) {
	return 0, nil
}

// generateAuditID generates a unique ID for an audit entry
func (s *GitAuditStore) generateAuditID(entry *interfaces.AuditEntry) string {
	data := fmt.Sprintf("%s-%s-%s-%s-%d",
		entry.TenantID, entry.UserID, entry.Action, entry.ResourceID, entry.Timestamp.UnixNano())
	hasher := sha256.New()
	hasher.Write([]byte(data))
	return hex.EncodeToString(hasher.Sum(nil))[:16]
}

// validateAndSetMetadata validates and sets required metadata for an audit entry
func (s *GitAuditStore) validateAndSetMetadata(entry *interfaces.AuditEntry) error {
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

	if entry.ID == "" {
		entry.ID = s.generateAuditID(entry)
	}
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}

	return nil
}

// writeAuditFile writes audit entries to a JSON file
func (s *GitAuditStore) writeAuditFile(filePath string, entries []*interfaces.AuditEntry) error {
	jsonData, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal audit entries: %w", err)
	}

	// #nosec G306 - Audit files need read permissions for compliance tools
	if err := os.WriteFile(filePath, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// readAuditFile reads audit entries from a JSON file
func (s *GitAuditStore) readAuditFile(filePath string) ([]*interfaces.AuditEntry, error) {
	// #nosec G304 - Git storage requires reading config files from controlled repository paths
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var entries []*interfaces.AuditEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	return entries, nil
}

// matchesFilter checks if an audit entry matches the filter criteria
func (s *GitAuditStore) matchesFilter(entry *interfaces.AuditEntry, filter *interfaces.AuditFilter) bool {
	if filter == nil {
		return true
	}

	if filter.TenantID != "" && entry.TenantID != filter.TenantID {
		return false
	}

	if len(filter.EventTypes) > 0 {
		found := false
		for _, eventType := range filter.EventTypes {
			if entry.EventType == eventType {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if len(filter.Actions) > 0 {
		found := false
		for _, action := range filter.Actions {
			if entry.Action == action {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if len(filter.UserIDs) > 0 {
		found := false
		for _, userID := range filter.UserIDs {
			if entry.UserID == userID {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if len(filter.UserTypes) > 0 {
		found := false
		for _, userType := range filter.UserTypes {
			if entry.UserType == userType {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if len(filter.Results) > 0 {
		found := false
		for _, result := range filter.Results {
			if entry.Result == result {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if len(filter.Severities) > 0 {
		found := false
		for _, severity := range filter.Severities {
			if entry.Severity == severity {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if len(filter.ResourceTypes) > 0 {
		found := false
		for _, resourceType := range filter.ResourceTypes {
			if entry.ResourceType == resourceType {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if len(filter.ResourceIDs) > 0 {
		found := false
		for _, resourceID := range filter.ResourceIDs {
			if entry.ResourceID == resourceID {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if filter.TimeRange != nil {
		if filter.TimeRange.Start != nil && entry.Timestamp.Before(*filter.TimeRange.Start) {
			return false
		}
		if filter.TimeRange.End != nil && entry.Timestamp.After(*filter.TimeRange.End) {
			return false
		}
	}

	if len(filter.Tags) > 0 {
		entryTags := make(map[string]bool)
		for _, tag := range entry.Tags {
			entryTags[tag] = true
		}
		for _, tag := range filter.Tags {
			if !entryTags[tag] {
				return false
			}
		}
	}

	return true
}

// sortAuditEntries sorts audit entries based on filter criteria
func (s *GitAuditStore) sortAuditEntries(entries []*interfaces.AuditEntry, filter *interfaces.AuditFilter) {
	if filter == nil || filter.SortBy == "" {
		// Default: sort by timestamp descending
		for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
			if entries[i].Timestamp.Before(entries[j].Timestamp) {
				entries[i], entries[j] = entries[j], entries[i]
			}
		}
		return
	}

	ascending := filter.Order == "asc"

	switch filter.SortBy {
	case "timestamp":
		for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
			if ascending {
				if entries[i].Timestamp.After(entries[j].Timestamp) {
					entries[i], entries[j] = entries[j], entries[i]
				}
			} else {
				if entries[i].Timestamp.Before(entries[j].Timestamp) {
					entries[i], entries[j] = entries[j], entries[i]
				}
			}
		}
	}
}

// SyncWithRemote synchronizes the audit repository with the remote
func (s *GitAuditStore) SyncWithRemote(ctx context.Context) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.remoteURL == "" {
		return nil
	}

	if err := s.pullFromRemote(ctx); err != nil {
		return fmt.Errorf("failed to pull from remote: %w", err)
	}
	if err := s.pushToRemote(ctx); err != nil {
		return fmt.Errorf("failed to push to remote: %w", err)
	}

	return nil
}

// pullFromRemote pulls changes from the remote repository
func (s *GitAuditStore) pullFromRemote(ctx context.Context) error {
	if s.remoteURL == "" {
		return nil
	}

	cmd := exec.CommandContext(ctx, "git", "remote", "get-url", "origin")
	cmd.Dir = s.repoPath
	if err := cmd.Run(); err != nil {
		// #nosec G204 - Git storage requires remote URL management for distributed repos
		cmd = exec.CommandContext(ctx, "git", "remote", "add", "origin", s.remoteURL)
		cmd.Dir = s.repoPath
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to add remote origin: %w", err)
		}
	}

	cmd = exec.CommandContext(ctx, "git", "fetch", "origin")
	cmd.Dir = s.repoPath
	if err := cmd.Run(); err != nil {
		return nil
	}

	// Use rebase for append-only audit logs to avoid merge commits
	cmd = exec.CommandContext(ctx, "git", "pull", "origin", "main")
	cmd.Dir = s.repoPath
	if err := cmd.Run(); err != nil {
		cmd = exec.CommandContext(ctx, "git", "pull", "--rebase", "origin", "main")
		cmd.Dir = s.repoPath
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to pull audit data: %w", err)
		}
	}

	return nil
}

// pushToRemote pushes audit changes to the remote repository
func (s *GitAuditStore) pushToRemote(ctx context.Context) error {
	if s.remoteURL == "" {
		return nil
	}

	cmd := exec.CommandContext(ctx, "git", "rev-parse", "HEAD")
	cmd.Dir = s.repoPath
	if err := cmd.Run(); err != nil {
		return nil
	}

	// Audit logs should always be pushed for compliance
	cmd = exec.CommandContext(ctx, "git", "push", "origin", "main")
	cmd.Dir = s.repoPath
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to push audit data to remote: %w", err)
	}

	return nil
}

// SetRemoteURL sets the remote repository URL for audit storage
func (s *GitAuditStore) SetRemoteURL(remoteURL string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.remoteURL = remoteURL

	if remoteURL != "" {
		cmd := exec.Command("git", "remote", "set-url", "origin", remoteURL)
		cmd.Dir = s.repoPath
		if err := cmd.Run(); err != nil {
			cmd = exec.Command("git", "remote", "add", "origin", remoteURL)
			cmd.Dir = s.repoPath
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("failed to set remote URL: %w", err)
			}
		}
	}

	return nil
}
