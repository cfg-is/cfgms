// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package tagstore provides a durable controller-side tag store keyed by steward ID.
//
// Tags are controller-owned: they are never steward-reported, survive controller
// restarts, and are not clobbered when the controller replaces a steward's DNA
// on each DNARefreshLoop cycle. This separation is the clobber-proof source of
// truth for operator-assigned steward metadata used by the selector engine (S1b).
package tagstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	_ "modernc.org/sqlite" // Pure-Go SQLite driver (CGO-free)

	"github.com/cfgis/cfgms/pkg/logging"
)

// tagRE validates tag values: lowercase alphanumeric start, then alphanumeric-or-hyphen,
// total 1–64 characters. Keeps tags selector-safe and DNS-label-compatible.
var tagRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// ErrInvalidTag is returned when a tag value does not match ^[a-z0-9][a-z0-9-]{0,63}$.
var ErrInvalidTag = errors.New("invalid tag: must match ^[a-z0-9][a-z0-9-]{0,63}$")

// Store is a durable controller-side tag store backed by SQLite.
// Tags are keyed by steward ID; each steward has an ordered, deduplicated list of tags.
// The store survives controller restarts.
type Store struct {
	db     *sql.DB
	logger logging.Logger
}

// NewFromDSN opens a SQLite database at dsn and returns a Store.
// Call Initialize before any other method, and Close when done.
func NewFromDSN(dsn string, logger logging.Logger) (*Store, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("tagstore: open sqlite %s: %w", dsn, err)
	}
	// busy_timeout prevents SQLITE_BUSY under concurrent writers.
	if _, err := db.Exec("PRAGMA busy_timeout = 5000"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("tagstore: set busy_timeout: %w", err)
	}
	return &Store{db: db, logger: logger}, nil
}

// Initialize creates the steward_tags table if it does not already exist.
// Safe to call multiple times (idempotent).
func (s *Store) Initialize(_ context.Context) error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS steward_tags (
    steward_id  TEXT NOT NULL PRIMARY KEY,
    tags        TEXT NOT NULL DEFAULT '[]',
    updated_at  TEXT NOT NULL
)`)
	if err != nil {
		return fmt.Errorf("tagstore: create steward_tags table: %w", err)
	}
	return nil
}

// Close releases the database connection.
func (s *Store) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// Set replaces the full tag list for stewardID. An empty slice clears all tags but
// keeps the row (use Delete to remove the entry entirely).
// Returns ErrInvalidTag if any tag fails validation, or an error if any tag is duplicated.
func (s *Store) Set(ctx context.Context, stewardID string, tags []string) error {
	if err := validateTags(tags); err != nil {
		return err
	}
	encoded, err := marshalTags(tags)
	if err != nil {
		return fmt.Errorf("tagstore: marshal tags: %w", err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = s.db.ExecContext(ctx, `
INSERT INTO steward_tags (steward_id, tags, updated_at)
VALUES (?, ?, ?)
ON CONFLICT(steward_id) DO UPDATE SET tags = excluded.tags, updated_at = excluded.updated_at`,
		stewardID, encoded, now,
	)
	if err != nil {
		return fmt.Errorf("tagstore: set tags for %s: %w", logging.SanitizeLogValue(stewardID), err)
	}
	s.logger.Debug("Tags updated",
		"steward_id", logging.SanitizeLogValue(stewardID),
		"count", len(tags))
	return nil
}

// Get returns the tag list for stewardID.
// Returns an empty slice (not an error) when no entry exists for the steward.
func (s *Store) Get(ctx context.Context, stewardID string) ([]string, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT tags FROM steward_tags WHERE steward_id = ?`, stewardID)
	var encoded string
	if err := row.Scan(&encoded); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return []string{}, nil
		}
		return nil, fmt.Errorf("tagstore: get tags for %s: %w", logging.SanitizeLogValue(stewardID), err)
	}
	return unmarshalTags(encoded)
}

// Delete removes the tag entry for stewardID.
// Returns nil (not an error) when no entry exists.
func (s *Store) Delete(ctx context.Context, stewardID string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM steward_tags WHERE steward_id = ?`, stewardID)
	if err != nil {
		return fmt.Errorf("tagstore: delete tags for %s: %w", logging.SanitizeLogValue(stewardID), err)
	}
	return nil
}

// GetAll returns all steward-to-tag-list mappings in the store, ordered by steward ID.
// Returns an empty map (not an error) when the store is empty.
func (s *Store) GetAll(ctx context.Context) (map[string][]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT steward_id, tags FROM steward_tags ORDER BY steward_id`)
	if err != nil {
		return nil, fmt.Errorf("tagstore: get all: %w", err)
	}
	defer func() { _ = rows.Close() }()

	result := make(map[string][]string)
	for rows.Next() {
		var stewardID, encoded string
		if err := rows.Scan(&stewardID, &encoded); err != nil {
			return nil, fmt.Errorf("tagstore: scan row: %w", err)
		}
		tags, err := unmarshalTags(encoded)
		if err != nil {
			return nil, fmt.Errorf("tagstore: unmarshal tags for %s: %w",
				logging.SanitizeLogValue(stewardID), err)
		}
		result[stewardID] = tags
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("tagstore: iterate rows: %w", err)
	}
	return result, nil
}

// TagsFor returns the tag list for stewardID. It is a convenience accessor that
// never returns an error — failures are logged and an empty slice is returned.
// Intended for use by the selector engine (S1b) and role adapter (S4) where a
// missing tag set should be treated as "no tags" rather than a fatal error.
func (s *Store) TagsFor(stewardID string) []string {
	tags, err := s.Get(context.Background(), stewardID)
	if err != nil {
		s.logger.Warn("TagsFor: failed to read tags",
			"steward_id", logging.SanitizeLogValue(stewardID),
			"error", err)
		return []string{}
	}
	return tags
}

// --- helpers -----------------------------------------------------------------

// validateTags checks that every tag in the slice is syntactically valid and
// that there are no duplicates within the slice.
func validateTags(tags []string) error {
	seen := make(map[string]struct{}, len(tags))
	for _, t := range tags {
		if !tagRE.MatchString(t) {
			return fmt.Errorf("%w: %q", ErrInvalidTag, t)
		}
		if _, dup := seen[t]; dup {
			return fmt.Errorf("tagstore: duplicate tag %q", t)
		}
		seen[t] = struct{}{}
	}
	return nil
}

// marshalTags serialises a tag slice to a JSON array string.
func marshalTags(tags []string) (string, error) {
	if tags == nil {
		tags = []string{}
	}
	b, err := json.Marshal(tags)
	if err != nil {
		return "", fmt.Errorf("tagstore: marshal: %w", err)
	}
	return string(b), nil
}

// unmarshalTags parses a JSON array string into a tag slice.
func unmarshalTags(encoded string) ([]string, error) {
	if encoded == "" || strings.EqualFold(encoded, "null") {
		return []string{}, nil
	}
	var tags []string
	if err := json.Unmarshal([]byte(encoded), &tags); err != nil {
		return nil, fmt.Errorf("tagstore: unmarshal: %w", err)
	}
	if tags == nil {
		return []string{}, nil
	}
	return tags, nil
}
