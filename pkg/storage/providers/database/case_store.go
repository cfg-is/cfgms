// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package database implements CaseStore using PostgreSQL (ADR-022 §8, Issue #3602).
package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "github.com/lib/pq"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Compile-time assertion.
var _ business.CaseStore = (*DatabaseCaseStore)(nil)

// DatabaseCaseStore implements business.CaseStore using PostgreSQL.
type DatabaseCaseStore struct {
	db *sql.DB
}

// NewDatabaseCaseStore opens a pooled Postgres connection, initialises the schema,
// and returns a ready-to-use CaseStore.
func NewDatabaseCaseStore(dsn string, config map[string]interface{}) (*DatabaseCaseStore, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("database: failed to open case store connection: %w", err)
	}
	db.SetMaxOpenConns(getIntFromConfig(config, "max_open_connections", 25))
	db.SetMaxIdleConns(getIntFromConfig(config, "max_idle_connections", 5))
	db.SetConnMaxLifetime(time.Duration(getIntFromConfig(config, "connection_max_lifetime_minutes", 30)) * time.Minute)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("database: failed to ping case store: %w", err)
	}
	store := &DatabaseCaseStore{db: db}
	if err := store.initSchema(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("database: failed to initialise case store schema: %w", err)
	}
	return store, nil
}

func (s *DatabaseCaseStore) initSchema() error {
	ctx := context.Background()
	const lockID = 71934863 // advisory lock unique to cockpit case schema
	if _, err := s.db.ExecContext(ctx, "SELECT pg_advisory_lock($1)", lockID); err != nil {
		return fmt.Errorf("database: failed to acquire case schema lock: %w", err)
	}
	defer func() { _, _ = s.db.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", lockID) }()
	return NewDatabaseSchemas().CreateCaseTables(ctx, s.db)
}

// Initialize is a no-op: the schema is created in NewDatabaseCaseStore.
func (s *DatabaseCaseStore) Initialize(ctx context.Context) error { return nil }

// Close releases the database connection.
func (s *DatabaseCaseStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// CreateCase persists a new case record.
func (s *DatabaseCaseStore) CreateCase(ctx context.Context, c *business.Case) error {
	if c == nil {
		return fmt.Errorf("database: case cannot be nil")
	}
	if c.ID == "" || c.TenantID == "" {
		return fmt.Errorf("database: case ID and tenant ID are required")
	}
	ticketJSON, err := dbMarshalTicket(c.Ticket)
	if err != nil {
		return fmt.Errorf("database: failed to marshal ticket for case %s: %w", c.ID, err)
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO cases (id, tenant_id, status, ticket_json, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		c.ID, c.TenantID, string(c.Status), ticketJSON, c.CreatedAt, c.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("database: failed to create case %s: %w", c.ID, err)
	}
	return nil
}

// GetCase retrieves a case by ID including its full aggregate (ticket + pins + content).
func (s *DatabaseCaseStore) GetCase(ctx context.Context, id string) (*business.Case, error) {
	if id == "" {
		return nil, fmt.Errorf("database: case ID cannot be empty")
	}
	row := s.db.QueryRowContext(ctx, `
		SELECT id, tenant_id, status, ticket_json, created_at, updated_at
		FROM cases WHERE id = $1`, id)

	c, err := scanDBCase(row)
	if err != nil {
		return nil, err
	}

	pins, err := s.listPinsInternal(ctx, id)
	if err != nil {
		return nil, err
	}
	c.Pins = pins

	content, err := s.listContentInternal(ctx, id)
	if err != nil {
		return nil, err
	}
	c.Content = content

	return c, nil
}

// ListCases returns all cases within the given tenantID's subtree (the tenant
// itself plus any descendant tenants), newest first.
func (s *DatabaseCaseStore) ListCases(ctx context.Context, tenantID string) ([]*business.Case, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("database: tenant ID cannot be empty")
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, tenant_id, status, ticket_json, created_at, updated_at
		FROM cases WHERE tenant_id = $1 OR tenant_id LIKE $2 ORDER BY created_at DESC`,
		tenantID, tenantID+"/%")
	if err != nil {
		return nil, fmt.Errorf("database: failed to list cases for tenant %s: %w", tenantID, err)
	}
	defer func() { _ = rows.Close() }()

	var out []*business.Case
	for rows.Next() {
		c, err := scanDBCaseRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// UpdateCase updates a case's status and ticket.
func (s *DatabaseCaseStore) UpdateCase(ctx context.Context, c *business.Case) error {
	if c == nil {
		return fmt.Errorf("database: case cannot be nil")
	}
	if c.ID == "" {
		return fmt.Errorf("database: case ID is required")
	}
	ticketJSON, err := dbMarshalTicket(c.Ticket)
	if err != nil {
		return fmt.Errorf("database: failed to marshal ticket for case %s: %w", c.ID, err)
	}
	result, err := s.db.ExecContext(ctx, `
		UPDATE cases SET status = $1, ticket_json = $2, updated_at = now() WHERE id = $3`,
		string(c.Status), ticketJSON, c.ID,
	)
	if err != nil {
		return fmt.Errorf("database: failed to update case %s: %w", c.ID, err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("database: failed to get rows affected: %w", err)
	}
	if n == 0 {
		return business.ErrCaseNotFound
	}
	return nil
}

// AddPin attaches a pin to an existing case.
func (s *DatabaseCaseStore) AddPin(ctx context.Context, caseID string, pin *business.Pin) error {
	if caseID == "" {
		return fmt.Errorf("database: case ID cannot be empty")
	}
	if pin == nil || pin.ID == "" {
		return fmt.Errorf("database: pin and pin ID are required")
	}
	var rangeStart, rangeEnd *time.Time
	if !pin.Ref.TimeRangeStart.IsZero() {
		t := pin.Ref.TimeRangeStart
		rangeStart = &t
	}
	if !pin.Ref.TimeRangeEnd.IsZero() {
		t := pin.Ref.TimeRangeEnd
		rangeEnd = &t
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO case_pins (id, case_id, ref_kind, ref_eid, ref_edge_identity,
			ref_obs_version, ref_drift_record, ref_subject, ref_range_start, ref_range_end,
			annotation, author, pinned_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		pin.ID, caseID,
		string(pin.Ref.Kind), pin.Ref.EID, pin.Ref.EdgeIdentity,
		pin.Ref.ObservationVersion, pin.Ref.DriftRecord, pin.Ref.Subject,
		rangeStart, rangeEnd,
		pin.Annotation, pin.Author, pin.PinnedAt,
	)
	if err != nil {
		return fmt.Errorf("database: failed to add pin %s to case %s: %w", pin.ID, caseID, err)
	}
	return nil
}

// RemovePin detaches a pin from a case.
func (s *DatabaseCaseStore) RemovePin(ctx context.Context, caseID, pinID string) error {
	if caseID == "" || pinID == "" {
		return fmt.Errorf("database: case ID and pin ID cannot be empty")
	}
	result, err := s.db.ExecContext(ctx,
		`DELETE FROM case_pins WHERE case_id = $1 AND id = $2`, caseID, pinID)
	if err != nil {
		return fmt.Errorf("database: failed to remove pin %s from case %s: %w", pinID, caseID, err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("database: failed to get rows affected: %w", err)
	}
	if n == 0 {
		return business.ErrPinNotFound
	}
	return nil
}

// ListPins returns all pins attached to the given case.
func (s *DatabaseCaseStore) ListPins(ctx context.Context, caseID string) ([]*business.Pin, error) {
	if caseID == "" {
		return nil, fmt.Errorf("database: case ID cannot be empty")
	}
	return s.listPinsInternal(ctx, caseID)
}

// AddContent appends a content entry to an existing case.
func (s *DatabaseCaseStore) AddContent(ctx context.Context, caseID string, entry *business.ContentEntry) error {
	if caseID == "" {
		return fmt.Errorf("database: case ID cannot be empty")
	}
	if entry == nil || entry.ID == "" {
		return fmt.Errorf("database: content entry and entry ID are required")
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO case_content (id, case_id, kind, body, author, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		entry.ID, caseID, string(entry.Kind), entry.Body, entry.Author, entry.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("database: failed to add content %s to case %s: %w", entry.ID, caseID, err)
	}
	return nil
}

// ListContent returns all content entries for the given case, oldest first.
func (s *DatabaseCaseStore) ListContent(ctx context.Context, caseID string) ([]*business.ContentEntry, error) {
	if caseID == "" {
		return nil, fmt.Errorf("database: case ID cannot be empty")
	}
	return s.listContentInternal(ctx, caseID)
}

func (s *DatabaseCaseStore) listPinsInternal(ctx context.Context, caseID string) ([]*business.Pin, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, case_id, ref_kind, ref_eid, ref_edge_identity, ref_obs_version,
			ref_drift_record, ref_subject, ref_range_start, ref_range_end,
			annotation, author, pinned_at
		FROM case_pins WHERE case_id = $1 ORDER BY pinned_at ASC`, caseID)
	if err != nil {
		return nil, fmt.Errorf("database: failed to list pins for case %s: %w", caseID, err)
	}
	defer func() { _ = rows.Close() }()

	var out []*business.Pin
	for rows.Next() {
		p, err := scanDBPinRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *DatabaseCaseStore) listContentInternal(ctx context.Context, caseID string) ([]*business.ContentEntry, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, case_id, kind, body, author, created_at
		FROM case_content WHERE case_id = $1 ORDER BY created_at ASC`, caseID)
	if err != nil {
		return nil, fmt.Errorf("database: failed to list content for case %s: %w", caseID, err)
	}
	defer func() { _ = rows.Close() }()

	var out []*business.ContentEntry
	for rows.Next() {
		e, err := scanDBContentRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func scanDBCase(row *sql.Row) (*business.Case, error) {
	var c business.Case
	var status, ticketStr string
	err := row.Scan(&c.ID, &c.TenantID, &status, &ticketStr, &c.CreatedAt, &c.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, business.ErrCaseNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("database: failed to scan case: %w", err)
	}
	c.Status = business.CaseStatus(status)
	t, err := dbUnmarshalTicket(ticketStr)
	if err != nil {
		return nil, fmt.Errorf("database: failed to unmarshal ticket for case %s: %w", c.ID, err)
	}
	c.Ticket = t
	return &c, nil
}

func scanDBCaseRow(rows *sql.Rows) (*business.Case, error) {
	var c business.Case
	var status, ticketStr string
	if err := rows.Scan(&c.ID, &c.TenantID, &status, &ticketStr, &c.CreatedAt, &c.UpdatedAt); err != nil {
		return nil, fmt.Errorf("database: failed to scan case row: %w", err)
	}
	c.Status = business.CaseStatus(status)
	t, err := dbUnmarshalTicket(ticketStr)
	if err != nil {
		return nil, fmt.Errorf("database: failed to unmarshal ticket: %w", err)
	}
	c.Ticket = t
	return &c, nil
}

func scanDBPinRow(rows *sql.Rows) (*business.Pin, error) {
	var p business.Pin
	var refKind, refEID, refEdge, refObs, refDrift, refSubject string
	var rangeStart, rangeEnd sql.NullTime

	if err := rows.Scan(
		&p.ID, &p.CaseID, &refKind, &refEID, &refEdge,
		&refObs, &refDrift, &refSubject, &rangeStart, &rangeEnd,
		&p.Annotation, &p.Author, &p.PinnedAt,
	); err != nil {
		return nil, fmt.Errorf("database: failed to scan pin row: %w", err)
	}
	p.Ref = business.PinRef{
		Kind:               business.PinRefKind(refKind),
		EID:                refEID,
		EdgeIdentity:       refEdge,
		ObservationVersion: refObs,
		DriftRecord:        refDrift,
		Subject:            refSubject,
	}
	if rangeStart.Valid {
		p.Ref.TimeRangeStart = rangeStart.Time
	}
	if rangeEnd.Valid {
		p.Ref.TimeRangeEnd = rangeEnd.Time
	}
	return &p, nil
}

func scanDBContentRow(rows *sql.Rows) (*business.ContentEntry, error) {
	var e business.ContentEntry
	var kind string
	if err := rows.Scan(&e.ID, &e.CaseID, &kind, &e.Body, &e.Author, &e.CreatedAt); err != nil {
		return nil, fmt.Errorf("database: failed to scan content row: %w", err)
	}
	e.Kind = business.ContentKind(kind)
	return &e, nil
}

// dbTicketFieldJSON and dbTicketJSON are private JSON representations for the Postgres store.
type dbTicketFieldJSON struct {
	Value  string `json:"value"`
	Source string `json:"source"`
	Filled bool   `json:"filled"`
}

type dbTicketJSON struct {
	Title    dbTicketFieldJSON `json:"title"`
	Client   dbTicketFieldJSON `json:"client"`
	Contact  dbTicketFieldJSON `json:"contact"`
	Priority dbTicketFieldJSON `json:"priority"`
	Category dbTicketFieldJSON `json:"category"`
}

func dbMarshalTicket(t business.Ticket) (string, error) {
	tj := dbTicketJSON{
		Title:    dbTicketFieldJSON{Value: t.Title.Value, Source: string(t.Title.Source), Filled: t.Title.Filled},
		Client:   dbTicketFieldJSON{Value: t.Client.Value, Source: string(t.Client.Source), Filled: t.Client.Filled},
		Contact:  dbTicketFieldJSON{Value: t.Contact.Value, Source: string(t.Contact.Source), Filled: t.Contact.Filled},
		Priority: dbTicketFieldJSON{Value: t.Priority.Value, Source: string(t.Priority.Source), Filled: t.Priority.Filled},
		Category: dbTicketFieldJSON{Value: t.Category.Value, Source: string(t.Category.Source), Filled: t.Category.Filled},
	}
	b, err := json.Marshal(tj)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func dbUnmarshalTicket(s string) (business.Ticket, error) {
	if s == "" || s == "{}" {
		return business.Ticket{}, nil
	}
	var tj dbTicketJSON
	if err := json.Unmarshal([]byte(s), &tj); err != nil {
		return business.Ticket{}, err
	}
	return business.Ticket{
		Title:    business.TicketField{Value: tj.Title.Value, Source: business.TicketFieldSource(tj.Title.Source), Filled: tj.Title.Filled},
		Client:   business.TicketField{Value: tj.Client.Value, Source: business.TicketFieldSource(tj.Client.Source), Filled: tj.Client.Filled},
		Contact:  business.TicketField{Value: tj.Contact.Value, Source: business.TicketFieldSource(tj.Contact.Source), Filled: tj.Contact.Filled},
		Priority: business.TicketField{Value: tj.Priority.Value, Source: business.TicketFieldSource(tj.Priority.Source), Filled: tj.Priority.Filled},
		Category: business.TicketField{Value: tj.Category.Value, Source: business.TicketFieldSource(tj.Category.Source), Filled: tj.Category.Filled},
	}, nil
}
