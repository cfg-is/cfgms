// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package sqlite implements CaseStore using SQLite (ADR-022 §8, Issue #3602).
package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Compile-time assertion.
var _ business.CaseStore = (*SQLiteCaseStore)(nil)

// SQLiteCaseStore implements business.CaseStore using SQLite.
type SQLiteCaseStore struct {
	db *sql.DB
}

// Initialize is a no-op: schema is created in openAndInit before this store is returned.
func (s *SQLiteCaseStore) Initialize(ctx context.Context) error { return nil }

// Close closes the underlying database connection.
func (s *SQLiteCaseStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// CreateCase persists a new case record.
func (s *SQLiteCaseStore) CreateCase(ctx context.Context, c *business.Case) error {
	if c == nil {
		return fmt.Errorf("sqlite: case cannot be nil")
	}
	if c.ID == "" || c.TenantID == "" {
		return fmt.Errorf("sqlite: case ID and tenant ID are required")
	}
	ticketJSON, err := marshalTicket(c.Ticket)
	if err != nil {
		return fmt.Errorf("sqlite: failed to marshal ticket for case %s: %w", c.ID, err)
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO cases (id, tenant_id, status, ticket_json, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		c.ID, c.TenantID, string(c.Status), ticketJSON,
		formatTime(c.CreatedAt), formatTime(c.UpdatedAt),
	)
	if err != nil {
		return fmt.Errorf("sqlite: failed to create case %s: %w", c.ID, err)
	}
	return nil
}

// GetCase retrieves a case by ID including its full aggregate (ticket + pins + content).
func (s *SQLiteCaseStore) GetCase(ctx context.Context, id string) (*business.Case, error) {
	if id == "" {
		return nil, fmt.Errorf("sqlite: case ID cannot be empty")
	}
	row := s.db.QueryRowContext(ctx, `
		SELECT id, tenant_id, status, ticket_json, created_at, updated_at
		FROM cases WHERE id = ?`, id)

	c, err := scanCase(row)
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
func (s *SQLiteCaseStore) ListCases(ctx context.Context, tenantID string) ([]*business.Case, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("sqlite: tenant ID cannot be empty")
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, tenant_id, status, ticket_json, created_at, updated_at
		FROM cases WHERE tenant_id = ? OR tenant_id LIKE ? ORDER BY created_at DESC`,
		tenantID, tenantID+"/%")
	if err != nil {
		return nil, fmt.Errorf("sqlite: failed to list cases for tenant %s: %w", tenantID, err)
	}
	defer func() { _ = rows.Close() }()

	var out []*business.Case
	for rows.Next() {
		c, err := scanCaseRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// UpdateCase updates a case's status and ticket. Pins and content are managed
// via AddPin/RemovePin/AddContent.
func (s *SQLiteCaseStore) UpdateCase(ctx context.Context, c *business.Case) error {
	if c == nil {
		return fmt.Errorf("sqlite: case cannot be nil")
	}
	if c.ID == "" {
		return fmt.Errorf("sqlite: case ID is required")
	}
	ticketJSON, err := marshalTicket(c.Ticket)
	if err != nil {
		return fmt.Errorf("sqlite: failed to marshal ticket for case %s: %w", c.ID, err)
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE cases SET status = ?, ticket_json = ?, updated_at = ? WHERE id = ?`,
		string(c.Status), ticketJSON, formatTime(nowUTC()), c.ID,
	)
	if err != nil {
		return fmt.Errorf("sqlite: failed to update case %s: %w", c.ID, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return business.ErrCaseNotFound
	}
	return nil
}

// AddPin attaches a pin to an existing case.
func (s *SQLiteCaseStore) AddPin(ctx context.Context, caseID string, pin *business.Pin) error {
	if caseID == "" {
		return fmt.Errorf("sqlite: case ID cannot be empty")
	}
	if pin == nil || pin.ID == "" {
		return fmt.Errorf("sqlite: pin and pin ID are required")
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO case_pins (id, case_id, ref_kind, ref_eid, ref_edge_identity,
			ref_obs_version, ref_drift_record, ref_subject, ref_range_start, ref_range_end,
			annotation, author, pinned_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		pin.ID, caseID,
		string(pin.Ref.Kind), pin.Ref.EID, pin.Ref.EdgeIdentity,
		pin.Ref.ObservationVersion, pin.Ref.DriftRecord, pin.Ref.Subject,
		nullTime(zeroToNilTime(pin.Ref.TimeRangeStart)),
		nullTime(zeroToNilTime(pin.Ref.TimeRangeEnd)),
		pin.Annotation, pin.Author, formatTime(pin.PinnedAt),
	)
	if err != nil {
		return fmt.Errorf("sqlite: failed to add pin %s to case %s: %w", pin.ID, caseID, err)
	}
	return nil
}

// RemovePin detaches a pin from a case.
func (s *SQLiteCaseStore) RemovePin(ctx context.Context, caseID, pinID string) error {
	if caseID == "" || pinID == "" {
		return fmt.Errorf("sqlite: case ID and pin ID cannot be empty")
	}
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM case_pins WHERE case_id = ? AND id = ?`, caseID, pinID)
	if err != nil {
		return fmt.Errorf("sqlite: failed to remove pin %s from case %s: %w", pinID, caseID, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return business.ErrPinNotFound
	}
	return nil
}

// ListPins returns all pins attached to the given case.
func (s *SQLiteCaseStore) ListPins(ctx context.Context, caseID string) ([]*business.Pin, error) {
	if caseID == "" {
		return nil, fmt.Errorf("sqlite: case ID cannot be empty")
	}
	return s.listPinsInternal(ctx, caseID)
}

// AddContent appends a content entry to an existing case.
func (s *SQLiteCaseStore) AddContent(ctx context.Context, caseID string, entry *business.ContentEntry) error {
	if caseID == "" {
		return fmt.Errorf("sqlite: case ID cannot be empty")
	}
	if entry == nil || entry.ID == "" {
		return fmt.Errorf("sqlite: content entry and entry ID are required")
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO case_content (id, case_id, kind, body, author, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		entry.ID, caseID, string(entry.Kind), entry.Body, entry.Author, formatTime(entry.CreatedAt),
	)
	if err != nil {
		return fmt.Errorf("sqlite: failed to add content %s to case %s: %w", entry.ID, caseID, err)
	}
	return nil
}

// ListContent returns all content entries for the given case, oldest first.
func (s *SQLiteCaseStore) ListContent(ctx context.Context, caseID string) ([]*business.ContentEntry, error) {
	if caseID == "" {
		return nil, fmt.Errorf("sqlite: case ID cannot be empty")
	}
	return s.listContentInternal(ctx, caseID)
}

func (s *SQLiteCaseStore) listPinsInternal(ctx context.Context, caseID string) ([]*business.Pin, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, case_id, ref_kind, ref_eid, ref_edge_identity, ref_obs_version,
			ref_drift_record, ref_subject, ref_range_start, ref_range_end,
			annotation, author, pinned_at
		FROM case_pins WHERE case_id = ? ORDER BY pinned_at ASC`, caseID)
	if err != nil {
		return nil, fmt.Errorf("sqlite: failed to list pins for case %s: %w", caseID, err)
	}
	defer func() { _ = rows.Close() }()

	var out []*business.Pin
	for rows.Next() {
		p, err := scanPinRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *SQLiteCaseStore) listContentInternal(ctx context.Context, caseID string) ([]*business.ContentEntry, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, case_id, kind, body, author, created_at
		FROM case_content WHERE case_id = ? ORDER BY created_at ASC`, caseID)
	if err != nil {
		return nil, fmt.Errorf("sqlite: failed to list content for case %s: %w", caseID, err)
	}
	defer func() { _ = rows.Close() }()

	var out []*business.ContentEntry
	for rows.Next() {
		e, err := scanContentRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// scanCase scans a *sql.Row into a Case (without pins or content).
func scanCase(row *sql.Row) (*business.Case, error) {
	var c business.Case
	var status, ticketStr, createdStr, updatedStr string
	err := row.Scan(&c.ID, &c.TenantID, &status, &ticketStr, &createdStr, &updatedStr)
	if err == sql.ErrNoRows {
		return nil, business.ErrCaseNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: failed to scan case: %w", err)
	}
	c.Status = business.CaseStatus(status)
	c.CreatedAt = parseTime(createdStr)
	c.UpdatedAt = parseTime(updatedStr)
	t, err := unmarshalTicket(ticketStr)
	if err != nil {
		return nil, fmt.Errorf("sqlite: failed to unmarshal ticket for case %s: %w", c.ID, err)
	}
	c.Ticket = t
	return &c, nil
}

// scanCaseRow scans a *sql.Rows row into a Case (without pins or content).
func scanCaseRow(rows *sql.Rows) (*business.Case, error) {
	var c business.Case
	var status, ticketStr, createdStr, updatedStr string
	if err := rows.Scan(&c.ID, &c.TenantID, &status, &ticketStr, &createdStr, &updatedStr); err != nil {
		return nil, fmt.Errorf("sqlite: failed to scan case row: %w", err)
	}
	c.Status = business.CaseStatus(status)
	c.CreatedAt = parseTime(createdStr)
	c.UpdatedAt = parseTime(updatedStr)
	t, err := unmarshalTicket(ticketStr)
	if err != nil {
		return nil, fmt.Errorf("sqlite: failed to unmarshal ticket: %w", err)
	}
	c.Ticket = t
	return &c, nil
}

// scanPinRow scans a *sql.Rows row into a Pin.
func scanPinRow(rows *sql.Rows) (*business.Pin, error) {
	var p business.Pin
	var rangeStart, rangeEnd sql.NullString
	var refKind, refEID, refEdge, refObs, refDrift, refSubject string
	var pinnedStr string

	if err := rows.Scan(
		&p.ID, &p.CaseID, &refKind, &refEID, &refEdge,
		&refObs, &refDrift, &refSubject, &rangeStart, &rangeEnd,
		&p.Annotation, &p.Author, &pinnedStr,
	); err != nil {
		return nil, fmt.Errorf("sqlite: failed to scan pin row: %w", err)
	}
	p.PinnedAt = parseTime(pinnedStr)
	p.Ref = business.PinRef{
		Kind:               business.PinRefKind(refKind),
		EID:                refEID,
		EdgeIdentity:       refEdge,
		ObservationVersion: refObs,
		DriftRecord:        refDrift,
		Subject:            refSubject,
	}
	if rangeStart.Valid && rangeStart.String != "" {
		p.Ref.TimeRangeStart = parseTime(rangeStart.String)
	}
	if rangeEnd.Valid && rangeEnd.String != "" {
		p.Ref.TimeRangeEnd = parseTime(rangeEnd.String)
	}
	return &p, nil
}

// scanContentRow scans a *sql.Rows row into a ContentEntry.
func scanContentRow(rows *sql.Rows) (*business.ContentEntry, error) {
	var e business.ContentEntry
	var kind, createdStr string
	if err := rows.Scan(&e.ID, &e.CaseID, &kind, &e.Body, &e.Author, &createdStr); err != nil {
		return nil, fmt.Errorf("sqlite: failed to scan content row: %w", err)
	}
	e.Kind = business.ContentKind(kind)
	e.CreatedAt = parseTime(createdStr)
	return &e, nil
}

// zeroToNilTime returns nil when t is the zero value, otherwise a pointer to t.
// Used to map zero-value time.Time to SQL NULL for optional time fields.
func zeroToNilTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// ticketFieldJSON is the private JSON representation of a TicketField.
type ticketFieldJSON struct {
	Value  string `json:"value"`
	Source string `json:"source"`
	Filled bool   `json:"filled"`
}

// ticketJSON is the private JSON representation of a Ticket.
type ticketJSON struct {
	Title    ticketFieldJSON `json:"title"`
	Client   ticketFieldJSON `json:"client"`
	Contact  ticketFieldJSON `json:"contact"`
	Priority ticketFieldJSON `json:"priority"`
	Category ticketFieldJSON `json:"category"`
}

func marshalTicket(t business.Ticket) (string, error) {
	tj := ticketJSON{
		Title:    ticketFieldJSON{Value: t.Title.Value, Source: string(t.Title.Source), Filled: t.Title.Filled},
		Client:   ticketFieldJSON{Value: t.Client.Value, Source: string(t.Client.Source), Filled: t.Client.Filled},
		Contact:  ticketFieldJSON{Value: t.Contact.Value, Source: string(t.Contact.Source), Filled: t.Contact.Filled},
		Priority: ticketFieldJSON{Value: t.Priority.Value, Source: string(t.Priority.Source), Filled: t.Priority.Filled},
		Category: ticketFieldJSON{Value: t.Category.Value, Source: string(t.Category.Source), Filled: t.Category.Filled},
	}
	b, err := json.Marshal(tj)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func unmarshalTicket(s string) (business.Ticket, error) {
	if s == "" || s == "{}" {
		return business.Ticket{}, nil
	}
	var tj ticketJSON
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
