// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package sqlite implements ClientTenantStore using SQLite
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// SQLiteClientTenantStore implements interfaces.ClientTenantStore using SQLite.
// It includes nullable M365 extension columns to round-trip M365 consent fields
// without requiring the separate M365ClientTenantStore interface (ADR-003 §2).
type SQLiteClientTenantStore struct {
	db *sql.DB
}

// StoreClientTenant inserts or replaces a client tenant record.
func (s *SQLiteClientTenantStore) StoreClientTenant(client *interfaces.ClientTenant) error {
	if client == nil {
		return fmt.Errorf("client tenant cannot be nil")
	}

	now := nowUTC()
	if client.CreatedAt.IsZero() {
		client.CreatedAt = now
	}
	client.UpdatedAt = now
	if client.ID == "" {
		client.ID = client.TenantID
	}

	meta, err := marshalJSON(client.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	// Extract M365 extension fields from Metadata if present
	var m365TenantID, m365AdminEmail, m365ConsentedAt, m365Status sql.NullString
	if client.Metadata != nil {
		if v, ok := client.Metadata["m365_tenant_id"].(string); ok {
			m365TenantID = nullString(v)
		}
		if v, ok := client.Metadata["m365_admin_email"].(string); ok {
			m365AdminEmail = nullString(v)
		}
		if v, ok := client.Metadata["m365_consented_at"].(string); ok {
			m365ConsentedAt = nullString(v)
		}
		if v, ok := client.Metadata["m365_status"].(string); ok {
			m365Status = nullString(v)
		}
	}

	ctx := context.Background()
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO client_tenants
			(id, tenant_id, tenant_name, domain_name, admin_email, consented_at,
			 status, client_identifier, metadata,
			 m365_tenant_id, m365_admin_email, m365_consented_at, m365_status,
			 created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(tenant_id) DO UPDATE SET
			tenant_name       = excluded.tenant_name,
			domain_name       = excluded.domain_name,
			admin_email       = excluded.admin_email,
			consented_at      = excluded.consented_at,
			status            = excluded.status,
			client_identifier = excluded.client_identifier,
			metadata          = excluded.metadata,
			m365_tenant_id    = excluded.m365_tenant_id,
			m365_admin_email  = excluded.m365_admin_email,
			m365_consented_at = excluded.m365_consented_at,
			m365_status       = excluded.m365_status,
			updated_at        = excluded.updated_at`,
		client.ID,
		client.TenantID,
		client.TenantName,
		client.DomainName,
		client.AdminEmail,
		formatTime(client.ConsentedAt),
		string(client.Status),
		client.ClientIdentifier,
		meta,
		m365TenantID,
		m365AdminEmail,
		m365ConsentedAt,
		m365Status,
		formatTime(client.CreatedAt),
		formatTime(client.UpdatedAt),
	)
	if err != nil {
		return fmt.Errorf("failed to store client tenant %s: %w", client.TenantID, err)
	}
	return nil
}

// GetClientTenant retrieves a client tenant by Azure AD tenant ID.
func (s *SQLiteClientTenantStore) GetClientTenant(tenantID string) (*interfaces.ClientTenant, error) {
	ctx := context.Background()
	row := s.db.QueryRowContext(ctx, `
		SELECT id, tenant_id, tenant_name, domain_name, admin_email, consented_at,
		       status, client_identifier, metadata,
		       m365_tenant_id, m365_admin_email, m365_consented_at, m365_status,
		       created_at, updated_at
		FROM client_tenants WHERE tenant_id = ?`, tenantID)
	return scanClientTenant(row)
}

// GetClientTenantByIdentifier retrieves a client tenant by its CFGMS internal identifier.
func (s *SQLiteClientTenantStore) GetClientTenantByIdentifier(clientIdentifier string) (*interfaces.ClientTenant, error) {
	ctx := context.Background()
	row := s.db.QueryRowContext(ctx, `
		SELECT id, tenant_id, tenant_name, domain_name, admin_email, consented_at,
		       status, client_identifier, metadata,
		       m365_tenant_id, m365_admin_email, m365_consented_at, m365_status,
		       created_at, updated_at
		FROM client_tenants WHERE client_identifier = ?`, clientIdentifier)
	return scanClientTenant(row)
}

// ListClientTenants returns all client tenants, optionally filtered by status.
func (s *SQLiteClientTenantStore) ListClientTenants(status interfaces.ClientTenantStatus) ([]*interfaces.ClientTenant, error) {
	ctx := context.Background()

	var (
		rows *sql.Rows
		err  error
	)
	if status == "" {
		rows, err = s.db.QueryContext(ctx, `
			SELECT id, tenant_id, tenant_name, domain_name, admin_email, consented_at,
			       status, client_identifier, metadata,
			       m365_tenant_id, m365_admin_email, m365_consented_at, m365_status,
			       created_at, updated_at
			FROM client_tenants ORDER BY created_at DESC`)
	} else {
		rows, err = s.db.QueryContext(ctx, `
			SELECT id, tenant_id, tenant_name, domain_name, admin_email, consented_at,
			       status, client_identifier, metadata,
			       m365_tenant_id, m365_admin_email, m365_consented_at, m365_status,
			       created_at, updated_at
			FROM client_tenants WHERE status = ? ORDER BY created_at DESC`, string(status))
	}
	if err != nil {
		return nil, fmt.Errorf("failed to list client tenants: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var clients []*interfaces.ClientTenant
	for rows.Next() {
		c, err := scanClientTenantRow(rows)
		if err != nil {
			return nil, err
		}
		clients = append(clients, c)
	}
	return clients, rows.Err()
}

// UpdateClientTenantStatus updates only the status and updated_at fields of a client tenant.
func (s *SQLiteClientTenantStore) UpdateClientTenantStatus(tenantID string, status interfaces.ClientTenantStatus) error {
	ctx := context.Background()
	res, err := s.db.ExecContext(ctx, `
		UPDATE client_tenants SET status = ?, updated_at = ? WHERE tenant_id = ?`,
		string(status), formatTime(nowUTC()), tenantID)
	if err != nil {
		return fmt.Errorf("failed to update client tenant status: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("client tenant %s not found", tenantID)
	}
	return nil
}

// DeleteClientTenant removes a client tenant by Azure AD tenant ID.
func (s *SQLiteClientTenantStore) DeleteClientTenant(tenantID string) error {
	ctx := context.Background()
	res, err := s.db.ExecContext(ctx, `DELETE FROM client_tenants WHERE tenant_id = ?`, tenantID)
	if err != nil {
		return fmt.Errorf("failed to delete client tenant %s: %w", tenantID, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("client tenant %s not found", tenantID)
	}
	return nil
}

// StoreAdminConsentRequest persists an admin consent request (upsert on state).
func (s *SQLiteClientTenantStore) StoreAdminConsentRequest(request *interfaces.AdminConsentRequest) error {
	if request == nil {
		return fmt.Errorf("admin consent request cannot be nil")
	}
	if request.CreatedAt.IsZero() {
		request.CreatedAt = nowUTC()
	}

	meta, err := marshalJSON(request.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	ctx := context.Background()
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO admin_consent_requests
			(state, client_identifier, client_name, requested_by, expires_at, created_at, metadata)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(state) DO UPDATE SET
			client_identifier = excluded.client_identifier,
			client_name       = excluded.client_name,
			requested_by      = excluded.requested_by,
			expires_at        = excluded.expires_at,
			metadata          = excluded.metadata`,
		request.State,
		request.ClientIdentifier,
		request.ClientName,
		request.RequestedBy,
		formatTime(request.ExpiresAt),
		formatTime(request.CreatedAt),
		meta,
	)
	if err != nil {
		return fmt.Errorf("failed to store admin consent request %s: %w", request.State, err)
	}
	return nil
}

// GetAdminConsentRequest retrieves an admin consent request by OAuth2 state token.
func (s *SQLiteClientTenantStore) GetAdminConsentRequest(state string) (*interfaces.AdminConsentRequest, error) {
	ctx := context.Background()
	row := s.db.QueryRowContext(ctx, `
		SELECT state, client_identifier, client_name, requested_by, expires_at, created_at, metadata
		FROM admin_consent_requests WHERE state = ?`, state)

	req := &interfaces.AdminConsentRequest{}
	var expiresStr, createdStr, metaStr string

	if err := row.Scan(
		&req.State,
		&req.ClientIdentifier,
		&req.ClientName,
		&req.RequestedBy,
		&expiresStr,
		&createdStr,
		&metaStr,
	); err == sql.ErrNoRows {
		return nil, fmt.Errorf("admin consent request %s not found", state)
	} else if err != nil {
		return nil, fmt.Errorf("failed to get admin consent request: %w", err)
	}

	req.ExpiresAt = parseTime(expiresStr)
	req.CreatedAt = parseTime(createdStr)

	if time.Now().After(req.ExpiresAt) {
		return nil, fmt.Errorf("admin consent request %s has expired", state)
	}

	meta, err := unmarshalJSONMap(metaStr)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}
	req.Metadata = meta

	return req, nil
}

// DeleteAdminConsentRequest removes an admin consent request by state.
func (s *SQLiteClientTenantStore) DeleteAdminConsentRequest(state string) error {
	ctx := context.Background()
	_, err := s.db.ExecContext(ctx, `DELETE FROM admin_consent_requests WHERE state = ?`, state)
	if err != nil {
		return fmt.Errorf("failed to delete admin consent request %s: %w", state, err)
	}
	return nil
}

// ---- helpers ----------------------------------------------------------------

func scanClientTenant(row *sql.Row) (*interfaces.ClientTenant, error) {
	c := &interfaces.ClientTenant{}
	var (
		statusStr, consentedStr, createdStr, updatedStr, metaStr  string
		m365TenantID, m365AdminEmail, m365ConsentedAt, m365Status sql.NullString
	)
	err := row.Scan(
		&c.ID, &c.TenantID, &c.TenantName, &c.DomainName, &c.AdminEmail,
		&consentedStr, &statusStr, &c.ClientIdentifier, &metaStr,
		&m365TenantID, &m365AdminEmail, &m365ConsentedAt, &m365Status,
		&createdStr, &updatedStr,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("client tenant not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan client tenant: %w", err)
	}
	return populateClientTenant(c, statusStr, consentedStr, createdStr, updatedStr, metaStr,
		m365TenantID, m365AdminEmail, m365ConsentedAt, m365Status)
}

func scanClientTenantRow(rows *sql.Rows) (*interfaces.ClientTenant, error) {
	c := &interfaces.ClientTenant{}
	var (
		statusStr, consentedStr, createdStr, updatedStr, metaStr  string
		m365TenantID, m365AdminEmail, m365ConsentedAt, m365Status sql.NullString
	)
	err := rows.Scan(
		&c.ID, &c.TenantID, &c.TenantName, &c.DomainName, &c.AdminEmail,
		&consentedStr, &statusStr, &c.ClientIdentifier, &metaStr,
		&m365TenantID, &m365AdminEmail, &m365ConsentedAt, &m365Status,
		&createdStr, &updatedStr,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to scan client tenant row: %w", err)
	}
	return populateClientTenant(c, statusStr, consentedStr, createdStr, updatedStr, metaStr,
		m365TenantID, m365AdminEmail, m365ConsentedAt, m365Status)
}

func populateClientTenant(
	c *interfaces.ClientTenant,
	statusStr, consentedStr, createdStr, updatedStr, metaStr string,
	m365TenantID, m365AdminEmail, m365ConsentedAt, m365Status sql.NullString,
) (*interfaces.ClientTenant, error) {
	c.Status = interfaces.ClientTenantStatus(statusStr)
	c.ConsentedAt = parseTime(consentedStr)
	c.CreatedAt = parseTime(createdStr)
	c.UpdatedAt = parseTime(updatedStr)

	meta, err := unmarshalJSONMap(metaStr)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal client tenant metadata: %w", err)
	}
	c.Metadata = meta

	// Store M365 extension columns back into Metadata so callers can read them
	if m365TenantID.Valid {
		c.Metadata["m365_tenant_id"] = m365TenantID.String
	}
	if m365AdminEmail.Valid {
		c.Metadata["m365_admin_email"] = m365AdminEmail.String
	}
	if m365ConsentedAt.Valid {
		c.Metadata["m365_consented_at"] = m365ConsentedAt.String
	}
	if m365Status.Valid {
		c.Metadata["m365_status"] = m365Status.String
	}

	return c, nil
}

// Close closes the underlying database connection.
func (s *SQLiteClientTenantStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// ensure SQLiteClientTenantStore satisfies the interface at compile time
var _ interfaces.ClientTenantStore = (*SQLiteClientTenantStore)(nil)
