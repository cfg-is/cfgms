// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/pkg/secrets/interfaces"
	storageInterfaces "github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// DatabaseM365ClientTenantStore implements M365ClientTenantStore using PostgreSQL
// OAuth credentials are stored encrypted using pkg/secrets
type DatabaseM365ClientTenantStore struct {
	db          *sql.DB
	secretStore interfaces.SecretStore
}

// NewDatabaseM365ClientTenantStore creates a new database-based M365 client tenant store
func NewDatabaseM365ClientTenantStore(db *sql.DB, secretStore interfaces.SecretStore) (*DatabaseM365ClientTenantStore, error) {
	if db == nil {
		return nil, fmt.Errorf("database connection cannot be nil")
	}
	if secretStore == nil {
		return nil, fmt.Errorf("secretStore cannot be nil - OAuth credentials must be encrypted")
	}

	store := &DatabaseM365ClientTenantStore{
		db:          db,
		secretStore: secretStore,
	}

	return store, nil
}

// Initialize implements M365ClientTenantStore.Initialize
func (s *DatabaseM365ClientTenantStore) Initialize(ctx context.Context) error {
	// Create tables for M365 client tenant management
	queries := []string{
		`CREATE TABLE IF NOT EXISTS m365_client_tenants (
			id TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL UNIQUE,
			tenant_name TEXT NOT NULL,
			domain_name TEXT,
			admin_email TEXT,
			consented_at TIMESTAMP NOT NULL,
			status TEXT NOT NULL,
			client_identifier TEXT NOT NULL UNIQUE,
			metadata JSONB,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_m365_client_tenants_tenant_id ON m365_client_tenants(tenant_id)`,
		`CREATE INDEX IF NOT EXISTS idx_m365_client_tenants_client_identifier ON m365_client_tenants(client_identifier)`,
		`CREATE INDEX IF NOT EXISTS idx_m365_client_tenants_status ON m365_client_tenants(status)`,
		`CREATE TABLE IF NOT EXISTS m365_admin_consent_requests (
			state TEXT PRIMARY KEY,
			client_identifier TEXT NOT NULL,
			client_name TEXT NOT NULL,
			requested_by TEXT NOT NULL,
			expires_at TIMESTAMP NOT NULL,
			metadata JSONB,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_m365_consent_requests_expires_at ON m365_admin_consent_requests(expires_at)`,
		`CREATE INDEX IF NOT EXISTS idx_m365_consent_requests_client_identifier ON m365_admin_consent_requests(client_identifier)`,
	}

	for _, query := range queries {
		if _, err := s.db.ExecContext(ctx, query); err != nil {
			return fmt.Errorf("failed to execute schema query: %w", err)
		}
	}

	return nil
}

// Close implements M365ClientTenantStore.Close
func (s *DatabaseM365ClientTenantStore) Close() error {
	return nil
}

// StoreClientTenant implements M365ClientTenantStore.StoreClientTenant
func (s *DatabaseM365ClientTenantStore) StoreClientTenant(ctx context.Context, client *storageInterfaces.M365ClientTenant) error {
	if client == nil {
		return fmt.Errorf("client tenant cannot be nil")
	}
	if client.TenantID == "" {
		return fmt.Errorf("tenant ID cannot be empty")
	}

	// Update timestamp
	client.UpdatedAt = time.Now()

	// Serialize metadata
	metadataJSON, err := json.Marshal(client.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	// Upsert client tenant
	query := `
		INSERT INTO m365_client_tenants (
			id, tenant_id, tenant_name, domain_name, admin_email,
			consented_at, status, client_identifier, metadata, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (tenant_id) DO UPDATE SET
			tenant_name = EXCLUDED.tenant_name,
			domain_name = EXCLUDED.domain_name,
			admin_email = EXCLUDED.admin_email,
			consented_at = EXCLUDED.consented_at,
			status = EXCLUDED.status,
			client_identifier = EXCLUDED.client_identifier,
			metadata = EXCLUDED.metadata,
			updated_at = EXCLUDED.updated_at
	`

	_, err = s.db.ExecContext(ctx, query,
		client.ID,
		client.TenantID,
		client.TenantName,
		client.DomainName,
		client.AdminEmail,
		client.ConsentedAt,
		string(client.Status),
		client.ClientIdentifier,
		metadataJSON,
		client.CreatedAt,
		client.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to store client tenant: %w", err)
	}

	return nil
}

// GetClientTenant implements M365ClientTenantStore.GetClientTenant
func (s *DatabaseM365ClientTenantStore) GetClientTenant(ctx context.Context, tenantID string) (*storageInterfaces.M365ClientTenant, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("tenant ID cannot be empty")
	}

	query := `
		SELECT id, tenant_id, tenant_name, domain_name, admin_email,
		       consented_at, status, client_identifier, metadata, created_at, updated_at
		FROM m365_client_tenants
		WHERE tenant_id = $1
	`

	var client storageInterfaces.M365ClientTenant
	var metadataJSON []byte
	var status string

	err := s.db.QueryRowContext(ctx, query, tenantID).Scan(
		&client.ID,
		&client.TenantID,
		&client.TenantName,
		&client.DomainName,
		&client.AdminEmail,
		&client.ConsentedAt,
		&status,
		&client.ClientIdentifier,
		&metadataJSON,
		&client.CreatedAt,
		&client.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("client tenant not found: %s", tenantID)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get client tenant: %w", err)
	}

	client.Status = storageInterfaces.M365ClientTenantStatus(status)

	// Deserialize metadata
	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &client.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
	}

	return &client, nil
}

// GetClientTenantByIdentifier implements M365ClientTenantStore.GetClientTenantByIdentifier
func (s *DatabaseM365ClientTenantStore) GetClientTenantByIdentifier(ctx context.Context, clientIdentifier string) (*storageInterfaces.M365ClientTenant, error) {
	if clientIdentifier == "" {
		return nil, fmt.Errorf("client identifier cannot be empty")
	}

	query := `
		SELECT id, tenant_id, tenant_name, domain_name, admin_email,
		       consented_at, status, client_identifier, metadata, created_at, updated_at
		FROM m365_client_tenants
		WHERE client_identifier = $1
	`

	var client storageInterfaces.M365ClientTenant
	var metadataJSON []byte
	var status string

	err := s.db.QueryRowContext(ctx, query, clientIdentifier).Scan(
		&client.ID,
		&client.TenantID,
		&client.TenantName,
		&client.DomainName,
		&client.AdminEmail,
		&client.ConsentedAt,
		&status,
		&client.ClientIdentifier,
		&metadataJSON,
		&client.CreatedAt,
		&client.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("client tenant not found by identifier: %s", clientIdentifier)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get client tenant by identifier: %w", err)
	}

	client.Status = storageInterfaces.M365ClientTenantStatus(status)

	// Deserialize metadata
	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &client.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
	}

	return &client, nil
}

// ListClientTenants implements M365ClientTenantStore.ListClientTenants
func (s *DatabaseM365ClientTenantStore) ListClientTenants(ctx context.Context, status storageInterfaces.M365ClientTenantStatus) ([]*storageInterfaces.M365ClientTenant, error) {
	var query string
	var rows *sql.Rows
	var err error

	if status != "" {
		query = `
			SELECT id, tenant_id, tenant_name, domain_name, admin_email,
			       consented_at, status, client_identifier, metadata, created_at, updated_at
			FROM m365_client_tenants
			WHERE status = $1
			ORDER BY created_at DESC
		`
		rows, err = s.db.QueryContext(ctx, query, string(status))
	} else {
		query = `
			SELECT id, tenant_id, tenant_name, domain_name, admin_email,
			       consented_at, status, client_identifier, metadata, created_at, updated_at
			FROM m365_client_tenants
			ORDER BY created_at DESC
		`
		rows, err = s.db.QueryContext(ctx, query)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to list client tenants: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	var clients []*storageInterfaces.M365ClientTenant

	for rows.Next() {
		var client storageInterfaces.M365ClientTenant
		var metadataJSON []byte
		var statusStr string

		err := rows.Scan(
			&client.ID,
			&client.TenantID,
			&client.TenantName,
			&client.DomainName,
			&client.AdminEmail,
			&client.ConsentedAt,
			&statusStr,
			&client.ClientIdentifier,
			&metadataJSON,
			&client.CreatedAt,
			&client.UpdatedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan client tenant: %w", err)
		}

		client.Status = storageInterfaces.M365ClientTenantStatus(statusStr)

		// Deserialize metadata
		if len(metadataJSON) > 0 {
			if err := json.Unmarshal(metadataJSON, &client.Metadata); err != nil {
				return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
			}
		}

		clients = append(clients, &client)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating rows: %w", err)
	}

	return clients, nil
}

// UpdateClientTenantStatus implements M365ClientTenantStore.UpdateClientTenantStatus
func (s *DatabaseM365ClientTenantStore) UpdateClientTenantStatus(ctx context.Context, tenantID string, status storageInterfaces.M365ClientTenantStatus) error {
	query := `
		UPDATE m365_client_tenants
		SET status = $1, updated_at = $2
		WHERE tenant_id = $3
	`

	result, err := s.db.ExecContext(ctx, query, string(status), time.Now(), tenantID)
	if err != nil {
		return fmt.Errorf("failed to update client tenant status: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("client tenant not found: %s", tenantID)
	}

	return nil
}

// DeleteClientTenant implements M365ClientTenantStore.DeleteClientTenant
func (s *DatabaseM365ClientTenantStore) DeleteClientTenant(ctx context.Context, tenantID string) error {
	if tenantID == "" {
		return fmt.Errorf("tenant ID cannot be empty")
	}

	query := `DELETE FROM m365_client_tenants WHERE tenant_id = $1`

	result, err := s.db.ExecContext(ctx, query, tenantID)
	if err != nil {
		return fmt.Errorf("failed to delete client tenant: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("client tenant not found: %s", tenantID)
	}

	return nil
}

// StoreAdminConsentRequest implements M365ClientTenantStore.StoreAdminConsentRequest
func (s *DatabaseM365ClientTenantStore) StoreAdminConsentRequest(ctx context.Context, request *storageInterfaces.M365AdminConsentRequest) error {
	if request == nil {
		return fmt.Errorf("admin consent request cannot be nil")
	}
	if request.State == "" {
		return fmt.Errorf("state cannot be empty")
	}

	// Serialize metadata
	metadataJSON, err := json.Marshal(request.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	query := `
		INSERT INTO m365_admin_consent_requests (
			state, client_identifier, client_name, requested_by,
			expires_at, metadata, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (state) DO UPDATE SET
			client_identifier = EXCLUDED.client_identifier,
			client_name = EXCLUDED.client_name,
			requested_by = EXCLUDED.requested_by,
			expires_at = EXCLUDED.expires_at,
			metadata = EXCLUDED.metadata
	`

	_, err = s.db.ExecContext(ctx, query,
		request.State,
		request.ClientIdentifier,
		request.ClientName,
		request.RequestedBy,
		request.ExpiresAt,
		metadataJSON,
		request.CreatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to store admin consent request: %w", err)
	}

	return nil
}

// GetAdminConsentRequest implements M365ClientTenantStore.GetAdminConsentRequest
func (s *DatabaseM365ClientTenantStore) GetAdminConsentRequest(ctx context.Context, state string) (*storageInterfaces.M365AdminConsentRequest, error) {
	if state == "" {
		return nil, fmt.Errorf("state cannot be empty")
	}

	query := `
		SELECT state, client_identifier, client_name, requested_by,
		       expires_at, metadata, created_at
		FROM m365_admin_consent_requests
		WHERE state = $1
	`

	var request storageInterfaces.M365AdminConsentRequest
	var metadataJSON []byte

	err := s.db.QueryRowContext(ctx, query, state).Scan(
		&request.State,
		&request.ClientIdentifier,
		&request.ClientName,
		&request.RequestedBy,
		&request.ExpiresAt,
		&metadataJSON,
		&request.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("admin consent request not found: %s", state)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get admin consent request: %w", err)
	}

	// Check if request has expired
	if time.Now().After(request.ExpiresAt) {
		return nil, fmt.Errorf("admin consent request expired: %s", state)
	}

	// Deserialize metadata
	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &request.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
	}

	return &request, nil
}

// DeleteAdminConsentRequest implements M365ClientTenantStore.DeleteAdminConsentRequest
func (s *DatabaseM365ClientTenantStore) DeleteAdminConsentRequest(ctx context.Context, state string) error {
	if state == "" {
		return fmt.Errorf("state cannot be empty")
	}

	query := `DELETE FROM m365_admin_consent_requests WHERE state = $1`

	result, err := s.db.ExecContext(ctx, query, state)
	if err != nil {
		return fmt.Errorf("failed to delete admin consent request: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("admin consent request not found: %s", state)
	}

	return nil
}

// GetStats implements M365ClientTenantStore.GetStats
func (s *DatabaseM365ClientTenantStore) GetStats(ctx context.Context) (*storageInterfaces.M365ClientTenantStats, error) {
	stats := &storageInterfaces.M365ClientTenantStats{
		ClientsByStatus: make(map[storageInterfaces.M365ClientTenantStatus]int),
		LastUpdated:     time.Now(),
	}

	// Get total clients
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM m365_client_tenants`).Scan(&stats.TotalClients)
	if err != nil {
		return nil, fmt.Errorf("failed to count clients: %w", err)
	}

	// Get clients by status
	rows, err := s.db.QueryContext(ctx, `SELECT status, COUNT(*) FROM m365_client_tenants GROUP BY status`)
	if err != nil {
		return nil, fmt.Errorf("failed to get client counts by status: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return nil, fmt.Errorf("failed to scan status count: %w", err)
		}
		stats.ClientsByStatus[storageInterfaces.M365ClientTenantStatus(status)] = count
	}

	// Get pending consent requests
	err = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM m365_admin_consent_requests WHERE expires_at > $1`, time.Now()).Scan(&stats.PendingConsentRequests)
	if err != nil {
		return nil, fmt.Errorf("failed to count consent requests: %w", err)
	}

	return stats, nil
}

// CleanupExpiredRequests implements M365ClientTenantStore.CleanupExpiredRequests
func (s *DatabaseM365ClientTenantStore) CleanupExpiredRequests(ctx context.Context) (int, error) {
	query := `DELETE FROM m365_admin_consent_requests WHERE expires_at < $1`

	result, err := s.db.ExecContext(ctx, query, time.Now())
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup expired requests: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %w", err)
	}

	return int(rowsAffected), nil
}
