// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package tenant

import (
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Type aliases — redirected to business package to eliminate duplicates (Issue #1275).
// These keep existing callers outside features/tenant/ compiling without modification
// until they are updated in follow-on stories.
type Tenant = business.TenantData
type TenantStatus = business.TenantStatus
type TenantHierarchy = business.TenantHierarchy
type TenantFilter = business.TenantFilter

const (
	TenantStatusActive    = business.TenantStatusActive
	TenantStatusSuspended = business.TenantStatusSuspended
)

// TenantRequest represents a request to create or update a tenant
type TenantRequest struct {
	ID          string            `json:"id,omitempty"`
	Name        string            `json:"name,omitempty"`
	Description string            `json:"description,omitempty"`
	ParentID    string            `json:"parent_id,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}
