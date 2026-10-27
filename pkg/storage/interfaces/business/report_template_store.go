// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package business

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

var (
	// ErrReportTemplateNotFound is returned when no report template with the given ID is
	// visible to the calling tenant: it does not exist, belongs to another tenant without
	// an active share, or the share has expired. The three cases are deliberately
	// indistinguishable so a tenant cannot probe for another tenant's template IDs. Delete
	// and UpdateSharing return it for a non-owner too.
	ErrReportTemplateNotFound = errors.New("report template not found")

	// ErrReportTemplateExists is returned by Save when the template ID is already owned by
	// a different tenant. The existing record is left unchanged.
	ErrReportTemplateExists = errors.New("report template already exists")
)

// ReportTemplateShare grants another tenant access to a report template. It carries the
// same fields as features/reports/interfaces.TemplateShare; that package depends on this
// one, so the type is redeclared here rather than imported.
type ReportTemplateShare struct {
	// TenantID is the recipient tenant.
	TenantID    string
	SharedBy    string
	SharedAt    time.Time
	Permissions []string
	// ExpiresAt is the instant the share stops granting access. Nil means it never expires.
	ExpiresAt *time.Time
}

// ReportTemplate is one durable custom report template. It carries the same fields as
// features/reports/interfaces.CustomReportTemplate, except that the query and parameters
// are held as one opaque JSON document in Definition, which the template manager marshals
// from and unmarshals into CustomReportTemplate. The store never interprets it.
type ReportTemplate struct {
	// ID is globally unique (a UUID supplied by the caller), so that GetByID can resolve a
	// template owned by another tenant through a share.
	ID          string
	Name        string
	Description string
	// Definition is the JSON document holding the query and parameters. Empty or valid JSON.
	Definition json.RawMessage

	// TenantID is the owning tenant. It never changes after the first Save.
	TenantID   string
	CreatedBy  string
	CreatedAt  time.Time
	UpdatedAt  time.Time
	IsShared   bool
	SharedWith []ReportTemplateShare

	Tags       []string
	Category   string
	Version    string
	UsageCount int
	LastUsed   *time.Time
}

// ReportTemplateStore is the durable, tenant-scoped storage contract for custom report
// templates. The tenant is an explicit argument of every method and no method has an
// "all tenants" form. A tenant reaches a template it does not own only through a share
// that names it and has not expired, and a share grants read access only: write, delete,
// re-share and sharing updates are owner-only.
//
// Templates returned to a non-owner carry only that tenant's own share in SharedWith, so
// a recipient cannot learn which other tenants a template is shared with.
type ReportTemplateStore interface {
	// Save upserts a template owned by tenantID. It returns an error and writes nothing
	// when tenantID or template.TenantID is empty or invalid, or the two differ. When a
	// record with the same ID is owned by a different tenant it returns
	// ErrReportTemplateExists and leaves that record unchanged.
	Save(ctx context.Context, tenantID string, template *ReportTemplate) error

	// GetByID returns the template when tenantID owns it or holds a non-expired share of
	// it, otherwise ErrReportTemplateNotFound.
	GetByID(ctx context.Context, tenantID, id string) (*ReportTemplate, error)

	// ListOwned returns every template tenantID owns.
	ListOwned(ctx context.Context, tenantID string) ([]*ReportTemplate, error)

	// ListSharedWith returns the templates owned by other tenants whose non-expired
	// SharedWith names tenantID.
	ListSharedWith(ctx context.Context, tenantID string) ([]*ReportTemplate, error)

	// Delete removes a template tenantID owns. Any other caller gets
	// ErrReportTemplateNotFound.
	Delete(ctx context.Context, tenantID, id string) error

	// UpdateSharing replaces the share list of a template tenantID owns. Any other caller
	// gets ErrReportTemplateNotFound.
	UpdateSharing(ctx context.Context, tenantID, id string, shares []ReportTemplateShare) error
}
