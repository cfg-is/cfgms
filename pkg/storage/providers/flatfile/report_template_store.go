// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package flatfile

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/storage/providers/internal/reporttemplate"
)

// Compile-time assertion.
var _ business.ReportTemplateStore = (*FlatFileReportTemplateStore)(nil)

// FlatFileReportTemplateStore implements business.ReportTemplateStore backed by a single
// JSON file.
//
// File layout: <root>/report_templates/templates.json
//
// Templates for all tenants live in one JSON array keyed by their globally unique ID.
// No path is ever built from a tenant or template ID, so a traversal-shaped identifier
// cannot reach outside the report-template root; identifiers are still validated before
// use. Writes are atomic (temp-file + rename) and sync.Mutex serializes every
// read-modify-write within the process.
type FlatFileReportTemplateStore struct {
	root string
	mu   sync.Mutex
}

// reportTemplateJSON is the on-disk representation of a report template.
type reportTemplateJSON struct {
	ID          string                `json:"id"`
	Name        string                `json:"name"`
	Description string                `json:"description,omitempty"`
	Definition  json.RawMessage       `json:"definition,omitempty"`
	TenantID    string                `json:"tenant_id"`
	CreatedBy   string                `json:"created_by,omitempty"`
	CreatedAt   time.Time             `json:"created_at"`
	UpdatedAt   time.Time             `json:"updated_at"`
	IsShared    bool                  `json:"is_shared"`
	SharedWith  []reportTemplateShare `json:"shared_with,omitempty"`
	Tags        []string              `json:"tags,omitempty"`
	Category    string                `json:"category,omitempty"`
	Version     string                `json:"version,omitempty"`
	UsageCount  int                   `json:"usage_count"`
	LastUsed    *time.Time            `json:"last_used,omitempty"`
}

type reportTemplateShare struct {
	TenantID    string     `json:"tenant_id"`
	SharedBy    string     `json:"shared_by,omitempty"`
	SharedAt    time.Time  `json:"shared_at"`
	Permissions []string   `json:"permissions,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

// NewFlatFileReportTemplateStore creates a store rooted at <root>/report_templates.
// The directory is created if it does not exist.
func NewFlatFileReportTemplateStore(root string) (*FlatFileReportTemplateStore, error) {
	if err := os.MkdirAll(filepath.Join(root, "report_templates"), 0750); err != nil {
		return nil, fmt.Errorf("flatfile: failed to create report_templates directory: %w", err)
	}
	return &FlatFileReportTemplateStore{root: root}, nil
}

func (s *FlatFileReportTemplateStore) dataFilePath() string {
	return filepath.Join(s.root, "report_templates", "templates.json")
}

// load reads the templates file; a missing file is an empty store. Lock must be held.
func (s *FlatFileReportTemplateStore) load() ([]reportTemplateJSON, error) {
	raw, err := readFile(s.dataFilePath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("flatfile: failed to read report templates file: %w", err)
	}
	var list []reportTemplateJSON
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("flatfile: failed to parse report templates file: %w", err)
	}
	return list, nil
}

// save atomically writes the templates. Lock must be held. The file is written compact
// because indenting would rewrite the whitespace of the opaque Definition documents.
func (s *FlatFileReportTemplateStore) save(list []reportTemplateJSON) error {
	if list == nil {
		list = []reportTemplateJSON{}
	}
	raw, err := json.Marshal(list)
	if err != nil {
		return fmt.Errorf("flatfile: failed to marshal report templates: %w", err)
	}
	return writeAtomic(s.dataFilePath(), raw)
}

func toReportTemplateJSON(t *business.ReportTemplate) reportTemplateJSON {
	c := reporttemplate.Clone(t)
	j := reportTemplateJSON{
		ID: c.ID, Name: c.Name, Description: c.Description, Definition: c.Definition,
		TenantID: c.TenantID, CreatedBy: c.CreatedBy, CreatedAt: c.CreatedAt.UTC(),
		UpdatedAt: c.UpdatedAt.UTC(), IsShared: c.IsShared, Tags: c.Tags, Category: c.Category,
		Version: c.Version, UsageCount: c.UsageCount, LastUsed: c.LastUsed,
	}
	for _, sh := range c.SharedWith {
		j.SharedWith = append(j.SharedWith, reportTemplateShare{
			TenantID: sh.TenantID, SharedBy: sh.SharedBy, SharedAt: sh.SharedAt.UTC(),
			Permissions: sh.Permissions, ExpiresAt: sh.ExpiresAt,
		})
	}
	return j
}

func fromReportTemplateJSON(j reportTemplateJSON) *business.ReportTemplate {
	t := &business.ReportTemplate{
		ID: j.ID, Name: j.Name, Description: j.Description, Definition: j.Definition,
		TenantID: j.TenantID, CreatedBy: j.CreatedBy, CreatedAt: j.CreatedAt, UpdatedAt: j.UpdatedAt,
		IsShared: j.IsShared, Tags: j.Tags, Category: j.Category, Version: j.Version,
		UsageCount: j.UsageCount, LastUsed: j.LastUsed,
	}
	for _, sh := range j.SharedWith {
		t.SharedWith = append(t.SharedWith, business.ReportTemplateShare{
			TenantID: sh.TenantID, SharedBy: sh.SharedBy, SharedAt: sh.SharedAt,
			Permissions: sh.Permissions, ExpiresAt: sh.ExpiresAt,
		})
	}
	return t
}

// Save implements business.ReportTemplateStore.
func (s *FlatFileReportTemplateStore) Save(_ context.Context, tenantID string, template *business.ReportTemplate) error {
	if err := reporttemplate.ValidateSave(tenantID, template); err != nil {
		return fmt.Errorf("flatfile: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	list, err := s.load()
	if err != nil {
		return err
	}
	rec := toReportTemplateJSON(template)
	for i := range list {
		if list[i].ID != rec.ID {
			continue
		}
		if list[i].TenantID != tenantID {
			return business.ErrReportTemplateExists
		}
		list[i] = rec
		return s.save(list)
	}
	return s.save(append(list, rec))
}

// GetByID implements business.ReportTemplateStore.
func (s *FlatFileReportTemplateStore) GetByID(_ context.Context, tenantID, id string) (*business.ReportTemplate, error) {
	if err := reporttemplate.ValidateTenant(tenantID); err != nil {
		return nil, fmt.Errorf("flatfile: %w", err)
	}
	if err := reporttemplate.ValidateID(id); err != nil {
		return nil, fmt.Errorf("flatfile: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	list, err := s.load()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	for _, j := range list {
		if j.ID != id {
			continue
		}
		if view, ok := reporttemplate.ViewFor(fromReportTemplateJSON(j), tenantID, now); ok {
			return view, nil
		}
		break
	}
	return nil, business.ErrReportTemplateNotFound
}

// ListOwned implements business.ReportTemplateStore.
func (s *FlatFileReportTemplateStore) ListOwned(_ context.Context, tenantID string) ([]*business.ReportTemplate, error) {
	return s.list(tenantID, true)
}

// ListSharedWith implements business.ReportTemplateStore.
func (s *FlatFileReportTemplateStore) ListSharedWith(_ context.Context, tenantID string) ([]*business.ReportTemplate, error) {
	return s.list(tenantID, false)
}

func (s *FlatFileReportTemplateStore) list(tenantID string, owned bool) ([]*business.ReportTemplate, error) {
	if err := reporttemplate.ValidateTenant(tenantID); err != nil {
		return nil, fmt.Errorf("flatfile: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	all, err := s.load()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	result := make([]*business.ReportTemplate, 0)
	for _, j := range all {
		if (j.TenantID == tenantID) != owned {
			continue
		}
		if view, ok := reporttemplate.ViewFor(fromReportTemplateJSON(j), tenantID, now); ok {
			result = append(result, view)
		}
	}
	reporttemplate.Sort(result)
	return result, nil
}

// Delete implements business.ReportTemplateStore.
func (s *FlatFileReportTemplateStore) Delete(_ context.Context, tenantID, id string) error {
	return s.mutateOwned(tenantID, id, func(list []reportTemplateJSON, i int) []reportTemplateJSON {
		return append(list[:i], list[i+1:]...)
	})
}

// UpdateSharing implements business.ReportTemplateStore.
func (s *FlatFileReportTemplateStore) UpdateSharing(_ context.Context, tenantID, id string, shares []business.ReportTemplateShare) error {
	if err := reporttemplate.ValidateShares(shares); err != nil {
		return fmt.Errorf("flatfile: %w", err)
	}
	return s.mutateOwned(tenantID, id, func(list []reportTemplateJSON, i int) []reportTemplateJSON {
		updated := toReportTemplateJSON(&business.ReportTemplate{ID: id, SharedWith: shares})
		list[i].SharedWith = updated.SharedWith
		list[i].IsShared = len(shares) > 0
		return list
	})
}

// mutateOwned applies fn to the template with the given ID when tenantID owns it, and
// persists the result. Any other caller gets ErrReportTemplateNotFound.
func (s *FlatFileReportTemplateStore) mutateOwned(tenantID, id string,
	fn func([]reportTemplateJSON, int) []reportTemplateJSON) error {
	if err := reporttemplate.ValidateTenant(tenantID); err != nil {
		return fmt.Errorf("flatfile: %w", err)
	}
	if err := reporttemplate.ValidateID(id); err != nil {
		return fmt.Errorf("flatfile: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	list, err := s.load()
	if err != nil {
		return err
	}
	for i := range list {
		if list[i].ID == id && list[i].TenantID == tenantID {
			return s.save(fn(list, i))
		}
	}
	return business.ErrReportTemplateNotFound
}
