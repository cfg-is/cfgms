// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package reporttemplate holds the input validation and visibility rules shared by every
// business.ReportTemplateStore provider, so the three providers cannot drift on who may
// see a template or which identifiers are accepted.
package reporttemplate

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/storage/providers/internal/keysafe"
)

// ValidateTenant checks a tenant ID before it is used in a path or query.
func ValidateTenant(tenantID string) error {
	return keysafe.ValidateTenantID(tenantID)
}

// ValidateID checks a template ID: non-empty and a single path component.
func ValidateID(id string) error {
	if id == "" {
		return errors.New("template ID must not be empty")
	}
	return keysafe.ValidateLeafField("template ID", id)
}

// ValidateShares checks every share recipient's tenant ID.
func ValidateShares(shares []business.ReportTemplateShare) error {
	for _, s := range shares {
		if err := keysafe.ValidateTenantID(s.TenantID); err != nil {
			return fmt.Errorf("share recipient: %w", err)
		}
	}
	return nil
}

// ValidateSave checks a Save call: both tenants valid and equal, a valid template ID,
// valid share recipients and a Definition that is empty or valid JSON.
func ValidateSave(tenantID string, t *business.ReportTemplate) error {
	if t == nil {
		return errors.New("report template must not be nil")
	}
	if err := ValidateTenant(tenantID); err != nil {
		return err
	}
	if err := ValidateTenant(t.TenantID); err != nil {
		return err
	}
	if tenantID != t.TenantID {
		return errors.New("report template tenant does not match the saving tenant")
	}
	if err := ValidateID(t.ID); err != nil {
		return err
	}
	if err := ValidateShares(t.SharedWith); err != nil {
		return err
	}
	if len(t.Definition) > 0 && !json.Valid(t.Definition) {
		return errors.New("report template definition is not valid JSON")
	}
	return nil
}

// Expired reports whether a share no longer grants access at now.
func Expired(s business.ReportTemplateShare, now time.Time) bool {
	return s.ExpiresAt != nil && !now.Before(*s.ExpiresAt)
}

// ViewFor returns the template as tenantID may see it, and whether it may see it at all.
// The owner sees the whole record; a share recipient sees it with only its own non-expired
// shares. The result is a copy that shares no memory with t.
func ViewFor(t *business.ReportTemplate, tenantID string, now time.Time) (*business.ReportTemplate, bool) {
	out := Clone(t)
	if t.TenantID == tenantID {
		return out, true
	}
	var own []business.ReportTemplateShare
	for _, s := range out.SharedWith {
		if s.TenantID == tenantID && !Expired(s, now) {
			own = append(own, s)
		}
	}
	if len(own) == 0 {
		return nil, false
	}
	out.SharedWith = own
	return out, true
}

// Clone deep-copies a template.
func Clone(t *business.ReportTemplate) *business.ReportTemplate {
	c := *t
	if t.Definition != nil {
		c.Definition = append(json.RawMessage(nil), t.Definition...)
	}
	c.Tags = append([]string(nil), t.Tags...)
	if t.LastUsed != nil {
		lu := *t.LastUsed
		c.LastUsed = &lu
	}
	c.SharedWith = CloneShares(t.SharedWith)
	return &c
}

// CloneShares deep-copies a share list.
func CloneShares(shares []business.ReportTemplateShare) []business.ReportTemplateShare {
	if len(shares) == 0 {
		return nil
	}
	out := make([]business.ReportTemplateShare, len(shares))
	for i, s := range shares {
		out[i] = s
		out[i].Permissions = append([]string(nil), s.Permissions...)
		if s.ExpiresAt != nil {
			e := *s.ExpiresAt
			out[i].ExpiresAt = &e
		}
	}
	return out
}

// Sort orders templates by name, then ID, so listings are deterministic.
func Sort(list []*business.ReportTemplate) {
	sort.Slice(list, func(i, j int) bool {
		if list[i].Name != list[j].Name {
			return list[i].Name < list[j].Name
		}
		return list[i].ID < list[j].ID
	})
}

// shareJSON is the stored form of a share, used by the providers that keep the share list
// in one JSON column. The tenant_id key is queried by the providers' SQL, so it is fixed.
type shareJSON struct {
	TenantID    string     `json:"tenant_id"`
	SharedBy    string     `json:"shared_by,omitempty"`
	SharedAt    time.Time  `json:"shared_at"`
	Permissions []string   `json:"permissions,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

// EncodeShares marshals a share list for a JSON column; an empty list is "[]".
func EncodeShares(shares []business.ReportTemplateShare) (string, error) {
	out := make([]shareJSON, 0, len(shares))
	for _, s := range shares {
		out = append(out, shareJSON{TenantID: s.TenantID, SharedBy: s.SharedBy, SharedAt: s.SharedAt.UTC(),
			Permissions: s.Permissions, ExpiresAt: s.ExpiresAt})
	}
	raw, err := json.Marshal(out)
	if err != nil {
		return "", fmt.Errorf("failed to marshal shares: %w", err)
	}
	return string(raw), nil
}

// DecodeShares is the inverse of EncodeShares.
func DecodeShares(raw string) ([]business.ReportTemplateShare, error) {
	var in []shareJSON
	if err := json.Unmarshal([]byte(raw), &in); err != nil {
		return nil, fmt.Errorf("failed to parse shares: %w", err)
	}
	var out []business.ReportTemplateShare
	for _, s := range in {
		out = append(out, business.ReportTemplateShare{TenantID: s.TenantID, SharedBy: s.SharedBy,
			SharedAt: s.SharedAt, Permissions: s.Permissions, ExpiresAt: s.ExpiresAt})
	}
	return out, nil
}

// EncodeTags marshals a tag list for a JSON column; an empty list is "[]".
func EncodeTags(tags []string) (string, error) {
	if tags == nil {
		tags = []string{}
	}
	raw, err := json.Marshal(tags)
	if err != nil {
		return "", fmt.Errorf("failed to marshal tags: %w", err)
	}
	return string(raw), nil
}

// DecodeTags is the inverse of EncodeTags.
func DecodeTags(raw string) ([]string, error) {
	var tags []string
	if err := json.Unmarshal([]byte(raw), &tags); err != nil {
		return nil, fmt.Errorf("failed to parse tags: %w", err)
	}
	if len(tags) == 0 {
		return nil, nil
	}
	return tags, nil
}
