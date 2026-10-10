// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package tenant

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"sort"
	"strings"
)

const (
	// MetaKeyAdminContacts is the reserved tenant metadata key holding the
	// MSP-managed administrator contact list: a JSON array of lower-cased,
	// deduplicated bare email addresses. It is writable only through
	// SetAdminContacts; the generic create/update paths reject it.
	MetaKeyAdminContacts = "cfgms.admin_contacts"

	// MaxAdminContacts bounds the number of contact addresses per tenant.
	MaxAdminContacts = 20

	// maxAdminContactLen is the RFC 5321 maximum length of a forward-path address.
	maxAdminContactLen = 254
)

// ErrReservedMetadataKey is returned when a generic tenant create/update request
// supplies a metadata key the manager reserves for itself.
var ErrReservedMetadataKey = errors.New("metadata key " + MetaKeyAdminContacts + " is reserved")

// ErrInvalidAdminContacts is returned when a contact list fails validation.
var ErrInvalidAdminContacts = errors.New("invalid admin contacts")

// NormalizeAdminContacts validates and canonicalises a contact list: each entry
// must parse as a bare address (no display name, no CR/LF), is lower-cased, and
// duplicates are dropped. The result is sorted so the stored form is stable.
func NormalizeAdminContacts(addrs []string) ([]string, error) {
	if len(addrs) > MaxAdminContacts {
		return nil, fmt.Errorf("%w: at most %d addresses allowed", ErrInvalidAdminContacts, MaxAdminContacts)
	}
	seen := make(map[string]struct{}, len(addrs))
	out := make([]string, 0, len(addrs))
	for _, raw := range addrs {
		if strings.ContainsAny(raw, "\r\n") {
			return nil, fmt.Errorf("%w: address contains a line break", ErrInvalidAdminContacts)
		}
		if raw == "" || len(raw) > maxAdminContactLen {
			return nil, fmt.Errorf("%w: address is empty or too long", ErrInvalidAdminContacts)
		}
		parsed, err := mail.ParseAddress(raw)
		if err != nil || parsed.Address != raw {
			return nil, fmt.Errorf("%w: entries must be bare email addresses", ErrInvalidAdminContacts)
		}
		lower := strings.ToLower(raw)
		if _, dup := seen[lower]; dup {
			continue
		}
		seen[lower] = struct{}{}
		out = append(out, lower)
	}
	sort.Strings(out)
	return out, nil
}

// AdminContactsFromMetadata parses the contact list from tenant metadata. A
// missing or unparseable value yields an empty list.
func AdminContactsFromMetadata(md map[string]string) []string {
	raw, ok := md[MetaKeyAdminContacts]
	if !ok || raw == "" {
		return []string{}
	}
	var addrs []string
	if err := json.Unmarshal([]byte(raw), &addrs); err != nil || addrs == nil {
		return []string{}
	}
	return addrs
}

// GetAdminContacts returns the administrator contacts stored on tenantID.
func (m *Manager) GetAdminContacts(ctx context.Context, tenantID string) ([]string, error) {
	td, err := m.store.GetTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return AdminContactsFromMetadata(td.Metadata), nil
}

// SetAdminContacts validates addrs and replaces the stored contact list on
// tenantID, returning the normalised list. An empty list removes the key.
func (m *Manager) SetAdminContacts(ctx context.Context, tenantID string, addrs []string) ([]string, error) {
	normalized, err := NormalizeAdminContacts(addrs)
	if err != nil {
		return nil, err
	}
	existing, err := m.store.GetTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	md := make(map[string]string, len(existing.Metadata)+1)
	for k, v := range existing.Metadata {
		md[k] = v
	}
	if len(normalized) == 0 {
		delete(md, MetaKeyAdminContacts)
	} else {
		encoded, err := json.Marshal(normalized)
		if err != nil {
			return nil, fmt.Errorf("failed to encode admin contacts: %w", err)
		}
		md[MetaKeyAdminContacts] = string(encoded)
	}
	existing.Metadata = md
	if err := m.store.UpdateTenant(ctx, existing); err != nil {
		return nil, fmt.Errorf("failed to update tenant: %w", err)
	}
	return normalized, nil
}

// ResolveMSPAdminContacts returns the administrator contacts of the MSP that owns
// targetID: the contacts on the tenant in targetID's ancestry whose parent is the
// deployment root (the MSP seam tenant). It fails closed to an empty list when
// there is no root, the target is the root or not under it, or nothing is set.
func (m *Manager) ResolveMSPAdminContacts(ctx context.Context, targetID string) []string {
	rootID := m.RootTenantID(ctx)
	if rootID == "" || targetID == "" || targetID == rootID {
		return []string{}
	}
	path, err := m.store.GetTenantPath(ctx, targetID)
	if err != nil || len(path) < 2 || path[0] != rootID {
		return []string{}
	}
	td, err := m.store.GetTenant(ctx, path[1])
	if err != nil || td == nil || td.ParentID != rootID {
		return []string{}
	}
	return AdminContactsFromMetadata(td.Metadata)
}
