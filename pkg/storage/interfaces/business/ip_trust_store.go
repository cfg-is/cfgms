// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package business defines business-data storage contracts for CFGMS
package business

import (
	"context"
	"errors"
	"time"
)

// ErrIPTrustEntryNotFound is returned when an IP trust entry does not exist.
var ErrIPTrustEntryNotFound = errors.New("ip trust entry not found")

// IPTrustStore defines storage contract for tenant-scoped IP trust ranges.
// Each tenant maintains an independent set of trusted CIDRs; /32 entries
// represent single-host trust and broader CIDRs represent subnet trust.
type IPTrustStore interface {
	// AddTrustedRange records a trusted CIDR for a tenant. The CIDR is
	// normalised (network address, not host address) before storage, so
	// "192.168.1.1/24" and "192.168.1.0/24" produce the same entry.
	// If the CIDR was previously revoked it is re-activated.
	AddTrustedRange(ctx context.Context, tenantID, cidr string, preSeeded bool) error

	// IsTrusted returns true iff the given IP falls within at least one
	// non-revoked trusted CIDR for the tenant. Containment is evaluated in
	// Go (not SQL) via net.ParseCIDR + ipNet.Contains.
	IsTrusted(ctx context.Context, tenantID, ip string) (bool, error)

	// ListTrustedRanges returns all trust entries for the tenant, including
	// revoked ones (callers inspect the Revoked field).
	ListTrustedRanges(ctx context.Context, tenantID string) ([]*IPTrustEntry, error)

	// RevokeTrustedRange marks the entry for (tenantID, cidr) as revoked.
	// Subsequent IsTrusted calls for IPs in that range return false.
	// Returns ErrIPTrustEntryNotFound if no non-revoked entry exists.
	RevokeTrustedRange(ctx context.Context, tenantID, cidr string) error

	// RecordHealthySteward records a successful liveness event for the given
	// IP. It upserts last_activity and last_activity_ip on the CIDR entry
	// that contains the IP. No-op if no matching non-revoked entry exists.
	RecordHealthySteward(ctx context.Context, tenantID, ip string, at time.Time) error

	// GetLastActivity returns last-seen activity for the CIDR entry that
	// contains the given IP. Returns nil, nil when no matching entry or no
	// activity has been recorded yet.
	GetLastActivity(ctx context.Context, tenantID, ip string) (*IPTrustActivity, error)
}

// IPTrustEntry represents a trusted IP range in persistent storage.
type IPTrustEntry struct {
	ID           string
	TenantID     string
	CIDR         string
	PreSeeded    bool
	TrustedSince time.Time
	LastActivity time.Time // zero value means no activity recorded
	Revoked      bool
	RevokedAt    *time.Time
}

// IPTrustActivity holds last-seen information for a specific IP address.
type IPTrustActivity struct {
	TenantID string
	IP       string
	LastSeen time.Time
}
