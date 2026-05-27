// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package gdaptypes defines the canonical types for GDAP (Granular Delegated
// Admin Privileges) operations shared between the saas and gdap packages.
// It imports only standard library packages to avoid import cycles.
package gdaptypes

import (
	"context"
	"time"
)

// GDAPRelationshipStatus represents the status of a GDAP relationship.
type GDAPRelationshipStatus string

const (
	GDAPStatusPending    GDAPRelationshipStatus = "pending"
	GDAPStatusActive     GDAPRelationshipStatus = "active"
	GDAPStatusExpired    GDAPRelationshipStatus = "expired"
	GDAPStatusTerminated GDAPRelationshipStatus = "terminated"
)

// GDAPRole represents a role assignment within a GDAP relationship.
type GDAPRole struct {
	RoleDefinitionID string `json:"role_definition_id"`
	RoleName         string `json:"role_name"`
	RoleDescription  string `json:"role_description"`
}

// GDAPRelationship represents a GDAP relationship with a customer tenant.
type GDAPRelationship struct {
	RelationshipID   string                 `json:"relationship_id"`
	CustomerTenantID string                 `json:"customer_tenant_id"`
	CustomerName     string                 `json:"customer_name"`
	Status           GDAPRelationshipStatus `json:"status"`
	Roles            []GDAPRole             `json:"roles"`
	ExpiresAt        time.Time              `json:"expires_at"`
	CreatedAt        time.Time              `json:"created_at"`
	LastModified     time.Time              `json:"last_modified"`
}

// GDAPProvider defines the interface for GDAP relationship discovery and validation.
type GDAPProvider interface {
	DiscoverGDAPCustomers(ctx context.Context) ([]GDAPRelationship, error)
	ValidateGDAPAccess(ctx context.Context, customerTenantID string, requiredRoles []string) (*GDAPRelationship, error)
}
