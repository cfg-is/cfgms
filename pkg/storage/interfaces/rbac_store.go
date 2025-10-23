// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
// Package interfaces defines global storage contracts used by all CFGMS modules
package interfaces

import (
	"context"

	"github.com/cfgis/cfgms/api/proto/common"
)

// RBACStore defines storage interface for RBAC data persistence
// All RBAC modules use this interface - storage provider is chosen by controller
type RBACStore interface {
	// Permission management
	StorePermission(ctx context.Context, permission *common.Permission) error
	GetPermission(ctx context.Context, id string) (*common.Permission, error)
	ListPermissions(ctx context.Context, resourceType string) ([]*common.Permission, error)
	UpdatePermission(ctx context.Context, permission *common.Permission) error
	DeletePermission(ctx context.Context, id string) error

	// Role management
	StoreRole(ctx context.Context, role *common.Role) error
	GetRole(ctx context.Context, id string) (*common.Role, error)
	ListRoles(ctx context.Context, tenantID string) ([]*common.Role, error)
	UpdateRole(ctx context.Context, role *common.Role) error
	DeleteRole(ctx context.Context, id string) error

	// Subject management
	StoreSubject(ctx context.Context, subject *common.Subject) error
	GetSubject(ctx context.Context, id string) (*common.Subject, error)
	ListSubjects(ctx context.Context, tenantID string, subjectType common.SubjectType) ([]*common.Subject, error)
	UpdateSubject(ctx context.Context, subject *common.Subject) error
	DeleteSubject(ctx context.Context, id string) error

	// Role assignment management
	StoreRoleAssignment(ctx context.Context, assignment *common.RoleAssignment) error
	GetRoleAssignment(ctx context.Context, id string) (*common.RoleAssignment, error)
	ListRoleAssignments(ctx context.Context, subjectID, roleID, tenantID string) ([]*common.RoleAssignment, error)
	DeleteRoleAssignment(ctx context.Context, subjectID, roleID, tenantID string) error

	// Bulk operations for initial setup
	StoreBulkPermissions(ctx context.Context, permissions []*common.Permission) error
	StoreBulkRoles(ctx context.Context, roles []*common.Role) error
	StoreBulkSubjects(ctx context.Context, subjects []*common.Subject) error

	// Query operations
	GetSubjectRoles(ctx context.Context, subjectID, tenantID string) ([]*common.Role, error)
	GetRolePermissions(ctx context.Context, roleID string) ([]*common.Permission, error)
	GetSubjectAssignments(ctx context.Context, subjectID, tenantID string) ([]*common.RoleAssignment, error)

	// Initialize and cleanup
	Initialize(ctx context.Context) error
	Close() error
}

// RBACStoreProvider defines how storage providers create RBAC stores
type RBACStoreProvider interface {
	CreateRBACStore(config map[string]interface{}) (RBACStore, error)
}
