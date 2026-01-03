// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package rbac

import (
	"github.com/cfgis/cfgms/api/proto/common"
)

// Default system permissions aligned with CFGMS architecture
var DefaultPermissions = []*common.Permission{
	// Steward Management Permissions
	{
		Id:           "steward.register",
		Name:         "Register Steward",
		Description:  "Allow steward to register with the controller",
		ResourceType: "steward",
		Actions:      []string{"create"},
	},
	{
		Id:           "steward.heartbeat",
		Name:         "Send Heartbeat",
		Description:  "Allow steward to send heartbeat to controller",
		ResourceType: "steward",
		Actions:      []string{"update"},
	},
	{
		Id:           "steward.dna.sync",
		Name:         "Sync DNA",
		Description:  "Allow steward to sync DNA with controller",
		ResourceType: "steward",
		Actions:      []string{"create", "update"},
	},
	{
		Id:           "steward.read",
		Name:         "Read Steward",
		Description:  "Read steward information and status",
		ResourceType: "steward",
		Actions:      []string{"read"},
	},
	{
		Id:           "steward.manage",
		Name:         "Manage Steward",
		Description:  "Full management of steward instances",
		ResourceType: "steward",
		Actions:      []string{"create", "read", "update", "delete"},
	},

	// Configuration Management Permissions
	{
		Id:           "config.read",
		Name:         "Read Configuration",
		Description:  "Read configuration data",
		ResourceType: "configuration",
		Actions:      []string{"read"},
	},
	{
		Id:           "config.validate",
		Name:         "Validate Configuration",
		Description:  "Validate configuration data",
		ResourceType: "configuration",
		Actions:      []string{"read"},
	},
	{
		Id:           "config.create",
		Name:         "Create Configuration",
		Description:  "Create new configuration data",
		ResourceType: "configuration",
		Actions:      []string{"create"},
	},
	{
		Id:           "config.update",
		Name:         "Update Configuration",
		Description:  "Update existing configuration data",
		ResourceType: "configuration",
		Actions:      []string{"update"},
	},
	{
		Id:           "config.delete",
		Name:         "Delete Configuration",
		Description:  "Delete configuration data",
		ResourceType: "configuration",
		Actions:      []string{"delete"},
	},
	{
		Id:           "config.status.report",
		Name:         "Report Configuration Status",
		Description:  "Report configuration execution status",
		ResourceType: "configuration",
		Actions:      []string{"create", "update"},
	},

	// Tenant Management Permissions
	{
		Id:           "tenant.read",
		Name:         "Read Tenant",
		Description:  "Read tenant information",
		ResourceType: "tenant",
		Actions:      []string{"read"},
	},
	{
		Id:           "tenant.create",
		Name:         "Create Tenant",
		Description:  "Create new tenant",
		ResourceType: "tenant",
		Actions:      []string{"create"},
	},
	{
		Id:           "tenant.manage",
		Name:         "Manage Tenant",
		Description:  "Full tenant management",
		ResourceType: "tenant",
		Actions:      []string{"create", "read", "update", "delete"},
	},

	// RBAC Management Permissions
	{
		Id:           "rbac.role.read",
		Name:         "Read Roles",
		Description:  "Read role information",
		ResourceType: "rbac",
		Actions:      []string{"read"},
	},
	{
		Id:           "rbac.role.manage",
		Name:         "Manage Roles",
		Description:  "Create, update, and delete roles",
		ResourceType: "rbac",
		Actions:      []string{"create", "read", "update", "delete"},
	},
	{
		Id:           "rbac.permission.read",
		Name:         "Read Permissions",
		Description:  "Read permission information",
		ResourceType: "rbac",
		Actions:      []string{"read"},
	},
	{
		Id:           "rbac.assignment.manage",
		Name:         "Manage Role Assignments",
		Description:  "Assign and revoke roles",
		ResourceType: "rbac",
		Actions:      []string{"create", "read", "update", "delete"},
	},

	// Module Management Permissions
	{
		Id:           "module.execute",
		Name:         "Execute Module",
		Description:  "Execute configuration modules",
		ResourceType: "module",
		Actions:      []string{"execute"},
	},
	{
		Id:           "module.read",
		Name:         "Read Module",
		Description:  "Read module information and status",
		ResourceType: "module",
		Actions:      []string{"read"},
	},

	// Terminal Management Permissions
	{
		Id:           "terminal.session.create",
		Name:         "Create Terminal Session",
		Description:  "Create new terminal sessions",
		ResourceType: "terminal",
		Actions:      []string{"create"},
	},
	{
		Id:           "terminal.session.read",
		Name:         "Read Terminal Sessions",
		Description:  "View terminal session information and status",
		ResourceType: "terminal",
		Actions:      []string{"read"},
	},
	{
		Id:           "terminal.session.terminate",
		Name:         "Terminate Terminal Sessions",
		Description:  "Terminate active terminal sessions",
		ResourceType: "terminal",
		Actions:      []string{"delete"},
	},
	{
		Id:           "terminal.session.monitor",
		Name:         "Monitor Terminal Sessions",
		Description:  "Real-time monitoring of terminal sessions",
		ResourceType: "terminal",
		Actions:      []string{"read"},
	},
	{
		Id:           "terminal.recording.read",
		Name:         "Read Terminal Recordings",
		Description:  "Access terminal session recordings",
		ResourceType: "terminal",
		Actions:      []string{"read"},
	},
	{
		Id:           "terminal.admin",
		Name:         "Terminal Administration",
		Description:  "Full terminal system administration",
		ResourceType: "terminal",
		Actions:      []string{"create", "read", "update", "delete", "execute"},
	},

	// System Administration Permissions
	{
		Id:           "system.admin",
		Name:         "System Administration",
		Description:  "Full system administration access",
		ResourceType: "system",
		Actions:      []string{"create", "read", "update", "delete", "execute"},
	},
}

// Default system roles that combine permissions logically
var DefaultRoles = []*common.Role{
	// System Roles (tenant_id empty for system-wide)
	{
		Id:          "system.admin",
		Name:        "System Administrator",
		Description: "Full system administration privileges",
		PermissionIds: []string{
			"system.admin",
			"tenant.manage",
			"rbac.role.manage",
			"rbac.permission.read",
			"rbac.assignment.manage",
		},
		IsSystemRole: true,
		TenantId:     "", // System-wide role
	},
	{
		Id:          "steward.service",
		Name:        "Steward Service Account",
		Description: "Permissions for steward instances to operate",
		PermissionIds: []string{
			"steward.register",
			"steward.heartbeat",
			"steward.dna.sync",
			"config.read",
			"config.validate",
			"config.status.report",
			"module.execute",
		},
		IsSystemRole: true,
		TenantId:     "", // System-wide role
	},

	// Tenant Roles (will be created per tenant)
	{
		Id:          "tenant.admin",
		Name:        "Tenant Administrator",
		Description: "Full administration within tenant scope",
		PermissionIds: []string{
			"steward.read",
			"steward.manage",
			"config.create",
			"config.read",
			"config.update",
			"config.delete",
			"config.validate",
			"module.read",
			"rbac.role.read",
			"rbac.assignment.manage",
			"tenant.read",
			"terminal.session.create",
			"terminal.session.read",
			"terminal.session.terminate",
			"terminal.session.monitor",
			"terminal.recording.read",
			"terminal.admin",
		},
		IsSystemRole: false, // Tenant-specific role template
	},
	{
		Id:          "tenant.operator",
		Name:        "Tenant Operator",
		Description: "Operations and monitoring within tenant scope",
		PermissionIds: []string{
			"steward.read",
			"config.read",
			"config.validate",
			"config.status.report",
			"module.read",
			"tenant.read",
			"terminal.session.create",
			"terminal.session.read",
			"terminal.session.monitor",
			"terminal.recording.read",
		},
		IsSystemRole: false, // Tenant-specific role template
	},
	{
		Id:          "tenant.viewer",
		Name:        "Tenant Viewer",
		Description: "Read-only access within tenant scope",
		PermissionIds: []string{
			"steward.read",
			"config.read",
			"module.read",
			"tenant.read",
			"rbac.role.read",
			"terminal.session.read",
			"terminal.recording.read",
		},
		IsSystemRole: false, // Tenant-specific role template
	},
}

// GetSystemRoles returns roles that are system-wide
func GetSystemRoles() []*common.Role {
	var systemRoles []*common.Role
	for _, role := range DefaultRoles {
		if role.IsSystemRole {
			systemRoles = append(systemRoles, role)
		}
	}
	return systemRoles
}

// GetTenantRoleTemplates returns role templates for tenant-specific roles
func GetTenantRoleTemplates() []*common.Role {
	var tenantRoles []*common.Role
	for _, role := range DefaultRoles {
		if !role.IsSystemRole {
			tenantRoles = append(tenantRoles, role)
		}
	}
	return tenantRoles
}

// CreateTenantRole creates a tenant-specific role from a template
func CreateTenantRole(template *common.Role, tenantID string) *common.Role {
	return &common.Role{
		Id:            tenantID + "." + template.Id,
		Name:          template.Name,
		Description:   template.Description,
		PermissionIds: template.PermissionIds,
		IsSystemRole:  false,
		TenantId:      tenantID,
	}
}
