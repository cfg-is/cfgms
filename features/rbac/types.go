// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package rbac

import "github.com/cfgis/cfgms/features/rbac/memory"

// RoleHierarchy exposes the memory-layer type at the rbac package boundary so
// callers outside this feature do not need to import features/rbac/memory directly.
type RoleHierarchy = memory.RoleHierarchy

// EffectivePermissions exposes the memory-layer type at the rbac package boundary
// for the same reason.
type EffectivePermissions = memory.EffectivePermissions
