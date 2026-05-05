// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package ports_test

import (
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/features/rbac/ports"
)

// Compile-time assertion: rbac.Manager must satisfy ports.RBACManager.
var _ ports.RBACManager = (*rbac.Manager)(nil)
