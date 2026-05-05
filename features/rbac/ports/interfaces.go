// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package ports

import (
	"context"

	"github.com/cfgis/cfgms/api/proto/common"
)

// RBACManager is the canonical minimal interface shared across zerotrust, continuous, and risk subpackages.
// It is a leaf package — it imports only context and api/proto/common — so subpackages can import it without cycles.
type RBACManager interface {
	CheckPermission(ctx context.Context, request *common.AccessRequest) (*common.AccessResponse, error)
	GetEffectivePermissions(ctx context.Context, subjectID, tenantID string) ([]*common.Permission, error)
	GetSubjectPermissions(ctx context.Context, subjectID, tenantID string) ([]*common.Permission, error)
	Initialize(ctx context.Context) error
}

// JITManager is the canonical minimal interface for just-in-time access validation.
// ValidateJITAccess is the canonical method name (resolves the zerotrust/continuous naming conflict).
type JITManager interface {
	ValidateJITAccess(ctx context.Context, request *common.AccessRequest) (*common.AccessResponse, error)
}

// RiskManager is the canonical minimal interface for risk-based access assessment.
type RiskManager interface {
	AssessRisk(ctx context.Context, request *common.AccessRequest) (*common.AccessResponse, error)
}
