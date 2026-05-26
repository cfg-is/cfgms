// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package continuous

import (
	"time"

	"github.com/cfgis/cfgms/api/proto/common"
)

// ContinuousAuthRequest is the request type used by CacheManager for cache key generation
// and storage. The ContinuousAuthorizationEngine that consumed these requests has been
// removed; this type is preserved because CacheManager is a live production dependency
// of features/rbac/manager.go.
type ContinuousAuthRequest struct {
	*common.AccessRequest
	SessionID       string            `json:"session_id"`
	ResourceContext map[string]string `json:"resource_context,omitempty"`
	RequestTime     time.Time         `json:"request_time"`
}

// ContinuousAuthResponse is the response type stored in CacheManager.
// See ContinuousAuthRequest for the preservation rationale.
type ContinuousAuthResponse struct {
	AccessResponse *common.AccessResponse `json:"access_response"`
	ValidUntil     time.Time              `json:"valid_until"`
	DecisionID     string                 `json:"decision_id"`
	DecisionTime   time.Time              `json:"decision_time"`
	SessionValid   bool                   `json:"session_valid"`
}
