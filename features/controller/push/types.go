// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package push

import "time"

// StewardConfiguration is the canonical type for a configuration push payload
// delivered to a steward. Shared by the push handler, fan-out logic, and
// persistence layer so that no duplicate definitions are needed in test code.
type StewardConfiguration struct {
	ConfigID  string                 `json:"config_id"`
	Version   string                 `json:"version"`
	TenantID  string                 `json:"tenant_id"`
	Policies  map[string]interface{} `json:"policies"`
	Modules   []string               `json:"modules"`
	AppliedAt time.Time              `json:"applied_at"`
	Source    string                 `json:"source"`
}
