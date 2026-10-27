// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package interfaces

import "errors"

var (
	// ErrTemplateNotFound is returned when a template does not exist or is not visible to
	// the calling tenant. It never reveals which tenant owns a template.
	ErrTemplateNotFound = errors.New("report template not found")

	// ErrTemplateAccessDenied is returned when the caller can see a template but lacks the
	// right to perform the operation on it (for example a non-owner saving or sharing it,
	// or a share without read permission). Schedule ownership uses its own sentinel.
	ErrTemplateAccessDenied = errors.New("report template access denied")

	// ErrShareTargetInvalid is returned for every refused share target: empty, the owner
	// itself, nonexistent, or outside the owner's MSP subtree. The text deliberately names
	// no tenant and is identical for every reason so it cannot be used to probe tenants.
	ErrShareTargetInvalid = errors.New("invalid share target")
)
