// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package transport provides data plane handlers for controller operations.
package transport

import "errors"

var (
	// ErrStewardIdentityMismatch is returned when the steward ID in a request
	// does not match the CN from the peer's mTLS certificate.
	ErrStewardIdentityMismatch = errors.New("steward ID does not match authenticated mTLS peer CN")

	// ErrTenantIDMismatch is returned when the tenant ID in a request does not
	// match the authenticated mTLS peer CN.
	ErrTenantIDMismatch = errors.New("tenant ID does not match authenticated mTLS peer CN")
)
