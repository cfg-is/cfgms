// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package transport provides data plane handlers for controller operations.
package transport

import "errors"

// ErrStewardIdentityMismatch is returned when the steward ID in a request does
// not match the CN from the peer's mTLS certificate. S7 extends this file with
// ErrTenantIDMismatch.
var ErrStewardIdentityMismatch = errors.New("steward ID does not match authenticated mTLS peer CN")
