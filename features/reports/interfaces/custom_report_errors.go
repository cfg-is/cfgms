// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package interfaces

import "errors"

var (
	// ErrParameterValidationFailed is returned when a user-supplied report parameter
	// violates its definition. The error text names the offending parameter.
	ErrParameterValidationFailed = errors.New("report parameter validation failed")

	// ErrInvalidQuery is returned when a custom query is malformed or exceeds the
	// configured data source, filter or aggregation limits.
	ErrInvalidQuery = errors.New("invalid custom report query")

	// ErrDataSourceNotSupported is returned when a custom query names a data source the
	// builder cannot serve.
	ErrDataSourceNotSupported = errors.New("report data source not supported")

	// ErrStreamTokenInvalid is returned for a stream token that is unknown, expired,
	// malformed or issued to a different tenant. The reasons are indistinguishable.
	ErrStreamTokenInvalid = errors.New("stream token invalid")
)
