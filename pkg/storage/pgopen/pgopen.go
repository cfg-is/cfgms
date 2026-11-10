// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package pgopen holds the PostgreSQL open site shared by controller-side
// callers outside pkg/storage. It is stateless and is not a storage provider.
package pgopen

import (
	"database/sql"

	// Registers the "postgres" database/sql driver.
	_ "github.com/lib/pq"
)

// Open returns a database handle for a PostgreSQL connection string. It does
// not dial: callers ping the handle when they need to verify connectivity.
func Open(connString string) (*sql.DB, error) {
	return sql.Open("postgres", connString)
}
