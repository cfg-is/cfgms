// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package storage

import (
	"database/sql"
	"fmt"
)

// statementSpec describes one prepared statement: where the prepared handle is
// stored, the name used in error messages, and the dialect SQL text.
type statementSpec struct {
	dest **sql.Stmt
	name string
	sql  string
}

// prepareStatements prepares every spec against db in order, storing each handle
// in its destination. dialect is inserted into error text ("PostgreSQL " or "");
// the first failure is returned as "failed to prepare <dialect><name> statement".
func prepareStatements(db *sql.DB, dialect string, specs []statementSpec) error {
	for _, s := range specs {
		stmt, err := db.Prepare(s.sql)
		if err != nil {
			return fmt.Errorf("failed to prepare %s%s statement: %w", dialect, s.name, err)
		}
		*s.dest = stmt
	}
	return nil
}
