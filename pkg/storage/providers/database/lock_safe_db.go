// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package database

// Lock-safe schema re-apply (Epic #5978, zero-downtime schema evolution, N / N-1).
//
// Postgres takes the table lock for an ALTER TABLE before it evaluates IF NOT
// EXISTS on an ADD COLUMN. Re-running such a statement against an up-to-date
// table therefore queues an ACCESS EXCLUSIVE lock request behind any long
// transaction on the table, and every query that arrives after that request
// queues behind it. A controller node restarting in a rolling upgrade would stall
// live traffic on each such table for no change at all.
//
// lockSafeDB wraps the executor the schema functions receive. Before it runs an
// ALTER TABLE <t> ADD COLUMN IF NOT EXISTS <c> ... statement it reads
// information_schema.columns, which takes no table lock, and issues nothing when
// the column already exists. Every other statement passes through unchanged and in
// order. When the column is missing the statement runs as before.

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"regexp"
	"strings"
)

// schemaExecutor is the subset of *sql.DB the schema functions use. It carries no
// BeginTx: schemas.go opens no transaction of its own (applyTenantRLS does, on the
// *sql.DB it is handed through applyTenantRLSVia).
type schemaExecutor interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// sqlDBSource is implemented by an executor that sits on a *sql.DB but is not one
// (a test wrapper that counts statements, for example).
type sqlDBSource interface {
	sqlDB() *sql.DB
}

// lockSafeDB is a schemaExecutor that skips ADD COLUMN IF NOT EXISTS statements
// whose column already exists.
type lockSafeDB struct {
	schemaExecutor
}

// lockSafe wraps e so that re-applying an up-to-date schema takes no table lock.
// Wrapping a lockSafeDB returns it unchanged, so schema functions that call one
// another wrap once.
func lockSafe(e schemaExecutor) schemaExecutor {
	if l, ok := e.(*lockSafeDB); ok {
		return l
	}
	return &lockSafeDB{schemaExecutor: e}
}

// underlyingSQLDB returns the *sql.DB under e, for the one caller that needs a
// transaction (applyTenantRLS).
func underlyingSQLDB(e schemaExecutor) (*sql.DB, error) {
	for {
		switch v := e.(type) {
		case *sql.DB:
			return v, nil
		case *lockSafeDB:
			e = v.schemaExecutor
		case sqlDBSource:
			return v.sqlDB(), nil
		default:
			return nil, fmt.Errorf("schema executor %T does not expose a *sql.DB", e)
		}
	}
}

// applyTenantRLSVia runs applyTenantRLS on the *sql.DB under db. RLS statements
// are not rewritten by lockSafeDB.
func applyTenantRLSVia(ctx context.Context, db schemaExecutor, table string, policies []tenantRLSPolicy) error {
	raw, err := underlyingSQLDB(db)
	if err != nil {
		return fmt.Errorf("failed to configure %s RLS: %w", table, err)
	}
	return applyTenantRLS(ctx, raw, table, policies)
}

// sqlIdentPattern matches one unquoted or double-quoted identifier.
const sqlIdentPattern = `"(?:[^"]|"")+"|[A-Za-z_][A-Za-z0-9_$]*`

// addColumnIfNotExistsRe matches an unqualified single-table add-column statement.
// A schema-qualified table, ONLY, IF EXISTS on the table or comments inside the
// statement do not match and so pass through untouched.
var addColumnIfNotExistsRe = regexp.MustCompile(
	`(?is)^ALTER\s+TABLE\s+(` + sqlIdentPattern + `)\s+ADD\s+COLUMN\s+IF\s+NOT\s+EXISTS\s+(` + sqlIdentPattern + `)(?:\s|$)`)

// ExecContext skips the ADD COLUMN IF NOT EXISTS statements of query whose column
// exists and issues the rest in order. A query with arguments is a single
// statement and is passed through; so is a query from which nothing is skipped,
// byte for byte.
func (l *lockSafeDB) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	if len(args) > 0 {
		return l.schemaExecutor.ExecContext(ctx, query, args...)
	}
	statements := splitSQLStatements(query)
	kept := make([]string, 0, len(statements))
	skipped := false
	for _, stmt := range statements {
		table, column, ok := parseAddColumnIfNotExists(stmt)
		if ok {
			exists, err := l.columnExists(ctx, table, column)
			if err != nil {
				return nil, err
			}
			if exists {
				skipped = true
				continue
			}
		}
		kept = append(kept, stmt)
	}
	if !skipped {
		return l.schemaExecutor.ExecContext(ctx, query)
	}
	if len(kept) == 0 {
		return driver.ResultNoRows, nil
	}
	// One call, as before, so the remaining statements keep the implicit
	// transaction the simple query protocol gives a multi-statement string.
	return l.schemaExecutor.ExecContext(ctx, strings.Join(kept, ";\n")+";")
}

// columnExists reads the catalog only; it takes no lock on the table.
func (l *lockSafeDB) columnExists(ctx context.Context, table, column string) (bool, error) {
	var exists bool
	err := l.schemaExecutor.QueryRowContext(ctx,
		"SELECT EXISTS (SELECT 1 FROM information_schema.columns"+
			" WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2)",
		table, column).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check for column %s.%s: %w", table, column, err)
	}
	return exists, nil
}

// parseAddColumnIfNotExists reports whether stmt is ALTER TABLE <t> ADD COLUMN IF
// NOT EXISTS <c> ... with exactly one action, and returns the table and column as
// the catalog stores them: unquoted names folded to lower case, quoted names
// unquoted and kept as written.
func parseAddColumnIfNotExists(stmt string) (table, column string, ok bool) {
	body := trimLeadingSpaceAndComments(stmt)
	m := addColumnIfNotExistsRe.FindStringSubmatch(body)
	if m == nil {
		return "", "", false
	}
	// A comma outside parentheses and quotes starts a second action
	// (ADD COLUMN IF NOT EXISTS a INT, ADD COLUMN IF NOT EXISTS b INT), which one
	// catalog lookup cannot stand in for.
	if hasTopLevelComma(body) {
		return "", "", false
	}
	return foldIdentifier(m[1]), foldIdentifier(m[2]), true
}

// foldIdentifier resolves an identifier the way Postgres does.
func foldIdentifier(ident string) string {
	if strings.HasPrefix(ident, `"`) {
		return strings.ReplaceAll(ident[1:len(ident)-1], `""`, `"`)
	}
	return strings.ToLower(ident)
}

// splitSQLStatements splits query at top-level semicolons and returns each
// statement as written, trimmed, without its semicolon. Semicolons inside single-
// quoted strings, double-quoted identifiers, dollar-quoted bodies and comments do
// not split. A fragment holding nothing but whitespace and comments is dropped.
func splitSQLStatements(query string) []string {
	var out []string
	start := 0
	add := func(end int) {
		frag := strings.TrimSpace(query[start:end])
		if trimLeadingSpaceAndComments(frag) != "" {
			out = append(out, frag)
		}
	}
	for i := 0; i < len(query); {
		if end, ok := skipSQLRegion(query, i); ok {
			i = end
			continue
		}
		if query[i] == ';' {
			add(i)
			start = i + 1
		}
		i++
	}
	add(len(query))
	return out
}

// hasTopLevelComma reports whether stmt has a comma outside parentheses, quotes
// and comments.
func hasTopLevelComma(stmt string) bool {
	depth := 0
	for i := 0; i < len(stmt); {
		if end, ok := skipSQLRegion(stmt, i); ok {
			i = end
			continue
		}
		switch stmt[i] {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth <= 0 {
				return true
			}
		}
		i++
	}
	return false
}

// trimLeadingSpaceAndComments drops leading whitespace and comments from s.
func trimLeadingSpaceAndComments(s string) string {
	for {
		s = strings.TrimLeft(s, " \t\r\n\f")
		if !strings.HasPrefix(s, "--") && !strings.HasPrefix(s, "/*") {
			return s
		}
		end, _ := skipSQLRegion(s, 0)
		s = s[end:]
	}
}

// skipSQLRegion reports, for a position that opens a comment, string, quoted
// identifier or dollar-quoted body, the index just past it. An unterminated region
// runs to the end of src.
func skipSQLRegion(src string, i int) (end int, ok bool) {
	switch {
	case strings.HasPrefix(src[i:], "--"):
		return skipLineComment(src, i), true
	case strings.HasPrefix(src[i:], "/*"):
		return skipBlockComment(src, i), true
	case src[i] == '\'':
		return skipQuoted(src, i, isEscapeStringStart(src, i)), true
	case src[i] == '"':
		return skipQuoted(src, i, false), true
	case src[i] == '$':
		return skipDollarQuoted(src, i)
	}
	return 0, false
}

// skipLineComment returns the index of the newline that ends the comment at src[i].
func skipLineComment(src string, i int) int {
	if nl := strings.IndexByte(src[i:], '\n'); nl >= 0 {
		return i + nl
	}
	return len(src)
}

// skipBlockComment returns the index past the comment at src[i]. Block comments
// nest in Postgres.
func skipBlockComment(src string, i int) int {
	depth, j := 1, i+2
	for j < len(src) && depth > 0 {
		switch {
		case strings.HasPrefix(src[j:], "/*"):
			depth++
			j += 2
		case strings.HasPrefix(src[j:], "*/"):
			depth--
			j += 2
		default:
			j++
		}
	}
	return j
}

// skipDollarQuoted returns the index past the dollar-quoted body opened at src[i],
// or false when src[i] does not open one (a parameter such as $1, or a $ inside an
// identifier).
func skipDollarQuoted(src string, i int) (end int, ok bool) {
	if i > 0 && isIdentByte(src[i-1]) {
		return 0, false
	}
	tag := pgDollarTagRe.FindString(src[i:])
	if tag == "" {
		return 0, false
	}
	k := strings.Index(src[i+len(tag):], tag)
	if k < 0 {
		return len(src), true
	}
	return i + len(tag) + k + len(tag), true
}

// pgDollarTagRe matches the opening tag of a dollar-quoted body. A parameter such as
// $1 is not a tag.
var pgDollarTagRe = regexp.MustCompile(`^\$(?:[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*)?\$`)

// skipQuoted returns the index past the quote opened at src[i]. A doubled quote
// character stays inside the region; backslash escapes the next byte only in an
// E'...' string.
func skipQuoted(src string, i int, backslashEscapes bool) int {
	q := src[i]
	for j := i + 1; j < len(src); j++ {
		switch {
		case backslashEscapes && src[j] == '\\':
			j++
		case src[j] == q:
			if j+1 < len(src) && src[j+1] == q {
				j++
				continue
			}
			return j + 1
		}
	}
	return len(src)
}

// isEscapeStringStart reports whether the quote at src[i] opens an E'...' string.
func isEscapeStringStart(src string, i int) bool {
	if i == 0 || (src[i-1] != 'E' && src[i-1] != 'e') {
		return false
	}
	return i == 1 || !isIdentByte(src[i-2])
}

func isIdentByte(c byte) bool {
	return c == '_' || c == '$' || c >= 0x80 ||
		(c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
