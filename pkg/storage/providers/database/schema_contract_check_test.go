// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package database

// Static contract check (Epic #5978, zero-downtime schema evolution, N / N-1).
//
// The rule: a statement that removes, renames or narrows a schema object (DROP TABLE,
// DROP COLUMN, DROP CONSTRAINT, DROP INDEX, TRUNCATE, a rename, ALTER COLUMN ... TYPE,
// SET NOT NULL, ...) breaks the previous release running beside this one, so it may
// only ship as a declared contract step that names the schema version where the old
// shape stopped being used:
//
//   - Go: the statement is a string element of the Statements field of a ContractStep
//     composite literal whose UnusedSince is an integer literal with
//     1 <= UnusedSince < Version <= SchemaVersion.
//   - SQL (migrations/*.sql): the statement is immediately preceded by the comment
//     line "-- schema:contract unused-since=<n>" with 1 <= n < SchemaVersion.
//
// Every non-test .go file of the package and every migrations/*.sql file is scanned.
// Statements in _test.go files are not.
//
// Grandfathering: testdata/destructive_baseline.txt lists, exactly, the flagged
// statements that existed before this check. A flagged statement that matches a line
// is allowed. The list may only shrink: a line that matches no statement fails the
// check, and adding a line is a reviewed exception (its header says so). A moved or
// edited baseline statement is a new statement and needs a contract marker.
//
// Not flagged: DROP POLICY (the idempotent policy re-create pattern) and everything
// inside the function DropAllTables (test and clean-reinstall support).
//
// The classifier anchors on the start of a statement, so a literal that merely
// mentions DDL keywords (a regexp, an error message) is not a statement. A DO block is
// classified by the statements in its body, best effort: a statement composed at run
// time (EXECUTE of a built string) is not visible to a static check.
//
// collectSchemaStatements and splitStatements are shared with the lock-hazard check
// (the next story in the epic), which classifies the same statements.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	destructiveBaselinePath = "testdata/destructive_baseline.txt"
	// dropAllTablesFunc is exempt: test and clean-reinstall support with no non-test caller.
	dropAllTablesFunc = "DropAllTables"
)

// contractContext describes the ContractStep literal a Go statement sits in.
type contractContext struct {
	version, unusedSince      int
	versionIsLit, unusedIsLit bool
}

// schemaStatement is one SQL statement found in the package.
type schemaStatement struct {
	File string // path relative to the package directory, slash separated
	Func string // enclosing Go function name, "-" outside a function and for SQL files
	Line int
	Text string // comments stripped, whitespace collapsed, no trailing semicolon
	// Marker is the comment line immediately above the statement in a SQL file ("" if none).
	Marker string
	// Contract is set when a Go statement is an element of a ContractStep's Statements.
	Contract *contractContext
}

// ---- statement splitter ----------------------------------------------------

var dollarTagRe = regexp.MustCompile(`^\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$`)

// splitStatements splits SQL text into statements at top-level semicolons. It skips
// line and block comments, single-quoted strings, double-quoted identifiers and
// dollar-quoted bodies, so a semicolon inside any of them does not split. Marker is
// set from a comment line that sits on the line directly above the statement.
// File and Func are left for the caller.
func splitStatements(src string) []schemaStatement {
	var out []schemaStatement
	var cur strings.Builder
	line := 1
	curLine := 0
	lastComment, lastCommentLine, marker := "", 0, ""
	lineHasCode := false

	flush := func() {
		text := strings.Join(strings.Fields(cur.String()), " ")
		if text != "" {
			out = append(out, schemaStatement{Func: "-", Line: curLine, Text: text, Marker: marker})
		}
		cur.Reset()
		marker, lastComment = "", ""
	}
	start := func() {
		if strings.TrimSpace(cur.String()) == "" {
			curLine = line
			marker = ""
			if lastComment != "" && lastCommentLine == line-1 {
				marker = lastComment
			}
			lastComment = ""
		}
	}
	// copyTo copies src[i:end) into the statement and advances the line count.
	copyTo := func(i, end int) {
		seg := src[i:end]
		cur.WriteString(seg)
		line += strings.Count(seg, "\n")
	}

	for i := 0; i < len(src); {
		c := src[i]
		switch {
		case c == '\n':
			line++
			lineHasCode = false
			cur.WriteByte('\n')
			i++
		case c == ' ' || c == '\t' || c == '\r':
			cur.WriteByte(' ')
			i++
		case strings.HasPrefix(src[i:], "--"):
			end := strings.IndexByte(src[i:], '\n')
			if end < 0 {
				end = len(src)
			} else {
				end += i
			}
			if !lineHasCode && strings.TrimSpace(cur.String()) == "" {
				lastComment, lastCommentLine = strings.TrimSpace(src[i:end]), line
			}
			cur.WriteByte(' ')
			i = end
		case strings.HasPrefix(src[i:], "/*"):
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
			line += strings.Count(src[i:j], "\n")
			cur.WriteByte(' ')
			i = j
		case c == ';':
			flush()
			lineHasCode = true
			i++
		case c == '\'' || c == '"':
			start()
			lineHasCode = true
			j := i + 1
			for j < len(src) {
				if src[j] == c {
					if j+1 < len(src) && src[j+1] == c { // doubled quote
						j += 2
						continue
					}
					j++
					break
				}
				j++
			}
			copyTo(i, min(j, len(src)))
			i = min(j, len(src))
		case c == '$' && dollarTagRe.MatchString(src[i:]):
			start()
			lineHasCode = true
			tag := dollarTagRe.FindString(src[i:])
			j := len(src)
			if k := strings.Index(src[i+len(tag):], tag); k >= 0 {
				j = i + len(tag) + k + len(tag)
			}
			copyTo(i, j)
			i = j
		default:
			start()
			lineHasCode = true
			cur.WriteByte(c)
			i++
		}
	}
	flush()
	return out
}

// ---- collector -------------------------------------------------------------

// collectSchemaStatements returns every SQL statement in one file: for a .go file,
// every string literal (constant concatenations folded into one) split into
// statements; for a .sql file, the file text split into statements. name is the
// slash-separated path relative to the package directory.
func collectSchemaStatements(name string, src []byte) ([]schemaStatement, error) {
	if strings.HasSuffix(name, ".sql") {
		stmts := splitStatements(string(src))
		for i := range stmts {
			stmts[i].File = name
		}
		return stmts, nil
	}
	return collectGoStatements(name, src)
}

func collectGoStatements(name string, src []byte) ([]schemaStatement, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, name, src, 0)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", name, err)
	}
	contexts := contractStatementContexts(f)

	var out []schemaStatement
	for _, decl := range f.Decls {
		fn := "-"
		if fd, ok := decl.(*ast.FuncDecl); ok {
			fn = fd.Name.Name
		}
		ast.Inspect(decl, func(n ast.Node) bool {
			e, ok := n.(ast.Expr)
			if !ok {
				return true
			}
			val, ok := constString(e)
			if !ok {
				return true
			}
			line := fset.Position(e.Pos()).Line
			for _, st := range splitStatements(val) {
				st.File, st.Func, st.Line, st.Marker = name, fn, line, ""
				st.Contract = contexts[e]
				out = append(out, st)
			}
			return false
		})
	}
	return out, nil
}

// constString folds a string literal, or a concatenation of them, into its value.
func constString(e ast.Expr) (string, bool) {
	switch x := e.(type) {
	case *ast.BasicLit:
		if x.Kind != token.STRING {
			return "", false
		}
		v, err := strconv.Unquote(x.Value)
		return v, err == nil
	case *ast.ParenExpr:
		return constString(x.X)
	case *ast.BinaryExpr:
		if x.Op != token.ADD {
			return "", false
		}
		l, lok := constString(x.X)
		r, rok := constString(x.Y)
		return l + r, lok && rok
	}
	return "", false
}

func isIdent(e ast.Expr, name string) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == name
}

func intLiteral(e ast.Expr) (int, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.INT {
		return 0, false
	}
	n, err := strconv.Atoi(lit.Value)
	return n, err == nil
}

// contractStatementContexts maps every string element of the Statements field of a
// ContractStep literal (typed, &-taken, or an element with the type elided from a
// []ContractStep or []*ContractStep literal) to that step's version and marker.
func contractStatementContexts(f *ast.File) map[ast.Expr]*contractContext {
	out := map[ast.Expr]*contractContext{}
	register := func(step *ast.CompositeLit) {
		cc := &contractContext{}
		var statements ast.Expr
		for _, elt := range step.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			switch {
			case isIdent(kv.Key, "Version"):
				cc.version, cc.versionIsLit = intLiteral(kv.Value)
			case isIdent(kv.Key, "UnusedSince"):
				cc.unusedSince, cc.unusedIsLit = intLiteral(kv.Value)
			case isIdent(kv.Key, "Statements"):
				statements = kv.Value
			}
		}
		if lit, ok := statements.(*ast.CompositeLit); ok {
			for _, elt := range lit.Elts {
				out[elt] = cc
			}
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		cl, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		if isIdent(cl.Type, "ContractStep") {
			register(cl)
			return true
		}
		if at, ok := cl.Type.(*ast.ArrayType); ok {
			elem := at.Elt
			if star, ok := elem.(*ast.StarExpr); ok {
				elem = star.X
			}
			if isIdent(elem, "ContractStep") {
				for _, elt := range cl.Elts {
					if inner, ok := elt.(*ast.CompositeLit); ok && inner.Type == nil {
						register(inner)
					}
				}
			}
		}
		return true
	})
	return out
}

// ---- classifier ------------------------------------------------------------

var (
	dropObjectRe = regexp.MustCompile(`(?i)^DROP\s+(?:TABLE|VIEW|MATERIALIZED\s+VIEW|INDEX|TRIGGER|FUNCTION|PROCEDURE|AGGREGATE|TYPE|DOMAIN|SCHEMA|SEQUENCE|EXTENSION|RULE)\b`)
	truncateRe   = regexp.MustCompile(`(?i)^TRUNCATE\b`)
	alterRe      = regexp.MustCompile(`(?i)^ALTER\s+(?:TABLE|INDEX|VIEW|MATERIALIZED\s+VIEW|TYPE|DOMAIN|SEQUENCE|SCHEMA|FUNCTION)\b`)
	renameRe     = regexp.MustCompile(`(?i)\bRENAME\b`)
	alterTypeRe  = regexp.MustCompile(`(?i)\bALTER\s+(?:COLUMN\s+)?(?:"[^"]+"|\w+)\s+(?:SET\s+DATA\s+)?TYPE\b`)
	setNotNullRe = regexp.MustCompile(`(?i)\bSET\s+NOT\s+NULL\b`)
	dropClauseRe = regexp.MustCompile(`(?i)\bDROP\s+("[^"]*"|\w+)(?:\s+(\w+))?`)
	quotedStrRe  = regexp.MustCompile(`'(?:[^']|'')*'`)
	doStmtRe     = regexp.MustCompile(`(?i)^DO\b`)
	plpgsqlLead  = regexp.MustCompile(`(?is)^(?:BEGIN|DECLARE|ELSE|ELSIF\b.*?\bTHEN|IF\b.*?\bTHEN|THEN|LOOP|EXCEPTION|WHEN\b.*?\bTHEN)\s+`)
)

// isDestructiveStatement reports whether text (a normalised statement) removes,
// renames or narrows a schema object. DROP POLICY is not flagged.
func isDestructiveStatement(text string) bool {
	text = strings.TrimSpace(text)
	switch {
	case dropObjectRe.MatchString(text), truncateRe.MatchString(text):
		return true
	case doStmtRe.MatchString(text):
		return doBodyIsDestructive(text)
	case alterRe.MatchString(text):
		return alterIsDestructive(quotedStrRe.ReplaceAllString(text, "''"))
	}
	return false
}

func alterIsDestructive(text string) bool {
	if renameRe.MatchString(text) || alterTypeRe.MatchString(text) || setNotNullRe.MatchString(text) {
		return true
	}
	for _, m := range dropClauseRe.FindAllStringSubmatch(text, -1) {
		first, second := strings.ToUpper(m[1]), strings.ToUpper(m[2])
		switch {
		case first == "NOT" && second == "NULL":
		case first == "DEFAULT", first == "IDENTITY", first == "EXPRESSION":
		default: // COLUMN, CONSTRAINT, IF EXISTS <col>, ATTRIBUTE or a bare column name
			return true
		}
	}
	return false
}

// doBodyIsDestructive classifies the statements of a DO block's dollar-quoted body.
func doBodyIsDestructive(text string) bool {
	dollar := strings.Index(text, "$")
	if dollar < 0 {
		return false
	}
	tag := dollarTagRe.FindString(text[dollar:])
	if tag == "" {
		return false
	}
	open := dollar
	end := strings.LastIndex(text, tag)
	if end <= open {
		return false
	}
	for _, st := range splitStatements(text[open+len(tag) : end]) {
		inner := st.Text
		for {
			trimmed := plpgsqlLead.ReplaceAllString(inner, "")
			if trimmed == inner {
				break
			}
			inner = trimmed
		}
		if isDestructiveStatement(inner) {
			return true
		}
	}
	return false
}

var sqlMarkerRe = regexp.MustCompile(`^--\s*schema:contract\s+unused-since=(\d+)\s*$`)

// baselineKey is the identity of a grandfathered statement.
func baselineKey(st schemaStatement) string {
	return st.File + "|" + st.Func + "|" + st.Text
}

// contractProblem returns why a flagged statement's declared contract is not valid, or
// "" when it is valid. ceiling is the schema version of the build.
func contractProblem(st schemaStatement, ceiling int) string {
	if c := st.Contract; c != nil {
		switch {
		case !c.unusedIsLit:
			return "its ContractStep has no UnusedSince, or UnusedSince is not an integer literal"
		case !c.versionIsLit:
			return "its ContractStep has no Version, or Version is not an integer literal"
		case c.unusedSince < 1 || c.unusedSince >= c.version || c.version > ceiling:
			return fmt.Sprintf("its ContractStep must satisfy 1 <= UnusedSince < Version <= SchemaVersion, got UnusedSince %d, Version %d, SchemaVersion %d",
				c.unusedSince, c.version, ceiling)
		}
		return ""
	}
	if strings.HasSuffix(st.File, ".sql") && st.Marker != "" {
		m := sqlMarkerRe.FindStringSubmatch(st.Marker)
		if m == nil {
			return fmt.Sprintf("its preceding comment %q is not a %q line", st.Marker, "-- schema:contract unused-since=<n>")
		}
		n, _ := strconv.Atoi(m[1])
		if n < 1 || n >= ceiling {
			return fmt.Sprintf("its marker unused-since=%d must satisfy 1 <= n < SchemaVersion (%d)", n, ceiling)
		}
		return ""
	}
	if strings.HasSuffix(st.File, ".sql") {
		return `it has no preceding "-- schema:contract unused-since=<n>" comment`
	}
	return "it is not an element of a ContractStep's Statements"
}

// checkSchemaStatements returns one problem per flagged statement that is neither a
// valid contract step nor grandfathered, and one per baseline line that matches no
// statement. ceiling is the version ceiling: the tree check passes SchemaVersion.
func checkSchemaStatements(stmts []schemaStatement, baseline []string, ceiling int) []string {
	inBaseline := map[string]bool{}
	for _, b := range baseline {
		inBaseline[b] = false
	}
	var problems []string
	for _, st := range stmts {
		if st.Func == dropAllTablesFunc && !strings.HasSuffix(st.File, ".sql") {
			continue
		}
		if !isDestructiveStatement(st.Text) {
			continue
		}
		key := baselineKey(st)
		_, grandfathered := inBaseline[key]
		if grandfathered {
			inBaseline[key] = true
		}
		problem := contractProblem(st, ceiling)
		if problem == "" || grandfathered {
			continue
		}
		problems = append(problems, fmt.Sprintf("%s:%d: %q removes, renames or narrows schema and is not a valid contract step: %s",
			st.File, st.Line, st.Text, problem))
	}
	for _, b := range baseline {
		if !inBaseline[b] {
			problems = append(problems, fmt.Sprintf("baseline line %q matches no statement in the tree; remove it", b))
		}
	}
	sort.Strings(problems)
	return problems
}

// ---- baseline file ---------------------------------------------------------

// parseBaseline returns the entries of a baseline file, skipping blank and # lines.
func parseBaseline(content string) []string {
	var out []string
	for _, l := range strings.Split(content, "\n") {
		l = strings.TrimRight(l, "\r")
		if strings.TrimSpace(l) == "" || strings.HasPrefix(l, "#") {
			continue
		}
		out = append(out, l)
	}
	return out
}

// baselineHeaderProblem returns "" when the file starts with a comment header that
// says entries may only be removed and that adding one is a reviewed exception.
func baselineHeaderProblem(content string) string {
	if !strings.HasPrefix(content, "#") {
		return "the baseline file must start with a # header comment"
	}
	var header []string
	for _, l := range strings.Split(content, "\n") {
		if !strings.HasPrefix(l, "#") {
			break
		}
		header = append(header, l)
	}
	text := strings.ToLower(strings.Join(header, " "))
	text = strings.Join(strings.Fields(strings.ReplaceAll(text, "#", " ")), " ")
	for _, want := range []string{"may only shrink", "may only be removed", "reviewed exception"} {
		if !strings.Contains(text, want) {
			return fmt.Sprintf("the baseline header must state %q", want)
		}
	}
	return ""
}

// ---- tree scan -------------------------------------------------------------

func collectPackageStatements(t *testing.T) []schemaStatement {
	t.Helper()
	var files []string
	goFiles, err := filepath.Glob("*.go")
	require.NoError(t, err)
	for _, f := range goFiles {
		if !strings.HasSuffix(f, "_test.go") {
			files = append(files, f)
		}
	}
	sqlFiles, err := filepath.Glob("migrations/*.sql")
	require.NoError(t, err)
	files = append(files, sqlFiles...)
	require.NotEmpty(t, goFiles, "no Go files found: the test must run in the package directory")
	require.NotEmpty(t, sqlFiles, "no migrations found")

	var all []schemaStatement
	for _, f := range files {
		src, err := os.ReadFile(f)
		require.NoError(t, err)
		stmts, err := collectSchemaStatements(filepath.ToSlash(f), src)
		require.NoError(t, err)
		all = append(all, stmts...)
	}
	return all
}

func readBaseline(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(destructiveBaselinePath)
	require.NoError(t, err)
	return string(b)
}

// ---- self-test helpers -----------------------------------------------------

const testCeiling = 5 // with SchemaVersion = 1 no step can satisfy UnusedSince < Version <= 1

func goFile(body string) []byte {
	return []byte("package database\n\n" + body + "\n")
}

func checkGo(t *testing.T, body string, baseline ...string) []string {
	t.Helper()
	stmts, err := collectSchemaStatements("x.go", goFile(body))
	require.NoError(t, err)
	return checkSchemaStatements(stmts, baseline, testCeiling)
}

func checkSQL(t *testing.T, src string) []string {
	t.Helper()
	stmts, err := collectSchemaStatements("migrations/099_x.sql", []byte(src))
	require.NoError(t, err)
	return checkSchemaStatements(stmts, nil, testCeiling)
}

func inFunc(stmt string) string {
	return "func f() { _ = `" + stmt + "` }"
}

// ---- required tests --------------------------------------------------------

func TestSchemaContractCheck_CurrentTreePasses(t *testing.T) {
	baseline := parseBaseline(readBaseline(t))
	assert.Equal(t, []string{
		"schemas.go|CreateRateCountersTable|ALTER TABLE cfgms_rate_counters ALTER COLUMN expires_at SET NOT NULL",
		"schemas.go|CreateStewardRecordsTable|DROP INDEX IF EXISTS uq_steward_records_tenant_device",
		"schemas.go|dropSingleColumnRegistrationClaimKey|DROP TABLE cfgms_registration_token_claims",
	}, sortedStrings(baseline), "the baseline holds exactly the statements that predate the check")

	stmts := collectPackageStatements(t)
	assert.Empty(t, checkSchemaStatements(stmts, baseline, SchemaVersion))
}

func sortedStrings(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func TestSchemaContractCheck_IgnoresKeywordMentionsInRegexps(t *testing.T) {
	problems := checkGo(t, `
var re = regexp.MustCompile("(?is)^\\s*alter\\s+table")
var re2 = regexp.MustCompile(`+"`(?i)drop\\s+table|truncate\\s+table|rename\\s+to`"+`)
var msg = "failed to drop table: schema is read-only"
var msg2 = "cannot truncate or rename the file"
var ok = "ALTER TABLE t ADD COLUMN c TEXT"
`)
	assert.Empty(t, problems)

	// A statement that does start with the keywords is still found.
	assert.NotEmpty(t, checkGo(t, inFunc("DROP TABLE t")))
}

func TestSchemaContractCheck_RejectsUnmarkedDestructiveGo(t *testing.T) {
	cases := map[string]string{
		"drop table":                "DROP TABLE t",
		"drop table if exists":      "DROP TABLE IF EXISTS t",
		"lower case":                "drop table t",
		"whitespace":                "  DROP\n\tTABLE   t  ",
		"drop column":               "ALTER TABLE t DROP COLUMN c",
		"drop column if exists":     "ALTER TABLE t DROP COLUMN IF EXISTS c",
		"drop col without COLUMN":   "ALTER TABLE t DROP c",
		"drop col IF EXISTS no COL": "ALTER TABLE IF EXISTS t DROP IF EXISTS c",
		"drop constraint":           "ALTER TABLE t DROP CONSTRAINT k",
		"drop index":                "DROP INDEX idx",
		"drop index concurrently":   "DROP INDEX CONCURRENTLY IF EXISTS idx",
		"drop view":                 "DROP VIEW v",
		"drop materialized view":    "DROP MATERIALIZED VIEW IF EXISTS v",
		"drop trigger":              "DROP TRIGGER IF EXISTS trg ON t",
		"drop function":             "DROP FUNCTION IF EXISTS fn(int)",
		"drop type":                 "DROP TYPE ty",
		"drop schema":               "DROP SCHEMA s CASCADE",
		"truncate":                  "TRUNCATE t",
		"truncate table":            "TRUNCATE TABLE t RESTART IDENTITY",
		"rename table":              "ALTER TABLE t RENAME TO u",
		"rename column":             "ALTER TABLE t RENAME COLUMN a TO b",
		"rename column no COLUMN":   "ALTER TABLE t RENAME a TO b",
		"rename constraint":         "ALTER TABLE t RENAME CONSTRAINT a TO b",
		"rename index":              "ALTER INDEX i RENAME TO j",
		"rename enum value":         "ALTER TYPE ty RENAME VALUE 'a' TO 'b'",
		"alter type":                "ALTER TABLE t ALTER COLUMN c TYPE BIGINT",
		"alter set data type":       "ALTER TABLE t ALTER COLUMN c SET DATA TYPE BIGINT",
		"alter no COLUMN":           "ALTER TABLE t ALTER c TYPE BIGINT",
		"set not null":              "ALTER TABLE t ALTER COLUMN c SET NOT NULL",
		"in a multi-action alter":   "ALTER TABLE t ADD COLUMN a INT, DROP COLUMN b",
		"after a harmless one":      "SELECT 1; DROP TABLE t",
		"in a DO block":             "DO $$ BEGIN IF EXISTS (SELECT 1) THEN ALTER TABLE t DROP COLUMN c; END IF; END $$",
	}
	for name, stmt := range cases {
		t.Run(name, func(t *testing.T) {
			problems := checkGo(t, inFunc(stmt))
			require.Len(t, problems, 1, "statement %q", stmt)
			assert.Contains(t, problems[0], "not a valid contract step")
		})
	}

	t.Run("interpreted string literal and concatenation", func(t *testing.T) {
		assert.Len(t, checkGo(t, `func f() { _ = "DROP TABLE t" }`), 1)
		assert.Len(t, checkGo(t, `func f() { _ = "DROP " + "TABLE t" }`), 1)
		assert.Len(t, checkGo(t, `func f(n string) { _ = "DROP TABLE " + n }`), 1)
	})
	t.Run("package-level variable", func(t *testing.T) {
		assert.Len(t, checkGo(t, "var q = `ALTER TABLE t DROP COLUMN c`"), 1)
	})
	t.Run("method", func(t *testing.T) {
		assert.Len(t, checkGo(t, "func (s S) Drop() { _ = `DROP TABLE t` }"), 1)
	})
	t.Run("not in a ContractStep Statements field", func(t *testing.T) {
		assert.Len(t, checkGo(t, "var s = []string{`DROP TABLE t`}"), 1)
		assert.Len(t, checkGo(t, "var s = ContractStep{Version: 3, UnusedSince: 2, Description: `DROP TABLE t`}"), 1)
		assert.Len(t, checkGo(t, "var s = ContractStep{Version: 3, UnusedSince: 2, Statements: stmts}"), 0, "a non-literal list holds no statement text")
	})
	t.Run("harmless statements pass", func(t *testing.T) {
		assert.Empty(t, checkGo(t, inFunc("ALTER TABLE t ADD COLUMN c TEXT; ALTER TABLE t ALTER COLUMN c DROP NOT NULL; ALTER TABLE t ALTER COLUMN c SET DEFAULT 'drop it'; ALTER TABLE t ALTER COLUMN c DROP DEFAULT; CREATE INDEX IF NOT EXISTS i ON t(c); UPDATE t SET c = 'x'; DELETE FROM t")))
	})
	t.Run("keywords inside quotes do not split or flag", func(t *testing.T) {
		assert.Empty(t, checkGo(t, inFunc("INSERT INTO t VALUES ('a; DROP TABLE x')")))
	})
}

func TestSchemaContractCheck_AcceptsValidContractStep(t *testing.T) {
	assert.Empty(t, checkGo(t, "var steps = []ContractStep{{Version: 3, UnusedSince: 2, Statements: []string{`ALTER TABLE t DROP COLUMN c`, `DROP INDEX idx`}}}"),
		"element type elided from the slice literal")
	assert.Empty(t, checkGo(t, "var s = ContractStep{Version: 2, UnusedSince: 1, Statements: []string{`DROP TABLE t`}}"))
	assert.Empty(t, checkGo(t, "var s = &ContractStep{Version: 5, UnusedSince: 4, Statements: []string{`TRUNCATE t`}}"), "Version equal to the ceiling")
	assert.Empty(t, checkGo(t, "var s = []*ContractStep{{Version: 4, UnusedSince: 1, Statements: []string{\"ALTER TABLE t RENAME TO u\"}}}"))
	assert.Empty(t, checkGo(t, "func f() []ContractStep { return []ContractStep{{Version: 3, UnusedSince: 2, Statements: []string{`ALTER TABLE t ALTER COLUMN c SET NOT NULL`}}} }"))
}

func TestSchemaContractCheck_RejectsInvalidUnusedSince(t *testing.T) {
	step := func(fields string) string {
		return "var s = ContractStep{" + fields + ", Statements: []string{`DROP TABLE t`}}"
	}
	cases := map[string]string{
		"equal to Version":          step("Version: 3, UnusedSince: 3"),
		"above Version":             step("Version: 3, UnusedSince: 4"),
		"zero":                      step("Version: 3, UnusedSince: 0"),
		"missing":                   step("Version: 3"),
		"non-literal":               step("Version: 3, UnusedSince: someConst"),
		"expression":                step("Version: 3, UnusedSince: 1 + 1"),
		"Version above the ceiling": step("Version: 6, UnusedSince: 2"),
		"Version missing":           step("UnusedSince: 2"),
		"Version non-literal":       step("Version: v, UnusedSince: 2"),
		"unkeyed literal":           "var s = ContractStep{3, 2, \"d\", []string{`DROP TABLE t`}}",
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			problems := checkGo(t, src)
			// An unkeyed literal's statements are not recognisable as a Statements field,
			// so the statement is simply unmarked; either way the check fails.
			require.Len(t, problems, 1, src)
		})
	}
	problems := checkGo(t, step("Version: 3, UnusedSince: 3"))
	assert.Contains(t, problems[0], "UnusedSince")

	t.Run("a grandfathered statement is allowed whatever its step says", func(t *testing.T) {
		assert.Empty(t, checkGo(t, step("Version: 3, UnusedSince: 3"), "x.go|-|DROP TABLE t"))
	})
}

func TestSchemaContractCheck_SQLMarkerRequired(t *testing.T) {
	t.Run("unmarked fails", func(t *testing.T) {
		problems := checkSQL(t, "ALTER TABLE t DROP COLUMN c;\n")
		require.Len(t, problems, 1)
		assert.Contains(t, problems[0], "schema:contract unused-since")
	})
	t.Run("valid marker passes", func(t *testing.T) {
		assert.Empty(t, checkSQL(t, "-- schema:contract unused-since=2\nALTER TABLE t DROP COLUMN c;\n"))
		assert.Empty(t, checkSQL(t, "CREATE TABLE t (c INT);\n\n-- schema:contract unused-since=4\nDROP TABLE t;\n"))
		assert.Empty(t, checkSQL(t, "-- schema:contract   unused-since=1\nTRUNCATE t;"))
	})
	t.Run("marker applies to the next statement only", func(t *testing.T) {
		problems := checkSQL(t, "-- schema:contract unused-since=2\nDROP TABLE a;\nDROP TABLE b;\n")
		require.Len(t, problems, 1)
		assert.Contains(t, problems[0], `"DROP TABLE b"`)
	})
	t.Run("marker must be immediately above", func(t *testing.T) {
		assert.Len(t, checkSQL(t, "-- schema:contract unused-since=2\n\nDROP TABLE a;\n"), 1, "blank line between")
		assert.Len(t, checkSQL(t, "-- schema:contract unused-since=2\n-- why\nDROP TABLE a;\n"), 1, "another comment between")
	})
	t.Run("invalid marker values fail", func(t *testing.T) {
		assert.Len(t, checkSQL(t, "-- schema:contract unused-since=0\nDROP TABLE a;"), 1)
		assert.Len(t, checkSQL(t, "-- schema:contract unused-since=5\nDROP TABLE a;"), 1, "n must be below the ceiling")
		assert.Len(t, checkSQL(t, "-- schema:contract unused-since=x\nDROP TABLE a;"), 1)
		assert.Len(t, checkSQL(t, "-- schema:contract\nDROP TABLE a;"), 1)
		assert.Len(t, checkSQL(t, "-- unrelated comment\nDROP TABLE a;"), 1)
	})
	t.Run("a marker on a non-destructive statement is harmless", func(t *testing.T) {
		assert.Empty(t, checkSQL(t, "-- schema:contract unused-since=9\nCREATE TABLE t (c INT);"))
	})
	t.Run("Go marker comments do not count", func(t *testing.T) {
		src := "package database\n\nfunc f() {\n\t// schema:contract unused-since=2\n\t_ = `DROP TABLE t`\n}\n"
		stmts, err := collectSchemaStatements("x.go", []byte(src))
		require.NoError(t, err)
		assert.Len(t, checkSchemaStatements(stmts, nil, testCeiling), 1)
	})
	t.Run("DROP POLICY and DO blocks", func(t *testing.T) {
		assert.Empty(t, checkSQL(t, "DROP POLICY IF EXISTS p ON t;\nDO $$\nBEGIN\n\tIF NOT EXISTS (SELECT 1) THEN\n\t\tCREATE ROLE r NOLOGIN;\n\tEND IF;\nEND\n$$;\n"))
		assert.Len(t, checkSQL(t, "DO $$ BEGIN DROP TABLE t; END $$;"), 1)
	})
}

func TestSchemaContractCheck_BaselineMayOnlyShrink(t *testing.T) {
	src := inFunc("DROP TABLE t")
	live := "x.go|f|DROP TABLE t"

	t.Run("matching line grandfathers the statement", func(t *testing.T) {
		assert.Empty(t, checkGo(t, src, live))
	})
	t.Run("a line matching no statement fails", func(t *testing.T) {
		problems := checkGo(t, src, live, "x.go|f|DROP TABLE gone")
		require.Len(t, problems, 1)
		assert.Contains(t, problems[0], "matches no statement")
		assert.Contains(t, problems[0], "DROP TABLE gone")
	})
	t.Run("a stale line fails even when nothing is flagged", func(t *testing.T) {
		assert.Len(t, checkGo(t, inFunc("SELECT 1"), live), 1)
	})
	t.Run("an edited statement is new", func(t *testing.T) {
		problems := checkGo(t, inFunc("DROP TABLE t2"), live)
		require.Len(t, problems, 2, "the edited statement is unmarked and the old line is stale")
	})
	t.Run("a moved statement is new", func(t *testing.T) {
		problems := checkGo(t, "func g() { _ = `DROP TABLE t` }", live)
		require.Len(t, problems, 2)
	})
	t.Run("a second copy of a baseline statement is allowed only through the same line", func(t *testing.T) {
		// Same file, function and text: identical identity, so both match the line.
		assert.Empty(t, checkGo(t, "func f() { _ = `DROP TABLE t`; _ = `DROP TABLE t` }", live))
	})
	t.Run("an empty baseline is valid", func(t *testing.T) {
		assert.Empty(t, checkGo(t, inFunc("SELECT 1")))
	})
	t.Run("parseBaseline skips header and blank lines", func(t *testing.T) {
		assert.Equal(t, []string{"a|b|c", "d|-|e"}, parseBaseline("# header\n\n   \na|b|c\r\n# another\nd|-|e"))
	})
}

func TestSchemaContractCheck_ExemptsDropAllTablesAndDropPolicy(t *testing.T) {
	t.Run("DropAllTables is exempt, including a new table", func(t *testing.T) {
		assert.Empty(t, checkGo(t, `
func (s DatabaseSchemas) DropAllTables(ctx context.Context, db *sql.DB) error {
	dropQueries := []string{
		"DROP MATERIALIZED VIEW IF EXISTS audit_stats;",
		"DROP TABLE IF EXISTS brand_new_table;",
		"DROP TABLE IF EXISTS audit_entries;",
	}
	_ = dropQueries
	_, _ = db.ExecContext(ctx, "TRUNCATE t")
	return nil
}`))
	})
	t.Run("the exemption is the function, not the statement", func(t *testing.T) {
		assert.Len(t, checkGo(t, "func DropMostTables() { _ = `DROP TABLE IF EXISTS t` }"), 1)
		assert.Len(t, checkGo(t, "func Other() { _ = `DROP TABLE IF EXISTS t` }\nfunc DropAllTables() { _ = `DROP TABLE IF EXISTS u` }"), 1)
	})
	t.Run("DropAllTables in a SQL file is not exempt", func(t *testing.T) {
		assert.Len(t, checkSQL(t, "DROP TABLE a;"), 1)
	})
	t.Run("DROP POLICY is not flagged", func(t *testing.T) {
		assert.Empty(t, checkGo(t, inFunc("DROP POLICY IF EXISTS p ON t")))
		assert.Empty(t, checkGo(t, "func f() { _ = \"DROP POLICY p ON t;\" }"))
		assert.Empty(t, checkSQL(t, "DROP POLICY IF EXISTS p ON t;\nCREATE POLICY p ON t USING (true);"))
	})
}

func TestSchemaContractCheck_BaselineHeaderPresent(t *testing.T) {
	assert.Empty(t, baselineHeaderProblem(readBaseline(t)))

	t.Run("detects a missing or incomplete header", func(t *testing.T) {
		assert.NotEmpty(t, baselineHeaderProblem("a|b|c\n"))
		assert.NotEmpty(t, baselineHeaderProblem(""))
		assert.NotEmpty(t, baselineHeaderProblem("# a list\n\na|b|c\n"))
		assert.NotEmpty(t, baselineHeaderProblem("# entries may only be removed\na|b|c\n"), "must also say adding is a reviewed exception")
		assert.NotEmpty(t, baselineHeaderProblem("a|b|c\n# This list may only shrink; entries may only be removed; a reviewed exception\n"), "the header must come first")
		assert.Empty(t, baselineHeaderProblem("# This list may only shrink.\n# Entries may only be removed; adding one is a reviewed exception.\na|b|c\n"))
	})
}

// ---- splitter and collector self-tests -------------------------------------

func TestSplitStatements(t *testing.T) {
	texts := func(src string) []string {
		var out []string
		for _, s := range splitStatements(src) {
			out = append(out, s.Text)
		}
		return out
	}
	assert.Equal(t, []string{"SELECT 1", "SELECT 2"}, texts("SELECT 1; SELECT\n  2;"))
	assert.Equal(t, []string{"SELECT 1"}, texts("-- a comment; with a semicolon\nSELECT 1 -- trailing; comment\n;"))
	assert.Equal(t, []string{"SELECT 1"}, texts("/* block; /* nested; */ still comment; */ SELECT 1;"))
	assert.Equal(t, []string{"INSERT INTO t VALUES ('a;b', 'it''s; ok')"}, texts("INSERT INTO t VALUES ('a;b', 'it''s; ok');"))
	assert.Equal(t, []string{`SELECT "a;b" FROM t`}, texts(`SELECT "a;b" FROM t;`))
	assert.Equal(t, []string{"DO $$ BEGIN PERFORM 1; END $$", "SELECT 2"}, texts("DO $$ BEGIN PERFORM 1; END $$; SELECT 2;"))
	assert.Equal(t, []string{"SELECT $fn$ a; b $fn$", "SELECT 3"}, texts("SELECT $fn$ a; b $fn$; SELECT 3"))
	assert.Equal(t, []string{"SELECT $1, $2"}, texts("SELECT $1, $2;"), "placeholders are not dollar quotes")
	assert.Empty(t, texts("  -- only a comment\n"))
	assert.Empty(t, texts(";;"))
	assert.Equal(t, []string{"SELECT 'unterminated"}, texts("SELECT 'unterminated"))

	t.Run("line numbers and markers", func(t *testing.T) {
		got := splitStatements("-- one\nSELECT 1;\n\n-- schema:contract unused-since=2\nDROP TABLE t;\nSELECT 2 -- x\n")
		require.Len(t, got, 3)
		assert.Equal(t, "-- one", got[0].Marker)
		assert.Equal(t, 2, got[0].Line)
		assert.Equal(t, "-- schema:contract unused-since=2", got[1].Marker)
		assert.Equal(t, 5, got[1].Line)
		assert.Equal(t, "", got[2].Marker)
		assert.Equal(t, 6, got[2].Line)
	})
	t.Run("a trailing comment on the previous line is not a marker", func(t *testing.T) {
		got := splitStatements("SELECT 1; -- schema:contract unused-since=2\nDROP TABLE t;")
		require.Len(t, got, 2)
		assert.Equal(t, "", got[1].Marker)
	})
}

func TestCollectSchemaStatements(t *testing.T) {
	_, err := collectSchemaStatements("bad.go", []byte("package database\nfunc {"))
	assert.Error(t, err)

	stmts, err := collectSchemaStatements("x.go", goFile("var a = `SELECT 1; SELECT 2`\nfunc F() { _ = \"SELECT \" + \"3\" }"))
	require.NoError(t, err)
	require.Len(t, stmts, 3)
	assert.Equal(t, "-", stmts[0].Func)
	assert.Equal(t, "F", stmts[2].Func)
	assert.Equal(t, "SELECT 3", stmts[2].Text)

	sqlStmts, err := collectSchemaStatements("migrations/001.sql", []byte("SELECT 1;"))
	require.NoError(t, err)
	require.Len(t, sqlStmts, 1)
	assert.Equal(t, "migrations/001.sql", sqlStmts[0].File)
}
