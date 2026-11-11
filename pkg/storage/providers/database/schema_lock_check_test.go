// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package database

// Static lock-hazard check (Epic #5978, zero-downtime schema evolution, N / N-1).
//
// During a rolling deploy the previous release keeps serving traffic while this one
// applies its schema changes, so a statement that holds a long lock on a table with
// live traffic blocks the fleet. Two statement shapes do that and have an online form:
//
//   - CREATE [UNIQUE] INDEX takes a lock that blocks writes for the whole build. It
//     must use CONCURRENTLY.
//   - ALTER TABLE ... ADD CONSTRAINT of type FOREIGN KEY or CHECK scans the table while
//     holding a strong lock. It must use NOT VALID (a later, separate statement
//     validates it). ADD CONSTRAINT ... UNIQUE or PRIMARY KEY builds an index under the
//     same lock. It must use USING INDEX on an index built beforehand with CONCURRENTLY.
//
// Every non-test .go file of the package and every migrations/*.sql file is scanned.
// Statements in _test.go files are not.
//
// CONCURRENTLY has its own rules. A string literal that holds several statements runs
// as one implicit transaction, and Postgres refuses CREATE INDEX CONCURRENTLY inside a
// transaction block. A statement containing CONCURRENTLY (CREATE INDEX, DROP INDEX,
// REINDEX, ALTER ...) must therefore be the only statement in its string literal (the
// only statement in its file, for a SQL file), and the function it sits in must not
// have called Begin or BeginTx before it. The check enforces both, and a DO block, which
// always runs in a transaction, cannot hold one.
//
// New tables are exempt. A table created in the same schema version as the statement
// was empty when the statement first ran, so there was nothing to lock. The exemption
// is a comment line directly above the statement literal:
//
//	// schema:new-table <table> since=<n>      (Go; the // may be followed by no space)
//	-- schema:new-table <table> since=<n>      (SQL, on the line before the statement)
//
// The marker is valid only when testdata/table_versions_baseline.txt records <table> at
// version n, n <= SchemaVersion, and the statement's own target table is <table>.
// Because the file's lines are never edited and SchemaVersion only rises, a marker
// never goes stale: a table recorded at version 1 can not be claimed new at version 2.
// A CREATE TABLE whose table has no line in that file fails, so a new table must add a
// line (with the current SchemaVersion) in the same change.
//
// Grandfathering: testdata/lock_hazard_baseline.txt lists, exactly, the flagged
// statements that existed before this check. A flagged statement that matches a line
// is allowed. The list may only shrink: a line that matches no flagged statement fails
// the check, and adding a line is a reviewed exception (its header says so).
//
// The scanner anchors on the start of a statement, so a literal that merely mentions
// DDL keywords (a regexp, an error message) is not a statement. It folds constant
// concatenation within a file ("CREATE INDEX ... " + indexName + " ON ..."), splits
// multi-statement literals, and looks into DO blocks, best effort: a statement composed
// at run time from a non-constant is not visible to a static check.
//
// splitStatements and collectSchemaStatements (SQL files) are shared with the
// destructive-statement check in schema_contract_check_test.go.

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
	lockBaselinePath  = "testdata/lock_hazard_baseline.txt"
	tableVersionsPath = "testdata/table_versions_baseline.txt"
	// existingFlaggedCount is the number of distinct flagged statements on develop when
	// the baseline was frozen: CREATE INDEX statements in schemas.go and migrations/*.sql.
	existingFlaggedCount = 179
)

// lockStatement is a schemaStatement plus what the lock-hazard rules need to know about
// where it sits.
type lockStatement struct {
	schemaStatement
	// Siblings is the number of statements in the same Go string literal, or in the
	// same SQL file, this statement came from.
	Siblings int
	// TxBefore is set when the enclosing Go function called Begin or BeginTx earlier in
	// source order.
	TxBefore bool
}

// ---- collector -------------------------------------------------------------

// collectLockStatements returns every statement of one file. A .sql file is collected
// by collectSchemaStatements. A .go file is parsed here because the rules need more
// than the shared collector keeps: constant operands are folded, the comment line above
// a literal is the exemption marker, and Begin/BeginTx calls are located.
func collectLockStatements(name string, src []byte) ([]lockStatement, error) {
	if strings.HasSuffix(name, ".sql") {
		stmts, err := collectSchemaStatements(name, src)
		if err != nil {
			return nil, err
		}
		out := make([]lockStatement, len(stmts))
		for i, st := range stmts {
			out[i] = lockStatement{schemaStatement: st, Siblings: len(stmts)}
		}
		return out, nil
	}

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, name, src, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", name, err)
	}
	consts := fileStringConsts(f)
	markers := ownLineComments(fset, f, strings.Split(string(src), "\n"))

	var out []lockStatement
	for _, decl := range f.Decls {
		fn := "-"
		var txCalls []token.Pos
		if fd, ok := decl.(*ast.FuncDecl); ok {
			fn = fd.Name.Name
			txCalls = beginCalls(fd)
		}
		ast.Inspect(decl, func(n ast.Node) bool {
			e, ok := n.(ast.Expr)
			if !ok {
				return true
			}
			val, hasLit, ok := foldString(e, consts)
			if !ok || !hasLit {
				return true
			}
			line := fset.Position(e.Pos()).Line
			stmts := splitStatements(val)
			txBefore := false
			for _, p := range txCalls {
				if p < e.Pos() {
					txBefore = true
				}
			}
			for _, st := range stmts {
				st.File, st.Func, st.Line, st.Marker = name, fn, line, markers[line-1]
				out = append(out, lockStatement{schemaStatement: st, Siblings: len(stmts), TxBefore: txBefore})
			}
			return false
		})
	}
	return out, nil
}

// foldString folds a string literal, a constant identifier or a concatenation of them
// into its value. hasLit is false for an expression with no string literal in it (a
// bare identifier), which is not a statement of its own: its declaration is.
func foldString(e ast.Expr, consts map[string]string) (val string, hasLit, ok bool) {
	switch x := e.(type) {
	case *ast.BasicLit:
		if x.Kind != token.STRING {
			return "", false, false
		}
		v, err := strconv.Unquote(x.Value)
		return v, true, err == nil
	case *ast.Ident:
		v, ok := consts[x.Name]
		return v, false, ok
	case *ast.ParenExpr:
		return foldString(x.X, consts)
	case *ast.BinaryExpr:
		if x.Op != token.ADD {
			return "", false, false
		}
		l, llit, lok := foldString(x.X, consts)
		r, rlit, rok := foldString(x.Y, consts)
		return l + r, llit || rlit, lok && rok
	}
	return "", false, false
}

// fileStringConsts resolves the string constants declared anywhere in one file
// (package level or inside a function), including constants built from other constants.
func fileStringConsts(f *ast.File) map[string]string {
	type decl struct {
		name string
		expr ast.Expr
	}
	var decls []decl
	ast.Inspect(f, func(n ast.Node) bool {
		gd, ok := n.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			return true
		}
		for _, spec := range gd.Specs {
			vs := spec.(*ast.ValueSpec)
			if len(vs.Names) != len(vs.Values) {
				continue
			}
			for i, id := range vs.Names {
				decls = append(decls, decl{id.Name, vs.Values[i]})
			}
		}
		return true
	})
	consts := map[string]string{}
	for progress := true; progress; {
		progress = false
		for _, d := range decls {
			if _, done := consts[d.name]; done {
				continue
			}
			if v, _, ok := foldString(d.expr, consts); ok {
				consts[d.name] = v
				progress = true
			}
		}
	}
	return consts
}

// beginCalls returns the position of every Begin or BeginTx call in a function.
func beginCalls(fd *ast.FuncDecl) []token.Pos {
	var out []token.Pos
	ast.Inspect(fd, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := ""
		switch fun := call.Fun.(type) {
		case *ast.SelectorExpr:
			name = fun.Sel.Name
		case *ast.Ident:
			name = fun.Name
		}
		if name == "Begin" || name == "BeginTx" {
			out = append(out, call.Pos())
		}
		return true
	})
	return out
}

// ownLineComments maps a source line to the last comment line of a comment group that
// ends on it, when the comment starts its line. A comment trailing code (a GIN index
// note after a literal) is not a marker for the next literal.
func ownLineComments(fset *token.FileSet, f *ast.File, lines []string) map[int]string {
	out := map[int]string{}
	for _, g := range f.Comments {
		last := g.List[len(g.List)-1]
		pos := fset.Position(last.Pos())
		if pos.Line < 1 || pos.Line > len(lines) || strings.TrimSpace(lines[pos.Line-1][:min(pos.Column-1, len(lines[pos.Line-1]))]) != "" {
			continue
		}
		out[fset.Position(g.End()).Line] = last.Text
	}
	return out
}

// ---- classifier ------------------------------------------------------------

var (
	lockCreateTableRe  = regexp.MustCompile(`(?i)^CREATE\s+(?:(?:GLOBAL\s+|LOCAL\s+)?(?:TEMP|TEMPORARY)\s+|UNLOGGED\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?("[^"]+"|[\w.]+)`)
	lockCreateIndexRe  = regexp.MustCompile(`(?i)^CREATE\s+(?:UNIQUE\s+)?INDEX\s+(CONCURRENTLY\s+)?(?:IF\s+NOT\s+EXISTS\s+)?(?:(?:"[^"]+"|\w+)\s+)?ON\s+(?:ONLY\s+)?("[^"]+"|[\w.]+)`)
	lockAlterTableRe   = regexp.MustCompile(`(?i)^ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?("[^"]+"|[\w.]+)\s+(.*)$`)
	lockAddConstrRe    = regexp.MustCompile(`(?i)^ADD\s+(?:CONSTRAINT\s+(?:"[^"]+"|\w+)\s+)?(CHECK|FOREIGN\s+KEY|UNIQUE|PRIMARY\s+KEY)\b`)
	lockNotValidRe     = regexp.MustCompile(`(?i)\bNOT\s+VALID\b`)
	lockUsingIndexRe   = regexp.MustCompile(`(?i)\bUSING\s+INDEX\s+("[^"]+"|\w+)`)
	lockConcurrentRe   = regexp.MustCompile(`(?i)\bCONCURRENTLY\b`)
	lockConcurrentLead = regexp.MustCompile(`(?i)^(?:CREATE|DROP|REINDEX|ALTER)\b`)
	lockMarkerRe       = regexp.MustCompile(`^(?://|--)\s*schema:new-table\s+(\S+)\s+since=(\d+)\s*$`)
)

// lockHazard is one statement shape that holds a long lock on Table.
type lockHazard struct {
	Table, Reason string
}

// lockFacts is what one statement does that the lock-hazard rules care about.
type lockFacts struct {
	CreatesTables []string
	Hazards       []lockHazard
	// Concurrent is set for a statement that must run outside a transaction.
	Concurrent bool
	// InDO is set when Concurrent came from inside a DO block.
	InDO bool
}

func normTable(raw string) string {
	return strings.ToLower(strings.ReplaceAll(raw, `"`, ""))
}

// analyzeLock classifies a normalised statement (see schemaStatement.Text).
func analyzeLock(text string) lockFacts {
	text = strings.TrimSpace(text)
	var f lockFacts
	if doStmtRe.MatchString(text) {
		for _, inner := range doBodyStatements(text) {
			sub := analyzeLock(inner)
			f.CreatesTables = append(f.CreatesTables, sub.CreatesTables...)
			f.Hazards = append(f.Hazards, sub.Hazards...)
			if sub.Concurrent {
				f.Concurrent, f.InDO = true, true
			}
		}
		return f
	}
	plain := quotedStrRe.ReplaceAllString(text, "''")
	if lockConcurrentLead.MatchString(plain) && lockConcurrentRe.MatchString(plain) {
		f.Concurrent = true
	}
	switch {
	case lockCreateTableRe.MatchString(plain):
		f.CreatesTables = append(f.CreatesTables, normTable(lockCreateTableRe.FindStringSubmatch(plain)[1]))
	case lockCreateIndexRe.MatchString(plain):
		m := lockCreateIndexRe.FindStringSubmatch(plain)
		if m[1] == "" {
			f.Hazards = append(f.Hazards, lockHazard{normTable(m[2]),
				"CREATE INDEX without CONCURRENTLY blocks writes to the table while the index builds"})
		}
	case lockAlterTableRe.MatchString(plain):
		m := lockAlterTableRe.FindStringSubmatch(plain)
		table := normTable(m[1])
		for _, action := range splitTopLevelCommas(m[2]) {
			am := lockAddConstrRe.FindStringSubmatch(strings.TrimSpace(action))
			if am == nil {
				continue
			}
			kind := strings.ToUpper(strings.Join(strings.Fields(am[1]), " "))
			switch {
			case (kind == "CHECK" || kind == "FOREIGN KEY") && !lockNotValidRe.MatchString(action):
				f.Hazards = append(f.Hazards, lockHazard{table,
					"ADD CONSTRAINT " + kind + " without NOT VALID scans the table while holding a strong lock"})
			case (kind == "UNIQUE" || kind == "PRIMARY KEY") && !usesExistingIndex(action):
				f.Hazards = append(f.Hazards, lockHazard{table,
					"ADD CONSTRAINT " + kind + " without USING INDEX builds an index while holding a strong lock"})
			}
		}
	}
	return f
}

// usesExistingIndex reports whether a constraint action attaches an existing index
// (USING INDEX <name>). USING INDEX TABLESPACE <ts> is an index parameter of a new
// index, not that form.
func usesExistingIndex(action string) bool {
	m := lockUsingIndexRe.FindStringSubmatch(action)
	return m != nil && !strings.EqualFold(m[1], "TABLESPACE")
}

// splitTopLevelCommas splits the actions of an ALTER TABLE at commas outside
// parentheses.
func splitTopLevelCommas(s string) []string {
	var out []string
	depth, start := 0, 0
	for i, c := range s {
		switch c {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	return append(out, s[start:])
}

// doBodyStatements returns the statements of a DO block's dollar-quoted body, with the
// PL/pgSQL control-flow lead-in (IF ... THEN, BEGIN, ...) removed.
func doBodyStatements(text string) []string {
	dollar := strings.Index(text, "$")
	if dollar < 0 {
		return nil
	}
	tag := dollarTagRe.FindString(text[dollar:])
	end := strings.LastIndex(text, tag)
	if tag == "" || end <= dollar {
		return nil
	}
	var out []string
	for _, st := range splitStatements(text[dollar+len(tag) : end]) {
		inner := st.Text
		for {
			trimmed := plpgsqlLead.ReplaceAllString(inner, "")
			if trimmed == inner {
				break
			}
			inner = trimmed
		}
		out = append(out, inner)
	}
	return out
}

// ---- checker ---------------------------------------------------------------

// parseTableVersions parses table_versions_baseline.txt ("<table> <version>" lines).
// ceiling is the highest version a line may carry.
func parseTableVersions(content string, ceiling int) (map[string]int, []string) {
	versions := map[string]int{}
	var problems []string
	for _, line := range parseBaseline(content) {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			problems = append(problems, fmt.Sprintf("table versions line %q must be \"<table> <version>\"", line))
			continue
		}
		table := normTable(fields[0])
		v, err := strconv.Atoi(fields[1])
		switch {
		case err != nil || v < 1 || v > ceiling:
			problems = append(problems, fmt.Sprintf("table versions line %q: the version must be an integer from 1 to SchemaVersion (%d)", line, ceiling))
		default:
			if _, dup := versions[table]; dup {
				problems = append(problems, fmt.Sprintf("table versions line %q: table %s is listed twice", line, table))
			}
			versions[table] = v
		}
	}
	return versions, problems
}

// markerProblem returns why a statement's new-table exemption does not hold, or "" when
// it does. Every hazard of the statement must be on the table the marker names.
func markerProblem(st lockStatement, hazards []lockHazard, versions map[string]int, ceiling int) string {
	if st.Marker == "" {
		return `it has no preceding "// schema:new-table <table> since=<n>" comment line (Go) or "-- schema:new-table <table> since=<n>" line (SQL)`
	}
	m := lockMarkerRe.FindStringSubmatch(st.Marker)
	if m == nil || strings.HasPrefix(st.Marker, "//") == strings.HasSuffix(st.File, ".sql") {
		return fmt.Sprintf("its preceding comment %q is not a schema:new-table marker for this file type", st.Marker)
	}
	table := normTable(m[1])
	since, _ := strconv.Atoi(m[2])
	recorded, listed := versions[table]
	switch {
	case !listed:
		return fmt.Sprintf("its marker names table %s, which has no line in %s", table, tableVersionsPath)
	case since > ceiling:
		return fmt.Sprintf("its marker since=%d is above SchemaVersion (%d)", since, ceiling)
	case since != recorded:
		return fmt.Sprintf("its marker says table %s is new in schema version %d, but %s records it at version %d", table, since, tableVersionsPath, recorded)
	}
	for _, h := range hazards {
		if h.Table != table {
			return fmt.Sprintf("its marker names table %s but the statement targets table %s", table, h.Table)
		}
	}
	return ""
}

// lockKey is the identity of a grandfathered statement.
func lockKey(st lockStatement) string { return baselineKey(st.schemaStatement) }

// flaggedLockKeys returns the sorted, unique identities of every statement that has a
// lock hazard, exemptions not considered. It is what the baseline file must hold.
func flaggedLockKeys(stmts []lockStatement) []string {
	seen := map[string]bool{}
	var keys []string
	for _, st := range stmts {
		if len(analyzeLock(st.Text).Hazards) > 0 && !seen[lockKey(st)] {
			seen[lockKey(st)] = true
			keys = append(keys, lockKey(st))
		}
	}
	sort.Strings(keys)
	return keys
}

// checkLockStatements returns one problem per rule violation: a CREATE TABLE whose table
// has no version line, a CONCURRENTLY statement that cannot run outside a transaction,
// a hazardous statement that is neither exempt nor grandfathered, and a baseline line
// that matches no flagged statement. ceiling is the version ceiling: the tree check
// passes SchemaVersion. tableVersions is the content of table_versions_baseline.txt.
func checkLockStatements(stmts []lockStatement, baseline []string, tableVersions string, ceiling int) []string {
	versions, problems := parseTableVersions(tableVersions, ceiling)
	inBaseline := map[string]bool{}
	for _, b := range baseline {
		inBaseline[b] = false
	}
	for _, st := range stmts {
		facts := analyzeLock(st.Text)
		where := fmt.Sprintf("%s:%d: %q", st.File, st.Line, st.Text)

		for _, table := range facts.CreatesTables {
			if _, ok := versions[table]; !ok {
				problems = append(problems, fmt.Sprintf("%s: creates table %s, which has no line in %s; add %q (the current SchemaVersion)",
					where, table, tableVersionsPath, fmt.Sprintf("%s %d", table, ceiling)))
			}
		}
		if facts.Concurrent {
			switch {
			case facts.InDO:
				problems = append(problems, where+": CONCURRENTLY cannot run inside a DO block, which is one transaction, and Postgres refuses it inside a transaction")
			case st.Siblings > 1:
				problems = append(problems, fmt.Sprintf("%s: this CONCURRENTLY statement shares its string literal (or SQL file) with %d other statement(s), which run as one implicit transaction, and Postgres refuses CONCURRENTLY inside a transaction; put it in its own literal",
					where, st.Siblings-1))
			case st.TxBefore:
				problems = append(problems, where+": this CONCURRENTLY statement sits in a function that began a transaction before it, and Postgres refuses CONCURRENTLY inside a transaction; run it outside the transaction")
			}
		}
		if len(facts.Hazards) == 0 {
			continue
		}
		key := lockKey(st)
		if _, grandfathered := inBaseline[key]; grandfathered {
			inBaseline[key] = true
			continue
		}
		mp := markerProblem(st, facts.Hazards, versions, ceiling)
		if mp == "" {
			continue
		}
		for _, h := range facts.Hazards {
			problems = append(problems, fmt.Sprintf("%s: %s on live traffic during a rolling deploy; use the online form, or exempt it for a table created in this schema version: %s",
				where, h.Reason, mp))
		}
	}
	for _, b := range baseline {
		if !inBaseline[b] {
			problems = append(problems, fmt.Sprintf("baseline line %q matches no flagged statement in the tree; remove it", b))
		}
	}
	sort.Strings(problems)
	return problems
}

// tableVersionsHeaderProblem returns "" when the file starts with a comment header that
// says new tables add a line at the current SchemaVersion and existing lines are never
// edited.
func tableVersionsHeaderProblem(content string) string {
	if !strings.HasPrefix(content, "#") {
		return "the table versions file must start with a # header comment"
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
	for _, want := range []string{"never edited", "add a line", "schemaversion"} {
		if !strings.Contains(text, want) {
			return fmt.Sprintf("the table versions header must state %q", want)
		}
	}
	return ""
}

// ---- tree scan -------------------------------------------------------------

func collectPackageLockStatements(t *testing.T) []lockStatement {
	t.Helper()
	goFiles, err := filepath.Glob("*.go")
	require.NoError(t, err)
	sqlFiles, err := filepath.Glob("migrations/*.sql")
	require.NoError(t, err)
	require.NotEmpty(t, goFiles, "no Go files found: the test must run in the package directory")
	require.NotEmpty(t, sqlFiles, "no migrations found")

	var all []lockStatement
	for _, f := range append(goFiles, sqlFiles...) {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		require.NoError(t, err)
		stmts, err := collectLockStatements(filepath.ToSlash(f), src)
		require.NoError(t, err)
		all = append(all, stmts...)
	}
	return all
}

func readFileString(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(b)
}

// ---- self-test helpers -----------------------------------------------------

// lockCeiling is the version ceiling of the self-tests. With SchemaVersion = 1 a
// new-table marker could never be valid, so they pass a higher one.
const lockCeiling = 3

// lockVersions lists an existing table (version 1) and one created in version 2 and one
// in version 3.
const lockVersions = "# header\nexisting_t 1\nnew_t 2\nnewer_t 3\n"

func lockStmts(t *testing.T, name, src string) []lockStatement {
	t.Helper()
	stmts, err := collectLockStatements(name, []byte(src))
	require.NoError(t, err)
	return stmts
}

func checkLockGo(t *testing.T, body string, baseline ...string) []string {
	t.Helper()
	return checkLockStatements(lockStmts(t, "x.go", "package database\n\n"+body+"\n"), baseline, lockVersions, lockCeiling)
}

func checkLockSQL(t *testing.T, src string) []string {
	t.Helper()
	return checkLockStatements(lockStmts(t, "migrations/099_x.sql", src), nil, lockVersions, lockCeiling)
}

func lockInFunc(stmt string) string {
	return "func f() { _ = `" + stmt + "` }"
}

// ---- required tests --------------------------------------------------------

func TestSchemaLockCheck_CurrentTreePasses(t *testing.T) {
	stmts := collectPackageLockStatements(t)
	baseline := parseBaseline(readFileString(t, lockBaselinePath))
	versions := readFileString(t, tableVersionsPath)

	assert.Empty(t, checkLockStatements(stmts, baseline, versions, SchemaVersion))

	assert.ElementsMatch(t, flaggedLockKeys(stmts), baseline,
		"the baseline holds exactly the flagged statements the scanner finds")
	assert.NotEmpty(t, baseline)
	assert.LessOrEqual(t, len(baseline), existingFlaggedCount, "the baseline may only shrink")

	tables, problems := parseTableVersions(versions, SchemaVersion)
	require.Empty(t, problems)
	assert.Equal(t, 1, tables["cfgms_schema_version"], "the schema-version table is listed")
	assert.Equal(t, 1, tables["audit_entries"])
	created := map[string]bool{}
	for _, st := range stmts {
		for _, table := range analyzeLock(st.Text).CreatesTables {
			created[table] = true
		}
	}
	for table := range created {
		assert.Contains(t, tables, table, "every created table is listed")
	}
}

func TestSchemaLockCheck_FoldsConstantConcatenation(t *testing.T) {
	src := "const idxName = \"idx_t_c\"\n" +
		"const prefix = \"CREATE UNIQUE INDEX IF NOT EXISTS \"\n" +
		"const joined = prefix + idxName\n" +
		"func ensure() {\n" +
		"\t_ = \"CREATE UNIQUE INDEX IF NOT EXISTS \" + idxName +\n" +
		"\t\t\" ON existing_t(c) WHERE c > 0;\"\n" +
		"\t_ = joined + \" ON existing_t(d)\"\n" +
		"\tconst local = \"CREATE INDEX IF NOT EXISTS i ON \"\n" +
		"\t_ = local + \"existing_t(e)\"\n" +
		"}"
	stmts := lockStmts(t, "x.go", "package database\n\n"+src)

	var texts []string
	for _, st := range stmts {
		if st.Func == "ensure" {
			texts = append(texts, st.Text)
		}
	}
	// The constant declarations are visited too, as fragments that name no table.
	for _, want := range []string{
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_t_c ON existing_t(c) WHERE c > 0",
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_t_c ON existing_t(d)",
		"CREATE INDEX IF NOT EXISTS i ON existing_t(e)",
	} {
		assert.Contains(t, texts, want, "each statement is found whole, not as its literal pieces")
	}

	facts := analyzeLock("CREATE UNIQUE INDEX IF NOT EXISTS idx_t_c ON existing_t(c) WHERE c > 0")
	require.Len(t, facts.Hazards, 1)
	assert.Equal(t, "existing_t", facts.Hazards[0].Table)
	assert.Len(t, checkLockStatements(stmts, nil, lockVersions, lockCeiling), 3)

	t.Run("a constant folded from another constant", func(t *testing.T) {
		assert.Len(t, flaggedLockKeys(stmts), 3)
	})
	t.Run("a statement held in a constant is found once", func(t *testing.T) {
		got := lockStmts(t, "x.go", "package database\n\nconst ddl = `CREATE INDEX i ON existing_t(c)`\nfunc f() { _ = ddl }")
		assert.Len(t, got, 1)
	})
	t.Run("an operand that is not a constant leaves the literal pieces", func(t *testing.T) {
		got := lockStmts(t, "x.go", "package database\n\nfunc f(n string) { _ = \"CREATE INDEX i ON \" + n }")
		require.Len(t, got, 1)
		assert.Equal(t, "CREATE INDEX i ON", got[0].Text)
	})
	t.Run("the real audit sequence index is found whole", func(t *testing.T) {
		real := collectPackageLockStatements(t)
		want := "schemas.go|ensureAuditSequenceUniqueIndex|CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_entries_tenant_sequence_unique ON audit_entries(tenant_id, sequence_number) WHERE sequence_number > 0"
		assert.Contains(t, flaggedLockKeys(real), want)
		assert.Contains(t, parseBaseline(readFileString(t, lockBaselinePath)), want)
	})
}

func TestSchemaLockCheck_IgnoresKeywordMentionsInRegexps(t *testing.T) {
	problems := checkLockGo(t, `
var re = regexp.MustCompile("(?is)^\\s*create\\s+(unique\\s+)?index\\s+on\\s+t")
var re2 = regexp.MustCompile(`+"`(?is)^\\s*ALTER\\s+TABLE\\s+\\w+\\s+ADD\\s+CONSTRAINT\\s+\\w+\\s+FOREIGN\\s+KEY`"+`)
var re3 = regexp.MustCompile(`+"`(?i)CREATE TABLE\\s+(\\w+)`"+`)
var msg = "failed to create index: add constraint refused"
var msg2 = "cannot create table without a primary key"
var ok = "ALTER TABLE existing_t ADD COLUMN c TEXT"
`)
	assert.Empty(t, problems)

	// A statement that does start with the keywords is still found.
	assert.NotEmpty(t, checkLockGo(t, lockInFunc("CREATE INDEX i ON existing_t(c)")))
	assert.NotEmpty(t, checkLockGo(t, lockInFunc("CREATE TABLE brand_new(c INT)")))
}

func TestSchemaLockCheck_RejectsIndexWithoutConcurrently(t *testing.T) {
	cases := map[string]string{
		"index":                  "CREATE INDEX idx ON existing_t(c)",
		"if not exists":          "CREATE INDEX IF NOT EXISTS idx ON existing_t(c)",
		"unique":                 "CREATE UNIQUE INDEX idx ON existing_t(c)",
		"unique if not exists":   "CREATE UNIQUE INDEX IF NOT EXISTS idx ON existing_t(c)",
		"lower case":             "create index idx on existing_t(c)",
		"whitespace":             "  CREATE\n\tINDEX   idx\n ON   existing_t (c)  ",
		"only":                   "CREATE INDEX idx ON ONLY existing_t(c)",
		"gin":                    "CREATE INDEX idx ON existing_t USING GIN(tags)",
		"partial":                "CREATE INDEX idx ON existing_t(c) WHERE c IS NOT NULL",
		"unnamed":                "CREATE INDEX ON existing_t(c)",
		"quoted table":           `CREATE INDEX idx ON "existing_t"(c)`,
		"after a harmless one":   "SELECT 1; CREATE INDEX idx ON existing_t(c)",
		"in a DO block":          "DO $$ BEGIN IF NOT EXISTS (SELECT 1) THEN CREATE INDEX idx ON existing_t(c); END IF; END $$",
		"on a table not in file": "CREATE INDEX idx ON unknown_t(c)",
	}
	for name, stmt := range cases {
		t.Run(name, func(t *testing.T) {
			problems := checkLockGo(t, lockInFunc(stmt))
			require.Len(t, problems, 1, "statement %q", stmt)
			assert.Contains(t, problems[0], "CONCURRENTLY")
		})
	}

	t.Run("interpreted literal and package variable", func(t *testing.T) {
		assert.Len(t, checkLockGo(t, `func f() { _ = "CREATE INDEX i ON existing_t(c)" }`), 1)
		assert.Len(t, checkLockGo(t, "var q = `CREATE UNIQUE INDEX i ON existing_t(c)`"), 1)
		assert.Len(t, checkLockGo(t, "func (s S) M() { _ = `CREATE INDEX i ON existing_t(c)` }"), 1)
	})
	t.Run("in a SQL file", func(t *testing.T) {
		problems := checkLockSQL(t, "CREATE INDEX IF NOT EXISTS i ON existing_t(c);\n")
		require.Len(t, problems, 1)
		assert.Contains(t, problems[0], "CONCURRENTLY")
	})
	t.Run("CONCURRENTLY passes", func(t *testing.T) {
		assert.Empty(t, checkLockGo(t, lockInFunc("CREATE INDEX CONCURRENTLY IF NOT EXISTS idx ON existing_t(c)")))
		assert.Empty(t, checkLockGo(t, lockInFunc("CREATE UNIQUE INDEX CONCURRENTLY idx ON existing_t(c)")))
		assert.Empty(t, checkLockGo(t, lockInFunc("create index concurrently idx on existing_t(c)")))
		assert.Empty(t, checkLockSQL(t, "CREATE INDEX CONCURRENTLY IF NOT EXISTS i ON existing_t(c);\n"))
	})
	t.Run("other statements are not flagged", func(t *testing.T) {
		assert.Empty(t, checkLockGo(t, lockInFunc("ALTER TABLE existing_t ADD COLUMN c TEXT; DROP INDEX i; REFRESH MATERIALIZED VIEW CONCURRENTLY v; INSERT INTO existing_t VALUES ('CREATE INDEX i ON t(c)')")))
	})
	t.Run("a grandfathered statement is allowed", func(t *testing.T) {
		assert.Empty(t, checkLockGo(t, lockInFunc("CREATE INDEX idx ON existing_t(c)"), "x.go|f|CREATE INDEX idx ON existing_t(c)"))
	})
}

func TestSchemaLockCheck_ConcurrentlyMustBeSingleStatementOutsideTransaction(t *testing.T) {
	const idx = "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx ON existing_t(c)"

	t.Run("alone in its literal passes", func(t *testing.T) {
		assert.Empty(t, checkLockGo(t, lockInFunc(idx)))
		assert.Empty(t, checkLockGo(t, lockInFunc(idx+";")))
		assert.Empty(t, checkLockGo(t, "func f() {\n\t_ = `"+idx+"`\n\t_ = `"+idx+"2`\n}"), "separate literals are separate statements")
	})
	t.Run("a second statement in the literal fails with the reason", func(t *testing.T) {
		for name, stmt := range map[string]string{
			"after":  idx + "; SELECT 1",
			"before": "SELECT 1; " + idx,
			"two":    idx + "; " + idx + "2",
		} {
			problems := checkLockGo(t, lockInFunc(stmt))
			require.NotEmpty(t, problems, name)
			assert.Contains(t, problems[0], "implicit transaction", name)
			assert.Contains(t, problems[0], "own literal", name)
		}
	})
	t.Run("a SQL file with a second statement fails", func(t *testing.T) {
		problems := checkLockSQL(t, "CREATE INDEX CONCURRENTLY i ON existing_t(c);\nSELECT 1;\n")
		require.Len(t, problems, 1)
		assert.Contains(t, problems[0], "implicit transaction")
		assert.Empty(t, checkLockSQL(t, "-- a comment\nCREATE INDEX CONCURRENTLY i ON existing_t(c);\n"))
	})
	t.Run("a function that began a transaction first fails with the reason", func(t *testing.T) {
		for name, body := range map[string]string{
			"BeginTx":  "func f(ctx context.Context, db *sql.DB) error {\n\ttx, err := db.BeginTx(ctx, nil)\n\tif err != nil { return err }\n\t_, err = db.ExecContext(ctx, `" + idx + "`)\n\treturn err\n}",
			"Begin":    "func f(db *sql.DB) {\n\ttx, _ := db.Begin()\n\t_ = tx\n\t_ = `" + idx + "`\n}",
			"nested":   "func f(s *S) {\n\ttx, _ := s.db.BeginTx(ctx, nil)\n\t_ = tx\n\tfunc() { _ = `" + idx + "` }()\n}",
			"a method": "func (s *S) f() {\n\ttx, _ := s.db.BeginTx(ctx, nil)\n\t_ = tx\n\t_ = `" + idx + "`\n}",
		} {
			problems := checkLockGo(t, body)
			require.Len(t, problems, 1, name)
			assert.Contains(t, problems[0], "began a transaction", name)
			assert.Contains(t, problems[0], "refuses CONCURRENTLY", name)
		}
	})
	t.Run("a transaction opened after, or in another function, is fine", func(t *testing.T) {
		assert.Empty(t, checkLockGo(t, "func f(db *sql.DB) {\n\t_ = `"+idx+"`\n\ttx, _ := db.Begin()\n\t_ = tx\n}"))
		assert.Empty(t, checkLockGo(t, "func g(db *sql.DB) { _, _ = db.Begin() }\nfunc f() { _ = `"+idx+"` }"))
	})
	t.Run("inside a DO block fails", func(t *testing.T) {
		problems := checkLockGo(t, lockInFunc("DO $$ BEGIN CREATE INDEX CONCURRENTLY i ON existing_t(c); END $$"))
		require.Len(t, problems, 1)
		assert.Contains(t, problems[0], "DO block")
	})
	t.Run("other concurrent statements follow the same rule", func(t *testing.T) {
		assert.Len(t, checkLockGo(t, lockInFunc("DROP INDEX CONCURRENTLY i; SELECT 1")), 1)
		assert.Empty(t, checkLockGo(t, lockInFunc("DROP INDEX CONCURRENTLY i")))
		assert.Empty(t, checkLockGo(t, lockInFunc("REFRESH MATERIALIZED VIEW CONCURRENTLY v; SELECT 1")), "a refresh may run in a transaction")
	})
	t.Run("a grandfathered line does not excuse it", func(t *testing.T) {
		key := "x.go|f|" + idx
		assert.NotEmpty(t, checkLockGo(t, "func f(db *sql.DB) {\n\ttx, _ := db.Begin()\n\t_ = tx\n\t_ = `"+idx+"`\n}", key))
	})
}

func TestSchemaLockCheck_RejectsConstraintWithoutNotValid(t *testing.T) {
	rejected := map[string]string{
		"foreign key":            "ALTER TABLE existing_t ADD CONSTRAINT fk FOREIGN KEY (a) REFERENCES other(id)",
		"foreign key no name":    "ALTER TABLE existing_t ADD FOREIGN KEY (a) REFERENCES other(id)",
		"check":                  "ALTER TABLE existing_t ADD CONSTRAINT ck CHECK (a > 0)",
		"check no name":          "ALTER TABLE existing_t ADD CHECK (a > 0)",
		"lower case":             "alter table existing_t add constraint fk foreign key (a) references other(id)",
		"if exists only":         "ALTER TABLE IF EXISTS ONLY existing_t ADD CONSTRAINT ck CHECK (a > 0)",
		"quoted name":            `ALTER TABLE existing_t ADD CONSTRAINT "my ck" CHECK (a > 0)`,
		"unique":                 "ALTER TABLE existing_t ADD CONSTRAINT uq UNIQUE (a)",
		"primary key":            "ALTER TABLE existing_t ADD CONSTRAINT pk PRIMARY KEY (a)",
		"primary key no name":    "ALTER TABLE existing_t ADD PRIMARY KEY (a)",
		"unique with tablespace": "ALTER TABLE existing_t ADD CONSTRAINT uq UNIQUE (a) USING INDEX TABLESPACE ts",
		"not valid in a string":  "ALTER TABLE existing_t ADD CONSTRAINT ck CHECK (note <> 'NOT VALID')",
		"second action only":     "ALTER TABLE existing_t ADD COLUMN c INT, ADD CONSTRAINT ck CHECK (c > 0)",
		"one of two":             "ALTER TABLE existing_t ADD CONSTRAINT a CHECK (x > 0) NOT VALID, ADD CONSTRAINT b CHECK (y > 0)",
		"in a DO block":          "DO $$ BEGIN ALTER TABLE existing_t ADD CONSTRAINT ck CHECK (a > 0); END $$",
	}
	for name, stmt := range rejected {
		t.Run("rejects "+name, func(t *testing.T) {
			problems := checkLockGo(t, lockInFunc(stmt))
			require.Len(t, problems, 1, "statement %q", stmt)
			assert.Contains(t, problems[0], "ADD CONSTRAINT")
		})
	}
	problems := checkLockGo(t, lockInFunc("ALTER TABLE existing_t ADD CONSTRAINT uq UNIQUE (a)"))
	assert.Contains(t, problems[0], "USING INDEX")
	problems = checkLockGo(t, lockInFunc("ALTER TABLE existing_t ADD CONSTRAINT ck CHECK (a > 0)"))
	assert.Contains(t, problems[0], "NOT VALID")

	accepted := map[string]string{
		"foreign key not valid":   "ALTER TABLE existing_t ADD CONSTRAINT fk FOREIGN KEY (a) REFERENCES other(id) NOT VALID",
		"check not valid":         "ALTER TABLE existing_t ADD CONSTRAINT ck CHECK (a > 0) NOT VALID",
		"lower case not valid":    "alter table existing_t add constraint ck check (a > 0) not valid",
		"two actions":             "ALTER TABLE existing_t ADD CONSTRAINT a CHECK (x > 0) NOT VALID, ADD CONSTRAINT b CHECK (y > 0) NOT VALID",
		"comma in an expression":  "ALTER TABLE existing_t ADD CONSTRAINT ck CHECK (a IN (1, 2)) NOT VALID",
		"unique using index":      "ALTER TABLE existing_t ADD CONSTRAINT uq UNIQUE USING INDEX uq_idx",
		"primary key using index": "ALTER TABLE existing_t ADD CONSTRAINT pk PRIMARY KEY USING INDEX pk_idx",
		"add column":              "ALTER TABLE existing_t ADD COLUMN IF NOT EXISTS c TEXT NOT NULL DEFAULT ''",
		"add column no keyword":   "ALTER TABLE existing_t ADD unique_col TEXT",
		"drop constraint":         "ALTER TABLE existing_t DROP CONSTRAINT ck",
		"validate":                "ALTER TABLE existing_t VALIDATE CONSTRAINT ck",
	}
	for name, stmt := range accepted {
		t.Run("accepts "+name, func(t *testing.T) {
			// The destructive statement DROP CONSTRAINT is the previous check's concern.
			assert.Empty(t, checkLockGo(t, lockInFunc(stmt)), "statement %q", stmt)
		})
	}

	t.Run("in a SQL file", func(t *testing.T) {
		assert.Len(t, checkLockSQL(t, "ALTER TABLE existing_t ADD CONSTRAINT ck CHECK (a > 0);\n"), 1)
		assert.Empty(t, checkLockSQL(t, "ALTER TABLE existing_t ADD CONSTRAINT ck CHECK (a > 0) NOT VALID;\n"))
	})
	t.Run("a grandfathered statement is allowed", func(t *testing.T) {
		stmt := "ALTER TABLE existing_t ADD CONSTRAINT ck CHECK (a > 0)"
		assert.Empty(t, checkLockGo(t, lockInFunc(stmt), "x.go|f|"+stmt))
	})
}

func TestSchemaLockCheck_NewTableMarkerExemption(t *testing.T) {
	const idx = "CREATE INDEX IF NOT EXISTS idx ON new_t(c)"
	withMarker := func(marker, stmt string) string {
		return "func f() {\n\t" + marker + "\n\t_ = `" + stmt + "`\n}"
	}

	t.Run("valid marker passes", func(t *testing.T) {
		assert.Empty(t, checkLockGo(t, withMarker("// schema:new-table new_t since=2", idx)))
		assert.Empty(t, checkLockGo(t, withMarker("//schema:new-table new_t since=2", idx)), "no space after //")
		assert.Empty(t, checkLockGo(t, withMarker("// schema:new-table NEW_T since=2", idx)), "table names compare case-insensitively")
		assert.Empty(t, checkLockGo(t, withMarker("// schema:new-table newer_t since=3", "CREATE UNIQUE INDEX i ON newer_t(c)")), "since equal to the ceiling")
		assert.Empty(t, checkLockGo(t, withMarker("// schema:new-table new_t since=2", "ALTER TABLE new_t ADD CONSTRAINT ck CHECK (a > 0)")))
		assert.Empty(t, checkLockGo(t, withMarker("// schema:new-table new_t since=2", "ALTER TABLE new_t ADD CONSTRAINT uq UNIQUE (a)")))
	})
	t.Run("a marker in a slice literal and a package variable", func(t *testing.T) {
		assert.Empty(t, checkLockGo(t, "var idx = []string{\n\t// schema:new-table new_t since=2\n\t\"CREATE INDEX i ON new_t(a)\",\n\t// schema:new-table new_t since=2\n\t\"CREATE INDEX j ON new_t(b)\",\n}"))
		assert.Empty(t, checkLockGo(t, "// schema:new-table new_t since=2\nvar q = `CREATE INDEX i ON new_t(a)`"))
	})
	t.Run("the marker is checked against the table versions file", func(t *testing.T) {
		// The table was created in version 1: it is not empty when a later version adds an index.
		problems := checkLockGo(t, withMarker("// schema:new-table existing_t since=2", "CREATE INDEX i ON existing_t(c)"))
		require.Len(t, problems, 1)
		assert.Contains(t, problems[0], "records it at version 1")
		// Claiming the recorded version of an old table is valid: the index shipped with the table.
		assert.Empty(t, checkLockGo(t, withMarker("// schema:new-table existing_t since=1", "CREATE INDEX i ON existing_t(c)")))

		problems = checkLockGo(t, withMarker("// schema:new-table new_t since=3", idx))
		require.Len(t, problems, 1, "since must equal the recorded version")
		assert.Contains(t, problems[0], "records it at version 2")

		problems = checkLockGo(t, withMarker("// schema:new-table not_listed since=2", "CREATE INDEX i ON not_listed(c)"))
		require.Len(t, problems, 1)
		assert.Contains(t, problems[0], "no line in")
	})
	t.Run("since above the ceiling fails", func(t *testing.T) {
		problems := checkLockStatements(
			lockStmts(t, "x.go", "package database\n\n"+withMarker("// schema:new-table later_t since=4", "CREATE INDEX i ON later_t(c)")),
			nil, lockVersions+"later_t 3\n", lockCeiling)
		assert.NotEmpty(t, problems)
		// A table line above the ceiling is itself a problem.
		_, bad := parseTableVersions("later_t 4\n", lockCeiling)
		assert.Len(t, bad, 1)
	})
	t.Run("the statement must target the marked table", func(t *testing.T) {
		problems := checkLockGo(t, withMarker("// schema:new-table new_t since=2", "CREATE INDEX i ON existing_t(c)"))
		require.Len(t, problems, 1)
		assert.Contains(t, problems[0], "targets table existing_t")

		problems = checkLockGo(t, withMarker("// schema:new-table new_t since=2", "ALTER TABLE existing_t ADD CONSTRAINT fk FOREIGN KEY (a) REFERENCES new_t(id)"))
		assert.Len(t, problems, 1, "naming the table only as a reference target is not enough")
	})
	t.Run("a marker must be directly above and own its line", func(t *testing.T) {
		assert.Len(t, checkLockGo(t, "func f() {\n\t// schema:new-table new_t since=2\n\n\t_ = `"+idx+"`\n}"), 1, "blank line between")
		assert.Len(t, checkLockGo(t, "func f() {\n\t// schema:new-table new_t since=2\n\t// why\n\t_ = `"+idx+"`\n}"), 1, "another comment between")
		assert.Len(t, checkLockGo(t, "var s = []string{\n\t\"SELECT 1\", // schema:new-table new_t since=2\n\t\"CREATE INDEX i ON new_t(a)\",\n}"), 1, "trailing comment of the previous line")
		assert.Len(t, checkLockGo(t, "func f() {\n\t_ = `"+idx+"` // schema:new-table new_t since=2\n}"), 1, "comment after the statement")
		assert.Len(t, checkLockGo(t, "// schema:new-table new_t since=2\nfunc f() {\n\t_ = `"+idx+"`\n}"), 1, "comment above the function, not the literal")
	})
	t.Run("malformed markers fail", func(t *testing.T) {
		for _, m := range []string{
			"// schema:new-table new_t", "// schema:new-table new_t since=x", "// schema:new-table since=2",
			"// schema:new-table new_t since=2 extra", "// schema:contract unused-since=2",
			"// schema:new-table  new_t   since=2.", "/* schema:new-table new_t since=2 */",
		} {
			assert.Len(t, checkLockGo(t, withMarker(m, idx)), 1, m)
		}
	})
	t.Run("SQL marker", func(t *testing.T) {
		assert.Empty(t, checkLockSQL(t, "-- schema:new-table new_t since=2\nCREATE INDEX i ON new_t(c);\n"))
		assert.Empty(t, checkLockSQL(t, "CREATE TABLE IF NOT EXISTS new_t (c INT);\n\n-- schema:new-table new_t since=2\nCREATE INDEX i ON new_t(c);\n"))
		assert.Len(t, checkLockSQL(t, "-- schema:new-table new_t since=2\nCREATE INDEX i ON new_t(c);\nCREATE INDEX j ON new_t(d);\n"), 1, "the marker covers the next statement only")
		assert.Len(t, checkLockSQL(t, "-- schema:new-table existing_t since=2\nCREATE INDEX i ON existing_t(c);\n"), 1)
		assert.Len(t, checkLockSQL(t, "-- schema:new-table new_t since=2\n\nCREATE INDEX i ON new_t(c);\n"), 1)
	})
	t.Run("the marker does not exempt the CONCURRENTLY rules", func(t *testing.T) {
		problems := checkLockSQL(t, "-- schema:new-table new_t since=2\nCREATE INDEX CONCURRENTLY i ON new_t(c);\nSELECT 1;\n")
		assert.NotEmpty(t, problems)
	})
}

func TestSchemaLockCheck_RejectsUnregisteredTable(t *testing.T) {
	t.Run("a new table without a version line fails", func(t *testing.T) {
		problems := checkLockGo(t, lockInFunc("CREATE TABLE IF NOT EXISTS brand_new_t (id INT)"))
		require.Len(t, problems, 1)
		assert.Contains(t, problems[0], "brand_new_t")
		assert.Contains(t, problems[0], tableVersionsPath)
		assert.Contains(t, problems[0], `"brand_new_t 3"`, "the message names the line to add")
	})
	t.Run("listed tables pass at any version up to the ceiling", func(t *testing.T) {
		for _, table := range []string{"existing_t", "new_t", "newer_t", "EXISTING_T"} {
			assert.Empty(t, checkLockGo(t, lockInFunc("CREATE TABLE IF NOT EXISTS "+table+" (id INT)")), table)
		}
	})
	t.Run("statement shapes", func(t *testing.T) {
		for _, stmt := range []string{
			"CREATE TABLE brand_new_t (id INT)",
			"create table if not exists brand_new_t(id INT)",
			`CREATE TABLE "brand_new_t" (id INT)`,
			"CREATE UNLOGGED TABLE brand_new_t (id INT)",
			"CREATE TEMP TABLE brand_new_t (id INT)",
			"CREATE TABLE brand_new_t (LIKE existing_t)",
			"DO $$ BEGIN CREATE TABLE brand_new_t (id INT); END $$",
		} {
			assert.Len(t, checkLockGo(t, lockInFunc(stmt)), 1, stmt)
		}
	})
	t.Run("in a SQL file", func(t *testing.T) {
		assert.Len(t, checkLockSQL(t, "CREATE TABLE IF NOT EXISTS brand_new_t (id INT);\n"), 1)
		assert.Empty(t, checkLockSQL(t, "CREATE TABLE IF NOT EXISTS existing_t (id INT);\n"))
	})
	t.Run("an index on a table the same change creates is exempt only with a marker", func(t *testing.T) {
		src := "func f() {\n\t_ = `CREATE TABLE IF NOT EXISTS brand_new_t (id INT)`\n\t_ = `CREATE INDEX i ON brand_new_t(id)`\n}"
		assert.Len(t, checkLockGo(t, src), 2, "unregistered table and unmarked index")
	})
	t.Run("a table versions file with a bad line fails", func(t *testing.T) {
		stmts := lockStmts(t, "x.go", "package database\n\n"+lockInFunc("SELECT 1"))
		for _, content := range []string{"existing_t\n", "existing_t one\n", "existing_t 0\n", "existing_t 9\n", "existing_t 1\nexisting_t 1\n", "a 1 2\n"} {
			assert.NotEmpty(t, checkLockStatements(stmts, nil, content, lockCeiling), content)
		}
	})
	t.Run("the table is not required for statements that are not CREATE TABLE", func(t *testing.T) {
		assert.Empty(t, checkLockGo(t, lockInFunc("ALTER TABLE brand_new_t ADD COLUMN c INT; DROP TABLE brand_new_t")))
	})
}

func TestSchemaLockCheck_BaselinesMayOnlyShrink(t *testing.T) {
	src := lockInFunc("CREATE INDEX i ON existing_t(c)")
	live := "x.go|f|CREATE INDEX i ON existing_t(c)"

	t.Run("matching line grandfathers the statement", func(t *testing.T) {
		assert.Empty(t, checkLockGo(t, src, live))
	})
	t.Run("a line matching no statement fails", func(t *testing.T) {
		problems := checkLockGo(t, src, live, "x.go|f|CREATE INDEX gone ON existing_t(c)")
		require.Len(t, problems, 1)
		assert.Contains(t, problems[0], "matches no flagged statement")
		assert.Contains(t, problems[0], "gone")
	})
	t.Run("a stale line fails even when nothing is flagged", func(t *testing.T) {
		assert.Len(t, checkLockGo(t, lockInFunc("SELECT 1"), live), 1)
	})
	t.Run("a hazard rewritten to the online form leaves a stale line", func(t *testing.T) {
		assert.Len(t, checkLockGo(t, lockInFunc("CREATE INDEX CONCURRENTLY i ON existing_t(c)"), live), 1)
	})
	t.Run("an edited statement is new", func(t *testing.T) {
		problems := checkLockGo(t, lockInFunc("CREATE INDEX i2 ON existing_t(c)"), live)
		require.Len(t, problems, 2, "the edited statement is flagged and the old line is stale")
	})
	t.Run("a moved statement is new", func(t *testing.T) {
		assert.Len(t, checkLockGo(t, "func g() { _ = `CREATE INDEX i ON existing_t(c)` }", live), 2)
	})
	t.Run("a second copy under the same identity matches the same line", func(t *testing.T) {
		assert.Empty(t, checkLockGo(t, "func f() { _ = `CREATE INDEX i ON existing_t(c)`; _ = `CREATE INDEX i ON existing_t(c)` }", live))
	})
	t.Run("a statement in another file is new", func(t *testing.T) {
		stmts := lockStmts(t, "y.go", "package database\n\n"+src)
		assert.Len(t, checkLockStatements(stmts, []string{live}, lockVersions, lockCeiling), 2)
	})
	t.Run("a marked statement that is also listed still matches its line", func(t *testing.T) {
		body := "func f() {\n\t// schema:new-table existing_t since=1\n\t_ = `CREATE INDEX i ON existing_t(c)`\n}"
		assert.Empty(t, checkLockGo(t, body, live))
		assert.Len(t, checkLockGo(t, body, live, "x.go|f|CREATE INDEX other ON existing_t(c)"), 1)
	})
	t.Run("scanner keys are unique and sorted", func(t *testing.T) {
		stmts := lockStmts(t, "x.go", "package database\n\nfunc f() { _ = `CREATE INDEX b ON existing_t(c)`; _ = `CREATE INDEX a ON existing_t(c)`; _ = `CREATE INDEX a ON existing_t(c)` }")
		assert.Equal(t, []string{"x.go|f|CREATE INDEX a ON existing_t(c)", "x.go|f|CREATE INDEX b ON existing_t(c)"}, flaggedLockKeys(stmts))
	})
	t.Run("an empty baseline is valid", func(t *testing.T) {
		assert.Empty(t, checkLockGo(t, lockInFunc("SELECT 1")))
	})
}

func TestSchemaLockCheck_BaselineHeadersPresent(t *testing.T) {
	assert.Empty(t, baselineHeaderProblem(readFileString(t, lockBaselinePath)), "lock hazard baseline")
	assert.Empty(t, tableVersionsHeaderProblem(readFileString(t, tableVersionsPath)), "table versions baseline")

	t.Run("lock hazard baseline header", func(t *testing.T) {
		assert.NotEmpty(t, baselineHeaderProblem("a|b|c\n"))
		assert.NotEmpty(t, baselineHeaderProblem("# entries may only be removed\na|b|c\n"), "must also say adding is a reviewed exception")
		assert.Empty(t, baselineHeaderProblem("# This list may only shrink.\n# Entries may only be removed; adding one is a reviewed exception.\na|b|c\n"))
	})
	t.Run("table versions header", func(t *testing.T) {
		assert.NotEmpty(t, tableVersionsHeaderProblem(""))
		assert.NotEmpty(t, tableVersionsHeaderProblem("t 1\n"))
		assert.NotEmpty(t, tableVersionsHeaderProblem("# the tables\nt 1\n"))
		assert.NotEmpty(t, tableVersionsHeaderProblem("# existing lines are never edited\nt 1\n"), "must also say new tables add a line")
		assert.NotEmpty(t, tableVersionsHeaderProblem("t 1\n# New tables add a line at the current SchemaVersion; existing lines are never edited.\n"), "the header must come first")
		assert.Empty(t, tableVersionsHeaderProblem("# New tables add a line with the current SchemaVersion.\n# Existing lines are never edited.\nt 1\n"))
	})
}

// ---- collector self-tests --------------------------------------------------

func TestCollectLockStatements(t *testing.T) {
	_, err := collectLockStatements("bad.go", []byte("package database\nfunc {"))
	assert.Error(t, err)

	stmts := lockStmts(t, "x.go", "package database\n\nvar a = `SELECT 1; SELECT 2`\nfunc F() {\n\ttx, _ := db.Begin()\n\t_ = tx\n\t_ = \"SELECT \" + \"3\"\n}")
	require.Len(t, stmts, 3)
	assert.Equal(t, 2, stmts[0].Siblings)
	assert.False(t, stmts[0].TxBefore)
	assert.Equal(t, "-", stmts[0].Func)
	assert.Equal(t, 1, stmts[2].Siblings)
	assert.True(t, stmts[2].TxBefore)
	assert.Equal(t, "F", stmts[2].Func)
	assert.Equal(t, 7, stmts[2].Line)

	sqlStmts := lockStmts(t, "migrations/001.sql", "SELECT 1;\nSELECT 2;")
	require.Len(t, sqlStmts, 2)
	assert.Equal(t, "migrations/001.sql", sqlStmts[0].File)
	assert.Equal(t, 2, sqlStmts[0].Siblings)

	assert.Equal(t, []string{"a", "b", "c"}, splitTopLevelCommas("a,b,c"))
	assert.Equal(t, []string{"f(a, b)", " c"}, splitTopLevelCommas("f(a, b), c"))
}
