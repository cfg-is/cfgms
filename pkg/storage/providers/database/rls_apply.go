// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/lib/pq"
)

// Tenant RLS apply (Issue #6096, Epic #5978).
//
// With FORCE ROW LEVEL SECURITY a table that has no policy denies every row to
// every non-owner role. The inline blocks this replaces dropped each policy and
// re-created it in separate statements on every controller start, so a node that
// was still serving could hit the gap between a DROP and its CREATE and see an
// error or an empty result. A rolling deploy opened that deny-all window once per
// restarted node.
//
// applyTenantRLS closes it in two ways:
//
//   - Steady state issues no DDL. A policy carries a COMMENT holding a SHA-256 of
//     the table's desired policy definitions combined with the policy's live
//     catalog definition. When RLS is enabled and forced and every policy's
//     comment matches, nothing is executed.
//   - A real change runs in ONE transaction that holds the table lock, and an
//     existing policy is replaced with ALTER POLICY, never dropped. Policies a
//     concurrent reader can see are therefore always the old set or the new set.
//
// The guarantee holds for revisions that contain this helper. A node still
// running the older inline drop and create re-opens the window when it restarts.

const (
	// rlsDefCommentPrefix starts the COMMENT ON POLICY text; the SHA-256 follows.
	rlsDefCommentPrefix = "cfgms-rls-def:"

	// rlsLegacyPolicyName is the single FOR ALL policy that older revisions created
	// on sessions, steward_records and command_records. It is dropped, in the same
	// transaction that installs the current policies, wherever it is found.
	rlsLegacyPolicyName = "tenant_isolation_policy"

	// Postgres SQLSTATEs the change path retries on: lock_not_available (the
	// lock_timeout fired) and deadlock_detected.
	rlsSQLStateLockNotAvailable = "55P03"
	rlsSQLStateDeadlock         = "40P01"
)

// tenantRLSPolicy is one policy of a tenant-isolated table. Command is SELECT,
// INSERT, UPDATE or DELETE. Using and WithCheck are the SQL expressions, without
// the surrounding parentheses; an empty string omits the clause. Postgres accepts
// only USING for SELECT and DELETE and only WITH CHECK for INSERT.
type tenantRLSPolicy struct {
	Name      string
	Command   string
	Using     string
	WithCheck string
}

// rlsApplyConfig bounds the change path. The defaults are the production values;
// tests shorten them to keep a lock-timeout case fast.
type rlsApplyConfig struct {
	// lockTimeout is how long the change transaction waits for the table lock.
	lockTimeout time.Duration
	// attempts is how many times the change transaction is tried.
	attempts int
	// retryPause separates two attempts.
	retryPause time.Duration
}

var defaultRLSApplyConfig = rlsApplyConfig{
	lockTimeout: 5 * time.Second,
	attempts:    3,
	retryPause:  250 * time.Millisecond,
}

// applyTenantRLS brings table to the desired RLS state: row level security
// enabled and forced, exactly the given policies installed, and the legacy
// tenant_isolation_policy gone. table must be a constant from schemas.go.
func applyTenantRLS(ctx context.Context, db *sql.DB, table string, policies []tenantRLSPolicy) error {
	return applyTenantRLSWith(ctx, db, table, policies, defaultRLSApplyConfig)
}

func applyTenantRLSWith(ctx context.Context, db *sql.DB, table string, policies []tenantRLSPolicy, cfg rlsApplyConfig) error {
	if err := validateTenantRLSPolicies(policies); err != nil {
		return fmt.Errorf("invalid RLS policies for %s: %w", table, err)
	}
	tableHash := tenantRLSTableHash(table, policies)
	quotedTable := pq.QuoteIdentifier(table)

	state, err := readTenantRLSState(ctx, db, quotedTable)
	if err != nil {
		return fmt.Errorf("failed to read %s RLS state: %w", table, err)
	}
	if !state.needsChange(policies, tableHash) {
		return nil
	}

	err = withRLSRetries(ctx, cfg, func() error {
		return applyTenantRLSTx(ctx, db, quotedTable, policies, tableHash, cfg.lockTimeout)
	})
	if err != nil {
		return fmt.Errorf("failed to configure %s RLS: %w", table, err)
	}
	return nil
}

// withRLSRetries runs attempt up to cfg.attempts times, pausing between tries,
// and retries only when the failure is lock contention.
func withRLSRetries(ctx context.Context, cfg rlsApplyConfig, attempt func() error) error {
	attempts := max(cfg.attempts, 1)
	var err error
	for i := 1; i <= attempts; i++ {
		if err = attempt(); err == nil {
			return nil
		}
		if !isRetryableRLSError(err) || i == attempts {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(cfg.retryPause):
		}
	}
	return err
}

// isRetryableRLSError reports whether a change-transaction failure is the table
// lock being unavailable (or a deadlock), which a later attempt may not hit.
func isRetryableRLSError(err error) bool {
	var pqErr *pq.Error
	if !errors.As(err, &pqErr) {
		return false
	}
	code := string(pqErr.Code)
	return code == rlsSQLStateLockNotAvailable || code == rlsSQLStateDeadlock
}

// applyTenantRLSTx is one attempt at the change path, in a single transaction.
func applyTenantRLSTx(ctx context.Context, db *sql.DB, quotedTable string, policies []tenantRLSPolicy, tableHash string, lockTimeout time.Duration) (err error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	if err = convergeTenantRLS(ctx, tx, quotedTable, policies, tableHash, lockTimeout); err != nil {
		return err
	}
	return tx.Commit()
}

// convergeTenantRLS takes the table lock first, bounded by lock_timeout, then
// re-reads the catalog: a second node that converged the table while this one
// waited leaves nothing to do, and creating a policy the other node just created
// is impossible.
func convergeTenantRLS(ctx context.Context, tx *sql.Tx, quotedTable string, policies []tenantRLSPolicy, tableHash string, lockTimeout time.Duration) error {
	if err := lockTenantTable(ctx, tx, quotedTable, lockTimeout); err != nil {
		return err
	}
	state, err := readTenantRLSState(ctx, tx, quotedTable)
	if err != nil {
		return err
	}
	if !state.needsChange(policies, tableHash) {
		return nil
	}
	for _, stmt := range tableChangeStatements(quotedTable, policies, tableHash, state) {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return stampTenantRLSPolicies(ctx, tx, quotedTable, policies, tableHash)
}

// lockTenantTable takes ACCESS EXCLUSIVE on the table for the rest of the
// transaction, giving up after lockTimeout instead of queueing behind a reader.
func lockTenantTable(ctx context.Context, tx *sql.Tx, quotedTable string, lockTimeout time.Duration) error {
	if _, err := tx.ExecContext(ctx, `SELECT set_config('lock_timeout', $1, true)`,
		fmt.Sprintf("%dms", lockTimeout.Milliseconds())); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `LOCK TABLE `+quotedTable+` IN ACCESS EXCLUSIVE MODE`)
	return err
}

// stampTenantRLSPolicies marks every policy with the hash. The live definition is
// read back after the DDL so the stamp covers what the catalog actually holds,
// which is what lets the next steady-state check notice a hand-edited policy.
func stampTenantRLSPolicies(ctx context.Context, tx *sql.Tx, quotedTable string, policies []tenantRLSPolicy, tableHash string) error {
	after, err := readTenantRLSState(ctx, tx, quotedTable)
	if err != nil {
		return err
	}
	for _, p := range policies {
		live, ok := after.policies[p.Name]
		if !ok {
			return fmt.Errorf("policy %s missing after apply", p.Name)
		}
		comment := rlsDefCommentPrefix + livePolicyHash(tableHash, p.Name, live)
		if _, err := tx.ExecContext(ctx, commentPolicySQL(quotedTable, p.Name, comment)); err != nil {
			return err
		}
	}
	return nil
}

// commentPolicySQL is the COMMENT ON POLICY statement for one policy; the policy
// and table are quoted as identifiers and the comment as a literal.
func commentPolicySQL(quotedTable, policyName, comment string) string {
	return `COMMENT ON POLICY ` + pq.QuoteIdentifier(policyName) + ` ON ` + quotedTable + ` IS ` + pq.QuoteLiteral(comment)
}

// tableChangeStatements lists the DDL that takes a table from state to the
// desired policies. ENABLE and FORCE are issued only when the catalog shows them
// off; the legacy policy is dropped when present; each policy is created,
// altered or left alone (policyChangeStatements).
func tableChangeStatements(quotedTable string, policies []tenantRLSPolicy, tableHash string, state rlsTableState) []string {
	var stmts []string
	if !state.rowSecurity {
		stmts = append(stmts, `ALTER TABLE `+quotedTable+` ENABLE ROW LEVEL SECURITY`)
	}
	if !state.forceRowSecurity {
		stmts = append(stmts, `ALTER TABLE `+quotedTable+` FORCE ROW LEVEL SECURITY`)
	}
	if _, legacy := state.policies[rlsLegacyPolicyName]; legacy {
		stmts = append(stmts, `DROP POLICY `+pq.QuoteIdentifier(rlsLegacyPolicyName)+` ON `+quotedTable)
	}
	for _, p := range policies {
		live, exists := state.policies[p.Name]
		stmts = append(stmts, policyChangeStatements(quotedTable, p, live, exists, tableHash)...)
	}
	return stmts
}

// policyChangeStatements is the DDL for one policy. A missing policy is created;
// one that already matches is left alone; any other is altered in place, never
// dropped. The exception is a policy whose command differs or which is not
// permissive: ALTER POLICY cannot change either, so it is replaced, inside the
// transaction that holds the table lock, where no reader sees the table without it.
func policyChangeStatements(quotedTable string, p tenantRLSPolicy, live rlsLivePolicy, exists bool, tableHash string) []string {
	switch {
	case !exists:
		return []string{createPolicySQL(quotedTable, p)}
	case live.matchesDesired(tableHash, p):
		return nil
	case live.command != policyCommandCode(p.Command) || !live.permissive:
		return []string{`DROP POLICY ` + pq.QuoteIdentifier(p.Name) + ` ON ` + quotedTable, createPolicySQL(quotedTable, p)}
	default:
		return []string{alterPolicySQL(quotedTable, p)}
	}
}

// createPolicySQL and alterPolicySQL render a policy. Expressions are constants
// from this package, never caller data; names are quoted as identifiers.
func createPolicySQL(quotedTable string, p tenantRLSPolicy) string {
	return `CREATE POLICY ` + pq.QuoteIdentifier(p.Name) + ` ON ` + quotedTable +
		` FOR ` + p.Command + policyClauses(p)
}

func alterPolicySQL(quotedTable string, p tenantRLSPolicy) string {
	return `ALTER POLICY ` + pq.QuoteIdentifier(p.Name) + ` ON ` + quotedTable +
		` TO PUBLIC` + policyClauses(p)
}

func policyClauses(p tenantRLSPolicy) string {
	var b strings.Builder
	if p.Using != "" {
		b.WriteString(" USING (" + p.Using + ")")
	}
	if p.WithCheck != "" {
		b.WriteString(" WITH CHECK (" + p.WithCheck + ")")
	}
	return b.String()
}

// policyCommandCode maps a policy command to pg_policy.polcmd.
func policyCommandCode(command string) string {
	switch command {
	case "SELECT":
		return "r"
	case "INSERT":
		return "a"
	case "UPDATE":
		return "w"
	case "DELETE":
		return "d"
	}
	return ""
}

// clauseRule says whether a policy command takes a USING or WITH CHECK clause.
type clauseRule int

const (
	clauseForbidden clauseRule = iota
	clauseOptional
	clauseRequired
)

// policyClauseRules is what Postgres accepts per command: USING only for SELECT
// and DELETE, WITH CHECK only for INSERT, both for UPDATE.
var policyClauseRules = map[string]struct{ using, withCheck clauseRule }{
	"SELECT": {clauseRequired, clauseForbidden},
	"INSERT": {clauseForbidden, clauseRequired},
	"UPDATE": {clauseRequired, clauseOptional},
	"DELETE": {clauseRequired, clauseForbidden},
}

func checkPolicyClause(policy, clause string, rule clauseRule, value string) error {
	if rule == clauseRequired && value == "" {
		return fmt.Errorf("policy %s: %s clause is required", policy, clause)
	}
	if rule == clauseForbidden && value != "" {
		return fmt.Errorf("policy %s: %s clause is not allowed", policy, clause)
	}
	return nil
}

func validateTenantRLSPolicy(p tenantRLSPolicy) error {
	if p.Name == "" || p.Name == rlsLegacyPolicyName {
		return fmt.Errorf("invalid policy name %q", p.Name)
	}
	rules, ok := policyClauseRules[p.Command]
	if !ok {
		return fmt.Errorf("policy %s: unsupported command %q", p.Name, p.Command)
	}
	if err := checkPolicyClause(p.Name, "USING", rules.using, p.Using); err != nil {
		return err
	}
	return checkPolicyClause(p.Name, "WITH CHECK", rules.withCheck, p.WithCheck)
}

func validateTenantRLSPolicies(policies []tenantRLSPolicy) error {
	if len(policies) == 0 {
		return errors.New("no policies")
	}
	seen := map[string]bool{}
	for _, p := range policies {
		if err := validateTenantRLSPolicy(p); err != nil {
			return err
		}
		if seen[p.Name] {
			return fmt.Errorf("duplicate policy %q", p.Name)
		}
		seen[p.Name] = true
	}
	return nil
}

// tenantRLSTableHash is the SHA-256 of the table's canonical desired policy
// definitions. Whitespace inside expressions is normalised so reformatting the
// source does not count as a definition change.
func tenantRLSTableHash(table string, policies []tenantRLSPolicy) string {
	sorted := append([]tenantRLSPolicy(nil), policies...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	h := sha256.New()
	writeField := func(s string) {
		_, _ = h.Write([]byte(s))
		_, _ = h.Write([]byte{0})
	}
	writeField(table)
	for _, p := range sorted {
		writeField(p.Name)
		writeField(p.Command)
		writeField(strings.Join(strings.Fields(p.Using), " "))
		writeField(strings.Join(strings.Fields(p.WithCheck), " "))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// rlsLivePolicy is a policy as the catalog holds it.
type rlsLivePolicy struct {
	permissive bool
	command    string
	roles      string
	qual       string
	withCheck  string
	comment    string
}

// livePolicyHash binds the desired table hash to one policy's live catalog
// definition. A source change alters tableHash; a hand edit alters the live
// fields. Either way the stored comment stops matching.
func livePolicyHash(tableHash, name string, live rlsLivePolicy) string {
	h := sha256.New()
	for _, s := range []string{tableHash, name, fmt.Sprint(live.permissive), live.command, live.roles, live.qual, live.withCheck} {
		_, _ = h.Write([]byte(s))
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// matchesDesired reports whether the policy carries the hash of the desired
// definition combined with what the catalog holds now.
func (l rlsLivePolicy) matchesDesired(tableHash string, p tenantRLSPolicy) bool {
	return l.comment == rlsDefCommentPrefix+livePolicyHash(tableHash, p.Name, l)
}

// rlsTableState is the catalog view of one table's RLS configuration.
type rlsTableState struct {
	rowSecurity      bool
	forceRowSecurity bool
	policies         map[string]rlsLivePolicy
}

// needsChange reports whether any DDL is required.
func (s rlsTableState) needsChange(policies []tenantRLSPolicy, tableHash string) bool {
	if !s.rowSecurity || !s.forceRowSecurity {
		return true
	}
	if _, legacy := s.policies[rlsLegacyPolicyName]; legacy {
		return true
	}
	for _, p := range policies {
		live, ok := s.policies[p.Name]
		if !ok || !live.matchesDesired(tableHash, p) {
			return true
		}
	}
	return false
}

// rlsQuerier is satisfied by both *sql.DB and *sql.Tx.
type rlsQuerier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// readTenantRLSState reads the table's RLS flags and policies from the catalog.
// quotedTable is resolved through the connection's search_path, the same way the
// DDL that created the table resolved it. No lock is taken on the table.
func readTenantRLSState(ctx context.Context, q rlsQuerier, quotedTable string) (rlsTableState, error) {
	state := rlsTableState{policies: map[string]rlsLivePolicy{}}
	err := q.QueryRowContext(ctx,
		`SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = to_regclass($1)`,
		quotedTable).Scan(&state.rowSecurity, &state.forceRowSecurity)
	if errors.Is(err, sql.ErrNoRows) {
		return state, fmt.Errorf("table %s does not exist", quotedTable)
	}
	if err != nil {
		return state, err
	}

	rows, err := q.QueryContext(ctx, `
		SELECT p.polname::text,
		       p.polpermissive,
		       p.polcmd::text,
		       array_to_string(ARRAY(
		           SELECT CASE WHEN r = 0 THEN 'public' ELSE pg_get_userbyid(r) END
		           FROM unnest(p.polroles) AS r ORDER BY 1), ','),
		       coalesce(pg_get_expr(p.polqual, p.polrelid), ''),
		       coalesce(pg_get_expr(p.polwithcheck, p.polrelid), ''),
		       coalesce(obj_description(p.oid, 'pg_policy'), '')
		FROM pg_policy p
		WHERE p.polrelid = to_regclass($1)`, quotedTable)
	if err != nil {
		return state, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var name string
		var live rlsLivePolicy
		if err := rows.Scan(&name, &live.permissive, &live.command, &live.roles,
			&live.qual, &live.withCheck, &live.comment); err != nil {
			return state, err
		}
		state.policies[name] = live
	}
	return state, rows.Err()
}

// standardTenantPolicies is the policy set shared by every tenant-isolated table
// except steward_records.
func standardTenantPolicies() []tenantRLSPolicy {
	return []tenantRLSPolicy{
		// SELECT: permissive when no tenant context is set (auth lookups, by-ID
		// reads, cross-tenant startup sweeps), filtered when a context is set.
		{
			Name: "rls_read", Command: "SELECT",
			Using: `coalesce(current_setting('app.current_tenant', true), '') = ''
			OR tenant_id = current_setting('app.current_tenant', true)`,
		},
		// INSERT: the tenant must be set in the transaction before inserting.
		{
			Name: "rls_write", Command: "INSERT",
			WithCheck: `tenant_id = current_setting('app.current_tenant', true)`,
		},
		// UPDATE/DELETE (Issue #4321): the target row must belong to the caller's
		// current tenant, and an UPDATE may not move a row to a different tenant --
		// an unset tenant matches nothing (fail closed), not every row.
		{
			Name: "rls_update", Command: "UPDATE",
			Using:     `tenant_id = current_setting('app.current_tenant', true)`,
			WithCheck: `tenant_id = current_setting('app.current_tenant', true)`,
		},
		{
			Name: "rls_delete", Command: "DELETE",
			Using: `tenant_id = current_setting('app.current_tenant', true)`,
		},
	}
}
