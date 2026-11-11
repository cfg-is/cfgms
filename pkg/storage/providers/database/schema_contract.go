// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// contractStatementTimeout bounds every statement of a contract step. Contract steps
// run while sharedPool holds poolMu, so a stuck database must not be able to hold the
// provider-wide mutex indefinitely. It is a deadline on the whole statement, in
// addition to the server-side lock_timeout, which only bounds lock waits.
const contractStatementTimeout = 30 * time.Second

// contractLockTimeout is the lock_timeout set (SET LOCAL) inside every step
// transaction, so a step that cannot get a lock fails fast instead of queueing behind
// long transactions and stalling live traffic behind its own queued lock request.
const contractLockTimeout = "5s"

// ErrContractStepBlocked is wrapped by the error ApplyContractSteps returns when a
// step was not applied because a live node still needs the old schema shape. It is
// not a failure: a rolling deploy is exactly this state. sharedPool logs it and
// continues.
var ErrContractStepBlocked = errors.New("database contract step blocked by a node that still needs the old schema")

// ErrInvalidContractStep is wrapped by the error ApplyContractSteps returns for a
// malformed step list. It is returned before the database is touched.
var ErrInvalidContractStep = errors.New("invalid database contract step")

// ContractStep removes or narrows schema that older nodes may still use: it drops or
// narrows a column, table, constraint or index. It is the only kind of schema change
// that cannot be rolled back by running the previous release, so it is the only one
// that ApplyContractSteps guards.
//
// The rule: a step is applied only when no live node needs the old shape. A node needs
// the old shape when its schema version is below UnusedSince. That covers a node that
// is registered in cfgms_node_registry and live, and a node that passed the
// schema-version gate within business.NodeRegistryStaleAfter but has not registered
// yet. A node exactly at UnusedSince does not block, so a normal roll (N-1 beside N)
// can proceed and rollback by one version still works.
//
// Applying a step raises the database's contract floor (min_node_version) to
// UnusedSince, so a node older than UnusedSince that starts later is refused by the
// schema-version gate rather than running against a schema it cannot use.
//
// A step is valid only when 1 <= UnusedSince < Version <= the node's SchemaVersion.
//
// Statements run in one transaction (the step is atomic) under a 5s lock_timeout.
// Because a transaction cannot contain DROP INDEX CONCURRENTLY, a step that drops an
// index uses plain DROP INDEX and relies on that lock_timeout to fail fast.
type ContractStep struct {
	// Version is the schema version this step belongs to. Steps apply in ascending
	// Version order, and a step whose Version is at or below the recorded
	// contract_applied is skipped.
	Version int
	// UnusedSince is the contract marker: the schema version at which the old shape
	// stopped being used. The step raises the contract floor to this value.
	UnusedSince int
	// Description says what the step removes and why it is safe.
	Description string
	// Statements are run in order inside the step transaction.
	Statements []string
}

// contractSteps is the production step list. It is empty: the first contract step
// ships with a later schema change.
var contractSteps = []ContractStep{}

// validateContractSteps checks every step against r before any database access and
// returns the steps in ascending Version order.
func validateContractSteps(r schemaRange, steps []ContractStep) ([]ContractStep, error) {
	ordered := make([]ContractStep, len(steps))
	copy(ordered, steps)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Version < ordered[j].Version })

	for i, s := range ordered {
		if s.UnusedSince < 1 || s.UnusedSince >= s.Version || s.Version > r.SchemaVersion {
			return nil, fmt.Errorf("%w: step version %d with unused-since %d must satisfy 1 <= unused-since < version <= schema version %d",
				ErrInvalidContractStep, s.Version, s.UnusedSince, r.SchemaVersion)
		}
		if i > 0 && ordered[i-1].Version == s.Version {
			return nil, fmt.Errorf("%w: step version %d is listed more than once", ErrInvalidContractStep, s.Version)
		}
	}
	return ordered, nil
}

// ApplyContractSteps applies, in ascending Version order, every step of steps whose
// Version is above the recorded contract_applied, and only while no live node needs
// the old shape (see ContractStep). Production passes the package list (empty today)
// and the package schemaRange; tests pass their own.
//
// Each step runs in its own transaction that first locks the cfgms_schema_version row.
// The schema-version gate locks the same row, so either the gate runs first and the
// guard sees the node it admitted, or the guard raises the floor first and the gate
// refuses that node. Racing nodes serialise on it too, so a step applies exactly once.
//
// A step is blocked when a live row in cfgms_node_registry has schema_required below
// UnusedSince (a row of 0, written by a node that predates the column, blocks by
// design: fail closed), or when a node passed the gate within the staleness window
// without registering yet. A blocked step is not applied, nothing is changed, and the
// returned error wraps ErrContractStepBlocked and names the blocking nodes. Later
// steps are not attempted.
//
// A blocked step is not retried by this process, and there is no timer. It applies on
// the next node start after the older nodes' registry rows go stale. The restarting
// node's own pre-restart row, fresh for up to business.NodeRegistryStaleAfter, blocks
// it too. A contract therefore ships a release later; this is accepted.
//
// Any other error (a statement failure, or a lock timeout) rolls the step back and is
// returned unwrapped by ErrContractStepBlocked.
//
// The caller (sharedPool) holds the provider-wide pool mutex, so every statement is
// bounded by contractStatementTimeout and every step transaction by a lock_timeout.
func ApplyContractSteps(ctx context.Context, db *sql.DB, r schemaRange, steps []ContractStep) error {
	ordered, err := validateContractSteps(r, steps)
	if err != nil {
		return err
	}
	for _, step := range ordered {
		if err := applyContractStep(ctx, db, step); err != nil {
			return err
		}
	}
	return nil
}

// applyContractStep applies one step in its own transaction.
func applyContractStep(ctx context.Context, db *sql.DB, step ContractStep) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("contract step %d: begin transaction: %w", step.Version, err)
	}
	if err := runContractStep(ctx, tx, step); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("contract step %d: commit: %w", step.Version, err)
	}
	return nil
}

// stmtExec runs one statement under contractStatementTimeout.
func stmtExec(ctx context.Context, tx *sql.Tx, query string, args ...any) error {
	ctx, cancel := context.WithTimeout(ctx, contractStatementTimeout)
	defer cancel()
	_, err := tx.ExecContext(ctx, query, args...)
	return err
}

// contractState is the part of the version row a step decision reads.
type contractState struct {
	applied      int64
	gateRequired sql.NullInt64
	gateIsRecent bool
}

// lockContractState locks the version row and reads it. The lock serialises racing
// nodes and the schema-version gate, which locks the same row.
func lockContractState(ctx context.Context, tx *sql.Tx) (contractState, error) {
	ctx, cancel := context.WithTimeout(ctx, contractStatementTimeout)
	defer cancel()

	var st contractState
	var applied sql.NullInt64
	err := tx.QueryRowContext(ctx, `
		SELECT contract_applied, recent_gate_required,
		       COALESCE(recent_gate_at >= now() - ($1::double precision * interval '1 second'), false)
		FROM cfgms_schema_version WHERE id = 1 FOR UPDATE`,
		business.NodeRegistryStaleAfter.Seconds(),
	).Scan(&applied, &st.gateRequired, &st.gateIsRecent)
	st.applied = applied.Int64
	return st, err
}

// contractBlockers describes every live node that still needs the old shape of step:
// registered nodes below step.UnusedSince, and a recent gate pass below it from a node
// that has not registered yet (invisible to the registry).
func contractBlockers(ctx context.Context, tx *sql.Tx, step ContractStep, st contractState) ([]string, error) {
	blockers, err := liveNodesBelow(ctx, tx, step.UnusedSince)
	if err != nil {
		return nil, err
	}
	if st.gateIsRecent && st.gateRequired.Valid && st.gateRequired.Int64 < int64(step.UnusedSince) {
		blockers = append(blockers, fmt.Sprintf("a node that passed the schema-version gate at schema version %d and has not registered", st.gateRequired.Int64))
	}
	return blockers, nil
}

// runContractStep is the body of a step transaction; the caller commits or rolls back.
func runContractStep(ctx context.Context, tx *sql.Tx, step ContractStep) error {
	if err := stmtExec(ctx, tx, `SET LOCAL lock_timeout = '`+contractLockTimeout+`'`); err != nil {
		return fmt.Errorf("contract step %d: set lock timeout: %w", step.Version, err)
	}

	st, err := lockContractState(ctx, tx)
	if err != nil {
		return fmt.Errorf("contract step %d: lock version row: %w", step.Version, err)
	}
	// The floor cannot say what was applied: a later step may have a smaller
	// UnusedSince, so contract_applied is the record.
	if int64(step.Version) <= st.applied {
		return nil
	}

	blockers, err := contractBlockers(ctx, tx, step, st)
	if err != nil {
		return fmt.Errorf("contract step %d: %w", step.Version, err)
	}
	if len(blockers) > 0 {
		return fmt.Errorf("%w: step version %d (%s) needs every live node at schema version %d or later, blocked by: %s",
			ErrContractStepBlocked, step.Version, step.Description, step.UnusedSince, strings.Join(blockers, "; "))
	}

	for i, stmt := range step.Statements {
		if err := stmtExec(ctx, tx, stmt); err != nil {
			return fmt.Errorf("contract step %d: statement %d: %w", step.Version, i+1, err)
		}
	}
	if err := stmtExec(ctx, tx, `
		UPDATE cfgms_schema_version SET
			min_node_version = GREATEST(min_node_version, $1::integer),
			contract_applied = GREATEST(contract_applied, $2::integer),
			updated_at = now()
		WHERE id = 1`, step.UnusedSince, step.Version); err != nil {
		return fmt.Errorf("contract step %d: record step: %w", step.Version, err)
	}
	return nil
}

// liveNodesBelow describes every live registry node whose schema_required is below
// unusedSince. Liveness uses the database clock and the window of
// business.NodeRegistryStaleAfter, as ListNodes does.
//
// The registry is created by the node registry store constructor, which runs after
// sharedPool, so the table can be absent (no registered nodes) and, when an older
// revision created it, can exist without schema_required. Each case is detected from
// the catalog rather than inferred from a query error. A table without the column is
// read as schema_required = 0 for every live row, which blocks (fail closed).
func liveNodesBelow(ctx context.Context, tx *sql.Tx, unusedSince int) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, contractStatementTimeout)
	defer cancel()

	var tableExists, columnExists bool
	if err := tx.QueryRowContext(ctx, `
		SELECT to_regclass('cfgms_node_registry') IS NOT NULL,
		       EXISTS (SELECT 1 FROM information_schema.columns
		               WHERE table_schema = current_schema()
		                 AND table_name = 'cfgms_node_registry'
		                 AND column_name = 'schema_required')`,
	).Scan(&tableExists, &columnExists); err != nil {
		return nil, fmt.Errorf("inspect node registry: %w", err)
	}
	if !tableExists {
		return nil, nil
	}

	versionExpr := "0::integer"
	if columnExists {
		versionExpr = "schema_required"
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT node_id, `+versionExpr+` FROM cfgms_node_registry
		WHERE updated_at >= now() - ($1::double precision * interval '1 second')
		  AND `+versionExpr+` < $2::integer
		ORDER BY node_id`,
		business.NodeRegistryStaleAfter.Seconds(), unusedSince)
	if err != nil {
		return nil, fmt.Errorf("read node registry: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var blockers []string
	for rows.Next() {
		var id string
		var version int
		if err := rows.Scan(&id, &version); err != nil {
			return nil, fmt.Errorf("scan node registry: %w", err)
		}
		blockers = append(blockers, fmt.Sprintf("node %q at schema version %d", id, version))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read node registry: %w", err)
	}
	return blockers, nil
}
