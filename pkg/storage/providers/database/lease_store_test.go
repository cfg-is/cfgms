// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package database

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

func newTestLeaseStore(t *testing.T) *DatabaseLeaseStore {
	t.Helper()
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	schemas := NewDatabaseSchemas()
	ctx := context.Background()
	require.NoError(t, schemas.CreateLeaseTable(ctx, db))
	return &DatabaseLeaseStore{db: db, schemas: schemas}
}

func TestDatabaseLeaseStore_GetLease_NotFound(t *testing.T) {
	store := newTestLeaseStore(t)
	_, err := store.GetLease(context.Background(), "never-acquired")
	require.ErrorIs(t, err, business.ErrLeaseNotFound)
}

func TestDatabaseLeaseStore_AcquireOrRenew_FirstAcquisition(t *testing.T) {
	store := newTestLeaseStore(t)
	ctx := context.Background()

	state, err := store.AcquireOrRenew(ctx, "singleton-x", "holder-1", time.Minute)
	require.NoError(t, err)
	assert.True(t, state.Acquired)
	assert.Equal(t, uint64(1), state.Token)
	assert.Equal(t, "holder-1", state.HolderID)
	assert.True(t, state.Valid, "a freshly acquired lease must be reported valid by the database")
}

// [REQUIRED TEST] The expiry written by AcquireOrRenew is derived from the
// PostgreSQL server's clock, not the calling host's. The assertion is stated
// entirely in server-clock terms (expires_at - now(), both evaluated inside
// the database) so it holds regardless of any offset between this test
// process's wall clock and the server's — and would fail on a skewed host if
// the store went back to sending a client-computed timestamp, which is the
// fail-open split-brain this guards (ADR-029 Decision 2 / Issue #2037).
func TestDatabaseLeaseStore_AcquireOrRenew_ExpiryDerivedFromServerClock(t *testing.T) {
	store := newTestLeaseStore(t)
	ctx := context.Background()

	const ttl = 90 * time.Second
	_, err := store.AcquireOrRenew(ctx, "singleton-x", "holder-1", ttl)
	require.NoError(t, err)

	var remainingSeconds float64
	require.NoError(t, store.db.QueryRowContext(ctx,
		`SELECT EXTRACT(EPOCH FROM (expires_at - now())) FROM cfgms_leases WHERE name = $1`,
		"singleton-x").Scan(&remainingSeconds))

	assert.InDelta(t, ttl.Seconds(), remainingSeconds, 10,
		"expires_at must sit one full TTL ahead of the database server's own now()")
}

// [REQUIRED TEST] GetLease reports validity as computed by the database
// against its own now(), so a caller never has to (and must never) compare the
// stored timestamp to its own clock. Rows are planted with server-relative
// expiries, so the test never references the client clock either.
func TestDatabaseLeaseStore_GetLease_ValidityComputedByServer(t *testing.T) {
	store := newTestLeaseStore(t)
	ctx := context.Background()

	// Both rows are planted relative to the server's own now(), so the test
	// never expresses an expiry in this host's clock.
	_, err := store.db.ExecContext(ctx,
		`INSERT INTO cfgms_leases (name, holder_id, token, expires_at)
		 VALUES ('live-lease', 'holder-1', 1, now() + interval '1 hour'),
		        ('stale-lease', 'holder-1', 1, now() - interval '1 hour')`)
	require.NoError(t, err)

	live, err := store.GetLease(ctx, "live-lease")
	require.NoError(t, err)
	assert.True(t, live.Valid, "a row expiring an hour after server now() must be reported valid")

	stale, err := store.GetLease(ctx, "stale-lease")
	require.NoError(t, err)
	assert.False(t, stale.Valid, "a row that expired an hour before server now() must be reported invalid")
	assert.Equal(t, "holder-1", stale.HolderID, "the last holder stays visible on an expired row")
}

// [REQUIRED TEST] Structural guard for the invariant above: no caller-side
// wall clock may reach the lease SQL. This runs even where no PostgreSQL test
// database is reachable (every behavioral test in this file skips there), so
// the regression cannot land unnoticed. Elapsed-time helpers are unaffected —
// the ban is on time.Now, the absolute wall clock.
func TestDatabaseLeaseStore_NoClientClockInLeaseAuthorityPath(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "lease_store.go", nil, 0)
	require.NoError(t, err)

	guarded := map[string]bool{"AcquireOrRenew": true, "getLease": true, "GetLease": true, "Release": true}

	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || !guarded[fn.Name.Name] {
			return true
		}
		ast.Inspect(fn.Body, func(inner ast.Node) bool {
			sel, ok := inner.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			assert.False(t, pkg.Name == "time" && sel.Sel.Name == "Now",
				"%s must not read this host's wall clock: expiry and validity are derived by the database server, "+
					"and a cross-host clock offset must never enter a lease authority decision", fn.Name.Name)
			return true
		})
		return false
	})
}

func TestDatabaseLeaseStore_AcquireOrRenew_RenewByCurrentHolderKeepsToken(t *testing.T) {
	store := newTestLeaseStore(t)
	ctx := context.Background()

	first, err := store.AcquireOrRenew(ctx, "singleton-x", "holder-1", time.Second)
	require.NoError(t, err)

	second, err := store.AcquireOrRenew(ctx, "singleton-x", "holder-1", time.Second)
	require.NoError(t, err)
	assert.True(t, second.Acquired)
	assert.Equal(t, first.Token, second.Token, "renew by the current holder must never change the fencing token")
}

func TestDatabaseLeaseStore_AcquireOrRenew_ContendedByDifferentHolder(t *testing.T) {
	store := newTestLeaseStore(t)
	ctx := context.Background()

	first, err := store.AcquireOrRenew(ctx, "singleton-x", "holder-1", time.Minute)
	require.NoError(t, err)
	require.True(t, first.Acquired)

	second, err := store.AcquireOrRenew(ctx, "singleton-x", "holder-2", time.Minute)
	require.NoError(t, err)
	assert.False(t, second.Acquired, "a second holder must not acquire an unexpired lease held by someone else")
	assert.Equal(t, "holder-1", second.HolderID)
	assert.Equal(t, first.Token, second.Token)
}

// [REQUIRED TEST] Fencing-token monotonicity: a lease acquired, allowed to
// expire, and re-acquired by a different holder yields a strictly greater
// token than the first holder ever held.
func TestDatabaseLeaseStore_FencingTokenMonotonicity_AcrossExpiry(t *testing.T) {
	store := newTestLeaseStore(t)
	ctx := context.Background()

	first, err := store.AcquireOrRenew(ctx, "singleton-x", "holder-1", 200*time.Millisecond)
	require.NoError(t, err)
	require.True(t, first.Acquired)

	time.Sleep(300 * time.Millisecond)

	second, err := store.AcquireOrRenew(ctx, "singleton-x", "holder-2", time.Minute)
	require.NoError(t, err)
	require.True(t, second.Acquired)
	assert.Greater(t, second.Token, first.Token,
		"a token issued to an expired holder must be strictly lower than the token issued to the next holder")
}

func TestDatabaseLeaseStore_FencingTokenMonotonicity_SameHolderReacquiringAfterExpiry(t *testing.T) {
	store := newTestLeaseStore(t)
	ctx := context.Background()

	first, err := store.AcquireOrRenew(ctx, "singleton-x", "holder-1", 200*time.Millisecond)
	require.NoError(t, err)
	require.True(t, first.Acquired)

	time.Sleep(300 * time.Millisecond)

	second, err := store.AcquireOrRenew(ctx, "singleton-x", "holder-1", time.Minute)
	require.NoError(t, err)
	require.True(t, second.Acquired)
	assert.Greater(t, second.Token, first.Token,
		"even the same holder re-acquiring after its own lease expired must receive a strictly greater token")
}

func TestDatabaseLeaseStore_Release_PreservesTokenAsHighWaterMark(t *testing.T) {
	store := newTestLeaseStore(t)
	ctx := context.Background()

	first, err := store.AcquireOrRenew(ctx, "singleton-x", "holder-1", time.Minute)
	require.NoError(t, err)

	require.NoError(t, store.Release(ctx, "singleton-x", "holder-1", first.Token))

	second, err := store.AcquireOrRenew(ctx, "singleton-x", "holder-2", time.Minute)
	require.NoError(t, err)
	require.True(t, second.Acquired)
	assert.Greater(t, second.Token, first.Token)
}

func TestDatabaseLeaseStore_Release_StaleTokenIsNoOp(t *testing.T) {
	store := newTestLeaseStore(t)
	ctx := context.Background()

	first, err := store.AcquireOrRenew(ctx, "singleton-x", "holder-1", time.Minute)
	require.NoError(t, err)

	require.NoError(t, store.Release(ctx, "singleton-x", "holder-1", first.Token+1))

	current, err := store.GetLease(ctx, "singleton-x")
	require.NoError(t, err)
	assert.Equal(t, "holder-1", current.HolderID)
	assert.Equal(t, first.Token, current.Token)
}

// [REQUIRED TEST] Concurrent TryAcquire calls for the same lease name from
// multiple goroutines against one real database result in exactly one
// winner. Goroutines share the store's *sql.DB connection pool, so this
// exercises real concurrent connections against PostgreSQL, not
// in-process serialization.
func TestDatabaseLeaseStore_ConcurrentAcquire_ExactlyOneWinner(t *testing.T) {
	store := newTestLeaseStore(t)
	ctx := context.Background()

	const n = 20
	var wg sync.WaitGroup
	results := make([]*business.LeaseState, n)
	errs := make([]error, n)

	var ready sync.WaitGroup
	ready.Add(n)
	start := make(chan struct{})

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			holderID := "holder-" + string(rune('A'+i))
			ready.Done()
			<-start
			results[i], errs[i] = store.AcquireOrRenew(ctx, "contended-singleton", holderID, time.Minute)
		}(i)
	}

	ready.Wait()
	close(start)
	wg.Wait()

	winners := 0
	var winningToken uint64
	for i := 0; i < n; i++ {
		require.NoError(t, errs[i])
		if results[i].Acquired {
			winners++
			winningToken = results[i].Token
		}
	}
	assert.Equal(t, 1, winners, "exactly one goroutine must win contention for a fresh lease")

	current, err := store.GetLease(ctx, "contended-singleton")
	require.NoError(t, err)
	assert.Equal(t, winningToken, current.Token)
}

// TestDatabaseLeaseStore_ConcurrentAcquire_AfterExpiryTokensStrictlyIncrease
// hammers AcquireOrRenew from many goroutines across several expiry cycles
// and asserts the token sequence issued to winners is strictly increasing
// with no repeats — the monotonicity property under real contention, not
// just in the uncontended two-step case above.
func TestDatabaseLeaseStore_ConcurrentAcquire_AfterExpiryTokensStrictlyIncrease(t *testing.T) {
	store := newTestLeaseStore(t)
	ctx := context.Background()

	const rounds = 5
	const gorosPerRound = 8
	ttl := 30 * time.Millisecond

	var issuedTokens []uint64
	for r := 0; r < rounds; r++ {
		var wg sync.WaitGroup
		results := make([]*business.LeaseState, gorosPerRound)
		errs := make([]error, gorosPerRound)

		for i := 0; i < gorosPerRound; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				holderID := "holder-" + string(rune('A'+i))
				results[i], errs[i] = store.AcquireOrRenew(ctx, "cyclic-singleton", holderID, ttl)
			}(i)
		}
		wg.Wait()

		var roundWinners []uint64
		for i := 0; i < gorosPerRound; i++ {
			require.NoError(t, errs[i])
			if results[i].Acquired {
				roundWinners = append(roundWinners, results[i].Token)
			}
		}
		require.Len(t, roundWinners, 1, "exactly one winner per round")
		issuedTokens = append(issuedTokens, roundWinners[0])

		time.Sleep(ttl + 20*time.Millisecond) // let the round's winner expire before the next round
	}

	for i := 1; i < len(issuedTokens); i++ {
		assert.Greater(t, issuedTokens[i], issuedTokens[i-1],
			"tokens issued across successive expiry cycles must be strictly increasing")
	}
}

// TestDatabaseLeaseStore_SharedAcrossNodes_True pins the substrate declaration the
// controller's cluster-mode startup gate reads (ADR-031 Decision 5): every cluster
// node connects to the same PostgreSQL instance, so contention for a lease name is
// resolved across nodes by that one server. Asserted on a bare value because the
// declaration is a property of the backend, not of a particular connection — no
// database is required to state it.
func TestDatabaseLeaseStore_SharedAcrossNodes_True(t *testing.T) {
	var store business.LeaseStore = &DatabaseLeaseStore{}
	assert.True(t, business.LeaseStoreIsNodeShared(store),
		"the shared PostgreSQL backend is the only substrate that can carry cluster leadership")
}
