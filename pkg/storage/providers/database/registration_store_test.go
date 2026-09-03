// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package database

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

func newTestRegistrationStore(t *testing.T) *DatabaseRegistrationTokenStore {
	t.Helper()
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	schemas := NewDatabaseSchemas()
	ctx := context.Background()
	require.NoError(t, schemas.CreateRegistrationTokensTable(ctx, db))
	return &DatabaseRegistrationTokenStore{db: db, config: nil, schemas: schemas}
}

func TestDatabaseRegistrationStore_RotateToken_Basic(t *testing.T) {
	store := newTestRegistrationStore(t)
	ctx := context.Background()

	seed := &business.RegistrationTokenData{
		Token:         "db-rotate-seed",
		TenantID:      "tenant-rotate",
		ControllerURL: "grpc://controller:7443",
		Group:         "prod",
		CreatedAt:     time.Now().UTC(),
	}
	require.NoError(t, store.SaveToken(ctx, seed))

	newTok, err := store.RotateToken(ctx, "tenant-rotate", "prod")
	require.NoError(t, err)
	assert.NotEmpty(t, newTok.Token)
	assert.NotEqual(t, seed.Token, newTok.Token)
	assert.Equal(t, "tenant-rotate", newTok.TenantID)
	assert.Equal(t, "grpc://controller:7443", newTok.ControllerURL)
	assert.Equal(t, "prod", newTok.Group)

	// Old token must be revoked.
	old, err := store.GetToken(ctx, seed.Token)
	require.NoError(t, err)
	assert.True(t, old.Revoked)

	// New token must be valid.
	got, err := store.GetToken(ctx, newTok.Token)
	require.NoError(t, err)
	assert.True(t, got.IsValid())
}

func TestDatabaseRegistrationStore_RESTClaimIsAtomicAndRetryable(t *testing.T) {
	store := newTestRegistrationStore(t)
	ctx := context.Background()
	expires := time.Now().Add(time.Hour)
	require.NoError(t, store.SaveToken(ctx, &business.RegistrationTokenData{
		Token: "db-rest-claim-canary", TenantID: "tenant-claim",
		ControllerURL: "grpc://controller:7443", ExpiresAt: &expires,
	}))

	// One device, many concurrent attempts: exactly one may create the claim, so
	// only one private key can ever be issued to it.
	const contenders = 16
	const deviceID = "device-under-contention"
	var successes atomic.Int32
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < contenders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			created, err := store.ClaimToken(ctx, "db-rest-claim-canary", deviceID)
			if err == nil && created {
				successes.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	require.Equal(t, int32(1), successes.Load())

	created, err := store.ClaimToken(ctx, "db-rest-claim-canary", deviceID)
	require.NoError(t, err)
	assert.False(t, created, "same-device retry must not create another claim")

	// The token is perennial (Issue #1690): one device's claim must not lock the
	// rest of the fleet out of the same enrolment token.
	created, err = store.ClaimToken(ctx, "db-rest-claim-canary", "second-device")
	require.NoError(t, err)
	assert.True(t, created, "a second device must enrol on the same perennial token")

	require.NoError(t, store.ReleaseTokenClaim(ctx, "db-rest-claim-canary", deviceID))
	created, err = store.ClaimToken(ctx, "db-rest-claim-canary", deviceID)
	require.NoError(t, err)
	assert.True(t, created, "released pre-issuance claim must be retryable")

	got, err := store.GetToken(ctx, "db-rest-claim-canary")
	require.NoError(t, err)
	assert.True(t, got.IsValid(), "enrolment must not revoke the fleet token")
}

func TestDatabaseRegistrationStore_RotateToken_NoActiveTokens(t *testing.T) {
	store := newTestRegistrationStore(t)
	ctx := context.Background()

	_, err := store.RotateToken(ctx, "tenant-none", "group-none")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no active tokens found")
}

func TestDatabaseRegistrationStore_RotateToken_RevokedTokenNotCounted(t *testing.T) {
	store := newTestRegistrationStore(t)
	ctx := context.Background()

	revoked := &business.RegistrationTokenData{
		Token:         "db-already-revoked",
		TenantID:      "tenant-rev",
		ControllerURL: "grpc://controller:7443",
		Group:         "group-a",
		Revoked:       true,
		CreatedAt:     time.Now().UTC(),
	}
	require.NoError(t, store.SaveToken(ctx, revoked))

	_, err := store.RotateToken(ctx, "tenant-rev", "group-a")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no active tokens found")
}

func TestDatabaseRegistrationStore_RotateToken_Race(t *testing.T) {
	store := newTestRegistrationStore(t)
	ctx := context.Background()

	seed := &business.RegistrationTokenData{
		Token:         "db-race-seed",
		TenantID:      "tenant-race",
		ControllerURL: "grpc://controller:7443",
		Group:         "race-group",
		CreatedAt:     time.Now().UTC(),
	}
	require.NoError(t, store.SaveToken(ctx, seed))

	const goroutines = 20
	var (
		successCount atomic.Int32
		wg           sync.WaitGroup
		start        = make(chan struct{})
	)

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			<-start
			_, err := store.RotateToken(ctx, "tenant-race", "race-group")
			if err == nil {
				successCount.Add(1)
			}
		}()
	}

	close(start)
	wg.Wait()

	// All rotations must succeed (each finds the previous rotation's token as active).
	assert.Equal(t, int32(goroutines), successCount.Load(), "all concurrent rotations must succeed")

	// Exactly one valid token must remain.
	tokens, err := store.ListTokens(ctx, &business.RegistrationTokenFilter{TenantID: "tenant-race"})
	require.NoError(t, err)

	validCount := 0
	for _, tok := range tokens {
		if !tok.Revoked {
			validCount++
		}
	}
	assert.Equal(t, 1, validCount, "exactly one valid token must exist after all rotations")
}

func TestDatabaseRegistrationStore_SaveAndGetByID(t *testing.T) {
	store := newTestRegistrationStore(t)
	ctx := context.Background()

	token := &business.RegistrationTokenData{
		ID:            "aaaaaaaa-0000-4000-8000-000000000001",
		Token:         "db-byid-token",
		TenantID:      "tenant-byid",
		ControllerURL: "grpc://controller:7443",
		Group:         "prod",
		CreatedAt:     time.Now().UTC(),
	}
	require.NoError(t, store.SaveToken(ctx, token))

	// The id must round-trip through the id-addressed lookup used by the web UI.
	byID, err := store.GetTokenByID(ctx, token.ID)
	require.NoError(t, err)
	assert.Equal(t, business.RegistrationTokenLookupKey(token.Token), byID.Token)
	assert.Equal(t, token.ID, byID.ID)
	assert.Equal(t, "tenant-byid", byID.TenantID)
	assert.Equal(t, "prod", byID.Group)

	// ...and through the token-addressed lookup and the list endpoint.
	byToken, err := store.GetToken(ctx, token.Token)
	require.NoError(t, err)
	assert.Equal(t, token.ID, byToken.ID)

	listed, err := store.ListTokens(ctx, &business.RegistrationTokenFilter{TenantID: "tenant-byid"})
	require.NoError(t, err)
	require.Len(t, listed, 1)
	assert.Equal(t, token.ID, listed[0].ID)
}

func TestDatabaseRegistrationStore_GetTokenByID_NotFound(t *testing.T) {
	store := newTestRegistrationStore(t)
	ctx := context.Background()

	token := &business.RegistrationTokenData{
		ID:            "aaaaaaaa-0000-4000-8000-000000000002",
		Token:         "db-byid-nf",
		TenantID:      "tenant-byid",
		ControllerURL: "grpc://controller:7443",
		CreatedAt:     time.Now().UTC(),
	}
	require.NoError(t, store.SaveToken(ctx, token))

	// An unknown id must be reported as not-found (404 at the API), never as a
	// driver error that the handler would turn into a 500.
	_, err := store.GetTokenByID(ctx, "aaaaaaaa-0000-4000-8000-0000000000ff")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	// The secret string must not resolve through the id column.
	_, err = store.GetTokenByID(ctx, token.Token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	_, err = store.GetTokenByID(ctx, "")
	require.Error(t, err)
}

func TestDatabaseRegistrationStore_SaveToken_AssignsIDWhenMissing(t *testing.T) {
	store := newTestRegistrationStore(t)
	ctx := context.Background()

	token := &business.RegistrationTokenData{
		Token:         "db-no-id",
		TenantID:      "tenant-noid",
		ControllerURL: "grpc://controller:7443",
		CreatedAt:     time.Now().UTC(),
	}
	require.NoError(t, store.SaveToken(ctx, token))
	require.NotEmpty(t, token.ID, "SaveToken must assign an id when the caller supplies none")
	assignedID := token.ID

	byID, err := store.GetTokenByID(ctx, assignedID)
	require.NoError(t, err)
	assert.Equal(t, business.RegistrationTokenLookupKey("db-no-id"), byID.Token)

	// Upserting the same token must not reassign the id.
	resaved := &business.RegistrationTokenData{
		Token:         "db-no-id",
		TenantID:      "tenant-noid",
		ControllerURL: "grpc://controller:7443",
		CreatedAt:     token.CreatedAt,
	}
	require.NoError(t, store.SaveToken(ctx, resaved))
	assert.Equal(t, assignedID, resaved.ID, "token id must be stable across saves")
}

// TestDatabaseRegistrationStore_SaveToken_HealsEmptyStoredID covers a row whose stored id
// is the empty string rather than NULL (an out-of-band write, or a row the back-fill has
// not run against yet). Such a row is unaddressable by GetTokenByID, so the next save must
// heal it instead of preserving the empty value forever.
func TestDatabaseRegistrationStore_SaveToken_HealsEmptyStoredID(t *testing.T) {
	store := newTestRegistrationStore(t)
	ctx := context.Background()

	seed := &business.RegistrationTokenData{
		Token:         "db-empty-id",
		TenantID:      "tenant-noid",
		ControllerURL: "grpc://controller:7443",
		CreatedAt:     time.Now().UTC(),
	}
	require.NoError(t, store.SaveToken(ctx, seed))

	// Force the stored id to the empty string, bypassing the store's own assignment.
	// The token column holds the hashed lookup key (SaveToken never stores the raw
	// token string), so the WHERE clause must match on that same derived value or
	// this UPDATE silently affects zero rows.
	result, err := store.db.ExecContext(ctx,
		`UPDATE cfgms_registration_tokens SET id = '' WHERE token = $1`,
		business.RegistrationTokenLookupKey("db-empty-id"))
	require.NoError(t, err)
	rowsAffected, err := result.RowsAffected()
	require.NoError(t, err)
	require.Equal(t, int64(1), rowsAffected, "precondition setup: expected to clear the id of exactly one row")

	stale, err := store.GetToken(ctx, "db-empty-id")
	require.NoError(t, err)
	require.Empty(t, stale.ID, "precondition: the row is unaddressable by id")

	resaved := &business.RegistrationTokenData{
		Token:         "db-empty-id",
		TenantID:      "tenant-noid",
		ControllerURL: "grpc://controller:7443",
		CreatedAt:     seed.CreatedAt,
	}
	require.NoError(t, store.SaveToken(ctx, resaved))
	require.NotEmpty(t, resaved.ID, "an empty stored id must be healed, not preserved")

	byID, err := store.GetTokenByID(ctx, resaved.ID)
	require.NoError(t, err)
	assert.Equal(t, business.RegistrationTokenLookupKey("db-empty-id"), byID.Token)
}

func TestDatabaseRegistrationStore_RotateToken_AssignsID(t *testing.T) {
	store := newTestRegistrationStore(t)
	ctx := context.Background()

	seed := &business.RegistrationTokenData{
		Token:         "db-rotate-id-seed",
		TenantID:      "tenant-rotate-id",
		ControllerURL: "grpc://controller:7443",
		Group:         "prod",
		CreatedAt:     time.Now().UTC(),
	}
	require.NoError(t, store.SaveToken(ctx, seed))

	rotated, err := store.RotateToken(ctx, "tenant-rotate-id", "prod")
	require.NoError(t, err)
	require.NotEmpty(t, rotated.ID, "rotation must mint an id for the new token")
	assert.NotEqual(t, seed.ID, rotated.ID)

	got, err := store.GetTokenByID(ctx, rotated.ID)
	require.NoError(t, err)
	assert.Equal(t, business.RegistrationTokenLookupKey(rotated.Token), got.Token)
	assert.True(t, got.IsValid())

	old, err := store.GetTokenByID(ctx, seed.ID)
	require.NoError(t, err)
	assert.True(t, old.Revoked)
}

// TestDatabaseRegistrationStore_BackfillLegacyRows verifies that a table created before
// Issue #2970 gains the id column and that every pre-existing row is assigned a UUID —
// without it, legacy tokens report an empty token_id and can never be revoked or deleted
// from the web UI.
func TestDatabaseRegistrationStore_BackfillLegacyRows(t *testing.T) {
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()

	// Legacy schema: no id column.
	_, err := db.ExecContext(ctx, `
		CREATE TABLE cfgms_registration_tokens (
			token VARCHAR(255) PRIMARY KEY,
			tenant_id VARCHAR(255) NOT NULL,
			controller_url VARCHAR(1000) NOT NULL,
			group_name VARCHAR(255) DEFAULT '',
			created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			expires_at TIMESTAMP WITH TIME ZONE DEFAULT NULL,
			revoked BOOLEAN NOT NULL DEFAULT FALSE,
			revoked_at TIMESTAMP WITH TIME ZONE DEFAULT NULL
		)`)
	require.NoError(t, err)

	for _, tok := range []string{"legacy-a", "legacy-b"} {
		_, err = db.ExecContext(ctx, `
			INSERT INTO cfgms_registration_tokens (token, tenant_id, controller_url, created_at)
			VALUES ($1, 'tenant-legacy', 'grpc://controller:7443', NOW())`, tok)
		require.NoError(t, err)
	}

	schemas := NewDatabaseSchemas()
	require.NoError(t, schemas.CreateRegistrationTokensTable(ctx, db))

	store := &DatabaseRegistrationTokenStore{db: db, config: nil, schemas: schemas}
	ids := make(map[string]string, 2)
	for _, tok := range []string{"legacy-a", "legacy-b"} {
		got, err := store.GetToken(ctx, tok)
		require.NoError(t, err)
		require.NotEmpty(t, got.ID, "legacy row %q must be assigned a UUID", tok)
		assert.Regexp(t,
			`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`,
			got.ID, "backfilled id must be a UUID v4")

		byID, err := store.GetTokenByID(ctx, got.ID)
		require.NoError(t, err, "backfilled token must be addressable by id")
		assert.Equal(t, tok, byID.Token)

		ids[tok] = got.ID
	}
	assert.NotEqual(t, ids["legacy-a"], ids["legacy-b"], "each legacy row gets a distinct id")

	// Re-running schema init must be idempotent — ids stay stable.
	require.NoError(t, schemas.CreateRegistrationTokensTable(ctx, db))
	for tok, id := range ids {
		got, err := store.GetToken(ctx, tok)
		require.NoError(t, err)
		assert.Equal(t, id, got.ID, "re-running the migration must not reassign %q", tok)
	}
}

func TestDatabaseGenerateTokenID(t *testing.T) {
	const iterations = 100
	pattern := `^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`
	seen := make(map[string]struct{}, iterations)
	for i := 0; i < iterations; i++ {
		id, err := generateTokenID()
		require.NoError(t, err)
		assert.Regexp(t, pattern, id)
		_, dup := seen[id]
		require.False(t, dup, "generateTokenID must not repeat an id")
		seen[id] = struct{}{}
	}
}
