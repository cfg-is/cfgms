// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package credentials

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/logging"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type fixture struct {
	t        *testing.T
	cfg      cfgconfig.ConfigStore
	secrets  secretsif.SecretStore
	secDir   string
	clock    *testClock
	store    CredentialStore
	svc      *Service
	auditMgr *audit.Manager
}

// newFixture builds the store and service over the real flatfile config store and
// a real SOPS secret store in per-test temp directories.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	cfg := pkgtesting.SetupTestStorage(t).GetConfigStore()

	base := t.TempDir()
	secDir := filepath.Join(base, "data")
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	keyPath := filepath.Join(base, "secrets.key")
	require.NoError(t, os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(key)), 0o600))
	secrets, err := secretsif.CreateSecretStoreFromConfig("sops", map[string]interface{}{
		"storage_provider": "flatfile",
		"storage_config":   map[string]interface{}{"root": secDir},
		"cache_enabled":    false,
		"key_file":         keyPath,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = secrets.Close() })

	clock := &testClock{t: time.Now()}
	store, err := NewStore(cfg, secrets, WithClock(clock.Now))
	require.NoError(t, err)
	auditMgr := pkgtesting.SetupTestAuditManager(t)
	svc, err := NewService(store, ConfigBindingChecker{Store: cfg}, logging.NewNoopLogger(),
		WithServiceClock(clock.Now), WithAudit(auditMgr))
	require.NoError(t, err)
	return &fixture{t: t, cfg: cfg, secrets: secrets, secDir: secDir, clock: clock, store: store, svc: svc, auditMgr: auditMgr}
}

func (f *fixture) getSecret(k Key, id string) (*secretsif.Secret, error) {
	return f.secrets.(secretsif.TenantSecretAccessor).GetTenantSecret(context.Background(), k.TenantID, secretName(k, id))
}

func (f *fixture) bind(key Key) {
	f.t.Helper()
	require.NoError(f.t, f.cfg.StoreConfig(context.Background(), &cfgconfig.ConfigEntry{
		Key: BindingConfigKey(key), Data: []byte(`{"guid":"x"}`), Format: cfgconfig.ConfigFormatJSON,
	}))
}

func (f *fixture) auditActions(action string) []*business.AuditEntry {
	f.t.Helper()
	require.NoError(f.t, f.auditMgr.Flush(context.Background()))
	entries, err := f.auditMgr.QueryEntries(context.Background(), &business.AuditFilter{Actions: []string{action}})
	require.NoError(f.t, err)
	return entries
}

var testKey = Key{TenantID: "tenant-a", StewardID: "steward-1", ResourceID: "user-jdoe"}

func TestGeneratePassword_MeetsComplexity(t *testing.T) {
	const samples = 3000
	symbolCount := map[rune]int{}
	seen := map[string]bool{}
	for i := 0; i < samples; i++ {
		pw, err := GeneratePassword()
		require.NoError(t, err)
		require.Len(t, pw, PasswordLength)
		assert.False(t, seen[pw], "passwords must not repeat")
		seen[pw] = true

		var upper, lower, digit, symbol int
		for _, r := range pw {
			switch {
			case strings.ContainsRune(upperChars, r):
				upper++
			case strings.ContainsRune(lowerChars, r):
				lower++
			case strings.ContainsRune(digitChars, r):
				digit++
			case strings.ContainsRune(symbolChars, r):
				symbol++
				symbolCount[r]++
			default:
				t.Fatalf("character %q outside every class", r)
			}
		}
		require.Positive(t, upper)
		require.Positive(t, lower)
		require.Positive(t, digit)
		require.Positive(t, symbol)
	}
	// Uniform within a class: every symbol appears, near the mean.
	total := 0
	for _, n := range symbolCount {
		total += n
	}
	mean := float64(total) / float64(len(symbolChars))
	require.Len(t, symbolCount, len(symbolChars))
	for r, n := range symbolCount {
		assert.InDelta(t, mean, float64(n), mean*0.25, "symbol %q frequency", r)
	}
}

func TestCredentialStore_PutGetClaimDelete(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	_, err := f.store.Get(ctx, testKey)
	require.ErrorIs(t, err, ErrNotFound)

	id, err := NewRecordID()
	require.NoError(t, err)
	assert.Len(t, id, 32, "128-bit id, hex")
	now := f.clock.Now()
	rec := &Record{ID: id, TenantID: testKey.TenantID, StewardID: testKey.StewardID, ResourceID: testKey.ResourceID,
		CreatedAt: now, ExpiresAt: now.Add(DefaultTTL), State: StatePending}
	require.NoError(t, f.store.Put(ctx, rec, "pw-one", nil))
	id2, err := NewRecordID()
	require.NoError(t, err)
	rival := *rec
	rival.ID = id2
	require.ErrorIs(t, f.store.Put(ctx, &rival, "pw-two", nil), ErrExists)
	_, err = f.getSecret(testKey, id2)
	require.ErrorIs(t, err, secretsif.ErrSecretNotFound, "a losing Put leaves no secret behind")

	got, err := f.store.Get(ctx, testKey)
	require.NoError(t, err)
	assert.Equal(t, "pw-one", got.Password)
	assert.NotContains(t, fmt.Sprintf("%v %+v %#v %s", got, got, got, got), "pw-one")

	// Exactly one concurrent Claim wins.
	var wins, conflicts int
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, cerr := f.store.Claim(ctx, testKey, id, StatePending, StateRevealing)
			mu.Lock()
			defer mu.Unlock()
			switch cerr {
			case nil:
				wins++
			case ErrConflict:
				conflicts++
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, 1, wins)
	assert.Equal(t, 7, conflicts)

	_, err = f.store.Claim(ctx, testKey, id, StateRevealed, StatePending)
	require.Error(t, err, "revealed is terminal")

	list, err := f.store.List(ctx, Filter{TenantID: testKey.TenantID, State: StateRevealing})
	require.NoError(t, err)
	require.Len(t, list, 1)

	require.NoError(t, f.store.Delete(ctx, testKey))
	_, err = f.store.Get(ctx, testKey)
	require.ErrorIs(t, err, ErrNotFound)
	_, err = f.getSecret(testKey, id)
	require.ErrorIs(t, err, secretsif.ErrSecretNotFound)
}

func TestCredentialStore_RejectsUnsafeKeys(t *testing.T) {
	f := newFixture(t)
	for _, k := range []Key{
		{TenantID: "t", StewardID: "../x", ResourceID: "r"},
		{TenantID: "t", StewardID: "s", ResourceID: "a/b"},
		{TenantID: "", StewardID: "s", ResourceID: "r"},
		{TenantID: "t", StewardID: "s", ResourceID: ""},
	} {
		_, err := f.store.Get(context.Background(), k)
		require.ErrorIs(t, err, ErrInvalidKey, "%+v", k)
	}
}

func TestCredentialExpiry_DeletesSecretAndAudits(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	pw, err := f.svc.Issue(ctx, testKey)
	require.NoError(t, err)
	cred, err := f.store.Get(ctx, testKey)
	require.NoError(t, err)
	_, err = f.getSecret(testKey, cred.ID)
	require.NoError(t, err, "secret exists before expiry")

	// Not yet expired: the sweep leaves it alone.
	n, err := f.svc.Sweep(ctx)
	require.NoError(t, err)
	assert.Zero(t, n)

	f.clock.Advance(DefaultTTL + time.Minute)
	n, err = f.svc.Sweep(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n)

	_, err = f.getSecret(testKey, cred.ID)
	require.ErrorIs(t, err, secretsif.ErrSecretNotFound, "expired secret is deleted")
	after, err := f.store.Get(ctx, testKey)
	require.NoError(t, err)
	assert.Equal(t, StateExpired, after.State)
	assert.Empty(t, after.Password)

	events := f.auditActions("credential_expired_unrevealed")
	require.Len(t, events, 1)
	assert.Equal(t, testKey.TenantID, events[0].TenantID)
	assert.NotContains(t, fmt.Sprintf("%+v", events[0]), pw)

	// A second sweep neither re-audits nor errors.
	n, err = f.svc.Sweep(ctx)
	require.NoError(t, err)
	assert.Zero(t, n)
	assert.Len(t, f.auditActions("credential_expired_unrevealed"), 1)

	// An expired record is replaced by a fresh password.
	pw2, err := f.svc.Issue(ctx, testKey)
	require.NoError(t, err)
	assert.NotEqual(t, pw, pw2)
}

func TestCredentialExpiry_RevealedRecordKeepsRefusal(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, err := f.svc.Issue(ctx, testKey)
	require.NoError(t, err)
	cred, err := f.store.Get(ctx, testKey)
	require.NoError(t, err)
	_, err = f.store.Claim(ctx, testKey, cred.ID, StatePending, StateRevealing)
	require.NoError(t, err)
	_, err = f.store.Claim(ctx, testKey, cred.ID, StateRevealing, StateRevealed)
	require.NoError(t, err)
	f.bind(testKey)

	f.clock.Advance(DefaultTTL + time.Minute)
	n, err := f.svc.Sweep(ctx)
	require.NoError(t, err)
	assert.Zero(t, n, "a revealed record is not expired")
	_, err = f.getSecret(testKey, cred.ID)
	require.ErrorIs(t, err, secretsif.ErrSecretNotFound)
	assert.Empty(t, f.auditActions("credential_expired_unrevealed"), "revealed expiry is not an unrevealed expiry")

	_, err = f.svc.Issue(ctx, testKey)
	require.ErrorIs(t, err, ErrAlreadyIssued)
}
