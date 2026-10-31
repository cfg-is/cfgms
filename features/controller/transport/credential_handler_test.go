// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package transport

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpccreds "google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	stewardtypes "github.com/cfgis/cfgms/features/config/stewardtypes"
	"github.com/cfgis/cfgms/features/controller/credentials"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/pkg/audit"
	cfgcert "github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// recordingLogger is a Logger that keeps every line at every level, so a test can
// prove a secret appears in none of them.
type recordingLogger struct {
	mu    sync.Mutex
	lines []string
}

func (l *recordingLogger) add(level, msg string, kv []interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf("%s %s %v", level, msg, kv))
}
func (l *recordingLogger) all() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}
func (l *recordingLogger) Debug(m string, kv ...interface{}) { l.add("DEBUG", m, kv) }
func (l *recordingLogger) Info(m string, kv ...interface{})  { l.add("INFO", m, kv) }
func (l *recordingLogger) Warn(m string, kv ...interface{})  { l.add("WARN", m, kv) }
func (l *recordingLogger) Error(m string, kv ...interface{}) { l.add("ERROR", m, kv) }
func (l *recordingLogger) Fatal(m string, kv ...interface{}) { l.add("FATAL", m, kv) }
func (l *recordingLogger) DebugCtx(_ context.Context, m string, kv ...interface{}) {
	l.add("DEBUG", m, kv)
}
func (l *recordingLogger) InfoCtx(_ context.Context, m string, kv ...interface{}) {
	l.add("INFO", m, kv)
}
func (l *recordingLogger) WarnCtx(_ context.Context, m string, kv ...interface{}) {
	l.add("WARN", m, kv)
}
func (l *recordingLogger) ErrorCtx(_ context.Context, m string, kv ...interface{}) {
	l.add("ERROR", m, kv)
}
func (l *recordingLogger) FatalCtx(_ context.Context, m string, kv ...interface{}) {
	l.add("FATAL", m, kv)
}

type credFixture struct {
	t        *testing.T
	ca       *cfgcert.CA
	cfgSvc   *service.ConfigurationServiceV2
	ctrl     *service.ControllerService
	cfgStore cfgconfig.ConfigStore
	secrets  secretsif.SecretStore
	secDir   string
	store    credentials.CredentialStore
	svc      *credentials.Service
	auditMgr *audit.Manager
	logs     *recordingLogger
	h        *CredentialHandler
	peers    map[string]context.Context
}

func newCredFixture(t *testing.T) *credFixture {
	t.Helper()
	sm := pkgtesting.SetupTestStorage(t)
	ctrl := service.NewControllerService(logging.NewNoopLogger())
	cfgSvc := service.NewConfigurationServiceV2(logging.NewNoopLogger(), sm, ctrl)
	for _, id := range []string{"tenant-x", "tenant-y"} {
		require.NoError(t, sm.GetTenantStore().CreateTenant(ctxkeys.WithSystem(context.Background()),
			&business.TenantData{ID: id, Name: id, Status: business.TenantStatusActive}))
	}

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

	cfgStore := sm.GetConfigStore()
	store, err := credentials.NewStore(cfgStore, secrets)
	require.NoError(t, err)
	auditMgr := pkgtesting.SetupTestAuditManager(t)
	logs := &recordingLogger{}
	svc, err := credentials.NewService(store, credentials.ConfigBindingChecker{Store: cfgStore}, logs, credentials.WithAudit(auditMgr))
	require.NoError(t, err)

	return &credFixture{
		t: t, ca: newTestCA(t), cfgSvc: cfgSvc, ctrl: ctrl, cfgStore: cfgStore, secrets: secrets, secDir: secDir,
		store: store, svc: svc, auditMgr: auditMgr, logs: logs,
		h:     NewCredentialHandler(svc, cfgSvc, ctrl, logs),
		peers: map[string]context.Context{},
	}
}

// steward registers a steward under tenant and stores its device configuration
// declaring one activedirectory.user resource per name.
func (f *credFixture) steward(id, tenant string, resources ...string) {
	f.t.Helper()
	require.NoError(f.t, f.ctrl.RegisterSteward(id, tenant, "localhost:4433", "connected"))
	cfg := minimalStewardConfig(id)
	for _, r := range resources {
		cfg.Resources = append(cfg.Resources, stewardtypes.ResourceConfig{
			Name: r, Module: credentials.KindActiveDirectoryUser, Config: map[string]interface{}{"sam_account_name": r},
		})
	}
	require.NoError(f.t, f.cfgSvc.SetConfiguration(ctxkeys.WithSystem(context.Background()), tenant, id, cfg))
}

func (f *credFixture) peerCtx(id string) context.Context {
	if c, ok := f.peers[id]; ok {
		return c
	}
	c := peerContextWithCA(f.t, f.ca, id)
	f.peers[id] = c
	return c
}

func (f *credFixture) issue(steward, resource string) (string, error) {
	resp, err := f.h.HandleGRPC(f.peerCtx(steward), &transportpb.IssueInitialCredentialRequest{
		ResourceId: resource, Kind: credentials.KindActiveDirectoryUser,
	})
	if err != nil {
		return "", err
	}
	return resp.GetPassword(), nil
}

func (f *credFixture) mustIssue(steward, resource string) string {
	f.t.Helper()
	pw, err := f.issue(steward, resource)
	require.NoError(f.t, err)
	require.Len(f.t, pw, credentials.PasswordLength)
	return pw
}

func (f *credFixture) key(tenant, steward, resource string) credentials.Key {
	return credentials.Key{TenantID: tenant, StewardID: steward, ResourceID: resource}
}

func (f *credFixture) reveal(k credentials.Key) {
	f.t.Helper()
	ctx := context.Background()
	cred, err := f.store.Get(ctx, k)
	require.NoError(f.t, err)
	_, err = f.store.Claim(ctx, k, cred.ID, credentials.StatePending, credentials.StateRevealing)
	require.NoError(f.t, err)
	_, err = f.store.Claim(ctx, k, cred.ID, credentials.StateRevealing, credentials.StateRevealed)
	require.NoError(f.t, err)
}

func (f *credFixture) bind(k credentials.Key) {
	f.t.Helper()
	require.NoError(f.t, f.cfgStore.StoreConfig(context.Background(), &cfgconfig.ConfigEntry{
		Key: credentials.BindingConfigKey(k), Data: []byte(`{"guid":"x"}`), Format: cfgconfig.ConfigFormatJSON,
	}))
}

func (f *credFixture) auditText() string {
	f.t.Helper()
	require.NoError(f.t, f.auditMgr.Flush(context.Background()))
	entries, err := f.auditMgr.QueryEntries(context.Background(), &business.AuditFilter{})
	require.NoError(f.t, err)
	b, err := json.Marshal(entries)
	require.NoError(f.t, err)
	return string(b)
}

// filesContaining returns every file under dir whose bytes contain needle.
func filesContaining(t *testing.T, dir, needle string) []string {
	t.Helper()
	var hits []string
	require.NoError(t, filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		if bytes.Contains(b, []byte(needle)) {
			hits = append(hits, p)
		}
		return nil
	}))
	return hits
}

func requireCode(t *testing.T, err error, code codes.Code) {
	t.Helper()
	require.Error(t, err)
	assert.Equal(t, code, status.Code(err), err.Error())
}

func TestIssueInitialCredential_StoresEncryptedAndReturnsOnce(t *testing.T) {
	f := newCredFixture(t)
	f.steward("steward-a", "tenant-x", "user-jdoe")

	pw := f.mustIssue("steward-a", "user-jdoe")

	// The secret is on disk, encrypted: some file exists, none holds the cleartext.
	files := 0
	require.NoError(t, filepath.WalkDir(f.secDir, func(_ string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			files++
		}
		return err
	}))
	assert.Positive(t, files, "the secret file exists")
	assert.Empty(t, filesContaining(t, f.secDir, pw), "the secret file must not hold the cleartext")

	// The record is in the config store without the password.
	entries, err := f.cfgStore.ListConfigs(context.Background(), &cfgconfig.ConfigFilter{TenantID: "tenant-x", Namespace: credentials.Namespace})
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.NotContains(t, string(entries[0].Data), pw)
	assert.Contains(t, string(entries[0].Data), `"state":"pending"`)

	// Once revealed and the account exists, a further issue is refused.
	k := f.key("tenant-x", "steward-a", "user-jdoe")
	f.reveal(k)
	f.bind(k)
	_, err = f.issue("steward-a", "user-jdoe")
	requireCode(t, err, codes.FailedPrecondition)
	assert.Contains(t, err.Error(), "already issued")
}

func TestIssueInitialCredential_RepeatReturnsSamePasswordWhilePending(t *testing.T) {
	f := newCredFixture(t)
	f.steward("steward-a", "tenant-x", "user-jdoe", "user-other")

	first := f.mustIssue("steward-a", "user-jdoe")
	assert.Equal(t, first, f.mustIssue("steward-a", "user-jdoe"))
	assert.Equal(t, first, f.mustIssue("steward-a", "user-jdoe"))
	assert.NotEqual(t, first, f.mustIssue("steward-a", "user-other"), "each resource has its own password")
}

func TestIssueInitialCredential_UndeclaredResourceRejected(t *testing.T) {
	f := newCredFixture(t)
	f.steward("steward-a", "tenant-x", "user-jdoe")

	_, err := f.issue("steward-a", "user-nobody")
	requireCode(t, err, codes.PermissionDenied)

	// A resource of that name under another module does not count.
	require.NoError(t, f.ctrl.RegisterSteward("steward-d", "tenant-x", "localhost:4433", "connected"))
	cfg := minimalStewardConfig("steward-d")
	cfg.Resources = append(cfg.Resources, stewardtypes.ResourceConfig{Name: "user-jdoe", Module: "directory", Config: map[string]interface{}{"path": "/tmp/x", "permissions": "755"}})
	require.NoError(t, f.cfgSvc.SetConfiguration(ctxkeys.WithSystem(context.Background()), "tenant-x", "steward-d", cfg))
	_, err = f.issue("steward-d", "user-jdoe")
	requireCode(t, err, codes.PermissionDenied)

	// Wrong kind and unsafe ids are refused before any lookup.
	_, err = f.h.HandleGRPC(f.peerCtx("steward-a"), &transportpb.IssueInitialCredentialRequest{ResourceId: "user-jdoe", Kind: "directory"})
	requireCode(t, err, codes.PermissionDenied)
	_, err = f.issue("steward-a", "../user-jdoe")
	requireCode(t, err, codes.PermissionDenied)

	// No client certificate, no service.
	_, err = f.h.HandleGRPC(context.Background(), &transportpb.IssueInitialCredentialRequest{ResourceId: "user-jdoe", Kind: credentials.KindActiveDirectoryUser})
	requireCode(t, err, codes.Unauthenticated)

	// An unregistered steward is refused.
	_, err = f.issue("steward-ghost", "user-jdoe")
	requireCode(t, err, codes.PermissionDenied)

	recs, err := f.store.List(context.Background(), credentials.Filter{})
	require.NoError(t, err)
	assert.Empty(t, recs, "refused requests create nothing")
}

func TestIssueInitialCredential_OtherPeerCannotReplace(t *testing.T) {
	f := newCredFixture(t)
	f.steward("steward-a", "tenant-x", "user-jdoe")
	f.steward("steward-b", "tenant-x", "user-jdoe")

	pwA := f.mustIssue("steward-a", "user-jdoe")
	pwB := f.mustIssue("steward-b", "user-jdoe")
	assert.NotEqual(t, pwA, pwB, "a peer gets its own record, never another peer's password")

	// A's pending record is untouched by B's request.
	assert.Equal(t, pwA, f.mustIssue("steward-a", "user-jdoe"))
	recs, err := f.store.List(context.Background(), credentials.Filter{TenantID: "tenant-x"})
	require.NoError(t, err)
	owners := map[string]bool{}
	for _, r := range recs {
		owners[r.StewardID] = true
	}
	assert.Equal(t, map[string]bool{"steward-a": true, "steward-b": true}, owners)
}

func TestIssueInitialCredential_OtherStewardInSameTenantRefused(t *testing.T) {
	f := newCredFixture(t)
	f.steward("steward-a", "tenant-x", "user-jdoe")
	f.steward("steward-b", "tenant-x") // same tenant, resource not in its own cfg

	_, err := f.issue("steward-b", "user-jdoe")
	requireCode(t, err, codes.PermissionDenied)
	f.mustIssue("steward-a", "user-jdoe")
}

func TestIssueInitialCredential_ReissueOnlyWithoutBinding(t *testing.T) {
	f := newCredFixture(t)
	f.steward("steward-a", "tenant-x", "user-bound", "user-unbound")
	boundKey := f.key("tenant-x", "steward-a", "user-bound")
	unboundKey := f.key("tenant-x", "steward-a", "user-unbound")

	f.mustIssue("steward-a", "user-bound")
	f.reveal(boundKey)
	f.bind(boundKey)
	_, err := f.issue("steward-a", "user-bound")
	requireCode(t, err, codes.FailedPrecondition)

	old := f.mustIssue("steward-a", "user-unbound")
	oldCred, err := f.store.Get(context.Background(), unboundKey)
	require.NoError(t, err)
	f.reveal(unboundKey)
	fresh := f.mustIssue("steward-a", "user-unbound")
	assert.NotEqual(t, old, fresh)

	newCred, err := f.store.Get(context.Background(), unboundKey)
	require.NoError(t, err)
	assert.NotEqual(t, oldCred.ID, newCred.ID, "the old record is voided")
	assert.Equal(t, credentials.StatePending, newCred.State)
	assert.Equal(t, fresh, newCred.Password)
	_, err = f.secrets.(secretsif.TenantSecretAccessor).GetTenantSecret(context.Background(), "tenant-x",
		"credentials-initial_steward-a_user-unbound_"+oldCred.ID)
	require.ErrorIs(t, err, secretsif.ErrSecretNotFound, "the voided record's password is deleted")

	require.NoError(t, f.auditMgr.Flush(context.Background()))
	events, err := f.auditMgr.QueryEntries(context.Background(), &business.AuditFilter{Actions: []string{"credential_reissued"}})
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "user-unbound", events[0].ResourceID)
	ev, merr := json.Marshal(events[0])
	require.NoError(t, merr)
	assert.NotContains(t, string(ev), fresh)
	assert.NotContains(t, string(ev), old)
}

func TestIssueInitialCredential_TenantFromMTLSPeer(t *testing.T) {
	f := newCredFixture(t)
	f.steward("steward-x1", "tenant-x", "user-jdoe")
	f.steward("steward-y1", "tenant-y", "user-jdoe")

	// A payload naming another tenant is ignored: build the request with an
	// unknown field 3 carrying the other tenant's id.
	raw, err := proto.Marshal(&transportpb.IssueInitialCredentialRequest{ResourceId: "user-jdoe", Kind: credentials.KindActiveDirectoryUser})
	require.NoError(t, err)
	raw = protowire.AppendTag(raw, 3, protowire.BytesType)
	raw = protowire.AppendString(raw, "tenant-y")
	req := &transportpb.IssueInitialCredentialRequest{}
	require.NoError(t, proto.Unmarshal(raw, req))
	require.NotEmpty(t, req.ProtoReflect().GetUnknown())

	resp, err := f.h.HandleGRPC(f.peerCtx("steward-x1"), req)
	require.NoError(t, err)
	pwY := f.mustIssue("steward-y1", "user-jdoe")
	assert.NotEqual(t, resp.GetPassword(), pwY)

	for tenant, steward := range map[string]string{"tenant-x": "steward-x1", "tenant-y": "steward-y1"} {
		recs, lerr := f.store.List(context.Background(), credentials.Filter{TenantID: tenant})
		require.NoError(t, lerr)
		require.Len(t, recs, 1, tenant)
		assert.Equal(t, steward, recs[0].StewardID)
	}
}

func TestIssueInitialCredential_RevealedRecordRefusesIssue(t *testing.T) {
	f := newCredFixture(t)
	f.steward("steward-a", "tenant-x", "user-jdoe")
	k := f.key("tenant-x", "steward-a", "user-jdoe")
	f.mustIssue("steward-a", "user-jdoe")

	cred, err := f.store.Get(context.Background(), k)
	require.NoError(t, err)
	_, err = f.store.Claim(context.Background(), k, cred.ID, credentials.StatePending, credentials.StateRevealing)
	require.NoError(t, err)
	_, err = f.issue("steward-a", "user-jdoe")
	requireCode(t, err, codes.FailedPrecondition)

	_, err = f.store.Claim(context.Background(), k, cred.ID, credentials.StateRevealing, credentials.StateRevealed)
	require.NoError(t, err)
	f.bind(k)
	_, err = f.issue("steward-a", "user-jdoe")
	requireCode(t, err, codes.FailedPrecondition)
	assert.Contains(t, err.Error(), "already issued")
}

// seedPending writes n pending records for a steward straight through the store.
func (f *credFixture) seedPending(tenant, steward string, n int, prefix string) {
	f.t.Helper()
	now := time.Now()
	for i := 0; i < n; i++ {
		id, err := credentials.NewRecordID()
		require.NoError(f.t, err)
		require.NoError(f.t, f.store.Put(context.Background(), &credentials.Record{
			ID: id, TenantID: tenant, StewardID: steward, ResourceID: fmt.Sprintf("%s-%d", prefix, i),
			CreatedAt: now, ExpiresAt: now.Add(credentials.DefaultTTL), State: credentials.StatePending,
		}, "seed-pw", nil))
	}
}

func TestIssueInitialCredential_PendingCapEnforced(t *testing.T) {
	f := newCredFixture(t)
	f.steward("steward-a", "tenant-x", "user-new")
	f.steward("steward-b", "tenant-x", "user-new")

	// Per steward: steward-a holds the cap; steward-b is unaffected.
	f.seedPending("tenant-x", "steward-a", credentials.MaxPendingPerSteward, "seed-a")
	_, err := f.issue("steward-a", "user-new")
	requireCode(t, err, codes.ResourceExhausted)
	assert.NotContains(t, err.Error(), "seed")
	// The tenant cap is also reached now (1000 pending), so steward-b is refused
	// too; free the tenant by deleting one seeded record and both succeed.
	_, err = f.issue("steward-b", "user-new")
	requireCode(t, err, codes.ResourceExhausted)

	require.NoError(t, f.store.Delete(context.Background(), f.key("tenant-x", "steward-a", "seed-a-0")))
	f.mustIssue("steward-b", "user-new")
	// steward-a is back under the tenant cap but the tenant is full again at 1000.
	_, err = f.issue("steward-a", "user-new")
	requireCode(t, err, codes.ResourceExhausted)
}

func TestIssueInitialCredential_RateLimited(t *testing.T) {
	f := newCredFixture(t)
	f.steward("steward-a", "tenant-x", "user-jdoe")
	f.steward("steward-b", "tenant-x", "user-jdoe")
	now := time.Now()
	f.h.limiter.now = func() time.Time { return now }

	for i := 0; i < 60; i++ {
		f.mustIssue("steward-a", "user-jdoe")
	}
	_, err := f.issue("steward-a", "user-jdoe")
	requireCode(t, err, codes.ResourceExhausted)
	f.mustIssue("steward-b", "user-jdoe") // the limit is per steward

	now = now.Add(61 * time.Second)
	f.mustIssue("steward-a", "user-jdoe") // the window has passed
}

func TestIssueInitialCredential_ConcurrentIssue_OnePassword(t *testing.T) {
	f := newCredFixture(t)
	f.steward("steward-a", "tenant-x", "user-jdoe")
	f.peerCtx("steward-a") // build the certificate before racing

	const workers = 8
	results := make([]string, workers)
	errs := make([]error, workers)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i], errs[i] = f.issue("steward-a", "user-jdoe")
		}(i)
	}
	close(start)
	wg.Wait()

	for i := range results {
		require.NoError(t, errs[i])
		assert.Equal(t, results[0], results[i], "every concurrent issue returns the same password")
	}
	recs, err := f.store.List(context.Background(), credentials.Filter{})
	require.NoError(t, err)
	assert.Len(t, recs, 1)
	// No orphan secrets: exactly one password is on disk.
	n := 0
	require.NoError(t, filepath.WalkDir(f.secDir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.Contains(p, "credentials-initial") {
			n++
		}
		return err
	}))
	assert.Equal(t, 1, n, "losing issuers leave no secret behind")
}

func TestIssueInitialCredential_ClusterModeNonAtomicStore_Refuses(t *testing.T) {
	f := newCredFixture(t)
	f.steward("steward-a", "tenant-x", "user-jdoe")
	require.False(t, cfgconfig.ClusterAtomic(f.cfgStore), "the flatfile config store is not cluster-atomic")

	cfgconfig.SetClusterConfigured(true)
	t.Cleanup(func() { cfgconfig.SetClusterConfigured(false) })

	_, err := f.issue("steward-a", "user-jdoe")
	requireCode(t, err, codes.Unavailable)

	// Nothing was written.
	cfgconfig.SetClusterConfigured(false)
	recs, lerr := f.store.List(context.Background(), credentials.Filter{})
	require.NoError(t, lerr)
	assert.Empty(t, recs)
	assert.Empty(t, filesContaining(t, f.secDir, "credentials-initial"))

	// And the sentinel is the one callers test for.
	require.ErrorIs(t, credentials.ErrNotClusterAtomic, cfgconfig.ErrNotClusterAtomic)
}

// fixedPeerCreds is server transport credentials that perform no handshake and
// report a fixed, already verified TLS peer, so a real grpc.Server (with its real
// interceptor chain) sees the same AuthInfo a QUIC mTLS connection produces.
type fixedPeerCreds struct{ info grpccreds.TLSInfo }

func (c fixedPeerCreds) ClientHandshake(_ context.Context, _ string, conn net.Conn) (net.Conn, grpccreds.AuthInfo, error) {
	return conn, c.info, nil
}
func (c fixedPeerCreds) ServerHandshake(conn net.Conn) (net.Conn, grpccreds.AuthInfo, error) {
	return conn, c.info, nil
}
func (c fixedPeerCreds) Info() grpccreds.ProtocolInfo {
	return grpccreds.ProtocolInfo{SecurityProtocol: "tls"}
}
func (c fixedPeerCreds) Clone() grpccreds.TransportCredentials { return c }
func (c fixedPeerCreds) OverrideServerName(string) error       { return nil }

// credTransportServer is the StewardTransport server for this test: it routes
// IssueInitialCredential to the real handler exactly as the composite does.
type credTransportServer struct {
	transportpb.UnimplementedStewardTransportServer
	h *CredentialHandler
}

func (s *credTransportServer) IssueInitialCredential(ctx context.Context, req *transportpb.IssueInitialCredentialRequest) (*transportpb.IssueInitialCredentialResponse, error) {
	return s.h.HandleGRPC(ctx, req)
}

func TestLogsAndAuditNeverContainPassword(t *testing.T) {
	f := newCredFixture(t)
	f.steward("steward-a", "tenant-x", "user-jdoe", "user-unbound")

	p, ok := peer.FromContext(f.peerCtx("steward-a"))
	require.True(t, ok)
	tlsInfo := p.AuthInfo.(grpccreds.TLSInfo)

	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer(
		grpc.Creds(fixedPeerCreds{info: tlsInfo}),
		grpc.ChainUnaryInterceptor(NewUnaryAccessLogInterceptor(f.logs)),
	)
	transportpb.RegisterStewardTransportServer(srv, &credTransportServer{h: f.h})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	client := transportpb.NewStewardTransportClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	call := func(resource string) (string, error) {
		resp, cerr := client.IssueInitialCredential(ctx, &transportpb.IssueInitialCredentialRequest{
			ResourceId: resource, Kind: credentials.KindActiveDirectoryUser,
		})
		return resp.GetPassword(), cerr
	}

	var secretsSeen []string
	pw, err := call("user-jdoe")
	require.NoError(t, err)
	secretsSeen = append(secretsSeen, pw)
	again, err := call("user-jdoe")
	require.NoError(t, err)
	assert.Equal(t, pw, again)
	_, err = call("user-undeclared")
	requireCode(t, err, codes.PermissionDenied)

	// Drive a re-issue so the audit trail has a credential event too.
	old, err := call("user-unbound")
	require.NoError(t, err)
	f.reveal(f.key("tenant-x", "steward-a", "user-unbound"))
	fresh, err := call("user-unbound")
	require.NoError(t, err)
	secretsSeen = append(secretsSeen, old, fresh)

	logText := f.logs.all()
	require.Contains(t, logText, "gRPC unary call", "the interceptor ran")
	require.Contains(t, logText, transportpb.StewardTransport_IssueInitialCredential_FullMethodName)
	auditText := f.auditText()
	require.Contains(t, auditText, "credential_reissued")
	for _, s := range secretsSeen {
		assert.NotContains(t, logText, s, "no log line may hold a password")
		assert.NotContains(t, auditText, s, "no audit entry may hold a password")
	}
	assert.True(t, IsSecretBearingMethod(transportpb.StewardTransport_IssueInitialCredential_FullMethodName))
	assert.False(t, IsSecretBearingMethod(transportpb.StewardTransport_Ping_FullMethodName))
}
