// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	configgit "github.com/cfgis/cfgms/features/config/git"
	gitstorage "github.com/cfgis/cfgms/features/config/git/storage"
	"github.com/cfgis/cfgms/features/config/rollback"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/session"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// rollbackStack holds the controller's real rollback components for handler tests.
//
// Every component is the production implementation, wired exactly as
// initializeRollbackManager does in features/controller/server/server.go:
// rollback.DefaultRollbackManager over rollback.DefaultRollbackValidator, a real
// features/config/git DefaultGitManager backed by the go-git LocalRepositoryStore, the
// durable rollback.StorageRollbackStore over a real flatfile+sqlite storage manager in
// t.TempDir(), a real features/rbac Manager over the same storage, and the shipped
// rollback.DefaultRollbackNotifier. No CFGMS behaviour is substituted or re-implemented.
type rollbackStack struct {
	manager    rollback.RollbackManager
	store      rollback.RollbackStore
	gitManager configgit.GitManager
	gitOrigins *fsGitProvider
	// registry is the controller's real steward registry, wired as the rollback
	// manager's TargetTenantResolver exactly as server.go wires it. It is the
	// authority for which tenant owns a rollback target (Issue #4340).
	registry *service.ControllerService
	// subtree is the production ancestry predicate (Server.tenantSubtreeContains)
	// over a real tenant manager holding the seedTenantTree hierarchy.
	subtree tenantSubtreeFunc
}

// fsGitProvider hosts configuration repositories as real go-git repositories on the local
// filesystem.
//
// DefaultGitManager talks to a GitProvider for repository lifecycle and to the
// RepositoryStore for content, so hosting repositories on disk lets handler tests drive the
// production Git manager — and through it the production rollback manager's preview,
// validation and approval logic — against real commits and real diffs. Each repository is
// created with a baseline commit and a follow-up change commit, giving every target a real
// commit to roll back to.
//
// Hosting-service features (pull requests, webhooks, branch protection) have no filesystem
// equivalent and are refused rather than silently reported as successful. The rollback
// paths under test never reach them.
type fsGitProvider struct {
	root     string
	mu       sync.Mutex
	baseline map[string]string // repository ID -> baseline commit SHA
}

// errFSGitUnsupported is returned for hosting-service operations the filesystem has no
// equivalent for.
var errFSGitUnsupported = errors.New("filesystem git provider: hosting-service operation not supported")

func newFSGitProvider(root string) *fsGitProvider {
	return &fsGitProvider{root: root, baseline: make(map[string]string)}
}

func (p *fsGitProvider) CreateRepository(_ context.Context, config configgit.RepositoryConfig) (*configgit.Repository, error) {
	path := filepath.Join(p.root, config.Name)

	repo, err := gogit.PlainInit(path, false)
	if err != nil {
		return nil, fmt.Errorf("init repository %s: %w", config.Name, err)
	}
	worktree, err := repo.Worktree()
	if err != nil {
		return nil, fmt.Errorf("open worktree for %s: %w", config.Name, err)
	}

	baseline, err := fsGitCommit(worktree, path, "modules/firewall/config.yaml", "policy: baseline\n", "baseline configuration")
	if err != nil {
		return nil, err
	}
	if _, err := fsGitCommit(worktree, path, "modules/firewall/config.yaml", "policy: current\n", "tighten firewall policy"); err != nil {
		return nil, err
	}

	p.mu.Lock()
	p.baseline[config.Name] = baseline
	p.mu.Unlock()

	return &configgit.Repository{
		ID:            config.Name,
		Type:          config.Type,
		Name:          config.Name,
		Owner:         config.Owner,
		Provider:      "filesystem",
		CloneURL:      path,
		DefaultBranch: config.InitialBranch,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}, nil
}

// BaselineSHA returns the commit a rollback of the given repository targets.
func (p *fsGitProvider) BaselineSHA(repoID string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.baseline[repoID]
}

func (p *fsGitProvider) GetRepository(_ context.Context, _, name string) (*configgit.Repository, error) {
	path := filepath.Join(p.root, name)
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("repository not found: %s", name)
	}
	return &configgit.Repository{ID: name, Name: name, Provider: "filesystem", CloneURL: path}, nil
}

func (p *fsGitProvider) DeleteRepository(_ context.Context, _, name string) error {
	return os.RemoveAll(filepath.Join(p.root, name))
}

func (p *fsGitProvider) CreateBranch(_ context.Context, _, _, _, _ string) error { return nil }

func (p *fsGitProvider) DeleteBranch(_ context.Context, _, _, _ string) error { return nil }

func (p *fsGitProvider) GetDefaultBranch(_ context.Context, _, name string) (string, error) {
	repo, err := gogit.PlainOpen(filepath.Join(p.root, name))
	if err != nil {
		return "", err
	}
	head, err := repo.Head()
	if err != nil {
		return "", err
	}
	return head.Name().Short(), nil
}

func (p *fsGitProvider) CreatePullRequest(_ context.Context, _, _ string, _ configgit.PullRequestConfig) (string, error) {
	return "", errFSGitUnsupported
}

func (p *fsGitProvider) MergePullRequest(_ context.Context, _, _, _ string) error {
	return errFSGitUnsupported
}

func (p *fsGitProvider) CreateWebhook(_ context.Context, _, _ string, _ configgit.WebhookConfig) (string, error) {
	return "", errFSGitUnsupported
}

func (p *fsGitProvider) DeleteWebhook(_ context.Context, _, _, _ string) error {
	return errFSGitUnsupported
}

func (p *fsGitProvider) SetBranchProtection(_ context.Context, _, _ string, _ configgit.BranchProtectionRule) error {
	return errFSGitUnsupported
}

func (p *fsGitProvider) RemoveBranchProtection(_ context.Context, _, _, _ string) error {
	return errFSGitUnsupported
}

// fsGitCommit writes a file into the worktree and commits it, returning the commit SHA.
func fsGitCommit(worktree *gogit.Worktree, root, path, content, message string) (string, error) {
	full := filepath.Join(root, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		return "", fmt.Errorf("create %s: %w", path, err)
	}
	if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
		return "", fmt.Errorf("write %s: %w", path, err)
	}
	if _, err := worktree.Add(path); err != nil {
		return "", fmt.Errorf("stage %s: %w", path, err)
	}

	sha, err := worktree.Commit(message, &gogit.CommitOptions{
		Author: &object.Signature{Name: "CFGMS", Email: "system@cfgms.local", When: time.Now()},
	})
	if err != nil {
		return "", fmt.Errorf("commit %s: %w", path, err)
	}

	return sha.String(), nil
}

// noOpModuleRegistry is the module registry the controller wires into the rollback
// validator (server.go noOpModuleRegistry): CFGMS resolves module versions through the
// module distribution service, and the rollback validator runs against defaults until a
// registry is configured. Reproduced here so handler tests wire the validator the way
// production wires it.
type noOpModuleRegistry struct{}

func (r *noOpModuleRegistry) GetModuleVersion(_ context.Context, _ string) (string, error) {
	return "latest", nil
}

func (r *noOpModuleRegistry) GetModuleDependencies(_ context.Context, _ string) ([]string, error) {
	return nil, nil
}

func (r *noOpModuleRegistry) IsModuleCompatible(_ context.Context, _, _ string) (bool, error) {
	return true, nil
}

// newRollbackStack builds the production rollback manager over real storage in t.TempDir().
func newRollbackStack(t *testing.T) *rollbackStack {
	t.Helper()

	dir := t.TempDir()
	logger := logging.NewNoopLogger()

	storageManager, err := interfaces.CreateOSSStorageManager(
		filepath.Join(dir, "flatfile"),
		filepath.Join(dir, "cfgms.db"),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = storageManager.Close() })

	rbacManager := rbac.NewManagerWithStorage(
		storageManager.GetAuditStore(),
		storageManager.GetClientTenantStore(),
		storageManager.GetRBACStore(),
	)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = rbacManager.Close(ctx)
	})

	store := rollback.NewStorageRollbackStore(storageManager.GetConfigStore())
	validator := rollback.NewRollbackValidator(&noOpModuleRegistry{}, nil, rbacManager)
	origins := newFSGitProvider(filepath.Join(dir, "git-origins"))
	gitManager := configgit.NewGitManager(origins, gitstorage.NewLocalRepositoryStore("", ""), configgit.GitManagerConfig{
		DefaultBranch: "main",
		AutoSync:      false,
		CacheDir:      filepath.Join(dir, "git-cache"),
	}, logger)

	registry := service.NewControllerService(logger)

	tenantServer := setupTestServer(t)
	seedTenantTree(t, tenantServer)

	return &rollbackStack{
		subtree:    tenantServer.tenantSubtreeContains,
		manager:    rollback.NewRollbackManager(gitManager, validator, store, rollback.NewDefaultRollbackNotifier(logger), registry),
		store:      store,
		gitManager: gitManager,
		gitOrigins: origins,
		registry:   registry,
	}
}

// ownSteward records a steward and the tenant that owns it in the real registry,
// the way HTTP registration does. The rollback manager reads target ownership
// from here, so a target no test registers is owned by no tenant.
func (s *rollbackStack) ownSteward(t *testing.T, stewardID, tenantID string) {
	t.Helper()

	require.NoError(t, s.registry.RegisterSteward(stewardID, tenantID, "127.0.0.1:9000", "active"))
}

// seedRepository creates the configuration repository the rollback manager resolves for a
// target (DefaultRollbackManager.getRepositoryID derives the repository ID from the target
// type and ID) and returns the commit a rollback targets. Registration goes through the
// production Git manager, so the repository is cloned into its cache exactly as it is at
// runtime.
func (s *rollbackStack) seedRepository(t *testing.T, targetType rollback.TargetType, targetID string) string {
	t.Helper()

	repoID := fmt.Sprintf("%s-%s-repo", targetType, targetID)
	if targetType == rollback.TargetTypeMSP {
		repoID = "msp-global-repo"
	}

	_, err := s.gitManager.CreateRepository(context.Background(), configgit.RepositoryConfig{
		Name:          repoID,
		Owner:         "cfgms",
		Provider:      "filesystem",
		InitialBranch: "master",
	})
	require.NoError(t, err)

	baseline := s.gitOrigins.BaselineSHA(repoID)
	require.NotEmpty(t, baseline, "seeded repository must expose a baseline commit")
	return baseline
}

// requireRollbackError asserts the handler answered with the given status and error
// message, and that the production manager recorded no operation for the target.
func (s *rollbackStack) requireRollbackError(t *testing.T, rec *httptest.ResponseRecorder, status int, message string, targetType rollback.TargetType, targetID string) {
	t.Helper()

	require.Equal(t, status, rec.Code, "body: %s", rec.Body.String())

	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, message, resp["error"])

	assert.Empty(t, s.operationsFor(t, targetType, targetID),
		"a rejected rollback must not be recorded")
}

// seedLiveOperation records a live (in-progress) rollback operation for a target in the
// real rollback store and returns its ID.
//
// A target with a live operation makes the production manager's own concurrency guard
// (rollback.DefaultRollbackManager.checkNoRollbackInProgress) the first thing an admitted
// request hits, so handler tests can tell "the cross-tenant guard admitted the request and
// the real rollback manager answered it" (409, from CFGMS's own concurrency logic) apart
// from "the cross-tenant guard rejected the request before the manager saw it"
// (400 CROSS_TENANT_ROLLBACK) without substituting the manager.
func (s *rollbackStack) seedLiveOperation(t *testing.T, targetType rollback.TargetType, targetID string) string {
	t.Helper()

	id := uuid.NewString()
	require.NoError(t, s.store.SaveOperation(context.Background(), &rollback.RollbackOperation{
		ID:          id,
		Status:      rollback.RollbackStatusInProgress,
		InitiatedBy: "ops@example.com",
		InitiatedAt: time.Now(),
		Request: rollback.RollbackRequest{
			TargetType:   targetType,
			TargetID:     targetID,
			RollbackType: rollback.RollbackTypeFull,
			RollbackTo:   "seed0000000000",
			Reason:       "earlier rollback still running",
		},
	}))
	return id
}

// seedOperation records an operation with the given status in the real rollback store.
func (s *rollbackStack) seedOperation(t *testing.T, targetType rollback.TargetType, targetID string, status rollback.RollbackStatus) string {
	t.Helper()

	id := uuid.NewString()
	require.NoError(t, s.store.SaveOperation(context.Background(), &rollback.RollbackOperation{
		ID:          id,
		Status:      status,
		InitiatedBy: "ops@example.com",
		InitiatedAt: time.Now(),
		Request: rollback.RollbackRequest{
			TargetType:   targetType,
			TargetID:     targetID,
			RollbackType: rollback.RollbackTypeFull,
			RollbackTo:   "seed0000000000",
			Reason:       "revert bad config",
		},
	}))
	return id
}

// operationsFor reads a target's rollback operations back through the production manager.
func (s *rollbackStack) operationsFor(t *testing.T, targetType rollback.TargetType, targetID string) []rollback.RollbackOperation {
	t.Helper()

	// Root scope: this reads back what the store holds, independent of whatever
	// tenant the request under test was scoped to.
	ops, err := s.manager.ListRollbackHistory(rootScopedContext(), targetType, targetID, 0)
	require.NoError(t, err)
	return ops
}

// requireGuardRejected asserts the handler's cross-tenant guard rejected the request
// before the rollback manager was called: the seeded live operation must still be the only
// operation on record for the target.
func (s *rollbackStack) requireGuardRejected(t *testing.T, rec *httptest.ResponseRecorder, targetType rollback.TargetType, targetID string) {
	t.Helper()

	require.Equal(t, http.StatusBadRequest, rec.Code, "body: %s", rec.Body.String())

	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "CROSS_TENANT_ROLLBACK", resp["code"])

	ops := s.operationsFor(t, targetType, targetID)
	require.Len(t, ops, 1, "no rollback may be initiated after a cross-tenant rejection")
	assert.Equal(t, rollback.RollbackStatusInProgress, ops[0].Status)
}

// requireGuardAdmitted asserts the request passed the cross-tenant guard and was answered
// by the production rollback manager's concurrency guard.
func (s *rollbackStack) requireGuardAdmitted(t *testing.T, rec *httptest.ResponseRecorder, targetType rollback.TargetType, targetID string) {
	t.Helper()

	require.Equal(t, http.StatusConflict, rec.Code, "body: %s", rec.Body.String())

	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, rollback.ErrRollbackInProgress.Message, resp["error"],
		"the response must come from the rollback manager's concurrency guard")

	ops := s.operationsFor(t, targetType, targetID)
	require.Len(t, ops, 1, "a rejected concurrent rollback must not create a second operation")
}

// requireHandlerGuardPassed asserts the handler's own cross-tenant guard (the
// injected ancestry function) did not reject the request. It deliberately does not
// assert the final status: the rollback manager applies its own tenant check
// (features/config/rollback authorizeTenant) after the handler guard.
func requireHandlerGuardPassed(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()

	var resp map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.NotEqual(t, "CROSS_TENANT_ROLLBACK", resp["code"],
		"the handler guard must admit a ParentID descendant; body: %s", rec.Body.String())
}

// scopedPrincipalExtractor returns an extractor that yields a principal with the given TenantID.
func scopedPrincipalExtractor(tenantID string) func(*http.Request) *Principal {
	return func(_ *http.Request) *Principal {
		return &Principal{
			ID:        "admin-api-key",
			TenantID:  tenantID,
			Assurance: session.AssuranceMachine,
		}
	}
}

func adminPrincipalExtractor() func(*http.Request) *Principal {
	return func(_ *http.Request) *Principal {
		return &Principal{
			ID:          "admin-cert-cn",
			Assurance:   session.AssuranceBasic,
			GlobalScope: true,
		}
	}
}

// sessionPrincipalExtractor returns an extractor that yields a session principal with
// GlobalScope=true (as set by middleware) but a non-empty TenantID. This mirrors
// the middleware.go bug described in Issue #3143.
func sessionPrincipalExtractor(tenantID string) func(*http.Request) *Principal {
	return func(_ *http.Request) *Principal {
		return &Principal{
			ID:          "web-session-" + tenantID,
			GlobalScope: true, // middleware.go bug: hardcoded true for all session principals
			TenantID:    tenantID,
			Assurance:   session.AssuranceBasic,
		}
	}
}

// rootScopedContext carries the tenant scope authenticationMiddleware establishes
// for a verified mTLS admin certificate: unrestricted, cross-tenant access.
func rootScopedContext() context.Context {
	return context.WithValue(context.Background(), ctxkeys.TenantScopeKey, ctxkeys.NewRootScope())
}

// newRollbackRequest builds a POST /api/v1/rollback/execute request carrying the given JSON
// body, with actor identity and the admin certificate's root tenant scope in the context
// exactly as authenticationMiddleware sets them.
func newRollbackRequest(body, actor string) *http.Request {
	req := httptest.NewRequest("POST", "/api/v1/rollback/execute", strings.NewReader(body))
	ctx := context.WithValue(req.Context(), ctxkeys.UserIDKey, actor)
	return req.WithContext(context.WithValue(ctx, ctxkeys.TenantScopeKey, ctxkeys.NewRootScope()))
}

// newScopedRollbackRequest is newRollbackRequest for a tenant-scoped caller: an API-key
// or web-session principal, which authenticationMiddleware confines to its own subtree.
func newScopedRollbackRequest(body, actor, tenantPath string) *http.Request {
	req := httptest.NewRequest("POST", "/api/v1/rollback/execute", strings.NewReader(body))
	ctx := context.WithValue(req.Context(), ctxkeys.UserIDKey, actor)
	return req.WithContext(context.WithValue(ctx, ctxkeys.TenantScopeKey, ctxkeys.NewTenantScope(tenantPath)))
}

// withRootScope puts the admin certificate's root tenant scope on a GET/POST request the
// test builds itself, matching what authenticationMiddleware does for an admin principal.
func withRootScope(req *http.Request) *http.Request {
	return req.WithContext(context.WithValue(req.Context(), ctxkeys.TenantScopeKey, ctxkeys.NewRootScope()))
}

func TestConfigRollback_RejectsCrossTenantVersion(t *testing.T) {
	// Principal scoped to "msp-a" must not reach stewards in "msp-b".
	stack := newRollbackStack(t)
	stack.ownSteward(t, "steward-msp-b", "msp-b")
	stack.seedLiveOperation(t, rollback.TargetTypeSteward, "steward-msp-b")
	handler := NewRollbackHandler(stack.manager, scopedPrincipalExtractor("msp-a"), nil, nil, stack.subtree)

	body := `{"target_type":"steward","target_id":"steward-msp-b","rollback_type":"full","rollback_to":"abc1234567890","reason":"revert bad config","dry_run":false,"steward_tenant_path":"msp-b"}`
	rec := httptest.NewRecorder()

	handler.ExecuteRollback(rec, newScopedRollbackRequest(body, "admin-api-key", "msp-a"))

	stack.requireGuardRejected(t, rec, rollback.TargetTypeSteward, "steward-msp-b")
}

func TestConfigRollback_BlocksSiblingTenant(t *testing.T) {
	// "msp-ab" is a sibling, not a child of "msp-a" — prefix matching
	// without a segment boundary would incorrectly allow this.
	stack := newRollbackStack(t)
	stack.ownSteward(t, "steward-msp-ab", "msp-ab")
	stack.seedLiveOperation(t, rollback.TargetTypeSteward, "steward-msp-ab")
	handler := NewRollbackHandler(stack.manager, scopedPrincipalExtractor("msp-a"), nil, nil, stack.subtree)

	body := `{"target_type":"steward","target_id":"steward-msp-ab","rollback_type":"full","rollback_to":"abc1234567890","reason":"revert bad config","dry_run":false,"steward_tenant_path":"msp-ab"}`
	rec := httptest.NewRecorder()

	handler.ExecuteRollback(rec, newScopedRollbackRequest(body, "admin-api-key", "msp-a"))

	stack.requireGuardRejected(t, rec, rollback.TargetTypeSteward, "steward-msp-ab")
}

func TestConfigRollback_AllowsSameTenant(t *testing.T) {
	stack := newRollbackStack(t)
	stack.ownSteward(t, "steward-x", "msp-a")
	stack.seedLiveOperation(t, rollback.TargetTypeSteward, "steward-x")
	handler := NewRollbackHandler(stack.manager, scopedPrincipalExtractor("msp-a"), nil, nil, stack.subtree)

	body := `{"target_type":"steward","target_id":"steward-x","rollback_type":"full","rollback_to":"abc1234567890","reason":"revert bad config","dry_run":false,"steward_tenant_path":"msp-a"}`
	rec := httptest.NewRecorder()

	handler.ExecuteRollback(rec, newScopedRollbackRequest(body, "admin-api-key", "msp-a"))

	stack.requireGuardAdmitted(t, rec, rollback.TargetTypeSteward, "steward-x")
}

func TestConfigRollback_AllowsChildTenant(t *testing.T) {
	stack := newRollbackStack(t)
	stack.ownSteward(t, "steward-client-1", "client-1")
	stack.seedLiveOperation(t, rollback.TargetTypeSteward, "steward-client-1")
	handler := NewRollbackHandler(stack.manager, scopedPrincipalExtractor("msp-a"), nil, nil, stack.subtree)

	// "client-1" is a child of "msp-a" — must be allowed.
	body := `{"target_type":"steward","target_id":"steward-client-1","rollback_type":"full","rollback_to":"abc1234567890","reason":"revert bad config","dry_run":false,"steward_tenant_path":"client-1"}`
	rec := httptest.NewRecorder()

	handler.ExecuteRollback(rec, newScopedRollbackRequest(body, "admin-api-key", "msp-a"))

	requireHandlerGuardPassed(t, rec)
}

func TestConfigRollback_AdminPrincipalSkipsTenantCheck(t *testing.T) {
	// Full admin (Assurance >= AssuranceBasic, TenantID="") can access any tenant.
	stack := newRollbackStack(t)
	stack.seedLiveOperation(t, rollback.TargetTypeSteward, "steward-any")
	handler := NewRollbackHandler(stack.manager, adminPrincipalExtractor(), nil, nil, stack.subtree)

	body := `{"target_type":"steward","target_id":"steward-any","rollback_type":"full","rollback_to":"abc1234567890","reason":"revert bad config","dry_run":false,"steward_tenant_path":"any-tenant"}`
	rec := httptest.NewRecorder()

	handler.ExecuteRollback(rec, newRollbackRequest(body, "admin-cert-cn"))

	stack.requireGuardAdmitted(t, rec, rollback.TargetTypeSteward, "steward-any")
}

func TestConfigRollback_NoTenantPathSkipsCheck(t *testing.T) {
	// When steward_tenant_path is omitted, the early-rejection check is skipped.
	// The rollback manager remains the authoritative access check, and it admits the
	// request because the registry owns this steward in the caller's own tenant.
	stack := newRollbackStack(t)
	stack.ownSteward(t, "steward-xyz", "msp-a")
	stack.seedLiveOperation(t, rollback.TargetTypeSteward, "steward-xyz")
	handler := NewRollbackHandler(stack.manager, scopedPrincipalExtractor("msp-a"), nil, nil, stack.subtree)

	body := `{"target_type":"steward","target_id":"steward-xyz","rollback_type":"full","rollback_to":"abc1234567890","reason":"revert bad config","dry_run":false}`
	rec := httptest.NewRecorder()

	handler.ExecuteRollback(rec, newScopedRollbackRequest(body, "admin-api-key", "msp-a"))

	stack.requireGuardAdmitted(t, rec, rollback.TargetTypeSteward, "steward-xyz")
}

func TestConfigRollback_UnauthenticatedRequestIsRejectedByManager(t *testing.T) {
	// No user identity in the request context: the production manager refuses to execute
	// (DefaultRollbackManager.getCurrentUser) and nothing is recorded for the target.
	stack := newRollbackStack(t)
	handler := NewRollbackHandler(stack.manager, adminPrincipalExtractor(), nil, nil, stack.subtree)

	body := `{"target_type":"steward","target_id":"steward-noauth","rollback_type":"full","rollback_to":"abc1234567890","reason":"revert bad config"}`
	req := httptest.NewRequest("POST", "/api/v1/rollback/execute", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ExecuteRollback(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Empty(t, stack.operationsFor(t, rollback.TargetTypeSteward, "steward-noauth"),
		"an unauthenticated rollback must not be recorded")
}

func TestConfigRollback_ApprovalRequired(t *testing.T) {
	// A client-wide rollback exceeds the production approval threshold
	// (DefaultRollbackManager.requiresApproval: an estimated 500 affected users against a
	// threshold of 100), so the real manager refuses a request carrying no approval ID and
	// the handler translates that refusal to 412.
	stack := newRollbackStack(t)
	baseline := stack.seedRepository(t, rollback.TargetTypeClient, "7")
	handler := NewRollbackHandler(stack.manager, adminPrincipalExtractor(), nil, nil, stack.subtree)

	body := fmt.Sprintf(
		`{"target_type":"client","target_id":"7","rollback_type":"full","rollback_to":%q,"reason":"revert bad config"}`,
		baseline)
	rec := httptest.NewRecorder()

	handler.ExecuteRollback(rec, newRollbackRequest(body, "admin-cert-cn"))

	stack.requireRollbackError(t, rec, http.StatusPreconditionFailed,
		"This rollback requires approval", rollback.TargetTypeClient, "7")
}

func TestConfigRollback_ValidationFailed(t *testing.T) {
	// A partial rollback that names no configurations fails the production validator
	// (DefaultRollbackValidator.validateRollbackType), so the handler answers 422.
	stack := newRollbackStack(t)
	baseline := stack.seedRepository(t, rollback.TargetTypeDevice, "9")
	handler := NewRollbackHandler(stack.manager, adminPrincipalExtractor(), nil, nil, stack.subtree)

	body := fmt.Sprintf(
		`{"target_type":"device","target_id":"9","rollback_type":"partial","rollback_to":%q,"reason":"revert bad config"}`,
		baseline)
	rec := httptest.NewRecorder()

	handler.ExecuteRollback(rec, newRollbackRequest(body, "admin-cert-cn"))

	stack.requireRollbackError(t, rec, http.StatusUnprocessableEntity,
		rollback.ErrRollbackValidationFailed.Message, rollback.TargetTypeDevice, "9")
}

func TestConfigRollback_PermissionDenied(t *testing.T) {
	// An emergency rollback requires the "rollback.emergency" permission. The production
	// validator asks the real RBAC manager, which holds no such grant for this caller, so
	// the rollback is denied and the handler answers 403 rather than the generic 422.
	stack := newRollbackStack(t)
	baseline := stack.seedRepository(t, rollback.TargetTypeDevice, "11")
	handler := NewRollbackHandler(stack.manager, adminPrincipalExtractor(), nil, nil, stack.subtree)

	body := fmt.Sprintf(
		`{"target_type":"device","target_id":"11","rollback_type":"emergency","rollback_to":%q,"reason":"service outage","emergency":true}`,
		baseline)
	rec := httptest.NewRecorder()

	handler.ExecuteRollback(rec, newRollbackRequest(body, "admin-cert-cn"))

	stack.requireRollbackError(t, rec, http.StatusForbidden,
		rollback.ErrRollbackPermissionDenied.Message, rollback.TargetTypeDevice, "11")
}

func TestConfigRollback_InvalidBody(t *testing.T) {
	stack := newRollbackStack(t)
	handler := NewRollbackHandler(stack.manager, adminPrincipalExtractor(), nil, nil, stack.subtree)

	rec := httptest.NewRecorder()
	handler.ExecuteRollback(rec, newRollbackRequest("not json", "admin-cert-cn"))

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Empty(t, stack.operationsFor(t, rollback.TargetTypeSteward, "steward-x"))
}

func TestConfigRollback_ServerSideTenantLookup(t *testing.T) {
	// When stewardTenantLookup returns a different tenant from the principal's scope,
	// the handler must reject the request even if steward_tenant_path is absent or
	// matches the correct tenant — the server-side check is authoritative.
	t.Run("rejects cross-tenant steward via server-side lookup", func(t *testing.T) {
		stack := newRollbackStack(t)
		stack.ownSteward(t, "steward-msp-b", "msp-b")
		stack.seedLiveOperation(t, rollback.TargetTypeSteward, "steward-msp-b")
		lookup := func(_ string) string { return "msp-b" }
		handler := NewRollbackHandler(stack.manager, scopedPrincipalExtractor("msp-a"), lookup, nil, stack.subtree)

		// No steward_tenant_path in body — server-side lookup must catch this anyway.
		body := `{"target_type":"steward","target_id":"steward-msp-b","rollback_type":"full","rollback_to":"abc123","reason":"revert bad config"}`
		rec := httptest.NewRecorder()

		handler.ExecuteRollback(rec, newScopedRollbackRequest(body, "admin-api-key", "msp-a"))

		stack.requireGuardRejected(t, rec, rollback.TargetTypeSteward, "steward-msp-b")
	})

	t.Run("allows same-tenant steward via server-side lookup", func(t *testing.T) {
		stack := newRollbackStack(t)
		stack.ownSteward(t, "steward-msp-a", "msp-a")
		stack.seedLiveOperation(t, rollback.TargetTypeSteward, "steward-msp-a")
		lookup := func(_ string) string { return "msp-a" }
		handler := NewRollbackHandler(stack.manager, scopedPrincipalExtractor("msp-a"), lookup, nil, stack.subtree)

		body := `{"target_type":"steward","target_id":"steward-msp-a","rollback_type":"full","rollback_to":"abc123","reason":"revert bad config"}`
		rec := httptest.NewRecorder()

		handler.ExecuteRollback(rec, newScopedRollbackRequest(body, "admin-api-key", "msp-a"))

		stack.requireGuardAdmitted(t, rec, rollback.TargetTypeSteward, "steward-msp-a")
	})

	t.Run("lookup returns empty string leaves the manager to refuse the unknown steward", func(t *testing.T) {
		// Steward not in the registry (pre-registration edge case): the handler's own
		// lookup returns "" and its guard stands down, leaving the rollback manager as
		// the authoritative gatekeeper. The manager resolves target ownership from the
		// same registry, finds no owner, and refuses the scoped caller rather than
		// letting an unowned target through (Issue #4340).
		stack := newRollbackStack(t)
		stack.seedLiveOperation(t, rollback.TargetTypeSteward, "steward-unknown")
		lookup := func(_ string) string { return "" }
		handler := NewRollbackHandler(stack.manager, scopedPrincipalExtractor("msp-a"), lookup, nil, stack.subtree)

		body := `{"target_type":"steward","target_id":"steward-unknown","rollback_type":"full","rollback_to":"abc123","reason":"revert bad config"}`
		rec := httptest.NewRecorder()

		handler.ExecuteRollback(rec, newScopedRollbackRequest(body, "admin-api-key", "msp-a"))

		require.Equal(t, http.StatusForbidden, rec.Code, "body: %s", rec.Body.String())

		var resp map[string]interface{}
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		assert.Equal(t, rollback.ErrRollbackOutsideTenantScope.Message, resp["error"])

		// The seeded operation is still the only one on record: nothing was initiated.
		ops := stack.operationsFor(t, rollback.TargetTypeSteward, "steward-unknown")
		require.Len(t, ops, 1)
		assert.Equal(t, rollback.RollbackStatusInProgress, ops[0].Status)
	})

	t.Run("admin principal skips server-side lookup entirely", func(t *testing.T) {
		stack := newRollbackStack(t)
		stack.seedLiveOperation(t, rollback.TargetTypeSteward, "steward-any")
		// lookup would return a cross-tenant result but admin bypasses the check
		lookup := func(_ string) string { return "msp-z" }
		handler := NewRollbackHandler(stack.manager, adminPrincipalExtractor(), lookup, nil, stack.subtree)

		body := `{"target_type":"steward","target_id":"steward-any","rollback_type":"full","rollback_to":"abc123","reason":"revert bad config"}`
		rec := httptest.NewRecorder()

		handler.ExecuteRollback(rec, newRollbackRequest(body, "admin-cert-cn"))

		stack.requireGuardAdmitted(t, rec, rollback.TargetTypeSteward, "steward-any")
	})
}

// TestConfigRollback_SessionPrincipal_CrossTenantBlocked verifies the Issue #3143 fix
// for rollback_handler.go: a web-session principal has GlobalScope=true set by middleware
// even when scoped to a specific tenant. Before the fix, the !principal.GlobalScope guard
// would always pass (GlobalScope=true → !true=false → check skipped), allowing a session
// caller to roll back any tenant's steward. After the fix, only principal.TenantID governs
// the cross-tenant check.
func TestConfigRollback_SessionPrincipal_CrossTenantBlocked(t *testing.T) {
	stack := newRollbackStack(t)
	stack.ownSteward(t, "steward-msp-b", "msp-b")
	stack.seedLiveOperation(t, rollback.TargetTypeSteward, "steward-msp-b")
	// Session principal scoped to "msp-a" with GlobalScope=true (the bug).
	handler := NewRollbackHandler(stack.manager, sessionPrincipalExtractor("msp-a"), nil, nil, stack.subtree)

	// Target steward belongs to "msp-b" — a sibling tenant, not a child.
	body := `{"target_type":"steward","target_id":"steward-msp-b","rollback_type":"full","rollback_to":"abc1234567890","reason":"revert bad config","dry_run":false,"steward_tenant_path":"msp-b"}`
	rec := httptest.NewRecorder()

	handler.ExecuteRollback(rec, newScopedRollbackRequest(body, "web-session-msp-a", "msp-a"))

	stack.requireGuardRejected(t, rec, rollback.TargetTypeSteward, "steward-msp-b")
}

func TestConfigRollback_ListRollbackPointsRequiresTarget(t *testing.T) {
	stack := newRollbackStack(t)
	handler := NewRollbackHandler(stack.manager, adminPrincipalExtractor(), nil, nil, stack.subtree)

	req := withRootScope(httptest.NewRequest("GET", "/api/v1/rollback/points?target_type=steward", nil))
	rec := httptest.NewRecorder()
	handler.ListRollbackPoints(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestConfigRollback_GetRollbackStatus(t *testing.T) {
	stack := newRollbackStack(t)
	handler := NewRollbackHandler(stack.manager, adminPrincipalExtractor(), nil, nil, stack.subtree)

	t.Run("unknown rollback id returns 404", func(t *testing.T) {
		req := mux.SetURLVars(withRootScope(httptest.NewRequest("GET", "/api/v1/rollback/missing/status", nil)),
			map[string]string{"rollback_id": "missing"})
		rec := httptest.NewRecorder()
		handler.GetRollbackStatus(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("recorded operation is returned", func(t *testing.T) {
		id := stack.seedOperation(t, rollback.TargetTypeSteward, "steward-status", rollback.RollbackStatusPending)

		req := mux.SetURLVars(withRootScope(httptest.NewRequest("GET", "/api/v1/rollback/"+id+"/status", nil)),
			map[string]string{"rollback_id": id})
		rec := httptest.NewRecorder()
		handler.GetRollbackStatus(rec, req)

		require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
		var resp struct {
			Rollback rollback.RollbackOperation `json:"rollback"`
		}
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		assert.Equal(t, id, resp.Rollback.ID)
		assert.Equal(t, rollback.RollbackStatusPending, resp.Rollback.Status)
		assert.Equal(t, "steward-status", resp.Rollback.Request.TargetID)
	})
}

func TestConfigRollback_CancelRollback(t *testing.T) {
	t.Run("cancellable operation is cancelled in the store", func(t *testing.T) {
		stack := newRollbackStack(t)
		handler := NewRollbackHandler(stack.manager, adminPrincipalExtractor(), nil, nil, stack.subtree)
		id := stack.seedOperation(t, rollback.TargetTypeSteward, "steward-cancel", rollback.RollbackStatusPending)

		req := httptest.NewRequest("POST", "/api/v1/rollback/"+id+"/cancel", strings.NewReader(`{"reason":"superseded"}`))
		req = withRootScope(req.WithContext(context.WithValue(req.Context(), ctxkeys.UserIDKey, "admin-cert-cn")))
		req = mux.SetURLVars(req, map[string]string{"rollback_id": id})
		rec := httptest.NewRecorder()
		handler.CancelRollback(rec, req)

		require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

		// The production manager must have persisted the cancellation.
		operation, err := stack.store.GetOperation(context.Background(), id)
		require.NoError(t, err)
		require.NotNil(t, operation)
		assert.Equal(t, rollback.RollbackStatusCancelled, operation.Status)
		require.NotNil(t, operation.CompletedAt)
	})

	t.Run("in-progress operation cannot be cancelled", func(t *testing.T) {
		stack := newRollbackStack(t)
		handler := NewRollbackHandler(stack.manager, adminPrincipalExtractor(), nil, nil, stack.subtree)
		id := stack.seedLiveOperation(t, rollback.TargetTypeSteward, "steward-live")

		req := httptest.NewRequest("POST", "/api/v1/rollback/"+id+"/cancel", strings.NewReader(`{"reason":"stop it"}`))
		req = withRootScope(req.WithContext(context.WithValue(req.Context(), ctxkeys.UserIDKey, "admin-cert-cn")))
		req = mux.SetURLVars(req, map[string]string{"rollback_id": id})
		rec := httptest.NewRecorder()
		handler.CancelRollback(rec, req)

		assert.Equal(t, http.StatusConflict, rec.Code)

		operation, err := stack.store.GetOperation(context.Background(), id)
		require.NoError(t, err)
		require.NotNil(t, operation)
		assert.Equal(t, rollback.RollbackStatusInProgress, operation.Status,
			"a non-cancellable operation must keep its status")
	})

	t.Run("unknown rollback id returns 404", func(t *testing.T) {
		stack := newRollbackStack(t)
		handler := NewRollbackHandler(stack.manager, adminPrincipalExtractor(), nil, nil, stack.subtree)

		req := httptest.NewRequest("POST", "/api/v1/rollback/missing/cancel", strings.NewReader(`{"reason":"n/a"}`))
		req = withRootScope(req.WithContext(context.WithValue(req.Context(), ctxkeys.UserIDKey, "admin-cert-cn")))
		req = mux.SetURLVars(req, map[string]string{"rollback_id": "missing"})
		rec := httptest.NewRecorder()
		handler.CancelRollback(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
}

// TestConfigRollback_CancelRollback_CrossTenant_NotFound is the [REQUIRED TEST] for
// Issue #4335: a tenant-a caller cannot cancel a rollback whose target steward
// belongs to tenant-b, and gets the same 404 as an unknown rollback ID — not a
// distinguishable error — so the endpoint cannot be used to probe existence.
func TestConfigRollback_CancelRollback_CrossTenant_NotFound(t *testing.T) {
	stack := newRollbackStack(t)
	lookup := func(_ string) string { return "tenant-b" }
	handler := NewRollbackHandler(stack.manager, adminPrincipalExtractor(), lookup, nil, stack.subtree)
	id := stack.seedOperation(t, rollback.TargetTypeSteward, "steward-tenant-b", rollback.RollbackStatusPending)

	req := httptest.NewRequest("POST", "/api/v1/rollback/"+id+"/cancel", strings.NewReader(`{"reason":"cross-tenant attempt"}`))
	ctx := context.WithValue(req.Context(), ctxkeys.UserIDKey, "tenant-a-caller")
	ctx = context.WithValue(ctx, ctxkeys.TenantScopeKey, ctxkeys.NewTenantScope("tenant-a"))
	req = req.WithContext(ctx)
	req = mux.SetURLVars(req, map[string]string{"rollback_id": id})
	rec := httptest.NewRecorder()
	handler.CancelRollback(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code,
		"tenant-a caller must not be able to cancel tenant-b's rollback: %s", rec.Body.String())

	operation, err := stack.store.GetOperation(context.Background(), id)
	require.NoError(t, err)
	require.NotNil(t, operation)
	assert.Equal(t, rollback.RollbackStatusPending, operation.Status,
		"cross-tenant cancel must not modify the victim's rollback status")
}

// scopedRollbackRequest builds a request carrying the caller's ctxkeys.TenantScope exactly
// as authenticationMiddleware establishes it, plus the mux path vars the rollback routes
// read. It is the read-side counterpart to newRollbackRequest, which covers the
// execute route's actor-identity-only context.
func scopedRollbackRequest(method, url, body string, scope ctxkeys.TenantScope, vars map[string]string) *http.Request {
	req := httptest.NewRequest(method, url, strings.NewReader(body))
	ctx := context.WithValue(req.Context(), ctxkeys.UserIDKey, "scoped-caller")
	ctx = context.WithValue(ctx, ctxkeys.TenantScopeKey, scope)
	req = req.WithContext(ctx)
	if vars != nil {
		req = mux.SetURLVars(req, vars)
	}
	return req
}

// TestConfigRollback_ListRollbackPoints_CrossTenant_EmptyList is a [REQUIRED TEST] for
// Issue #4335: a tenant-a caller asking for the rollback points of a steward registered
// to tenant-b gets the same empty list as a target with no recorded rollback points, so
// the endpoint cannot be used to probe cross-tenant existence. The root-scoped control
// request proves the empty list is the authorization guard's work and not an empty
// repository.
func TestConfigRollback_ListRollbackPoints_CrossTenant_EmptyList(t *testing.T) {
	stack := newRollbackStack(t)
	// A device target is used because the production manager only derives repository IDs
	// for device/group/client/msp targets (getRepositoryID); the tenant guard under test
	// is target-type independent.
	stack.seedRepository(t, rollback.TargetTypeDevice, "device-tenant-b")
	lookup := func(_ string) string { return "tenant-b" }
	handler := NewRollbackHandler(stack.manager, adminPrincipalExtractor(), lookup, nil, stack.subtree)

	const url = "/api/v1/rollback/points?target_type=device&target_id=device-tenant-b"
	decodePoints := func(t *testing.T, rec *httptest.ResponseRecorder) []rollback.RollbackPoint {
		t.Helper()
		require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
		var resp struct {
			Points []rollback.RollbackPoint `json:"rollback_points"`
		}
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		return resp.Points
	}

	// Control: a root-scoped caller sees the target's real rollback points.
	rec := httptest.NewRecorder()
	handler.ListRollbackPoints(rec, scopedRollbackRequest("GET", url, "", ctxkeys.NewRootScope(), nil))
	require.NotEmpty(t, decodePoints(t, rec),
		"the seeded repository must expose rollback points to an in-scope caller")

	// A tenant-a caller must see nothing for tenant-b's steward.
	rec = httptest.NewRecorder()
	handler.ListRollbackPoints(rec, scopedRollbackRequest("GET", url, "", ctxkeys.NewTenantScope("tenant-a"), nil))
	assert.Empty(t, decodePoints(t, rec),
		"tenant-a must not see the rollback points of a steward registered to tenant-b")

	// An unset scope (the auth-plumbing-bug signature) must be refused the same way.
	rec = httptest.NewRecorder()
	handler.ListRollbackPoints(rec, scopedRollbackRequest("GET", url, "", ctxkeys.TenantScope{}, nil))
	assert.Empty(t, decodePoints(t, rec),
		"an unset tenant scope must not be treated as unrestricted")
}

// TestConfigRollback_PreviewRollback_CrossTenant_Rejected is a [REQUIRED TEST] for Issue
// #4335: previewing a rollback of another tenant's steward is refused with the same
// CROSS_TENANT_ROLLBACK response ExecuteRollback returns, so the preview route cannot be
// used to read a cross-tenant diff. The root-scoped control proves the rejection comes
// from the guard rather than from the preview failing for unrelated reasons.
func TestConfigRollback_PreviewRollback_CrossTenant_Rejected(t *testing.T) {
	stack := newRollbackStack(t)
	// Device target, for the same getRepositoryID reason as the rollback-points test above.
	baseline := stack.seedRepository(t, rollback.TargetTypeDevice, "device-tenant-b")
	lookup := func(_ string) string { return "tenant-b" }
	handler := NewRollbackHandler(stack.manager, adminPrincipalExtractor(), lookup, nil, stack.subtree)

	body := fmt.Sprintf(
		`{"target_type":"device","target_id":"device-tenant-b","rollback_type":"full","rollback_to":%q,"reason":"revert bad config"}`,
		baseline)

	// Control: a root-scoped caller gets a real preview from the production manager.
	rec := httptest.NewRecorder()
	handler.PreviewRollback(rec, scopedRollbackRequest("POST", "/api/v1/rollback/preview", body, ctxkeys.NewRootScope(), nil))
	require.Equal(t, http.StatusOK, rec.Code, "in-scope preview must reach the manager: %s", rec.Body.String())
	var previewResp struct {
		Preview *rollback.RollbackPreview `json:"preview"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&previewResp))
	require.NotNil(t, previewResp.Preview, "in-scope preview must return a preview")

	// tenant-a must be refused before the manager is consulted.
	for name, scope := range map[string]ctxkeys.TenantScope{
		"cross-tenant scope": ctxkeys.NewTenantScope("tenant-a"),
		"unset scope":        {},
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler.PreviewRollback(rec, scopedRollbackRequest("POST", "/api/v1/rollback/preview", body, scope, nil))

			require.Equal(t, http.StatusBadRequest, rec.Code, "body: %s", rec.Body.String())
			var resp map[string]interface{}
			require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
			assert.Equal(t, "CROSS_TENANT_ROLLBACK", resp["code"])
			assert.Nil(t, resp["preview"], "a refused preview must not disclose a diff")
		})
	}
}

// TestConfigRollback_SubtreeGuard_ThroughInjectedAncestry covers preview and execute
// for a caller scoped to msp-a over real tenants: a steward in client-1 (a ParentID
// child) passes the handler guard, and one in msp-b or the shared-prefix sibling
// msp-ab is refused with CROSS_TENANT_ROLLBACK.
func TestConfigRollback_SubtreeGuard_ThroughInjectedAncestry(t *testing.T) {
	scope := ctxkeys.NewTenantScope("msp-a")
	for _, tc := range []struct {
		tenant   string
		admitted bool
	}{
		{"client-1", true},
		{"msp-b", false},
		{"msp-ab", false},
	} {
		t.Run(tc.tenant, func(t *testing.T) {
			stack := newRollbackStack(t)
			lookup := func(_ string) string { return tc.tenant }
			handler := NewRollbackHandler(stack.manager, scopedPrincipalExtractor("msp-a"), lookup, nil, stack.subtree)
			body := `{"target_type":"steward","target_id":"steward-x","rollback_type":"full","rollback_to":"abc1234567890","reason":"revert bad config"}`

			for name, call := range map[string]func(http.ResponseWriter, *http.Request){
				"preview": handler.PreviewRollback,
				"execute": handler.ExecuteRollback,
			} {
				t.Run(name, func(t *testing.T) {
					rec := httptest.NewRecorder()
					call(rec, scopedRollbackRequest("POST", "/api/v1/rollback/"+name, body, scope, nil))
					if tc.admitted {
						requireHandlerGuardPassed(t, rec)
						return
					}
					require.Equal(t, http.StatusBadRequest, rec.Code, "body: %s", rec.Body.String())
					var resp map[string]interface{}
					require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
					assert.Equal(t, "CROSS_TENANT_ROLLBACK", resp["code"])
				})
			}
		})
	}
}

// TestConfigRollback_GetRollbackStatus_CrossTenant_NotFound is a [REQUIRED TEST] for
// Issue #4335: reading the status of a rollback whose target steward belongs to another
// tenant returns the same 404 as an unknown rollback ID. The root-scoped control proves
// the operation is readable when the caller is in scope.
func TestConfigRollback_GetRollbackStatus_CrossTenant_NotFound(t *testing.T) {
	stack := newRollbackStack(t)
	lookup := func(_ string) string { return "tenant-b" }
	handler := NewRollbackHandler(stack.manager, adminPrincipalExtractor(), lookup, nil, stack.subtree)
	id := stack.seedOperation(t, rollback.TargetTypeSteward, "steward-tenant-b", rollback.RollbackStatusPending)

	url := "/api/v1/rollback/" + id + "/status"
	vars := map[string]string{"rollback_id": id}

	// Control: a root-scoped caller can read the operation.
	rec := httptest.NewRecorder()
	handler.GetRollbackStatus(rec, scopedRollbackRequest("GET", url, "", ctxkeys.NewRootScope(), vars))
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
	var resp struct {
		Rollback rollback.RollbackOperation `json:"rollback"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.Equal(t, id, resp.Rollback.ID)

	for name, scope := range map[string]ctxkeys.TenantScope{
		"cross-tenant scope": ctxkeys.NewTenantScope("tenant-a"),
		"unset scope":        {},
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler.GetRollbackStatus(rec, scopedRollbackRequest("GET", url, "", scope, vars))

			require.Equal(t, http.StatusNotFound, rec.Code,
				"an out-of-scope status read must be indistinguishable from an unknown rollback ID: %s", rec.Body.String())
			assert.NotContains(t, rec.Body.String(), "steward-tenant-b",
				"the refusal must not disclose the victim's target")
		})
	}
}

// TestConfigRollback_ListRollbackHistory_CrossTenant_EmptyList is a [REQUIRED TEST] for
// Issue #4335, covering the fourth read path guarded by authorizedForTargetTenant: the
// history of another tenant's steward reads as empty rather than 403, so the endpoint
// cannot be used to probe cross-tenant existence.
func TestConfigRollback_ListRollbackHistory_CrossTenant_EmptyList(t *testing.T) {
	stack := newRollbackStack(t)
	lookup := func(_ string) string { return "tenant-b" }
	handler := NewRollbackHandler(stack.manager, adminPrincipalExtractor(), lookup, nil, stack.subtree)
	wanted := stack.seedOperation(t, rollback.TargetTypeSteward, "steward-tenant-b", rollback.RollbackStatusCompleted)

	const url = "/api/v1/rollback/history?target_type=steward&target_id=steward-tenant-b"
	decodeOps := func(t *testing.T, rec *httptest.ResponseRecorder) []rollback.RollbackOperation {
		t.Helper()
		require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
		var resp struct {
			Operations []rollback.RollbackOperation `json:"rollback_operations"`
		}
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		return resp.Operations
	}

	// Control: a root-scoped caller sees the recorded operation.
	rec := httptest.NewRecorder()
	handler.ListRollbackHistory(rec, scopedRollbackRequest("GET", url, "", ctxkeys.NewRootScope(), nil))
	ops := decodeOps(t, rec)
	require.Len(t, ops, 1)
	require.Equal(t, wanted, ops[0].ID)

	for name, scope := range map[string]ctxkeys.TenantScope{
		"cross-tenant scope": ctxkeys.NewTenantScope("tenant-a"),
		"unset scope":        {},
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler.ListRollbackHistory(rec, scopedRollbackRequest("GET", url, "", scope, nil))
			assert.Empty(t, decodeOps(t, rec),
				"tenant-a must not read the rollback history of a steward registered to tenant-b")
		})
	}
}

func TestConfigRollback_ListRollbackHistory(t *testing.T) {
	stack := newRollbackStack(t)
	handler := NewRollbackHandler(stack.manager, adminPrincipalExtractor(), nil, nil, stack.subtree)

	wanted := stack.seedOperation(t, rollback.TargetTypeSteward, "steward-history", rollback.RollbackStatusCompleted)
	stack.seedOperation(t, rollback.TargetTypeSteward, "steward-other", rollback.RollbackStatusCompleted)

	req := withRootScope(httptest.NewRequest("GET", "/api/v1/rollback/history?target_type=steward&target_id=steward-history", nil))
	rec := httptest.NewRecorder()
	handler.ListRollbackHistory(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
	var resp struct {
		Operations []rollback.RollbackOperation `json:"rollback_operations"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.Len(t, resp.Operations, 1, "history must be scoped to the requested target")
	assert.Equal(t, wanted, resp.Operations[0].ID)

	// Missing parameters are rejected before the manager is consulted.
	rec = httptest.NewRecorder()
	handler.ListRollbackHistory(rec, withRootScope(httptest.NewRequest("GET", "/api/v1/rollback/history?target_type=steward", nil)))
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// Tenant-boundary tests over the production stack (Issue #4340).
//
// These drive the live HTTP handlers against the real rollback manager, the real
// features/config/git DefaultGitManager over the go-git LocalRepositoryStore and
// the controller's real steward registry. The repositories hold genuine commits
// written by go-git, so the commit metadata a rollback point is built from is
// whatever the production Git stack actually records — which carries no tenant.
// The boundary therefore has to come from the registry, and these tests fail if
// it is ever read back from Git history instead.

func TestConfigRollback_ListRollbackPoints_TenantBoundary(t *testing.T) {
	t.Run("scoped caller cannot enumerate another tenant's rollback points", func(t *testing.T) {
		stack := newRollbackStack(t)
		stack.seedRepository(t, rollback.TargetTypeDevice, "device-msp-b")
		stack.ownSteward(t, "device-msp-b", "msp-b")
		handler := NewRollbackHandler(stack.manager, scopedPrincipalExtractor("msp-a"), nil, nil, stack.subtree)

		req := httptest.NewRequest("GET", "/api/v1/rollback/points?target_type=device&target_id=device-msp-b", nil)
		req = req.WithContext(context.WithValue(req.Context(), ctxkeys.TenantScopeKey, ctxkeys.NewTenantScope("msp-a")))
		rec := httptest.NewRecorder()
		handler.ListRollbackPoints(rec, req)

		require.Equal(t, http.StatusForbidden, rec.Code, "body: %s", rec.Body.String())

		var resp map[string]interface{}
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		assert.Equal(t, rollback.ErrRollbackOutsideTenantScope.Message, resp["error"])
		assert.NotContains(t, rec.Body.String(), "rollback_points",
			"no commit SHA, message, author or path of another tenant may reach the caller")
	})

	t.Run("scoped caller receives its own tenant's rollback points", func(t *testing.T) {
		stack := newRollbackStack(t)
		stack.seedRepository(t, rollback.TargetTypeDevice, "device-msp-a")
		stack.ownSteward(t, "device-msp-a", "msp-a")
		handler := NewRollbackHandler(stack.manager, scopedPrincipalExtractor("msp-a"), nil, nil, stack.subtree)

		req := httptest.NewRequest("GET", "/api/v1/rollback/points?target_type=device&target_id=device-msp-a", nil)
		req = req.WithContext(context.WithValue(req.Context(), ctxkeys.TenantScopeKey, ctxkeys.NewTenantScope("msp-a")))
		rec := httptest.NewRecorder()
		handler.ListRollbackPoints(rec, req)

		require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

		var resp struct {
			Points []rollback.RollbackPoint `json:"rollback_points"`
		}
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		require.NotEmpty(t, resp.Points,
			"the caller's own tenant must still see the points the real Git history holds")
		assert.NotEmpty(t, resp.Points[0].CommitSHA)
	})

	t.Run("unknown target is refused for a scoped caller", func(t *testing.T) {
		// The repository exists but the registry owns no such steward: ownership is
		// not established, so the target is outside every tenant.
		stack := newRollbackStack(t)
		stack.seedRepository(t, rollback.TargetTypeDevice, "device-unowned")
		handler := NewRollbackHandler(stack.manager, scopedPrincipalExtractor("msp-a"), nil, nil, stack.subtree)

		req := httptest.NewRequest("GET", "/api/v1/rollback/points?target_type=device&target_id=device-unowned", nil)
		req = req.WithContext(context.WithValue(req.Context(), ctxkeys.TenantScopeKey, ctxkeys.NewTenantScope("msp-a")))
		rec := httptest.NewRecorder()
		handler.ListRollbackPoints(rec, req)

		assert.Equal(t, http.StatusForbidden, rec.Code, "body: %s", rec.Body.String())
	})

	t.Run("root-scoped admin still enumerates every target", func(t *testing.T) {
		stack := newRollbackStack(t)
		stack.seedRepository(t, rollback.TargetTypeDevice, "device-msp-b")
		stack.ownSteward(t, "device-msp-b", "msp-b")
		handler := NewRollbackHandler(stack.manager, adminPrincipalExtractor(), nil, nil, stack.subtree)

		req := withRootScope(httptest.NewRequest("GET", "/api/v1/rollback/points?target_type=device&target_id=device-msp-b", nil))
		rec := httptest.NewRecorder()
		handler.ListRollbackPoints(rec, req)

		require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

		var resp struct {
			Points []rollback.RollbackPoint `json:"rollback_points"`
		}
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		assert.NotEmpty(t, resp.Points)
	})
}

func TestConfigRollback_StatusCancelAndHistory_TenantBoundary(t *testing.T) {
	// One rollback operation belonging to msp-b, reached by a caller scoped to
	// msp-a through each of the three endpoints that take a rollback or target
	// ID: status, cancel and history.
	stack := newRollbackStack(t)
	stack.ownSteward(t, "steward-msp-b", "msp-b")
	handler := NewRollbackHandler(stack.manager, scopedPrincipalExtractor("msp-a"), nil, nil, stack.subtree)

	id := stack.seedOperation(t, rollback.TargetTypeSteward, "steward-msp-b", rollback.RollbackStatusPending)
	scoped := func(req *http.Request) *http.Request {
		ctx := context.WithValue(req.Context(), ctxkeys.UserIDKey, "admin-api-key")
		return req.WithContext(context.WithValue(ctx, ctxkeys.TenantScopeKey, ctxkeys.NewTenantScope("msp-a")))
	}

	t.Run("status of another tenant's rollback is refused", func(t *testing.T) {
		req := mux.SetURLVars(scoped(httptest.NewRequest("GET", "/api/v1/rollback/"+id+"/status", nil)),
			map[string]string{"rollback_id": id})
		rec := httptest.NewRecorder()
		handler.GetRollbackStatus(rec, req)

		// Indistinguishable from an unknown rollback ID (Issue #4335/#4340), matching
		// TestConfigRollback_GetRollbackStatus_CrossTenant_NotFound.
		require.Equal(t, http.StatusNotFound, rec.Code, "body: %s", rec.Body.String())
		assert.NotContains(t, rec.Body.String(), "ops@example.com",
			"the initiating operator of another tenant's rollback must not be disclosed")
	})

	t.Run("cancelling another tenant's rollback is refused and leaves it running", func(t *testing.T) {
		req := mux.SetURLVars(scoped(httptest.NewRequest("POST", "/api/v1/rollback/"+id+"/cancel", strings.NewReader(`{"reason":"not mine"}`))),
			map[string]string{"rollback_id": id})
		rec := httptest.NewRecorder()
		handler.CancelRollback(rec, req)

		// Indistinguishable from an unknown rollback ID (Issue #4335/#4340), matching
		// TestConfigRollback_CancelRollback_CrossTenant_NotFound.
		require.Equal(t, http.StatusNotFound, rec.Code, "body: %s", rec.Body.String())

		operation, err := stack.store.GetOperation(context.Background(), id)
		require.NoError(t, err)
		require.NotNil(t, operation)
		assert.Equal(t, rollback.RollbackStatusPending, operation.Status,
			"a refused cancel must not touch the other tenant's operation")
	})

	t.Run("history of another tenant's target is empty", func(t *testing.T) {
		req := scoped(httptest.NewRequest("GET", "/api/v1/rollback/history?target_type=steward&target_id=steward-msp-b", nil))
		rec := httptest.NewRecorder()
		handler.ListRollbackHistory(rec, req)

		require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

		var resp struct {
			Operations []rollback.RollbackOperation `json:"rollback_operations"`
		}
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		assert.Empty(t, resp.Operations,
			"another tenant's rollback history, and its audit trail, must not be enumerable")
	})
}
