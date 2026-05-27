// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2025 CFGMS Contributors
// Package git provides module repository management functionality
package git

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/pkg/logging"
)

// ModuleRepositoryManager manages script and module repositories
type ModuleRepositoryManager struct {
	gitManager GitManager
	store      RepositoryStore
	// Authoritative in-memory state: RepositoryStore (git filesystem) has no metadata persistence layer. These maps are the only record of registered repositories and their local paths. Not a cache — pkg/cache migration would make repository registration non-durable across restarts.
	moduleCache  map[string]*CustomModule // module_id -> module
	repoCache    map[string]*Repository   // repo_id -> repository
	mu           sync.RWMutex
	secValidator *ModuleSecurityValidator
	logger       logging.Logger
	// cacheDir is the base directory for cloned module repositories.
	// Defaults to filepath.Join(os.TempDir(), "cfgms-modules"); overridable for test isolation.
	cacheDir string
}

// NewModuleRepositoryManager creates a new module repository manager
func NewModuleRepositoryManager(gitManager GitManager, store RepositoryStore, logger logging.Logger) *ModuleRepositoryManager {
	if logger == nil {
		logger = logging.NewNoopLogger()
	}
	return &ModuleRepositoryManager{
		gitManager:   gitManager,
		store:        store,
		moduleCache:  make(map[string]*CustomModule),
		repoCache:    make(map[string]*Repository),
		secValidator: NewModuleSecurityValidator(),
		logger:       logger,
		cacheDir:     filepath.Join(os.TempDir(), "cfgms-modules"),
	}
}

// CreateModuleRepository creates a repository specifically for modules
func (mrm *ModuleRepositoryManager) CreateModuleRepository(ctx context.Context, config RepositoryConfig) (*Repository, error) {
	// Ensure this is a module repository type
	if !mrm.isModuleRepositoryType(config.Type) {
		return nil, fmt.Errorf("invalid repository type for modules: %s", config.Type)
	}

	// Set module-specific defaults
	mrm.setModuleRepositoryDefaults(&config)

	// Create the repository
	repo, err := mrm.gitManager.CreateRepository(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create module repository: %w", err)
	}

	// Initialize module repository structure
	if err := mrm.initializeModuleRepository(ctx, repo); err != nil {
		// Clean up on failure
		_ = mrm.gitManager.DeleteRepository(ctx, repo.ID)
		return nil, fmt.Errorf("failed to initialize module repository: %w", err)
	}

	// Cache the repository
	mrm.mu.Lock()
	mrm.repoCache[repo.ID] = repo
	mrm.mu.Unlock()

	return repo, nil
}

// LinkModuleRepository links a module repository to a configuration repository
func (mrm *ModuleRepositoryManager) LinkModuleRepository(ctx context.Context, configRepoID, moduleRepoID string, linkConfig ModuleRepository) error {
	// Get the configuration repository
	configRepo, err := mrm.gitManager.GetRepository(ctx, configRepoID)
	if err != nil {
		return fmt.Errorf("failed to get configuration repository: %w", err)
	}

	// Validate the module repository exists
	moduleRepo, err := mrm.gitManager.GetRepository(ctx, moduleRepoID)
	if err != nil {
		return fmt.Errorf("failed to get module repository: %w", err)
	}

	// Validate that this is a module repository
	if !mrm.isModuleRepositoryType(moduleRepo.Type) {
		return fmt.Errorf("repository %s is not a module repository", moduleRepoID)
	}

	// Initialize repository links if needed
	if configRepo.ModuleLinks == nil {
		configRepo.ModuleLinks = &RepositoryLinks{
			ConfigRepository:     configRepoID,
			ModuleRepositories:   []ModuleRepository{},
			TemplateRepositories: []string{},
		}
	}

	// Add the link
	linkConfig.ID = moduleRepoID
	linkConfig.URL = moduleRepo.CloneURL
	linkConfig.Enabled = true

	// Validate security policy
	if err := mrm.validateSecurityPolicy(linkConfig.SecurityPolicy); err != nil {
		return fmt.Errorf("invalid security policy: %w", err)
	}

	configRepo.ModuleLinks.ModuleRepositories = append(configRepo.ModuleLinks.ModuleRepositories, linkConfig)

	return nil
}

// LoadModulesFromRepository loads modules from a module repository
func (mrm *ModuleRepositoryManager) LoadModulesFromRepository(ctx context.Context, repoID string) ([]*CustomModule, error) {
	repo, err := mrm.getModuleRepository(ctx, repoID)
	if err != nil {
		return nil, err
	}

	// Get local path
	localPath, err := mrm.ensureModuleRepository(ctx, repo)
	if err != nil {
		return nil, err
	}

	// Scan for module specifications
	moduleSpecs, err := mrm.scanForModuleSpecs(ctx, localPath)
	if err != nil {
		return nil, fmt.Errorf("failed to scan for modules: %w", err)
	}

	var modules []*CustomModule
	for _, spec := range moduleSpecs {
		module, err := mrm.loadModule(ctx, repo, localPath, spec)
		if err != nil {
			mrm.logger.Warn("failed to load module",
				"spec", logging.SanitizeLogValue(spec),
				"error", err,
			)
			continue
		}

		// Validate security
		if err := mrm.secValidator.ValidateModule(ctx, module); err != nil {
			mrm.logger.Warn("module failed security validation",
				"module", logging.SanitizeLogValue(module.Name),
				"error", err,
			)
			module.SecurityStatus.Status = SecurityStatusRejected
			module.SecurityStatus.Issues = []SecurityIssue{{
				Type:        "security_validation",
				Severity:    "high",
				Description: err.Error(),
			}}
		} else {
			module.SecurityStatus.Status = SecurityStatusApproved
			module.SecurityStatus.LastScanned = time.Now()
		}

		modules = append(modules, module)

		// Cache the module
		mrm.mu.Lock()
		mrm.moduleCache[module.Name] = module
		mrm.mu.Unlock()
	}

	return modules, nil
}

// GetModule retrieves a specific module by name
func (mrm *ModuleRepositoryManager) GetModule(ctx context.Context, moduleName string) (*CustomModule, error) {
	mrm.mu.RLock()
	module, exists := mrm.moduleCache[moduleName]
	mrm.mu.RUnlock()

	if exists {
		return module, nil
	}

	// Search across all linked repositories
	// This is a simplified implementation
	return nil, fmt.Errorf("module not found: %s", moduleName)
}

// UpdateModule updates a module in its repository
func (mrm *ModuleRepositoryManager) UpdateModule(ctx context.Context, module *CustomModule) error {
	repo, err := mrm.getModuleRepository(ctx, module.Repository)
	if err != nil {
		return err
	}

	// Validate permissions
	if err := mrm.validateUpdatePermissions(ctx, repo, module); err != nil {
		return fmt.Errorf("permission denied: %w", err)
	}

	localPath, err := mrm.ensureModuleRepository(ctx, repo)
	if err != nil {
		return err
	}

	// Write module specification
	specPath := filepath.Join(module.Path, "module.yaml")
	if err := mrm.writeModuleSpec(ctx, localPath, specPath, module); err != nil {
		return fmt.Errorf("failed to write module spec: %w", err)
	}

	// Write script files
	for platform, content := range module.Scripts {
		scriptPath := filepath.Join(module.Path, module.Spec.Script.Files[platform])
		if err := mrm.store.WriteFile(ctx, localPath, scriptPath, content); err != nil {
			return fmt.Errorf("failed to write script file %s: %w", scriptPath, err)
		}
	}

	// Commit changes
	author := CommitAuthor{
		Name:     "Module Manager",
		Email:    "modules@cfgms.local",
		Username: "system",
		Role:     "system",
	}

	message := fmt.Sprintf("Update module: %s\n\nVersion: %s\nAuthor: %s",
		module.Name, module.Version, module.Spec.Metadata.Author)

	if _, err := mrm.store.Commit(ctx, localPath, message, author); err != nil {
		return fmt.Errorf("failed to commit module update: %w", err)
	}

	// Push changes
	if err := mrm.store.Push(ctx, localPath); err != nil {
		return fmt.Errorf("failed to push module update: %w", err)
	}

	// Update cache
	mrm.mu.Lock()
	mrm.moduleCache[module.Name] = module
	mrm.mu.Unlock()

	return nil
}

// Helper methods

func (mrm *ModuleRepositoryManager) isModuleRepositoryType(repoType RepositoryType) bool {
	return repoType == RepositoryTypeScriptModules ||
		repoType == RepositoryTypeMSPModules ||
		repoType == RepositoryTypeClientModules
}

func (mrm *ModuleRepositoryManager) setModuleRepositoryDefaults(config *RepositoryConfig) {
	// Set security defaults for module repositories
	if config.AccessControl == nil {
		config.AccessControl = &RepositoryAccessControl{
			Mode: AccessModeReadWrite,
			WriteProtection: WriteProtectionConfig{
				RequireApproval: true,
				PreventDrift:    true,
			},
		}
	}

	// Add default branch protection
	if len(config.AccessControl.ProtectedBranches) == 0 {
		config.AccessControl.ProtectedBranches = []BranchProtection{
			{
				Pattern:             "main",
				RequireReview:       true,
				RequiredReviewers:   2,
				DismissStaleReviews: true,
				RequiredChecks:      []string{"security-scan", "syntax-check"},
			},
		}
	}
}

func (mrm *ModuleRepositoryManager) initializeModuleRepository(ctx context.Context, repo *Repository) error {
	// Create initial module repository structure
	// This would create directories like:
	// - modules/ (for module specifications)
	// - scripts/ (for script files)
	// - tests/ (for module tests)
	// - docs/ (for documentation)

	return nil
}

func (mrm *ModuleRepositoryManager) getModuleRepository(ctx context.Context, repoID string) (*Repository, error) {
	mrm.mu.RLock()
	repo, exists := mrm.repoCache[repoID]
	mrm.mu.RUnlock()

	if exists {
		return repo, nil
	}

	// Fetch from git manager
	repo, err := mrm.gitManager.GetRepository(ctx, repoID)
	if err != nil {
		return nil, err
	}

	// Cache it
	mrm.mu.Lock()
	mrm.repoCache[repoID] = repo
	mrm.mu.Unlock()

	return repo, nil
}

func (mrm *ModuleRepositoryManager) ensureModuleRepository(ctx context.Context, repo *Repository) (string, error) {
	if strings.Contains(repo.ID, "..") || strings.ContainsRune(repo.ID, '/') || strings.ContainsRune(repo.ID, '\\') {
		return "", fmt.Errorf("invalid repository ID (must not contain path separators or dot sequences): %s", logging.SanitizeLogValue(repo.ID))
	}

	clonePath := filepath.Join(mrm.cacheDir, repo.ID)

	// Idempotent: skip if the clone already exists
	if _, err := os.Stat(filepath.Join(clonePath, ".git")); err == nil {
		return clonePath, nil
	}

	gitBin, err := exec.LookPath("git")
	if err != nil {
		return "", fmt.Errorf("git binary not found: %w", err)
	}

	mrm.logger.Info("cloning module repository",
		"repo_id", logging.SanitizeLogValue(repo.ID),
		"url", logging.SanitizeLogValue(repo.CloneURL),
		"path", clonePath,
	)

	// "-- <url>" prevents git from interpreting a URL beginning with "-" as a flag (argument injection defense).
	// #nosec G204 - gitBin is resolved via exec.LookPath; CloneURL is separated from flags by "--"
	cmd := exec.CommandContext(ctx, gitBin, "clone", "--", repo.CloneURL, clonePath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("failed to clone repository %s: %w (output: %s)",
			logging.SanitizeLogValue(repo.ID), err, string(output))
	}

	return clonePath, nil
}

func (mrm *ModuleRepositoryManager) scanForModuleSpecs(ctx context.Context, localPath string) ([]string, error) {
	var specs []string
	err := filepath.WalkDir(localPath, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if entry.Name() == "module.yaml" {
			rel, relErr := filepath.Rel(localPath, path)
			if relErr != nil {
				return relErr
			}
			specs = append(specs, rel)
		}
		return nil
	})
	return specs, err
}

func (mrm *ModuleRepositoryManager) loadModule(ctx context.Context, repo *Repository, localPath, specPath string) (*CustomModule, error) {
	fullPath := filepath.Join(localPath, specPath)
	// #nosec G304 - path is derived from filepath.WalkDir within the cloned module repository
	data, err := os.ReadFile(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read module spec %s: %w", logging.SanitizeLogValue(specPath), err)
	}

	var spec ModuleSpec
	if err := yaml.Unmarshal(data, &spec); err != nil {
		return nil, fmt.Errorf("failed to parse module spec %s: %w", logging.SanitizeLogValue(specPath), err)
	}

	return &CustomModule{
		Name:        spec.Metadata.Name,
		Version:     spec.Metadata.Version,
		Description: spec.Metadata.Description,
		Repository:  repo.ID,
		Path:        filepath.Dir(specPath),
		Spec:        spec,
		AccessLevel: AccessLevelReadOnly,
		SecurityStatus: SecurityStatus{
			Status:      SecurityStatusPending,
			LastScanned: time.Now(),
		},
	}, nil
}

func (mrm *ModuleRepositoryManager) writeModuleSpec(ctx context.Context, localPath, specPath string, module *CustomModule) error {
	data, err := yaml.Marshal(module.Spec)
	if err != nil {
		return fmt.Errorf("failed to marshal module spec: %w", err)
	}

	fullPath := filepath.Join(localPath, specPath)
	if err := os.MkdirAll(filepath.Dir(fullPath), 0750); err != nil {
		return fmt.Errorf("failed to create directory for module spec: %w", err)
	}

	// #nosec G306 - module spec is configuration data, not executable code
	return os.WriteFile(fullPath, data, 0600)
}

func (mrm *ModuleRepositoryManager) validateSecurityPolicy(policy ModuleSecurityPolicy) error {
	// Validate that security policy is reasonable
	if policy.RequireValidation && len(policy.AllowedExecutors) == 0 {
		return fmt.Errorf("validation required but no executors allowed")
	}

	return nil
}

func (mrm *ModuleRepositoryManager) validateUpdatePermissions(ctx context.Context, repo *Repository, module *CustomModule) error {
	// Design decision: permission validation is delegated to the caller; write access is enforced via the repository access-level field.
	if module.AccessLevel == AccessLevelReadOnly {
		return fmt.Errorf("module is read-only")
	}

	return nil
}

// ModuleSecurityValidator validates module security
type ModuleSecurityValidator struct {
	scanners map[string]SecurityScanner
}

// SecurityScanner interface for different security scanners
type SecurityScanner interface {
	ScanModule(ctx context.Context, module *CustomModule) ([]SecurityIssue, error)
}

// NewModuleSecurityValidator creates a new security validator
func NewModuleSecurityValidator() *ModuleSecurityValidator {
	return &ModuleSecurityValidator{
		scanners: make(map[string]SecurityScanner),
	}
}

// ValidateModule validates a module's security
func (msv *ModuleSecurityValidator) ValidateModule(ctx context.Context, module *CustomModule) error {
	var allIssues []SecurityIssue

	// Run all configured scanners
	for name, scanner := range msv.scanners {
		issues, err := scanner.ScanModule(ctx, module)
		if err != nil {
			return fmt.Errorf("scanner %s failed: %w", name, err)
		}
		allIssues = append(allIssues, issues...)
	}

	// Check for high severity issues
	for _, issue := range allIssues {
		if issue.Severity == "high" || issue.Severity == "critical" {
			return fmt.Errorf("high severity security issue: %s", issue.Description)
		}
	}

	module.SecurityStatus.Issues = allIssues
	return nil
}

// RegisterScanner registers a security scanner
func (msv *ModuleSecurityValidator) RegisterScanner(name string, scanner SecurityScanner) {
	msv.scanners[name] = scanner
}

// BasicSecurityScanner provides basic security scanning
type BasicSecurityScanner struct{}

// NewBasicSecurityScanner creates a basic security scanner
func NewBasicSecurityScanner() *BasicSecurityScanner {
	return &BasicSecurityScanner{}
}

// ScanModule performs basic security scanning
func (bss *BasicSecurityScanner) ScanModule(ctx context.Context, module *CustomModule) ([]SecurityIssue, error) {
	var issues []SecurityIssue

	// Check for suspicious patterns in scripts
	for platform, script := range module.Scripts {
		scriptContent := string(script)

		// Check for dangerous commands
		dangerousPatterns := []string{
			"rm -rf /",
			"format c:",
			"del /s",
			"sudo rm",
			"> /dev/zero",
		}

		for _, pattern := range dangerousPatterns {
			if strings.Contains(strings.ToLower(scriptContent), pattern) {
				issues = append(issues, SecurityIssue{
					Type:           "dangerous_command",
					Severity:       "critical",
					Description:    fmt.Sprintf("Dangerous command detected in %s script: %s", platform, pattern),
					File:           fmt.Sprintf("%s/%s", module.Path, module.Spec.Script.Files[platform]),
					Recommendation: "Remove or replace dangerous command",
				})
			}
		}

		// Check for network access without proper restrictions
		networkPatterns := []string{
			"curl ",
			"wget ",
			"http://",
			"https://",
			"ftp://",
		}

		hasNetworkAccess := false
		for _, pattern := range networkPatterns {
			if strings.Contains(strings.ToLower(scriptContent), pattern) {
				hasNetworkAccess = true
				break
			}
		}

		if hasNetworkAccess && module.SecurityStatus.Status != SecurityStatusApproved {
			issues = append(issues, SecurityIssue{
				Type:           "network_access",
				Severity:       "medium",
				Description:    fmt.Sprintf("Network access detected in %s script", platform),
				File:           fmt.Sprintf("%s/%s", module.Path, module.Spec.Script.Files[platform]),
				Recommendation: "Ensure network access is necessary and properly restricted",
			})
		}
	}

	return issues, nil
}
