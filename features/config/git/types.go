// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
// Package git provides Git-based configuration storage and version control
// for the CFGMS system. It implements a hybrid repository model with separate
// repositories per client and a global MSP repository for templates.
package git

import (
	"context"
	"fmt"
	"time"
)

// RepositoryType defines the type of repository
type RepositoryType string

const (
	// RepositoryTypeMSPGlobal is the global MSP repository containing templates and policies
	RepositoryTypeMSPGlobal RepositoryType = "msp-global"

	// RepositoryTypeClient is a client-specific repository
	RepositoryTypeClient RepositoryType = "client"

	// RepositoryTypeShared is a shared resource repository
	RepositoryTypeShared RepositoryType = "shared"

	// RepositoryTypeScriptModules contains custom script modules
	RepositoryTypeScriptModules RepositoryType = "script-modules"

	// RepositoryTypeMSPModules contains MSP-wide custom modules
	RepositoryTypeMSPModules RepositoryType = "msp-modules"

	// RepositoryTypeClientModules contains client-specific modules
	RepositoryTypeClientModules RepositoryType = "client-modules"
)

// RepositoryConfig defines configuration for creating a repository
type RepositoryConfig struct {
	// Type is the repository type
	Type RepositoryType

	// Name is the repository name
	Name string

	// Description is the repository description
	Description string

	// Owner is the repository owner (MSP ID or client ID)
	Owner string

	// Provider is the Git provider (github, gitlab, bitbucket)
	Provider string

	// Private indicates if the repository should be private
	Private bool

	// InitialBranch is the name of the initial branch (default: main)
	InitialBranch string

	// Templates to inherit from parent repository
	Templates []TemplateReference

	// SOPS configuration for secrets management
	SOPSConfig *SOPSConfig

	// Access control configuration
	AccessControl *RepositoryAccessControl

	// Module repositories linked to this config repository
	ModuleLinks *RepositoryLinks

	// Metadata contains additional repository metadata
	Metadata map[string]interface{}
}

// Repository represents a Git repository
type Repository struct {
	// ID is the unique repository identifier
	ID string

	// Type is the repository type
	Type RepositoryType

	// Name is the repository name
	Name string

	// Owner is the repository owner
	Owner string

	// Provider is the Git provider
	Provider string

	// CloneURL is the URL for cloning the repository
	CloneURL string

	// DefaultBranch is the default branch name
	DefaultBranch string

	// CreatedAt is when the repository was created
	CreatedAt time.Time

	// UpdatedAt is when the repository was last updated
	UpdatedAt time.Time

	// SOPS configuration for this repository
	SOPSConfig *SOPSConfig

	// Access control configuration
	AccessControl *RepositoryAccessControl

	// Module repository links
	ModuleLinks *RepositoryLinks

	// Metadata contains additional repository information
	Metadata map[string]interface{}
}

// ConfigurationRef references a configuration in a repository
type ConfigurationRef struct {
	// RepositoryID is the repository identifier
	RepositoryID string

	// Branch is the branch name (optional, defaults to default branch)
	Branch string

	// Path is the path to the configuration file
	Path string

	// Commit is a specific commit SHA (optional)
	Commit string
}

// Configuration represents a configuration file
type Configuration struct {
	// Path is the file path in the repository
	Path string

	// Content is the configuration content
	Content []byte

	// Format is the configuration format (yaml, json, toml)
	Format string

	// Metadata contains configuration metadata
	Metadata ConfigMetadata
}

// ConfigMetadata contains metadata about a configuration
type ConfigMetadata struct {
	// Version is the configuration version
	Version string

	// Author is who created/modified the configuration
	Author string

	// Description describes the configuration
	Description string

	// Tags are labels for the configuration
	Tags []string

	// Checksum is the content checksum
	Checksum string

	// LastModified is when the configuration was last modified
	LastModified time.Time
}

// Commit represents a Git commit
type Commit struct {
	// SHA is the commit hash
	SHA string

	// Author is the commit author
	Author CommitAuthor

	// Message is the commit message
	Message string

	// Timestamp is when the commit was made
	Timestamp time.Time

	// Parents are the parent commit SHAs
	Parents []string

	// Files are the files changed in this commit
	Files []FileChange

	// Metadata contains CFGMS-specific commit metadata
	Metadata CommitMetadata
}

// CommitAuthor represents the author of a commit
type CommitAuthor struct {
	// Name is the author's name
	Name string

	// Email is the author's email
	Email string

	// Username is the author's username in CFGMS
	Username string

	// Role is the author's role
	Role string
}

// CommitMetadata contains CFGMS-specific commit metadata
type CommitMetadata struct {
	// ChangeID is the unique change identifier
	ChangeID string

	// TenantID identifies the tenant (client/group)
	TenantID string

	// ActorIP is the IP address of the actor
	ActorIP string

	// ValidationResults contains validation check results
	ValidationResults map[string]ValidationResult

	// RollbackInfo contains rollback information
	RollbackInfo *RollbackInfo
}

// ValidationResult represents the result of a validation check
type ValidationResult struct {
	// Passed indicates if the validation passed
	Passed bool

	// Message contains the validation message
	Message string

	// Details contains additional validation details
	Details map[string]interface{}
}

// RollbackInfo contains information for rolling back a change
type RollbackInfo struct {
	// PreviousCommit is the commit to rollback to
	PreviousCommit string

	// CanRollback indicates if automatic rollback is possible
	CanRollback bool

	// RollbackScript contains the rollback commands
	RollbackScript string
}

// FileChange represents a file changed in a commit
type FileChange struct {
	// Path is the file path
	Path string

	// Action is what happened to the file (added, modified, deleted)
	Action string

	// OldPath is the previous path (for renames)
	OldPath string
}

// TemplateReference references a template in another repository
type TemplateReference struct {
	// Repository is the repository containing the template
	Repository string

	// Path is the template path in the repository
	Path string

	// OverrideAllowed indicates if the template can be overridden
	OverrideAllowed bool

	// MergeStrategy defines how to merge template changes
	MergeStrategy MergeStrategy
}

// MergeStrategy defines how to merge configuration changes
type MergeStrategy string

const (
	// MergeStrategyReplace replaces the entire configuration
	MergeStrategyReplace MergeStrategy = "replace"

	// MergeStrategyDeep performs deep merging of configuration
	MergeStrategyDeep MergeStrategy = "deep"

	// MergeStrategyShallow performs shallow merging
	MergeStrategyShallow MergeStrategy = "shallow"
)

// ChangeSet represents a set of configuration changes
type ChangeSet struct {
	// ID is the unique change set identifier
	ID string

	// Description describes the changes
	Description string

	// Changes are the individual configuration changes
	Changes []ConfigChange

	// Author is who is making the changes
	Author CommitAuthor

	// Metadata contains additional change metadata
	Metadata map[string]interface{}
}

// ConfigChange represents a single configuration change
type ConfigChange struct {
	// Repository is the target repository
	Repository string

	// Branch is the target branch
	Branch string

	// Path is the configuration file path
	Path string

	// OldContent is the previous content (for updates/deletes)
	OldContent []byte

	// NewContent is the new content (for creates/updates)
	NewContent []byte

	// Action is the change action (create, update, delete)
	Action string
}

// PullRequestConfig defines configuration for creating a pull request
type PullRequestConfig struct {
	// Title is the PR title
	Title string

	// Description is the PR description
	Description string

	// SourceBranch is the branch with changes
	SourceBranch string

	// TargetBranch is the branch to merge into
	TargetBranch string

	// Labels are PR labels
	Labels []string

	// Reviewers are requested reviewers
	Reviewers []string

	// AutoMerge indicates if the PR should auto-merge when checks pass
	AutoMerge bool
}

// WebhookConfig defines configuration for repository webhooks
type WebhookConfig struct {
	// URL is the webhook endpoint URL
	URL string

	// Events are the events that trigger the webhook
	Events []string

	// Secret is the webhook secret for verification
	Secret string

	// Active indicates if the webhook is active
	Active bool
}

// RepositoryFilter defines filters for listing repositories
type RepositoryFilter struct {
	// Type filters by repository type
	Type RepositoryType

	// Owner filters by repository owner
	Owner string

	// Tags filters by repository tags
	Tags []string

	// IncludeArchived includes archived repositories
	IncludeArchived bool
}

// BranchProtectionRule defines rules for protecting branches
type BranchProtectionRule struct {
	// Pattern is the branch name pattern (e.g., "main", "release/*")
	Pattern string

	// RequireReview requires pull request reviews
	RequireReview bool

	// RequiredReviewers is the number of required reviewers
	RequiredReviewers int

	// DismissStaleReviews dismisses reviews when new commits are pushed
	DismissStaleReviews bool

	// RequireUpToDate requires branches to be up to date before merging
	RequireUpToDate bool

	// RequiredChecks are status checks that must pass
	RequiredChecks []string

	// RestrictPushAccess restricts who can push to the branch
	RestrictPushAccess bool

	// PushAccessUsers are users allowed to push
	PushAccessUsers []string

	// PushAccessTeams are teams allowed to push
	PushAccessTeams []string
}

// GitManager orchestrates all Git operations
type GitManager interface {
	// Repository management
	CreateRepository(ctx context.Context, config RepositoryConfig) (*Repository, error)
	GetRepository(ctx context.Context, repoID string) (*Repository, error)
	ListRepositories(ctx context.Context, filter RepositoryFilter) ([]*Repository, error)
	DeleteRepository(ctx context.Context, repoID string) error

	// Configuration operations
	GetConfiguration(ctx context.Context, ref ConfigurationRef) (*Configuration, error)
	SaveConfiguration(ctx context.Context, ref ConfigurationRef, config *Configuration, message string) error
	DeleteConfiguration(ctx context.Context, ref ConfigurationRef, message string) error

	// Branch management
	CreateBranch(ctx context.Context, repoID, branchName, fromRef string) error
	DeleteBranch(ctx context.Context, repoID, branchName string) error
	MergeBranch(ctx context.Context, repoID, source, target string, message string) error
	ListBranches(ctx context.Context, repoID string) ([]string, error)

	// History operations
	GetCommitHistory(ctx context.Context, repoID string, branch string, limit int) ([]*Commit, error)
	GetCommit(ctx context.Context, repoID string, sha string) (*Commit, error)
	GetDiff(ctx context.Context, repoID string, fromRef, toRef string) ([]ConfigChange, error)

	// Synchronization
	SyncTemplates(ctx context.Context, clientRepoID string) error
	PropagateChange(ctx context.Context, change ChangeSet) error

	// Pull requests
	CreatePullRequest(ctx context.Context, repoID string, config PullRequestConfig) (string, error)
	MergePullRequest(ctx context.Context, repoID string, prID string) error

	// Webhooks
	CreateWebhook(ctx context.Context, repoID string, config WebhookConfig) error
	DeleteWebhook(ctx context.Context, repoID string, webhookID string) error

	// Branch protection
	SetBranchProtection(ctx context.Context, repoID string, rule BranchProtectionRule) error
	RemoveBranchProtection(ctx context.Context, repoID string, branch string) error
}

// GitProvider abstracts different Git providers (GitHub, GitLab, Bitbucket)
type GitProvider interface {
	// Repository operations
	CreateRepository(ctx context.Context, config RepositoryConfig) (*Repository, error)
	GetRepository(ctx context.Context, owner, name string) (*Repository, error)
	DeleteRepository(ctx context.Context, owner, name string) error

	// Branch operations
	CreateBranch(ctx context.Context, owner, repo, branch, fromRef string) error
	DeleteBranch(ctx context.Context, owner, repo, branch string) error
	GetDefaultBranch(ctx context.Context, owner, repo string) (string, error)

	// Pull request operations
	CreatePullRequest(ctx context.Context, owner, repo string, config PullRequestConfig) (string, error)
	MergePullRequest(ctx context.Context, owner, repo, prID string) error

	// Webhook operations
	CreateWebhook(ctx context.Context, owner, repo string, config WebhookConfig) (string, error)
	DeleteWebhook(ctx context.Context, owner, repo, webhookID string) error

	// Branch protection
	SetBranchProtection(ctx context.Context, owner, repo string, rule BranchProtectionRule) error
	RemoveBranchProtection(ctx context.Context, owner, repo, branch string) error
}

// RepositoryStore handles local repository operations
type RepositoryStore interface {
	// Clone a repository locally
	Clone(ctx context.Context, cloneURL, localPath string) error

	// Pull latest changes
	Pull(ctx context.Context, localPath string) error

	// Push changes to remote
	Push(ctx context.Context, localPath string) error

	// Read a file from the repository
	ReadFile(ctx context.Context, localPath, filePath string) ([]byte, error)

	// Write a file to the repository
	WriteFile(ctx context.Context, localPath, filePath string, content []byte) error

	// Delete a file from the repository
	DeleteFile(ctx context.Context, localPath, filePath string) error

	// Commit changes
	Commit(ctx context.Context, localPath string, message string, author CommitAuthor) (string, error)

	// Get commit history
	GetHistory(ctx context.Context, localPath, filePath string, limit int) ([]*Commit, error)

	// Get diff between commits
	GetDiff(ctx context.Context, localPath string, fromRef, toRef string) ([]FileChange, error)

	// Branch operations
	CreateBranch(ctx context.Context, localPath, branchName string) error
	CheckoutBranch(ctx context.Context, localPath, branchName string) error
	ListBranches(ctx context.Context, localPath string) ([]string, error)
}

// SyncManager handles cross-repository synchronization
type SyncManager interface {
	// Sync templates from parent repository to client repository
	SyncTemplates(ctx context.Context, parentRepo, clientRepo *Repository) error

	// Propagate a change across multiple repositories
	PropagateChange(ctx context.Context, change ChangeSet, targetRepos []*Repository) error

	// Check for template updates
	CheckTemplateUpdates(ctx context.Context, clientRepo *Repository) ([]TemplateUpdate, error)

	// Apply template updates
	ApplyTemplateUpdates(ctx context.Context, clientRepo *Repository, updates []TemplateUpdate) error
}

// TemplateUpdate represents an available template update
type TemplateUpdate struct {
	// Template is the template reference
	Template TemplateReference

	// CurrentVersion is the current template version
	CurrentVersion string

	// NewVersion is the available new version
	NewVersion string

	// Changes describes what changed
	Changes string

	// Breaking indicates if this is a breaking change
	Breaking bool
}

// HookManager manages Git hooks
type HookManager interface {
	// Install hooks in a repository
	InstallHooks(ctx context.Context, repoPath string) error

	// Run pre-commit hooks
	RunPreCommitHooks(ctx context.Context, repoPath string, files []string) error

	// Run pre-receive hooks
	RunPreReceiveHooks(ctx context.Context, repoPath string, commits []string) error

	// Validate configuration
	ValidateConfiguration(ctx context.Context, config *Configuration) error
}

// SOPS Configuration Types

// SOPSConfig defines SOPS encryption configuration
type SOPSConfig struct {
	// Enabled indicates if SOPS is enabled for this repository
	Enabled bool `yaml:"enabled" json:"enabled"`

	// ConfigFile is the path to .sops.yaml file
	ConfigFile string `yaml:"config_file" json:"config_file"`

	// KMSProviders defines KMS providers for encryption
	KMSProviders map[string]KMSProvider `yaml:"kms_providers" json:"kms_providers"`

	// EncryptionRules define which files and fields to encrypt
	EncryptionRules []EncryptionRule `yaml:"encryption_rules" json:"encryption_rules"`

	// AutoEncrypt automatically encrypts sensitive fields
	AutoEncrypt bool `yaml:"auto_encrypt" json:"auto_encrypt"`

	// SensitiveFieldPatterns are regex patterns for sensitive fields
	SensitiveFieldPatterns []string `yaml:"sensitive_field_patterns" json:"sensitive_field_patterns"`
}

// KMSProvider defines a KMS provider configuration
type KMSProvider struct {
	// Type is the provider type (aws, gcp, azure, pgp)
	Type string `yaml:"type" json:"type"`

	// KeyID is the KMS key identifier
	KeyID string `yaml:"key_id" json:"key_id"`

	// Region is the cloud region (for cloud providers)
	Region string `yaml:"region,omitempty" json:"region,omitempty"`

	// Profile is the authentication profile
	Profile string `yaml:"profile,omitempty" json:"profile,omitempty"`

	// Config contains provider-specific configuration
	Config map[string]string `yaml:"config,omitempty" json:"config,omitempty"`
}

// EncryptionRule defines what to encrypt and how
type EncryptionRule struct {
	// PathRegex matches file paths that should be encrypted
	PathRegex string `yaml:"path_regex" json:"path_regex"`

	// FieldPatterns are field name patterns to encrypt
	FieldPatterns []string `yaml:"field_patterns" json:"field_patterns"`

	// KMSKey is the KMS key to use for this rule
	KMSKey string `yaml:"kms_key" json:"kms_key"`

	// Environment is the target environment
	Environment string `yaml:"environment" json:"environment"`
}

// Access Control Types

// RepositoryAccessControl defines repository access control settings
type RepositoryAccessControl struct {
	// Mode defines the access mode for this repository
	Mode AccessMode `yaml:"mode" json:"mode"`

	// WriteProtection defines write protection settings
	WriteProtection WriteProtectionConfig `yaml:"write_protection" json:"write_protection"`

	// ReadOnlyPaths are paths that cannot be modified by controller
	ReadOnlyPaths []string `yaml:"read_only_paths" json:"read_only_paths"`

	// ControllerManagedPaths are paths only controller can modify
	ControllerManagedPaths []string `yaml:"controller_managed_paths" json:"controller_managed_paths"`

	// ProtectedBranches defines branch protection rules
	ProtectedBranches []BranchProtection `yaml:"protected_branches" json:"protected_branches"`
}

// AccessMode defines how the repository can be accessed
type AccessMode string

const (
	// AccessModeReadOnly - Git is source of truth, controller cannot modify
	AccessModeReadOnly AccessMode = "read_only"

	// AccessModeReadWrite - Controller can modify all files
	AccessModeReadWrite AccessMode = "read_write"

	// AccessModeHybrid - Mixed control based on path rules
	AccessModeHybrid AccessMode = "hybrid"

	// AccessModeValidateOnly - Controller validates but never modifies
	AccessModeValidateOnly AccessMode = "validate_only"
)

// WriteProtectionConfig defines write protection settings
type WriteProtectionConfig struct {
	// PreventDrift monitors for unauthorized changes
	PreventDrift bool `yaml:"prevent_drift" json:"prevent_drift"`

	// AllowedUsers can bypass write protection
	AllowedUsers []string `yaml:"allowed_users" json:"allowed_users"`

	// RequireApproval requires approval for changes
	RequireApproval bool `yaml:"require_approval" json:"require_approval"`

	// AutoRevertChanges automatically reverts unauthorized changes
	AutoRevertChanges bool `yaml:"auto_revert_changes" json:"auto_revert_changes"`
}

// BranchProtection defines protection rules for branches
type BranchProtection struct {
	// Pattern is the branch name pattern
	Pattern string `yaml:"pattern" json:"pattern"`

	// RequireReview requires pull request reviews
	RequireReview bool `yaml:"require_review" json:"require_review"`

	// RequiredReviewers is the minimum number of reviewers
	RequiredReviewers int `yaml:"required_reviewers" json:"required_reviewers"`

	// DismissStaleReviews dismisses reviews on new commits
	DismissStaleReviews bool `yaml:"dismiss_stale_reviews" json:"dismiss_stale_reviews"`

	// RequiredChecks are status checks that must pass
	RequiredChecks []string `yaml:"required_checks" json:"required_checks"`
}

// Module Repository Types

// RepositoryLinks defines links to other repositories
type RepositoryLinks struct {
	// ConfigRepository is the main configuration repository
	ConfigRepository string `yaml:"config_repository" json:"config_repository"`

	// ModuleRepositories are linked script/module repositories
	ModuleRepositories []ModuleRepository `yaml:"module_repositories" json:"module_repositories"`

	// TemplateRepositories are additional template repositories
	TemplateRepositories []string `yaml:"template_repositories" json:"template_repositories"`
}

// ModuleRepository defines a linked module repository
type ModuleRepository struct {
	// ID is the unique identifier for this module repository
	ID string `yaml:"id" json:"id"`

	// URL is the repository URL
	URL string `yaml:"url" json:"url"`

	// Branch is the branch to use
	Branch string `yaml:"branch,omitempty" json:"branch,omitempty"`

	// Version pins to a specific version/tag
	Version string `yaml:"version,omitempty" json:"version,omitempty"`

	// Type defines what kind of modules this repository contains
	Type ModuleRepoType `yaml:"type" json:"type"`

	// AccessLevel defines access permissions
	AccessLevel ModuleAccessLevel `yaml:"access_level" json:"access_level"`

	// Enabled indicates if this repository is currently enabled
	Enabled bool `yaml:"enabled" json:"enabled"`

	// SecurityPolicy defines security requirements for this repository
	SecurityPolicy ModuleSecurityPolicy `yaml:"security_policy" json:"security_policy"`
}

// ModuleRepoType defines the type of modules in a repository
type ModuleRepoType string

const (
	// ModuleRepoTypeScripts contains script modules
	ModuleRepoTypeScripts ModuleRepoType = "scripts"

	// ModuleRepoTypeWorkflows contains workflow definitions
	ModuleRepoTypeWorkflows ModuleRepoType = "workflows"

	// ModuleRepoTypeTemplates contains configuration templates
	ModuleRepoTypeTemplates ModuleRepoType = "templates"

	// ModuleRepoTypePolicies contains policy definitions
	ModuleRepoTypePolicies ModuleRepoType = "policies"
)

// ModuleAccessLevel defines access level to module repository
type ModuleAccessLevel string

const (
	// AccessLevelReadOnly can only use existing modules
	AccessLevelReadOnly ModuleAccessLevel = "read_only"

	// AccessLevelContribute can contribute new modules
	AccessLevelContribute ModuleAccessLevel = "contribute"

	// AccessLevelMaintainer can manage the repository
	AccessLevelMaintainer ModuleAccessLevel = "maintainer"
)

// ModuleSecurityPolicy defines security requirements for modules
type ModuleSecurityPolicy struct {
	// RequireValidation requires security validation
	RequireValidation bool `yaml:"require_validation" json:"require_validation"`

	// RequireApproval requires manual approval for new modules
	RequireApproval bool `yaml:"require_approval" json:"require_approval"`

	// AllowedExecutors define who can execute modules from this repository
	AllowedExecutors []string `yaml:"allowed_executors" json:"allowed_executors"`

	// RestrictedPaths are paths modules cannot access
	RestrictedPaths []string `yaml:"restricted_paths" json:"restricted_paths"`

	// NetworkAccess defines network access level for modules
	NetworkAccess NetworkAccessLevel `yaml:"network_access" json:"network_access"`
}

// NetworkAccessLevel defines network access for modules
type NetworkAccessLevel string

const (
	// NetworkAccessNone - no network access
	NetworkAccessNone NetworkAccessLevel = "none"

	// NetworkAccessLimited - limited network access
	NetworkAccessLimited NetworkAccessLevel = "limited"

	// NetworkAccessFull - full network access
	NetworkAccessFull NetworkAccessLevel = "full"
)

// CustomModule represents a custom module loaded from a repository
type CustomModule struct {
	// Name is the module name
	Name string `json:"name"`

	// Version is the module version
	Version string `json:"version"`

	// Description describes the module
	Description string `json:"description"`

	// Repository is the source repository ID
	Repository string `json:"repository"`

	// Path is the path within the repository
	Path string `json:"path"`

	// Spec is the module specification
	Spec ModuleSpec `json:"spec"`

	// Scripts contains the actual script content for different platforms
	Scripts map[string][]byte `json:"scripts"`

	// AccessLevel is the access level for this module
	AccessLevel ModuleAccessLevel `json:"access_level"`

	// Tags are metadata tags
	Tags []string `json:"tags"`

	// SecurityStatus indicates security validation status
	SecurityStatus SecurityStatus `json:"security_status"`
}

// ModuleSpec defines a module specification
type ModuleSpec struct {
	// Metadata contains module metadata
	Metadata ModuleMetadata `yaml:"metadata" json:"metadata"`

	// Script defines script execution configuration
	Script ScriptConfig `yaml:"script" json:"script"`

	// Parameters define module parameters
	Parameters []ModuleParameter `yaml:"parameters" json:"parameters"`

	// Validation defines validation rules
	Validation ValidationConfig `yaml:"validation" json:"validation"`

	// Permissions define required permissions
	Permissions PermissionConfig `yaml:"permissions" json:"permissions"`
}

// ModuleMetadata contains module metadata
type ModuleMetadata struct {
	// Name is the module name
	Name string `yaml:"name" json:"name"`

	// Version is the module version
	Version string `yaml:"version" json:"version"`

	// Description describes the module
	Description string `yaml:"description" json:"description"`

	// Author is the module author
	Author string `yaml:"author" json:"author"`

	// Created is when the module was created
	Created string `yaml:"created" json:"created"`

	// Tags are metadata tags
	Tags []string `yaml:"tags" json:"tags"`
}

// ScriptConfig defines script execution configuration
type ScriptConfig struct {
	// Files maps platforms to script files
	Files map[string]string `yaml:"files" json:"files"`

	// Timeout is the execution timeout
	Timeout int `yaml:"timeout" json:"timeout"`

	// WorkingDirectory is the working directory for execution
	WorkingDirectory string `yaml:"working_directory,omitempty" json:"working_directory,omitempty"`

	// Environment variables for script execution
	Environment map[string]string `yaml:"environment,omitempty" json:"environment,omitempty"`
}

// ModuleParameter defines a module parameter
type ModuleParameter struct {
	// Name is the parameter name
	Name string `yaml:"name" json:"name"`

	// Type is the parameter type
	Type string `yaml:"type" json:"type"`

	// Required indicates if parameter is required
	Required bool `yaml:"required" json:"required"`

	// Description describes the parameter
	Description string `yaml:"description" json:"description"`

	// Default is the default value
	Default interface{} `yaml:"default,omitempty" json:"default,omitempty"`

	// Validation defines parameter validation rules
	Validation map[string]interface{} `yaml:"validation,omitempty" json:"validation,omitempty"`
}

// ValidationConfig defines validation configuration
type ValidationConfig struct {
	// SyntaxCheck enables syntax checking
	SyntaxCheck bool `yaml:"syntax_check" json:"syntax_check"`

	// SecurityScan enables security scanning
	SecurityScan bool `yaml:"security_scan" json:"security_scan"`

	// ApprovalRequired requires manual approval
	ApprovalRequired bool `yaml:"approval_required" json:"approval_required"`

	// CustomValidators are custom validation scripts
	CustomValidators []string `yaml:"custom_validators,omitempty" json:"custom_validators,omitempty"`
}

// PermissionConfig defines required permissions
type PermissionConfig struct {
	// RequiredRoles are roles required to execute this module
	RequiredRoles []string `yaml:"required_roles" json:"required_roles"`

	// RestrictedPaths are paths this module cannot access
	RestrictedPaths []string `yaml:"restricted_paths" json:"restricted_paths"`

	// RequiredCapabilities are system capabilities required
	RequiredCapabilities []string `yaml:"required_capabilities,omitempty" json:"required_capabilities,omitempty"`
}

// SecurityStatus indicates security validation status
type SecurityStatus struct {
	// Status is the overall security status
	Status SecurityStatusType `json:"status"`

	// LastScanned is when security scan was last performed
	LastScanned time.Time `json:"last_scanned"`

	// Issues are any security issues found
	Issues []SecurityIssue `json:"issues,omitempty"`

	// ApprovedBy indicates who approved this module
	ApprovedBy string `json:"approved_by,omitempty"`

	// ApprovedAt is when the module was approved
	ApprovedAt *time.Time `json:"approved_at,omitempty"`
}

// SecurityStatusType defines security status types
type SecurityStatusType string

const (
	// SecurityStatusPending - security scan pending
	SecurityStatusPending SecurityStatusType = "pending"

	// SecurityStatusApproved - security scan passed and approved
	SecurityStatusApproved SecurityStatusType = "approved"

	// SecurityStatusRejected - security scan failed or rejected
	SecurityStatusRejected SecurityStatusType = "rejected"

	// SecurityStatusExpired - approval expired, needs re-scan
	SecurityStatusExpired SecurityStatusType = "expired"
)

// SecurityIssue represents a security issue found in a module
type SecurityIssue struct {
	// Type is the issue type
	Type string `json:"type"`

	// Severity is the issue severity
	Severity string `json:"severity"`

	// Description describes the issue
	Description string `json:"description"`

	// File is the file where issue was found
	File string `json:"file,omitempty"`

	// Line is the line number where issue was found
	Line int `json:"line,omitempty"`

	// Recommendation is the recommended fix
	Recommendation string `json:"recommendation,omitempty"`
}

// Configuration drift detection types

// DriftDetection represents detected configuration drift
type DriftDetection struct {
	// Path is the file path where drift was detected
	Path string `json:"path"`

	// ExpectedHash is the expected content hash
	ExpectedHash string `json:"expected_hash"`

	// ActualHash is the actual content hash
	ActualHash string `json:"actual_hash"`

	// DriftType is the type of drift detected
	DriftType DriftType `json:"drift_type"`

	// DetectedAt is when the drift was detected
	DetectedAt time.Time `json:"detected_at"`

	// UnauthorizedBy indicates who made unauthorized changes
	UnauthorizedBy string `json:"unauthorized_by,omitempty"`

	// AutoReverted indicates if the change was automatically reverted
	AutoReverted bool `json:"auto_reverted"`
}

// DriftType defines types of configuration drift
type DriftType string

const (
	// DriftTypeUnauthorizedChange - unauthorized modification
	DriftTypeUnauthorizedChange DriftType = "unauthorized_change"

	// DriftTypeDeletedFile - file was deleted
	DriftTypeDeletedFile DriftType = "deleted_file"

	// DriftTypeNewFile - new file was added
	DriftTypeNewFile DriftType = "new_file"

	// DriftTypePermissionChange - file permissions changed
	DriftTypePermissionChange DriftType = "permission_change"
)

// Error types for enhanced Git operations

// ConfigurationDriftError indicates configuration drift was detected
type ConfigurationDriftError struct {
	Message           string
	Repository        string
	Path              string
	RecommendedAction string
}

func (e *ConfigurationDriftError) Error() string {
	return fmt.Sprintf("configuration drift detected in %s:%s - %s. %s",
		e.Repository, e.Path, e.Message, e.RecommendedAction)
}

// ValidationOnlyError indicates repository is in validation-only mode
type ValidationOnlyError struct {
	Message string
}

func (e *ValidationOnlyError) Error() string {
	return e.Message
}

// PathProtectedError indicates a path is protected from controller changes
type PathProtectedError struct {
	Path    string
	Message string
}

func (e *PathProtectedError) Error() string {
	return fmt.Sprintf("path protected: %s - %s", e.Path, e.Message)
}
