// Package diff provides configuration version comparison and differential analysis
// for CFGMS. It enables detailed diff views, semantic analysis, and change impact
// assessment for configuration management and approval workflows.
package diff

import (
	"context"
	"time"
)

// DiffType represents the type of difference between configurations
type DiffType string

const (
	// DiffTypeAdd indicates a new item was added
	DiffTypeAdd DiffType = "add"
	
	// DiffTypeDelete indicates an item was deleted
	DiffTypeDelete DiffType = "delete"
	
	// DiffTypeModify indicates an item was modified
	DiffTypeModify DiffType = "modify"
	
	// DiffTypeMove indicates an item was moved/renamed
	DiffTypeMove DiffType = "move"
)

// ImpactLevel represents the potential impact of a change
type ImpactLevel string

const (
	// ImpactLevelLow indicates minimal impact changes
	ImpactLevelLow ImpactLevel = "low"
	
	// ImpactLevelMedium indicates moderate impact changes
	ImpactLevelMedium ImpactLevel = "medium"
	
	// ImpactLevelHigh indicates high impact changes
	ImpactLevelHigh ImpactLevel = "high"
	
	// ImpactLevelCritical indicates critical/breaking changes
	ImpactLevelCritical ImpactLevel = "critical"
)

// ChangeCategory represents the category of change
type ChangeCategory string

const (
	// ChangeCategoryStructural indicates structural configuration changes
	ChangeCategoryStructural ChangeCategory = "structural"
	
	// ChangeCategoryValue indicates value-only changes
	ChangeCategoryValue ChangeCategory = "value"
	
	// ChangeCategorySecurity indicates security-related changes
	ChangeCategorySecurity ChangeCategory = "security"
	
	// ChangeCategoryNetwork indicates network configuration changes
	ChangeCategoryNetwork ChangeCategory = "network"
	
	// ChangeCategoryAccess indicates access control changes
	ChangeCategoryAccess ChangeCategory = "access"
	
	// ChangeCategoryPolicy indicates policy changes
	ChangeCategoryPolicy ChangeCategory = "policy"
)

// DiffEntry represents a single difference between configurations
type DiffEntry struct {
	// Path is the configuration path where the difference occurs
	Path string `json:"path"`
	
	// Type is the type of difference
	Type DiffType `json:"type"`
	
	// OldValue is the previous value (for modify/delete operations)
	OldValue interface{} `json:"old_value,omitempty"`
	
	// NewValue is the new value (for add/modify operations)
	NewValue interface{} `json:"new_value,omitempty"`
	
	// OldPath is the previous path (for move operations)
	OldPath string `json:"old_path,omitempty"`
	
	// Impact describes the potential impact of this change
	Impact ChangeImpact `json:"impact"`
	
	// Context provides additional context about the change
	Context DiffContext `json:"context"`
}

// ChangeImpact describes the potential impact of a configuration change
type ChangeImpact struct {
	// Level indicates the severity level of the impact
	Level ImpactLevel `json:"level"`
	
	// Category indicates the category of change
	Category ChangeCategory `json:"category"`
	
	// Description explains the potential impact
	Description string `json:"description"`
	
	// AffectedSystems are systems that might be affected
	AffectedSystems []string `json:"affected_systems"`
	
	// RequiresRestart indicates if the change requires a service restart
	RequiresRestart bool `json:"requires_restart"`
	
	// RequiresDowntime indicates if the change requires downtime
	RequiresDowntime bool `json:"requires_downtime"`
	
	// BreakingChange indicates if this is a breaking change
	BreakingChange bool `json:"breaking_change"`
	
	// SecurityImplications describes security implications
	SecurityImplications []string `json:"security_implications"`
	
	// RollbackComplexity indicates how difficult rollback would be
	RollbackComplexity ImpactLevel `json:"rollback_complexity"`
}

// DiffContext provides additional context about a difference
type DiffContext struct {
	// LineNumber is the line number in the configuration file
	LineNumber int `json:"line_number,omitempty"`
	
	// Section is the configuration section name
	Section string `json:"section,omitempty"`
	
	// Module is the module that owns this configuration
	Module string `json:"module,omitempty"`
	
	// ParentPath is the parent configuration path
	ParentPath string `json:"parent_path,omitempty"`
	
	// ChildCount is the number of child items affected
	ChildCount int `json:"child_count,omitempty"`
	
	// RelatedPaths are paths that might be affected by this change
	RelatedPaths []string `json:"related_paths,omitempty"`
}

// ComparisonResult contains the complete comparison between two configurations
type ComparisonResult struct {
	// ID is the unique comparison identifier
	ID string `json:"id"`
	
	// FromRef identifies the source configuration
	FromRef ConfigurationReference `json:"from_ref"`
	
	// ToRef identifies the target configuration
	ToRef ConfigurationReference `json:"to_ref"`
	
	// Summary provides a summary of changes
	Summary DiffSummary `json:"summary"`
	
	// Entries are the individual differences found
	Entries []DiffEntry `json:"entries"`
	
	// Metadata contains comparison metadata
	Metadata ComparisonMetadata `json:"metadata"`
}

// ConfigurationReference identifies a specific configuration version
type ConfigurationReference struct {
	// Repository is the repository identifier
	Repository string `json:"repository"`
	
	// Branch is the branch name
	Branch string `json:"branch"`
	
	// Commit is the commit SHA
	Commit string `json:"commit"`
	
	// Path is the configuration file path
	Path string `json:"path"`
	
	// Timestamp is when this version was created
	Timestamp time.Time `json:"timestamp"`
	
	// Author is who created this version
	Author string `json:"author"`
	
	// Message is the commit message
	Message string `json:"message"`
}

// DiffSummary provides a high-level summary of changes
type DiffSummary struct {
	// TotalChanges is the total number of changes
	TotalChanges int `json:"total_changes"`
	
	// AddedItems is the number of added items
	AddedItems int `json:"added_items"`
	
	// DeletedItems is the number of deleted items
	DeletedItems int `json:"deleted_items"`
	
	// ModifiedItems is the number of modified items
	ModifiedItems int `json:"modified_items"`
	
	// MovedItems is the number of moved items
	MovedItems int `json:"moved_items"`
	
	// ImpactBreakdown shows changes by impact level
	ImpactBreakdown map[ImpactLevel]int `json:"impact_breakdown"`
	
	// CategoryBreakdown shows changes by category
	CategoryBreakdown map[ChangeCategory]int `json:"category_breakdown"`
	
	// BreakingChanges is the number of breaking changes
	BreakingChanges int `json:"breaking_changes"`
	
	// SecurityChanges is the number of security-related changes
	SecurityChanges int `json:"security_changes"`
}

// ComparisonMetadata contains metadata about the comparison process
type ComparisonMetadata struct {
	// CreatedAt is when the comparison was performed
	CreatedAt time.Time `json:"created_at"`
	
	// Duration is how long the comparison took
	Duration time.Duration `json:"duration"`
	
	// Engine is the diff engine used
	Engine string `json:"engine"`
	
	// Version is the engine version
	Version string `json:"version"`
	
	// Options are the comparison options used
	Options DiffOptions `json:"options"`
	
	// Warnings are any warnings generated during comparison
	Warnings []string `json:"warnings"`
}

// DiffOptions configure how the comparison should be performed
type DiffOptions struct {
	// IgnoreWhitespace ignores whitespace differences
	IgnoreWhitespace bool `json:"ignore_whitespace"`
	
	// IgnoreComments ignores changes in comments
	IgnoreComments bool `json:"ignore_comments"`
	
	// IgnoreOrder ignores order changes in arrays/lists
	IgnoreOrder bool `json:"ignore_order"`
	
	// ContextLines is the number of context lines to include
	ContextLines int `json:"context_lines"`
	
	// SemanticDiff enables semantic understanding of configuration
	SemanticDiff bool `json:"semantic_diff"`
	
	// ImpactAnalysis enables change impact analysis
	ImpactAnalysis bool `json:"impact_analysis"`
	
	// IncludeBinaryFiles includes binary files in comparison
	IncludeBinaryFiles bool `json:"include_binary_files"`
	
	// MaxFileSize is the maximum file size to compare (in bytes)
	MaxFileSize int64 `json:"max_file_size"`
	
	// IgnorePaths are paths to ignore during comparison
	IgnorePaths []string `json:"ignore_paths"`
	
	// FocusPaths are paths to focus on during comparison
	FocusPaths []string `json:"focus_paths"`
}

// ExportFormat represents the format for exporting diffs
type ExportFormat string

const (
	// ExportFormatText exports as plain text
	ExportFormatText ExportFormat = "text"
	
	// ExportFormatJSON exports as JSON
	ExportFormatJSON ExportFormat = "json"
	
	// ExportFormatHTML exports as HTML
	ExportFormatHTML ExportFormat = "html"
	
	// ExportFormatUnified exports as unified diff
	ExportFormatUnified ExportFormat = "unified"
	
	// ExportFormatSideBySide exports as side-by-side diff
	ExportFormatSideBySide ExportFormat = "side_by_side"
	
	// ExportFormatMarkdown exports as Markdown
	ExportFormatMarkdown ExportFormat = "markdown"
)

// ExportOptions configure how diffs should be exported
type ExportOptions struct {
	// Format is the export format
	Format ExportFormat `json:"format"`
	
	// IncludeSummary includes the summary in the export
	IncludeSummary bool `json:"include_summary"`
	
	// IncludeMetadata includes metadata in the export
	IncludeMetadata bool `json:"include_metadata"`
	
	// IncludeContext includes context information
	IncludeContext bool `json:"include_context"`
	
	// ColorizeOutput adds color to the output (for text formats)
	ColorizeOutput bool `json:"colorize_output"`
	
	// LineNumbers includes line numbers in the output
	LineNumbers bool `json:"line_numbers"`
	
	// FilterByImpact filters changes by impact level
	FilterByImpact []ImpactLevel `json:"filter_by_impact"`
	
	// FilterByCategory filters changes by category
	FilterByCategory []ChangeCategory `json:"filter_by_category"`
	
	// MaxEntries limits the number of entries in the export
	MaxEntries int `json:"max_entries"`
}

// ThreeWayDiffResult represents a three-way diff comparison
type ThreeWayDiffResult struct {
	// BaseRef is the common ancestor reference
	BaseRef ConfigurationReference `json:"base_ref"`
	
	// LeftRef is the left side reference
	LeftRef ConfigurationReference `json:"left_ref"`
	
	// RightRef is the right side reference
	RightRef ConfigurationReference `json:"right_ref"`
	
	// BaseToLeft are changes from base to left
	BaseToLeft []DiffEntry `json:"base_to_left"`
	
	// BaseToRight are changes from base to right
	BaseToRight []DiffEntry `json:"base_to_right"`
	
	// Conflicts are conflicting changes
	Conflicts []MergeConflict `json:"conflicts"`
	
	// Summary provides a summary of the three-way diff
	Summary ThreeWayDiffSummary `json:"summary"`
	
	// Metadata contains comparison metadata
	Metadata ComparisonMetadata `json:"metadata"`
}

// MergeConflict represents a conflict in a three-way merge
type MergeConflict struct {
	// Path is where the conflict occurs
	Path string `json:"path"`
	
	// BaseValue is the value in the common ancestor
	BaseValue interface{} `json:"base_value"`
	
	// LeftValue is the value in the left side
	LeftValue interface{} `json:"left_value"`
	
	// RightValue is the value in the right side
	RightValue interface{} `json:"right_value"`
	
	// ConflictType describes the type of conflict
	ConflictType ConflictType `json:"conflict_type"`
	
	// ResolutionStrategy suggests how to resolve the conflict
	ResolutionStrategy ResolutionStrategy `json:"resolution_strategy"`
}

// ConflictType represents the type of merge conflict
type ConflictType string

const (
	// ConflictTypeModifyModify indicates both sides modified the same item
	ConflictTypeModifyModify ConflictType = "modify_modify"
	
	// ConflictTypeAddAdd indicates both sides added the same item
	ConflictTypeAddAdd ConflictType = "add_add"
	
	// ConflictTypeDeleteModify indicates one side deleted, other modified
	ConflictTypeDeleteModify ConflictType = "delete_modify"
	
	// ConflictTypeModifyDelete indicates one side modified, other deleted
	ConflictTypeModifyDelete ConflictType = "modify_delete"
)

// ResolutionStrategy suggests how to resolve a merge conflict
type ResolutionStrategy string

const (
	// ResolutionStrategyLeft prefers the left side value
	ResolutionStrategyLeft ResolutionStrategy = "left"
	
	// ResolutionStrategyRight prefers the right side value
	ResolutionStrategyRight ResolutionStrategy = "right"
	
	// ResolutionStrategyBase prefers the base value
	ResolutionStrategyBase ResolutionStrategy = "base"
	
	// ResolutionStrategyMerge attempts to merge both values
	ResolutionStrategyMerge ResolutionStrategy = "merge"
	
	// ResolutionStrategyManual requires manual resolution
	ResolutionStrategyManual ResolutionStrategy = "manual"
)

// ThreeWayDiffSummary provides a summary of three-way diff results
type ThreeWayDiffSummary struct {
	// LeftChanges is the number of changes on the left side
	LeftChanges int `json:"left_changes"`
	
	// RightChanges is the number of changes on the right side
	RightChanges int `json:"right_changes"`
	
	// Conflicts is the number of conflicts found
	Conflicts int `json:"conflicts"`
	
	// AutoResolvable is the number of conflicts that can be auto-resolved
	AutoResolvable int `json:"auto_resolvable"`
	
	// ManualResolution is the number of conflicts requiring manual resolution
	ManualResolution int `json:"manual_resolution"`
}

// DiffEngine performs configuration comparisons and analysis
type DiffEngine interface {
	// Compare performs a two-way comparison between configurations
	Compare(ctx context.Context, from, to ConfigurationReference, options DiffOptions) (*ComparisonResult, error)
	
	// ThreeWayCompare performs a three-way comparison
	ThreeWayCompare(ctx context.Context, base, left, right ConfigurationReference, options DiffOptions) (*ThreeWayDiffResult, error)
	
	// AnalyzeImpact analyzes the impact of changes
	AnalyzeImpact(ctx context.Context, result *ComparisonResult) error
	
	// Export exports diff results in various formats
	Export(ctx context.Context, result *ComparisonResult, options ExportOptions) ([]byte, error)
	
	// ExportThreeWay exports three-way diff results
	ExportThreeWay(ctx context.Context, result *ThreeWayDiffResult, options ExportOptions) ([]byte, error)
}

// SemanticAnalyzer provides semantic understanding of configuration structures
type SemanticAnalyzer interface {
	// AnalyzeStructure analyzes the structure of a configuration
	AnalyzeStructure(ctx context.Context, config []byte, format string) (*ConfigStructure, error)
	
	// CompareStructures compares two configuration structures
	CompareStructures(ctx context.Context, from, to *ConfigStructure) ([]StructuralChange, error)
	
	// DetectPatterns detects common configuration patterns
	DetectPatterns(ctx context.Context, config []byte, format string) ([]ConfigPattern, error)
}

// ConfigStructure represents the semantic structure of a configuration
type ConfigStructure struct {
	// Format is the configuration format (yaml, json, toml)
	Format string `json:"format"`
	
	// Schema is the detected schema (if any)
	Schema string `json:"schema,omitempty"`
	
	// Sections are the main sections in the configuration
	Sections []ConfigSection `json:"sections"`
	
	// Dependencies are dependencies between sections
	Dependencies []SectionDependency `json:"dependencies"`
	
	// Patterns are detected configuration patterns
	Patterns []ConfigPattern `json:"patterns"`
}

// ConfigSection represents a section within a configuration
type ConfigSection struct {
	// Name is the section name
	Name string `json:"name"`
	
	// Path is the path to this section
	Path string `json:"path"`
	
	// Type is the section type
	Type string `json:"type"`
	
	// Children are child sections
	Children []ConfigSection `json:"children,omitempty"`
	
	// Properties are section properties
	Properties map[string]interface{} `json:"properties,omitempty"`
}

// SectionDependency represents a dependency between configuration sections
type SectionDependency struct {
	// From is the source section
	From string `json:"from"`
	
	// To is the target section
	To string `json:"to"`
	
	// Type is the dependency type
	Type string `json:"type"`
	
	// Description describes the dependency
	Description string `json:"description"`
}

// ConfigPattern represents a detected configuration pattern
type ConfigPattern struct {
	// Name is the pattern name
	Name string `json:"name"`
	
	// Type is the pattern type
	Type string `json:"type"`
	
	// Path is where the pattern was found
	Path string `json:"path"`
	
	// Confidence is the confidence level (0-1)
	Confidence float64 `json:"confidence"`
	
	// Description describes the pattern
	Description string `json:"description"`
}

// StructuralChange represents a structural change between configurations
type StructuralChange struct {
	// Type is the type of structural change
	Type StructuralChangeType `json:"type"`
	
	// Path is where the change occurred
	Path string `json:"path"`
	
	// Description describes the change
	Description string `json:"description"`
	
	// Impact describes the potential impact
	Impact ChangeImpact `json:"impact"`
}

// StructuralChangeType represents types of structural changes
type StructuralChangeType string

const (
	// StructuralChangeTypeSectionAdded indicates a new section was added
	StructuralChangeTypeSectionAdded StructuralChangeType = "section_added"
	
	// StructuralChangeTypeSectionRemoved indicates a section was removed
	StructuralChangeTypeSectionRemoved StructuralChangeType = "section_removed"
	
	// StructuralChangeTypeSectionRenamed indicates a section was renamed
	StructuralChangeTypeSectionRenamed StructuralChangeType = "section_renamed"
	
	// StructuralChangeTypeDependencyAdded indicates a new dependency was added
	StructuralChangeTypeDependencyAdded StructuralChangeType = "dependency_added"
	
	// StructuralChangeTypeDependencyRemoved indicates a dependency was removed
	StructuralChangeTypeDependencyRemoved StructuralChangeType = "dependency_removed"
	
	// StructuralChangeTypePatternChanged indicates a pattern changed
	StructuralChangeTypePatternChanged StructuralChangeType = "pattern_changed"
)

// ImpactAnalyzer analyzes the potential impact of configuration changes
type ImpactAnalyzer interface {
	// AnalyzeChange analyzes the impact of a single change
	AnalyzeChange(ctx context.Context, entry *DiffEntry, structure *ConfigStructure) (*ChangeImpact, error)
	
	// AnalyzeChanges analyzes the impact of multiple changes
	AnalyzeChanges(ctx context.Context, entries []DiffEntry, structure *ConfigStructure) ([]ChangeImpact, error)
	
	// AssessRisk assesses the overall risk of a set of changes
	AssessRisk(ctx context.Context, result *ComparisonResult) (*RiskAssessment, error)
}

// RiskAssessment represents an overall assessment of change risk
type RiskAssessment struct {
	// OverallRisk is the overall risk level
	OverallRisk ImpactLevel `json:"overall_risk"`
	
	// RiskFactors are factors contributing to the risk
	RiskFactors []RiskFactor `json:"risk_factors"`
	
	// Recommendations are recommendations for reducing risk
	Recommendations []string `json:"recommendations"`
	
	// RequiredApprovals are approvals required for these changes
	RequiredApprovals []ApprovalRequirement `json:"required_approvals"`
	
	// TestingRecommendations recommend testing strategies
	TestingRecommendations []string `json:"testing_recommendations"`
}

// RiskFactor represents a factor contributing to change risk
type RiskFactor struct {
	// Factor is the risk factor name
	Factor string `json:"factor"`
	
	// Level is the risk level for this factor
	Level ImpactLevel `json:"level"`
	
	// Description describes the risk factor
	Description string `json:"description"`
	
	// Mitigation suggests how to mitigate this risk
	Mitigation string `json:"mitigation"`
}

// ApprovalRequirement represents a required approval for changes
type ApprovalRequirement struct {
	// Type is the approval type
	Type string `json:"type"`
	
	// Required indicates if this approval is required
	Required bool `json:"required"`
	
	// Reason explains why this approval is required
	Reason string `json:"reason"`
	
	// Approvers are who can provide this approval
	Approvers []string `json:"approvers"`
}

// Exporter handles exporting diff results in various formats
type Exporter interface {
	// ExportText exports as plain text
	ExportText(ctx context.Context, result *ComparisonResult, options ExportOptions) ([]byte, error)
	
	// ExportJSON exports as JSON
	ExportJSON(ctx context.Context, result *ComparisonResult, options ExportOptions) ([]byte, error)
	
	// ExportHTML exports as HTML
	ExportHTML(ctx context.Context, result *ComparisonResult, options ExportOptions) ([]byte, error)
	
	// ExportUnified exports as unified diff
	ExportUnified(ctx context.Context, result *ComparisonResult, options ExportOptions) ([]byte, error)
	
	// ExportSideBySide exports as side-by-side diff
	ExportSideBySide(ctx context.Context, result *ComparisonResult, options ExportOptions) ([]byte, error)
	
	// ExportMarkdown exports as Markdown
	ExportMarkdown(ctx context.Context, result *ComparisonResult, options ExportOptions) ([]byte, error)
}

// ApprovalIntegration integrates with approval workflows
type ApprovalIntegration interface {
	// CreateApprovalRequest creates an approval request for changes
	CreateApprovalRequest(ctx context.Context, result *ComparisonResult, assessment *RiskAssessment) (*ApprovalRequest, error)
	
	// UpdateApprovalRequest updates an existing approval request
	UpdateApprovalRequest(ctx context.Context, requestID string, result *ComparisonResult) error
	
	// GetApprovalStatus gets the status of an approval request
	GetApprovalStatus(ctx context.Context, requestID string) (*ApprovalStatus, error)
	
	// CancelApprovalRequest cancels an approval request
	CancelApprovalRequest(ctx context.Context, requestID string) error
}

// ApprovalRequest represents an approval request for configuration changes
type ApprovalRequest struct {
	// ID is the unique request identifier
	ID string `json:"id"`
	
	// Title is the request title
	Title string `json:"title"`
	
	// Description describes the changes
	Description string `json:"description"`
	
	// Changes are the configuration changes
	Changes *ComparisonResult `json:"changes"`
	
	// RiskAssessment is the risk assessment
	RiskAssessment *RiskAssessment `json:"risk_assessment"`
	
	// Requester is who requested the approval
	Requester string `json:"requester"`
	
	// RequiredApprovers are who needs to approve
	RequiredApprovers []string `json:"required_approvers"`
	
	// Status is the current approval status
	Status ApprovalStatus `json:"status"`
	
	// CreatedAt is when the request was created
	CreatedAt time.Time `json:"created_at"`
	
	// ExpiresAt is when the request expires
	ExpiresAt time.Time `json:"expires_at"`
}

// ApprovalStatus represents the status of an approval request
type ApprovalStatus struct {
	// Status is the overall status
	Status string `json:"status"`
	
	// Approvals are individual approvals received
	Approvals []Approval `json:"approvals"`
	
	// PendingApprovers are approvers who haven't responded
	PendingApprovers []string `json:"pending_approvers"`
	
	// Comments are comments on the approval request
	Comments []ApprovalComment `json:"comments"`
	
	// UpdatedAt is when the status was last updated
	UpdatedAt time.Time `json:"updated_at"`
}

// Approval represents an individual approval
type Approval struct {
	// Approver is who provided the approval
	Approver string `json:"approver"`
	
	// Decision is the approval decision
	Decision string `json:"decision"`
	
	// Comment is an optional comment
	Comment string `json:"comment,omitempty"`
	
	// ApprovedAt is when the approval was given
	ApprovedAt time.Time `json:"approved_at"`
}

// ApprovalComment represents a comment on an approval request
type ApprovalComment struct {
	// Author is who made the comment
	Author string `json:"author"`
	
	// Comment is the comment text
	Comment string `json:"comment"`
	
	// CreatedAt is when the comment was made
	CreatedAt time.Time `json:"created_at"`
}