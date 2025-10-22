// Package dna provides DNA collection and drift detection for directory objects.
//
// This package extends CFGMS's DNA framework to treat directory objects (users, groups, OUs)
// as individual DNA-enabled entities, enabling comprehensive directory drift detection and
// unauthorized change monitoring in hybrid identity environments.
//
// Architecture:
// - Each directory object (user/group/OU) becomes a DNA-enabled entity
// - Directory DNA collection captures object attributes, relationships, and metadata
// - Drift detection monitors unauthorized changes in identity management systems
// - Hierarchical collection follows tenant and organizational unit structure
// - Integration with existing DNA storage and monitoring infrastructure
//
// Basic usage:
//
//	collector := dna.NewDirectoryDNACollector(directoryProvider, logger)
//	dnaRecords, err := collector.CollectAll(ctx)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	for _, record := range dnaRecords {
//		fmt.Printf("Object ID: %s, Type: %s\n", record.ObjectID, record.ObjectType)
//	}
package dna

import (
	"context"
	"time"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/pkg/directory/interfaces"
)

// DirectoryDNACollector defines the interface for collecting DNA from directory objects.
//
// This collector treats each directory object (user, group, OU) as an individual DNA-enabled
// entity, enabling fine-grained drift detection and change monitoring for identity systems.
type DirectoryDNACollector interface {
	// Object Collection - Individual DNA collection per directory object
	CollectUserDNA(ctx context.Context, userID string) (*DirectoryDNA, error)
	CollectGroupDNA(ctx context.Context, groupID string) (*DirectoryDNA, error)
	CollectOUDNA(ctx context.Context, ouID string) (*DirectoryDNA, error)

	// Bulk Collection - Efficient collection of multiple objects
	CollectAllUsers(ctx context.Context, filters *interfaces.SearchFilters) ([]*DirectoryDNA, error)
	CollectAllGroups(ctx context.Context, filters *interfaces.SearchFilters) ([]*DirectoryDNA, error)
	CollectAllOUs(ctx context.Context, filters *interfaces.SearchFilters) ([]*DirectoryDNA, error)
	CollectAll(ctx context.Context) ([]*DirectoryDNA, error)

	// Hierarchical Collection - Domain and organizational structure DNA collection
	CollectDomainDNA(ctx context.Context) (*DomainDNA, error)
	CollectHierarchicalDNA(ctx context.Context, rootOU string) (*HierarchicalDNA, error)

	// Relationship Collection - Captures relationships between directory objects
	CollectRelationships(ctx context.Context, objectID string) (*DirectoryRelationships, error)
	CollectGroupMemberships(ctx context.Context) ([]*GroupMembership, error)
	CollectOUHierarchy(ctx context.Context) (*OUHierarchy, error)

	// Provider Information
	GetProviderInfo() interfaces.ProviderInfo
	GetCollectionCapabilities() DirectoryCollectionCapabilities

	// Statistics
	GetCollectionStats() *CollectionStats
}

// DirectoryDNAStorage defines the interface for storing directory DNA records.
//
// This extends the existing DNA storage framework to support directory-specific
// operations while maintaining compatibility with the broader DNA ecosystem.
type DirectoryDNAStorage interface {
	// Directory DNA Storage
	StoreDirectoryDNA(ctx context.Context, dna *DirectoryDNA) error
	GetDirectoryDNA(ctx context.Context, objectID string, objectType interfaces.DirectoryObjectType) (*DirectoryDNA, error)

	// Historical Queries - Directory-specific query capabilities
	QueryDirectoryDNA(ctx context.Context, query *DirectoryDNAQuery) ([]*DirectoryDNA, error)
	GetDirectoryHistory(ctx context.Context, objectID string, timeRange *TimeRange) ([]*DirectoryDNA, error)

	// Relationship Storage
	StoreRelationships(ctx context.Context, relationships *DirectoryRelationships) error
	GetRelationships(ctx context.Context, objectID string) (*DirectoryRelationships, error)

	// Statistics and Health
	GetDirectoryStats(ctx context.Context) (*DirectoryDNAStats, error)
	GetObjectStats(ctx context.Context, objectType interfaces.DirectoryObjectType) (*ObjectTypeStats, error)
}

// DirectoryDriftDetector defines the interface for detecting drift in directory objects.
//
// This integrates with CFGMS's drift detection framework to monitor unauthorized
// changes in identity management systems and trigger automated responses.
type DirectoryDriftDetector interface {
	// Drift Detection
	DetectDrift(ctx context.Context, current *DirectoryDNA, baseline *DirectoryDNA) (*DirectoryDrift, error)
	DetectBulkDrift(ctx context.Context, currentSet []*DirectoryDNA, baselineSet []*DirectoryDNA) ([]*DirectoryDrift, error)

	// Monitoring Configuration
	SetMonitoringInterval(interval time.Duration) error
	GetMonitoringInterval() time.Duration
	SetDriftThresholds(thresholds *DriftThresholds) error
	GetDriftThresholds() *DriftThresholds

	// Event Handling
	RegisterDriftHandler(handler DirectoryDriftHandler) error
	UnregisterDriftHandler(handlerID string) error

	// Control
	StartMonitoring(ctx context.Context) error
	StopMonitoring() error
	IsMonitoring() bool

	// Statistics
	GetDriftDetectionStats() *DriftDetectionStats
}

// DirectoryDriftHandler defines the interface for handling directory drift events.
type DirectoryDriftHandler interface {
	HandleDrift(ctx context.Context, drift *DirectoryDrift) error
	GetHandlerID() string
	GetHandlerType() DirectoryDriftHandlerType
}

// Core Data Structures

// DirectoryDNA represents the DNA of a single directory object.
//
// This structure captures all attributes, relationships, and metadata for a directory
// object, enabling comprehensive drift detection and change monitoring.
type DirectoryDNA struct {
	// Core Identity
	ObjectID   string                         `json:"object_id"`   // Unique object identifier
	ObjectType interfaces.DirectoryObjectType `json:"object_type"` // Type of directory object

	// DNA Metadata (compatible with existing DNA framework)
	ID          string            `json:"id"`           // Generated DNA ID
	Attributes  map[string]string `json:"attributes"`   // All object attributes as strings
	LastUpdated *time.Time        `json:"last_updated"` // When DNA was collected

	// Directory-Specific Metadata
	Provider          string `json:"provider"`                     // Source directory provider
	TenantID          string `json:"tenant_id,omitempty"`          // Multi-tenant identifier
	Domain            string `json:"domain,omitempty"`             // Directory domain
	DistinguishedName string `json:"distinguished_name,omitempty"` // Full DN path

	// Object State
	ObjectState   *DirectoryObjectState `json:"object_state"`            // Structured object data
	Relationships []string              `json:"relationships,omitempty"` // Related object IDs
	Permissions   []string              `json:"permissions,omitempty"`   // Object permissions

	// DNA Framework Compatibility
	ConfigHash      string     `json:"config_hash,omitempty"`      // Configuration hash
	LastSyncTime    *time.Time `json:"last_sync_time,omitempty"`   // Last sync timestamp
	AttributeCount  int32      `json:"attribute_count"`            // Number of attributes
	SyncFingerprint string     `json:"sync_fingerprint,omitempty"` // Sync verification fingerprint

	// Change Tracking
	ChangeHistory  []*DirectoryChange `json:"change_history,omitempty"`   // Recent changes
	LastChangeTime *time.Time         `json:"last_change_time,omitempty"` // When last changed
	ChangeCount    int32              `json:"change_count"`               // Total number of changes
}

// DirectoryObjectState represents the structured state of a directory object.
//
// This preserves the original typed structure while also providing the flattened
// string attributes required by the DNA framework.
type DirectoryObjectState struct {
	// Typed Object Data (preserves original structure)
	User  *interfaces.DirectoryUser      `json:"user,omitempty"`
	Group *interfaces.DirectoryGroup     `json:"group,omitempty"`
	OU    *interfaces.OrganizationalUnit `json:"ou,omitempty"`

	// Metadata
	CollectedAt    time.Time     `json:"collected_at"`
	CollectionTime time.Duration `json:"collection_time"` // Time taken to collect
}

// DirectoryRelationships represents relationships between directory objects.
type DirectoryRelationships struct {
	ObjectID   string                         `json:"object_id"`
	ObjectType interfaces.DirectoryObjectType `json:"object_type"`

	// Group Relationships
	MemberOf []string `json:"member_of,omitempty"` // Groups this object belongs to
	Members  []string `json:"members,omitempty"`   // Members of this group

	// Organizational Relationships
	ParentOU   string   `json:"parent_ou,omitempty"`    // Parent organizational unit
	ChildOUs   []string `json:"child_ous,omitempty"`    // Child organizational units
	UsersInOU  []string `json:"users_in_ou,omitempty"`  // Users in this OU
	GroupsInOU []string `json:"groups_in_ou,omitempty"` // Groups in this OU

	// Management Relationships
	Manager       string   `json:"manager,omitempty"`        // Manager's ID
	DirectReports []string `json:"direct_reports,omitempty"` // Direct report IDs

	// Metadata
	CollectedAt time.Time `json:"collected_at"`
	Provider    string    `json:"provider"`
	TenantID    string    `json:"tenant_id,omitempty"`
}

// GroupMembership represents a group membership relationship.
type GroupMembership struct {
	UserID     string     `json:"user_id"`
	GroupID    string     `json:"group_id"`
	MemberType string     `json:"member_type"` // "direct", "indirect", "nested"
	GrantedAt  *time.Time `json:"granted_at,omitempty"`
	Source     string     `json:"source"` // How membership was granted
	Provider   string     `json:"provider"`
	TenantID   string     `json:"tenant_id,omitempty"`
}

// OUHierarchy represents the organizational unit hierarchy.
type OUHierarchy struct {
	RootOU      string             `json:"root_ou"`
	Hierarchy   map[string]*OUNode `json:"hierarchy"` // OU ID -> OUNode
	Depth       int                `json:"depth"`     // Maximum depth
	TotalOUs    int                `json:"total_ous"` // Total number of OUs
	CollectedAt time.Time          `json:"collected_at"`
	Provider    string             `json:"provider"`
	TenantID    string             `json:"tenant_id,omitempty"`
}

// OUNode represents a node in the organizational unit hierarchy.
type OUNode struct {
	OUID       string   `json:"ou_id"`
	Name       string   `json:"name"`
	ParentID   string   `json:"parent_id,omitempty"`
	Children   []string `json:"children,omitempty"`
	UserCount  int      `json:"user_count"`
	GroupCount int      `json:"group_count"`
	Depth      int      `json:"depth"`
}

// DirectoryDrift represents detected drift in a directory object.
type DirectoryDrift struct {
	// Drift Identity
	DriftID    string                         `json:"drift_id"`
	ObjectID   string                         `json:"object_id"`
	ObjectType interfaces.DirectoryObjectType `json:"object_type"`

	// Drift Details
	DriftType   DirectoryDriftType `json:"drift_type"`
	Severity    DriftSeverity      `json:"severity"`
	Description string             `json:"description"`

	// Changes
	Changes []*DirectoryChange `json:"changes"`
	Summary *DriftSummary      `json:"summary"`

	// Context
	DetectedAt time.Time `json:"detected_at"`
	Provider   string    `json:"provider"`
	TenantID   string    `json:"tenant_id,omitempty"`

	// Risk Assessment
	RiskScore float64              `json:"risk_score"` // 0-100 risk score
	Impact    DirectoryDriftImpact `json:"impact"`     // Impact assessment

	// Remediation
	SuggestedActions []string `json:"suggested_actions,omitempty"`
	AutoRemediable   bool     `json:"auto_remediable"`
}

// DirectoryChange represents a specific change in a directory object.
type DirectoryChange struct {
	ChangeID     string              `json:"change_id"`
	ChangeType   DirectoryChangeType `json:"change_type"`
	Field        string              `json:"field"`
	OldValue     interface{}         `json:"old_value"`
	NewValue     interface{}         `json:"new_value"`
	ChangedAt    time.Time           `json:"changed_at"`
	ChangedBy    string              `json:"changed_by,omitempty"`
	ChangeSource string              `json:"change_source,omitempty"`
}

// Supporting Types and Enums

// DirectoryDriftType represents different types of directory drift.
type DirectoryDriftType string

const (
	DirectoryDriftTypeNoChange             DirectoryDriftType = "no_change"
	DirectoryDriftTypeUnauthorizedChange   DirectoryDriftType = "unauthorized_change"
	DirectoryDriftTypePermissionEscalation DirectoryDriftType = "permission_escalation"
	DirectoryDriftTypeMembershipChange     DirectoryDriftType = "membership_change"
	DirectoryDriftTypeObjectCreation       DirectoryDriftType = "object_creation"
	DirectoryDriftTypeObjectDeletion       DirectoryDriftType = "object_deletion"
	DirectoryDriftTypeAttributeChange      DirectoryDriftType = "attribute_change"
	DirectoryDriftTypeRelationshipChange   DirectoryDriftType = "relationship_change"
)

// DriftSeverity represents the severity level of directory drift.
type DriftSeverity string

const (
	DriftSeverityLow      DriftSeverity = "low"
	DriftSeverityMedium   DriftSeverity = "medium"
	DriftSeverityHigh     DriftSeverity = "high"
	DriftSeverityCritical DriftSeverity = "critical"
)

// DirectoryDriftImpact represents the assessed impact of directory drift.
type DirectoryDriftImpact struct {
	SecurityImpact    ImpactLevel `json:"security_impact"`
	OperationalImpact ImpactLevel `json:"operational_impact"`
	ComplianceImpact  ImpactLevel `json:"compliance_impact"`
	UserImpact        ImpactLevel `json:"user_impact"`
}

// ImpactLevel represents the level of impact.
type ImpactLevel string

const (
	ImpactLevelNone     ImpactLevel = "none"
	ImpactLevelLow      ImpactLevel = "low"
	ImpactLevelMedium   ImpactLevel = "medium"
	ImpactLevelHigh     ImpactLevel = "high"
	ImpactLevelCritical ImpactLevel = "critical"
)

// DirectoryChangeType represents types of changes in directory objects.
type DirectoryChangeType string

const (
	DirectoryChangeTypeCreate DirectoryChangeType = "create"
	DirectoryChangeTypeUpdate DirectoryChangeType = "update"
	DirectoryChangeTypeDelete DirectoryChangeType = "delete"
	DirectoryChangeTypeMove   DirectoryChangeType = "move"
	DirectoryChangeTypeRename DirectoryChangeType = "rename"
)

// DirectoryDriftHandlerType represents types of drift handlers.
type DirectoryDriftHandlerType string

const (
	DirectoryDriftHandlerTypeAlert     DirectoryDriftHandlerType = "alert"
	DirectoryDriftHandlerTypeRemediate DirectoryDriftHandlerType = "remediate"
	DirectoryDriftHandlerTypeLog       DirectoryDriftHandlerType = "log"
	DirectoryDriftHandlerTypeWorkflow  DirectoryDriftHandlerType = "workflow"
)

// Configuration and Query Types

// DirectoryCollectionCapabilities describes what the collector can collect.
type DirectoryCollectionCapabilities struct {
	SupportsUsers         bool          `json:"supports_users"`
	SupportsGroups        bool          `json:"supports_groups"`
	SupportsOUs           bool          `json:"supports_ous"`
	SupportsRelationships bool          `json:"supports_relationships"`
	SupportsPermissions   bool          `json:"supports_permissions"`
	SupportedAttributes   []string      `json:"supported_attributes"`
	MaxBatchSize          int           `json:"max_batch_size"`
	CollectionInterval    time.Duration `json:"collection_interval"`
}

// DirectoryDNAQuery represents a query for directory DNA records.
type DirectoryDNAQuery struct {
	// Object Filters
	ObjectIDs   []string                         `json:"object_ids,omitempty"`
	ObjectTypes []interfaces.DirectoryObjectType `json:"object_types,omitempty"`

	// Provider Filters
	Providers []string `json:"providers,omitempty"`
	TenantIDs []string `json:"tenant_ids,omitempty"`
	Domains   []string `json:"domains,omitempty"`

	// Time Filters
	TimeRange *TimeRange `json:"time_range,omitempty"`

	// Change Filters
	ChangedSince   *time.Time `json:"changed_since,omitempty"`
	MinChangeCount int32      `json:"min_change_count,omitempty"`

	// Pagination
	Offset    int    `json:"offset"`
	Limit     int    `json:"limit"`
	SortBy    string `json:"sort_by,omitempty"`
	SortOrder string `json:"sort_order,omitempty"`
}

// TimeRange represents a time range for queries.
type TimeRange struct {
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
}

// DriftThresholds defines thresholds for drift detection.
type DriftThresholds struct {
	// Attribute Change Thresholds
	MaxAttributeChanges   int           `json:"max_attribute_changes"`
	AttributeChangeWindow time.Duration `json:"attribute_change_window"`

	// Membership Change Thresholds
	MaxMembershipChanges   int           `json:"max_membership_changes"`
	MembershipChangeWindow time.Duration `json:"membership_change_window"`

	// Critical Attribute Changes
	CriticalAttributes []string `json:"critical_attributes"`

	// Risk Scoring
	LowRiskThreshold      float64 `json:"low_risk_threshold"`
	MediumRiskThreshold   float64 `json:"medium_risk_threshold"`
	HighRiskThreshold     float64 `json:"high_risk_threshold"`
	CriticalRiskThreshold float64 `json:"critical_risk_threshold"`
}

// Statistics and Reporting

// DirectoryDNAStats provides statistics about directory DNA collection.
type DirectoryDNAStats struct {
	// Collection Statistics
	TotalObjects int64 `json:"total_objects"`
	UserCount    int64 `json:"user_count"`
	GroupCount   int64 `json:"group_count"`
	OUCount      int64 `json:"ou_count"`

	// Collection Performance
	LastCollectionTime        time.Time     `json:"last_collection_time"`
	AverageCollectionDuration time.Duration `json:"avg_collection_duration"`
	CollectionSuccessRate     float64       `json:"collection_success_rate"`

	// Storage Statistics
	TotalStorageUsed int64   `json:"total_storage_used"`
	CompressionRatio float64 `json:"compression_ratio"`

	// Change Statistics
	TotalChangesDetected int64    `json:"total_changes_detected"`
	ChangesPerDay        float64  `json:"changes_per_day"`
	MostActiveObjects    []string `json:"most_active_objects"`

	// Drift Statistics
	ActiveDrifts   int64   `json:"active_drifts"`
	CriticalDrifts int64   `json:"critical_drifts"`
	DriftsPerDay   float64 `json:"drifts_per_day"`

	// Provider Statistics
	ProviderStats map[string]*ProviderStats `json:"provider_stats"`

	// Health
	CollectionHealth string    `json:"collection_health"`
	LastHealthCheck  time.Time `json:"last_health_check"`
}

// ObjectTypeStats provides statistics for a specific object type.
type ObjectTypeStats struct {
	ObjectType        interfaces.DirectoryObjectType `json:"object_type"`
	TotalCount        int64                          `json:"total_count"`
	ActiveCount       int64                          `json:"active_count"`
	ChangedToday      int64                          `json:"changed_today"`
	AverageAttributes float64                        `json:"avg_attributes"`
	MostCommonChanges []string                       `json:"most_common_changes"`
}

// ProviderStats provides statistics for a specific directory provider.
type ProviderStats struct {
	Provider           string        `json:"provider"`
	ObjectCount        int64         `json:"object_count"`
	LastCollection     time.Time     `json:"last_collection"`
	CollectionDuration time.Duration `json:"collection_duration"`
	SuccessRate        float64       `json:"success_rate"`
	ErrorCount         int64         `json:"error_count"`
	LastError          string        `json:"last_error,omitempty"`
}

// DriftSummary provides a summary of detected drift.
type DriftSummary struct {
	TotalChanges       int           `json:"total_changes"`
	CriticalChanges    int           `json:"critical_changes"`
	SecurityRelevant   int           `json:"security_relevant"`
	AffectedAttributes []string      `json:"affected_attributes"`
	TimeSpan           time.Duration `json:"time_span"`
}

// DomainDNA represents DNA for an entire directory domain.
//
// This captures domain-level configuration, policies, and organizational structure
// for comprehensive domain drift detection and change monitoring.
type DomainDNA struct {
	// Domain Identity
	DomainName string `json:"domain_name"`
	DomainID   string `json:"domain_id"`
	ForestName string `json:"forest_name,omitempty"`

	// Domain Configuration DNA
	ID          string            `json:"id"`
	Attributes  map[string]string `json:"attributes"`
	LastUpdated *time.Time        `json:"last_updated"`

	// Domain Policies and Settings
	DomainPolicies   map[string]interface{} `json:"domain_policies,omitempty"`
	SecuritySettings map[string]interface{} `json:"security_settings,omitempty"`
	PasswordPolicy   map[string]interface{} `json:"password_policy,omitempty"`

	// Organizational Structure
	RootContainers []string `json:"root_containers"`
	TotalOUs       int      `json:"total_ous"`
	TotalUsers     int      `json:"total_users"`
	TotalGroups    int      `json:"total_groups"`

	// Provider Context
	Provider    string    `json:"provider"`
	TenantID    string    `json:"tenant_id,omitempty"`
	CollectedAt time.Time `json:"collected_at"`

	// DNA Framework Compatibility
	ConfigHash      string `json:"config_hash,omitempty"`
	AttributeCount  int32  `json:"attribute_count"`
	SyncFingerprint string `json:"sync_fingerprint"`
}

// HierarchicalDNA represents DNA for a complete organizational hierarchy.
//
// This captures the complete hierarchical structure including all child objects
// and their relationships for comprehensive organizational drift detection.
type HierarchicalDNA struct {
	// Root Identity
	RootOU      string `json:"root_ou"`
	HierarchyID string `json:"hierarchy_id"`

	// Hierarchy DNA
	ID          string            `json:"id"`
	Attributes  map[string]string `json:"attributes"`
	LastUpdated *time.Time        `json:"last_updated"`

	// Hierarchical Structure
	Structure     *OUHierarchy                                       `json:"structure"`
	AllObjects    []*DirectoryDNA                                    `json:"all_objects"`
	ObjectsByType map[interfaces.DirectoryObjectType][]*DirectoryDNA `json:"objects_by_type"`

	// Hierarchy Statistics
	MaxDepth   int `json:"max_depth"`
	TotalNodes int `json:"total_nodes"`
	LeafNodes  int `json:"leaf_nodes"`

	// Relationships
	AllRelationships []*DirectoryRelationships `json:"all_relationships"`
	AllMemberships   []*GroupMembership        `json:"all_memberships"`

	// Provider Context
	Provider       string        `json:"provider"`
	TenantID       string        `json:"tenant_id,omitempty"`
	CollectedAt    time.Time     `json:"collected_at"`
	CollectionTime time.Duration `json:"collection_time"`

	// DNA Framework Compatibility
	ConfigHash      string `json:"config_hash,omitempty"`
	AttributeCount  int32  `json:"attribute_count"`
	SyncFingerprint string `json:"sync_fingerprint"`
}

// Collection and Drift Detection Statistics

// Utility Functions and Helpers

// ToDNA converts a DirectoryDNA to a standard DNA structure for compatibility.
func (d *DirectoryDNA) ToDNA() *commonpb.DNA {
	// Note: This is a placeholder implementation - protobuf timestamps would be handled properly
	return &commonpb.DNA{
		Id:              d.ID,
		Attributes:      d.Attributes,
		ConfigHash:      d.ConfigHash,
		AttributeCount:  d.AttributeCount,
		SyncFingerprint: d.SyncFingerprint,
		// LastUpdated and LastSyncTime would be properly converted in real implementation
	}
}

// FromDNA creates a DirectoryDNA from a standard DNA structure.
func FromDNA(dna *commonpb.DNA, objectID string, objectType interfaces.DirectoryObjectType) *DirectoryDNA {
	return &DirectoryDNA{
		ObjectID:        objectID,
		ObjectType:      objectType,
		ID:              dna.Id,
		Attributes:      dna.Attributes,
		LastUpdated:     convertProtobufToTime(dna.LastUpdated),
		ConfigHash:      dna.ConfigHash,
		LastSyncTime:    convertProtobufToTime(dna.LastSyncTime),
		AttributeCount:  dna.AttributeCount,
		SyncFingerprint: dna.SyncFingerprint,
	}
}

// Helper functions for protobuf time conversion (to be implemented)

func convertProtobufToTime(pb interface{}) *time.Time {
	// Implementation depends on protobuf version - returning nil for now
	// In a real implementation, this would convert from *timestamppb.Timestamp
	return nil
}
