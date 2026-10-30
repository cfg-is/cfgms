// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package activedirectory

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/pkg/logging"
)

// ADModuleConfig represents the configuration for the system-context AD module
type ADModuleConfig struct {
	OperationType       string        `json:"operation_type" yaml:"operation_type"`
	ObjectTypes         []string      `json:"object_types" yaml:"object_types"`
	SearchBase          string        `json:"search_base,omitempty" yaml:"search_base,omitempty"`
	PageSize            int           `json:"page_size" yaml:"page_size"`
	RequestTimeout      time.Duration `json:"request_timeout" yaml:"request_timeout"`
	EnableDNACollection bool          `json:"enable_dna_collection" yaml:"enable_dna_collection"`
}

// Validate validates the AD module configuration
func (c *ADModuleConfig) Validate() error {
	if c.OperationType == "" {
		return fmt.Errorf("operation_type is required")
	}
	if len(c.ObjectTypes) == 0 {
		return fmt.Errorf("at least one object_type is required")
	}
	if c.PageSize < 0 {
		return fmt.Errorf("page_size must be non-negative")
	}
	if c.PageSize > maxPageSize {
		return fmt.Errorf("page_size must not exceed %d", maxPageSize)
	}
	if c.RequestTimeout < 0 {
		return fmt.Errorf("request_timeout must be non-negative")
	}
	return nil
}

// AsMap implements the ConfigState interface
func (c *ADModuleConfig) AsMap() map[string]interface{} {
	return map[string]interface{}{
		"operation_type":        c.OperationType,
		"object_types":          c.ObjectTypes,
		"search_base":           c.SearchBase,
		"page_size":             c.PageSize,
		"request_timeout":       c.RequestTimeout,
		"enable_dna_collection": c.EnableDNACollection,
	}
}

// GetManagedFields returns the fields that this module can modify
func (c *ADModuleConfig) GetManagedFields() []string {
	return []string{"operation_type", "object_types", "search_base", "page_size", "request_timeout", "enable_dna_collection"}
}

// ToYAML serializes the configuration to YAML
func (c *ADModuleConfig) ToYAML() ([]byte, error) {
	return yaml.Marshal(c)
}

// FromYAML deserializes YAML data into the configuration
func (c *ADModuleConfig) FromYAML(data []byte) error {
	return yaml.Unmarshal(data, c)
}

// ADSystemStatus represents the current status of the system-context AD module
type ADSystemStatus struct {
	SystemContext      bool      `json:"system_context"`
	Hostname           string    `json:"hostname"`
	Domain             string    `json:"domain"`
	DomainController   string    `json:"domain_controller"`
	ForestRoot         string    `json:"forest_root"`
	HealthStatus       string    `json:"health_status"`
	Error              string    `json:"error,omitempty"`
	RequestCount       int64     `json:"request_count"`
	ErrorCount         int64     `json:"error_count"`
	LastHealthCheck    time.Time `json:"last_health_check"`
	DNACollectionCount int64     `json:"dna_collection_count"`
	LastDNACollection  time.Time `json:"last_dna_collection"`
}

// AsMap implements the ConfigState interface
func (s *ADSystemStatus) AsMap() map[string]interface{} {
	return map[string]interface{}{
		"system_context":       s.SystemContext,
		"hostname":             s.Hostname,
		"domain":               s.Domain,
		"domain_controller":    s.DomainController,
		"forest_root":          s.ForestRoot,
		"health_status":        s.HealthStatus,
		"error":                s.Error,
		"request_count":        s.RequestCount,
		"error_count":          s.ErrorCount,
		"last_health_check":    s.LastHealthCheck,
		"dna_collection_count": s.DNACollectionCount,
		"last_dna_collection":  s.LastDNACollection,
	}
}

// GetManagedFields returns the fields that this status object tracks
func (s *ADSystemStatus) GetManagedFields() []string {
	return []string{"system_context", "hostname", "domain", "domain_controller", "forest_root", "health_status", "request_count", "error_count"}
}

// ToYAML serializes the status to YAML
func (s *ADSystemStatus) ToYAML() ([]byte, error) {
	return yaml.Marshal(s)
}

// FromYAML deserializes YAML data into the status
func (s *ADSystemStatus) FromYAML(data []byte) error {
	return yaml.Unmarshal(data, s)
}

// Validate validates the status object
func (s *ADSystemStatus) Validate() error {
	return nil // Status objects don't need validation
}

// DomainInfo represents basic domain information
type DomainInfo struct {
	Domain           string `json:"domain"`
	DomainController string `json:"domain_controller"`
	ForestRoot       string `json:"forest_root"`
	NetBIOSName      string `json:"netbios_name"`
}

// Inventory resource IDs. Get on these IDs returns per-object directory
// inventory (one DNA fragment per object, kind "<id>:<objectGUID>"). They are
// reserved: a declared resource may not use either name.
const (
	kindDirectoryUser  = "directory_user"
	kindDirectoryGroup = "directory_group"
)

const (
	// maxListEntries bounds member_of and other_members per object. A longer
	// list keeps its first maxListEntries entries in sorted order and is
	// flagged with the matching *_truncated attribute.
	maxListEntries = 10000

	// maxInventoryObjects bounds one Get. It matches the per-kind bound of the
	// steward's DNA assembler; one Get holds up to this many objects (about
	// 1 KB each) in memory once.
	maxInventoryObjects = 200000

	// defaultPageSize is the AD paging size used when none is configured.
	defaultPageSize = 1000

	// maxPageSize is the largest page size the read script accepts.
	maxPageSize = 5000
)

// otherMemberTypes are the member types reported in a group's other_members.
var otherMemberTypes = map[string]bool{
	"computer":                   true,
	"contact":                    true,
	"foreign_security_principal": true,
	"other":                      true,
}

// objectGUIDPattern matches the canonical lowercase objectGUID form the read
// script emits.
var objectGUIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// scriptRunner runs the module's fixed read script with request (a JSON
// document) on stdin and calls onLine for every line the script writes to
// stdout. On Windows it is the hash-checked PowerShell runner in
// scripts_windows.go; tests supply their own implementation.
type scriptRunner interface {
	Run(ctx context.Context, request []byte, onLine func(line []byte) error) error
}

// readRequest is the request document the read script validates.
type readRequest struct {
	Operation string `json:"operation"`
	PageSize  int    `json:"page_size"`
	Domain    string `json:"domain"`
}

// readRecord is one line of read script output.
type readRecord struct {
	Type   string `json:"type"`
	Code   string `json:"code"`
	Detail string `json:"detail"`

	ID                    string       `json:"id"`
	SamAccountName        string       `json:"sam_account_name"`
	UserPrincipalName     string       `json:"user_principal_name"`
	DisplayName           string       `json:"display_name"`
	Mail                  string       `json:"mail"`
	Enabled               bool         `json:"enabled"`
	DistinguishedName     string       `json:"distinguished_name"`
	ObjectSID             string       `json:"object_sid"`
	WhenCreated           string       `json:"when_created"`
	DirectoryDomain       string       `json:"directory_domain"`
	GroupScope            string       `json:"group_scope"`
	GroupCategory         string       `json:"group_category"`
	MemberOf              stringList   `json:"member_of"`
	MemberOfTruncated     bool         `json:"member_of_truncated"`
	OtherMembers          otherMembers `json:"other_members"`
	OtherMembersTruncated bool         `json:"other_members_truncated"`

	Domain           string `json:"domain"`
	DomainController string `json:"domain_controller"`
	ForestRoot       string `json:"forest_root"`
	NetBIOSName      string `json:"netbios_name"`
}

// stringList decodes a JSON string array, a single string or null. Windows
// PowerShell's ConvertTo-Json can render a one-element array as a scalar.
type stringList []string

func (l *stringList) UnmarshalJSON(data []byte) error {
	var list []string
	if err := json.Unmarshal(data, &list); err == nil {
		*l = list
		return nil
	}
	var one *string
	if err := json.Unmarshal(data, &one); err != nil {
		return err
	}
	*l = nil
	if one != nil {
		*l = []string{*one}
	}
	return nil
}

// otherMember is a direct group member that is neither a user nor a group.
type otherMember struct {
	Type string `json:"type"`
	ID   string `json:"id"`
	Name string `json:"name"`
}

// otherMembers decodes a JSON array of otherMember, a single object or null.
type otherMembers []otherMember

func (l *otherMembers) UnmarshalJSON(data []byte) error {
	var list []otherMember
	if err := json.Unmarshal(data, &list); err == nil {
		*l = list
		return nil
	}
	var one *otherMember
	if err := json.Unmarshal(data, &one); err != nil {
		return err
	}
	*l = nil
	if one != nil {
		*l = []otherMember{*one}
	}
	return nil
}

// inventoryState is the per-object ConfigState Get returns for
// directory_user and directory_group: the object list under
// modules.PerObjectKey, sorted by id.
type inventoryState struct {
	objects []interface{}
}

func (s *inventoryState) AsMap() map[string]interface{} {
	return map[string]interface{}{modules.PerObjectKey: s.objects}
}

func (s *inventoryState) ToYAML() ([]byte, error) { return yaml.Marshal(s.AsMap()) }

func (s *inventoryState) FromYAML([]byte) error {
	return fmt.Errorf("directory inventory state is read-only")
}

func (s *inventoryState) Validate() error { return nil }

func (s *inventoryState) GetManagedFields() []string { return nil }

// activeDirectoryModule implements the Module interface for local Active
// Directory management using the Windows system context.
type activeDirectoryModule struct {
	logger logging.Logger

	// runner runs the fixed read script.
	runner scriptRunner

	// Configuration management
	config    *ADModuleConfig
	configMux sync.RWMutex

	// Statistics tracking
	stats struct {
		sync.RWMutex
		requestCount       int64
		errorCount         int64
		lastRequest        time.Time
		dnaCollectionCount int64
		lastDNACollection  time.Time
	}
}

// New creates a new instance of the system-context Active Directory module
func New(logger logging.Logger) modules.Module {
	return newWithRunner(logger, newPlatformRunner())
}

// newWithRunner creates the module with the given script runner.
func newWithRunner(logger logging.Logger, runner scriptRunner) *activeDirectoryModule {
	if logger == nil {
		logger = logging.NewNoopLogger()
	}
	return &activeDirectoryModule{
		logger: logger,
		runner: runner,
	}
}

// validateDeclaredResourceID rejects a declared resource that uses one of the
// reserved inventory IDs.
func validateDeclaredResourceID(resourceID string) error {
	switch resourceID {
	case kindDirectoryUser, kindDirectoryGroup:
		return fmt.Errorf("resource ID %q is reserved for directory inventory and cannot be declared", resourceID)
	}
	return nil
}

// Get returns the AD system status ("status") or the per-object directory
// inventory ("directory_user", "directory_group").
func (m *activeDirectoryModule) Get(ctx context.Context, resourceID string) (modules.ConfigState, error) {
	m.logger.Debug("Getting local AD object", "resource_id", logging.SanitizeLogValue(resourceID))

	switch resourceID {
	case "status":
		return m.getSystemStatus(ctx)
	case kindDirectoryUser:
		return m.getInventory(ctx, kindDirectoryUser, "users", "user")
	case kindDirectoryGroup:
		return m.getInventory(ctx, kindDirectoryGroup, "groups", "group")
	default:
		return nil, fmt.Errorf("unsupported operation: %s", resourceID)
	}
}

// Set configures the system-context Active Directory module
func (m *activeDirectoryModule) Set(ctx context.Context, resourceID string, config modules.ConfigState) error {
	m.logger.Debug("Setting local AD module configuration", "resource_id", logging.SanitizeLogValue(resourceID))

	if err := validateDeclaredResourceID(resourceID); err != nil {
		return err
	}

	// Convert ConfigState to ADModuleConfig
	configMap := config.AsMap()
	adConfig := &ADModuleConfig{}

	// Extract configuration fields (minimal for system context)
	if opType, ok := configMap["operation_type"].(string); ok {
		adConfig.OperationType = opType
	}
	if objTypes, ok := configMap["object_types"].([]string); ok {
		adConfig.ObjectTypes = objTypes
	}
	if searchBase, ok := configMap["search_base"].(string); ok {
		adConfig.SearchBase = searchBase
	}
	if pageSize, ok := configMap["page_size"].(int); ok {
		adConfig.PageSize = pageSize
	}
	if timeout, ok := configMap["request_timeout"].(time.Duration); ok {
		adConfig.RequestTimeout = timeout
	}
	if enableDNA, ok := configMap["enable_dna_collection"].(bool); ok {
		adConfig.EnableDNACollection = enableDNA
	}

	// Set defaults
	if adConfig.PageSize == 0 {
		adConfig.PageSize = defaultPageSize
	}
	if adConfig.RequestTimeout == 0 {
		adConfig.RequestTimeout = 30 * time.Second
	}
	if adConfig.OperationType == "" {
		adConfig.OperationType = "read"
	}

	// Validate configuration
	if err := adConfig.Validate(); err != nil {
		return fmt.Errorf("invalid AD configuration: %w", err)
	}

	// Store configuration
	m.configMux.Lock()
	m.config = adConfig
	m.configMux.Unlock()

	// Verify system context AD access
	if err := m.verifySystemAccess(ctx); err != nil {
		return fmt.Errorf("failed to verify system AD access: %w", err)
	}

	m.logger.Info("Local AD module configured successfully using system context",
		"operation_type", logging.SanitizeLogValue(adConfig.OperationType),
		"dna_collection", adConfig.EnableDNACollection)

	return nil
}

// Test validates that the module is configured and can read the directory.
func (m *activeDirectoryModule) Test(ctx context.Context, resourceID string, config modules.ConfigState) (bool, error) {
	m.configMux.RLock()
	currentConfig := m.config
	m.configMux.RUnlock()

	if currentConfig == nil {
		return false, fmt.Errorf("module not configured")
	}

	if err := m.verifySystemAccess(ctx); err != nil {
		return false, fmt.Errorf("system AD access test failed: %w", err)
	}
	return true, nil
}

// getSystemStatus returns the current system context AD status
func (m *activeDirectoryModule) getSystemStatus(ctx context.Context) (modules.ConfigState, error) {
	status := &ADSystemStatus{
		SystemContext: true,
		Hostname:      m.getHostname(),
	}

	// Get domain information using system context
	domainInfo, err := m.getDomainInfo(ctx)
	if err != nil {
		status.HealthStatus = "unhealthy"
		status.Error = err.Error()
	} else {
		status.Domain = domainInfo.Domain
		status.DomainController = domainInfo.DomainController
		status.ForestRoot = domainInfo.ForestRoot
		status.HealthStatus = "healthy"
	}

	m.stats.RLock()
	status.RequestCount = m.stats.requestCount
	status.ErrorCount = m.stats.errorCount
	status.LastHealthCheck = time.Now()
	status.DNACollectionCount = m.stats.dnaCollectionCount
	status.LastDNACollection = m.stats.lastDNACollection
	m.stats.RUnlock()

	return status, nil
}

// verifySystemAccess verifies that the module can read the local domain.
func (m *activeDirectoryModule) verifySystemAccess(ctx context.Context) error {
	info, err := m.getDomainInfo(ctx)
	if err != nil {
		return fmt.Errorf("system context verification failed: %w", err)
	}
	m.logger.Debug("System AD access verified successfully",
		"domain", logging.SanitizeLogValue(info.Domain))
	return nil
}

// getDomainInfo reads the domain summary through the read script's status
// operation.
func (m *activeDirectoryModule) getDomainInfo(ctx context.Context) (*DomainInfo, error) {
	var info *DomainInfo
	err := m.runRead(ctx, "status", func(rec *readRecord) error {
		if rec.Type != "status" {
			return fmt.Errorf("unexpected %q record from the status read", rec.Type)
		}
		info = &DomainInfo{
			Domain:           rec.Domain,
			DomainController: rec.DomainController,
			ForestRoot:       rec.ForestRoot,
			NetBIOSName:      rec.NetBIOSName,
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get domain info: %w", err)
	}
	if info == nil {
		return nil, fmt.Errorf("failed to get domain info: the status read returned no record")
	}
	return info, nil
}

// pageSize returns the configured AD paging size, or the default.
func (m *activeDirectoryModule) pageSize() int {
	m.configMux.RLock()
	defer m.configMux.RUnlock()
	if m.config != nil && m.config.PageSize > 0 && m.config.PageSize <= maxPageSize {
		return m.config.PageSize
	}
	return defaultPageSize
}

// runRead runs the read script for operation and calls handle for every data
// record. A script error record ends the read with an error carrying only the
// script's fixed error code.
func (m *activeDirectoryModule) runRead(ctx context.Context, operation string, handle func(rec *readRecord) error) error {
	if m.runner == nil {
		return fmt.Errorf("activedirectory: no script runner")
	}
	request, err := json.Marshal(readRequest{Operation: operation, PageSize: m.pageSize()})
	if err != nil {
		return fmt.Errorf("activedirectory: encode read request: %w", err)
	}
	m.updateStats(true)
	err = m.runner.Run(ctx, request, func(line []byte) error {
		var rec readRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			return fmt.Errorf("activedirectory: decode read script output: %w", err)
		}
		if rec.Type == "error" {
			return fmt.Errorf("activedirectory: read script reported %s (%s)", rec.Code, rec.Detail)
		}
		return handle(&rec)
	})
	if err != nil {
		m.updateStats(false)
	}
	return err
}

// getInventory reads every object of one kind and returns it as per-object
// state sorted by objectGUID.
func (m *activeDirectoryModule) getInventory(ctx context.Context, kind, operation, recordType string) (modules.ConfigState, error) {
	byID := make(map[string]map[string]interface{})
	var skipped, duplicates, truncated int
	err := m.runRead(ctx, operation, func(rec *readRecord) error {
		if rec.Type != recordType {
			return fmt.Errorf("activedirectory: unexpected %q record in the %s read", rec.Type, operation)
		}
		if !objectGUIDPattern.MatchString(rec.ID) {
			skipped++
			return nil
		}
		if _, seen := byID[rec.ID]; seen {
			duplicates++
			return nil
		}
		if len(byID) >= maxInventoryObjects {
			return fmt.Errorf("activedirectory: %s read exceeds the %d-object bound", operation, maxInventoryObjects)
		}
		attrs, cut := objectAttrs(kind, rec)
		if cut {
			truncated++
		}
		byID[rec.ID] = attrs
		return nil
	})
	if err != nil {
		return nil, err
	}

	if skipped > 0 || duplicates > 0 {
		m.logger.Warn("AD inventory read skipped unusable objects",
			"kind", kind, "invalid_id_count", skipped, "duplicate_count", duplicates)
	}
	if truncated > 0 {
		m.logger.Warn("AD inventory membership lists truncated",
			"kind", kind, "object_count", truncated, "max_entries", maxListEntries)
	}

	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	objects := make([]interface{}, 0, len(ids))
	for _, id := range ids {
		objects = append(objects, map[string]interface{}{"id": id, "attrs": byID[id]})
	}

	m.stats.Lock()
	m.stats.dnaCollectionCount++
	m.stats.lastDNACollection = time.Now()
	m.stats.Unlock()

	return &inventoryState{objects: objects}, nil
}

// objectAttrs builds an object's DNA attributes. It reports whether any
// membership list was truncated.
func objectAttrs(kind string, rec *readRecord) (map[string]interface{}, bool) {
	memberOf, memberOfCut := boundedSortedIDs(rec.MemberOf)
	memberOfCut = memberOfCut || rec.MemberOfTruncated

	var attrs map[string]interface{}
	cut := memberOfCut
	switch kind {
	case kindDirectoryUser:
		attrs = map[string]interface{}{
			"sam_account_name":    rec.SamAccountName,
			"user_principal_name": rec.UserPrincipalName,
			"display_name":        rec.DisplayName,
			"mail":                rec.Mail,
			"enabled":             rec.Enabled,
			"distinguished_name":  rec.DistinguishedName,
			"object_sid":          rec.ObjectSID,
			"when_created":        rec.WhenCreated,
			"directory_domain":    rec.DirectoryDomain,
			"managed":             false,
			"member_of":           memberOf,
		}
	default:
		others, othersCut := boundedOtherMembers(rec.OtherMembers)
		othersCut = othersCut || rec.OtherMembersTruncated
		cut = cut || othersCut
		attrs = map[string]interface{}{
			"sam_account_name":   rec.SamAccountName,
			"display_name":       rec.DisplayName,
			"distinguished_name": rec.DistinguishedName,
			"group_scope":        rec.GroupScope,
			"group_category":     rec.GroupCategory,
			"directory_domain":   rec.DirectoryDomain,
			"managed":            false,
			"member_of":          memberOf,
			"other_members":      others,
		}
		if othersCut {
			attrs["other_members_truncated"] = true
		}
	}
	if memberOfCut {
		attrs["member_of_truncated"] = true
	}
	return attrs, cut
}

// boundedSortedIDs returns the valid objectGUIDs in ids, deduplicated and
// sorted, cut to maxListEntries. It reports whether it cut the list.
func boundedSortedIDs(ids []string) ([]string, bool) {
	seen := make(map[string]bool, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		id = strings.ToLower(id)
		if !objectGUIDPattern.MatchString(id) || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	sort.Strings(out)
	if len(out) > maxListEntries {
		return out[:maxListEntries], true
	}
	return out, false
}

// boundedOtherMembers returns members sorted by (type, id), deduplicated and
// cut to maxListEntries, as a list of {type, id, name} maps. Unknown types are
// reported as "other". It reports whether it cut the list.
func boundedOtherMembers(members []otherMember) ([]interface{}, bool) {
	seen := make(map[string]bool, len(members))
	list := make([]otherMember, 0, len(members))
	for _, om := range members {
		om.ID = strings.ToLower(om.ID)
		if !objectGUIDPattern.MatchString(om.ID) {
			continue
		}
		if !otherMemberTypes[om.Type] {
			om.Type = "other"
		}
		key := om.Type + "\x00" + om.ID
		if seen[key] {
			continue
		}
		seen[key] = true
		list = append(list, om)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Type != list[j].Type {
			return list[i].Type < list[j].Type
		}
		return list[i].ID < list[j].ID
	})
	cut := false
	if len(list) > maxListEntries {
		list = list[:maxListEntries]
		cut = true
	}
	out := make([]interface{}, 0, len(list))
	for _, om := range list {
		out = append(out, map[string]interface{}{"type": om.Type, "id": om.ID, "name": om.Name})
	}
	return out, cut
}

// getHostname returns the current hostname
func (m *activeDirectoryModule) getHostname() string {
	name, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return name
}

// Helper methods for updating statistics
func (m *activeDirectoryModule) updateStats(isRequest bool) {
	m.stats.Lock()
	defer m.stats.Unlock()

	if isRequest {
		m.stats.requestCount++
		m.stats.lastRequest = time.Now()
	} else {
		m.stats.errorCount++
	}
}

// GetCapabilities returns the capabilities of this system-context module
func (m *activeDirectoryModule) GetCapabilities() map[string]interface{} {
	return map[string]interface{}{
		"supports_read":      true,
		"supports_write":     false,
		"supports_monitor":   false, // Not yet implemented
		"supports_bulk":      true,
		"object_types":       []string{"user", "group"},
		"inventory_kinds":    []string{kindDirectoryUser, kindDirectoryGroup},
		"auth_methods":       []string{"system_context"},
		"platforms":          []string{"windows"},
		"requires_domain":    false, // Auto-discovers local domain
		"supports_discovery": true,
		"system_context":     true,
		"credential_free":    true,
		"advanced_features":  []string{"system_context_access", "per_object_inventory", "domain_info"},
	}
}
