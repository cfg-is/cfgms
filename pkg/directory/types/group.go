// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package types

import (
	"encoding/json"
	"time"
)

// DirectoryGroup represents a unified group object across all directory providers.
// This is the canonical representation used internally by CFGMS for all group operations.
type DirectoryGroup struct {
	// Core Identity
	ID          string `json:"id" yaml:"id"`                             // Unique identifier
	Name        string `json:"name" yaml:"name"`                         // Group name
	DisplayName string `json:"display_name" yaml:"display_name"`         // Display name
	Description string `json:"description,omitempty" yaml:"description"` // Group description

	// Group Properties
	GroupType  GroupType  `json:"group_type" yaml:"group_type"`             // Security vs Distribution
	GroupScope GroupScope `json:"group_scope,omitempty" yaml:"group_scope"` // Domain, Global, Universal

	// Microsoft 365 specific properties
	MailEnabled     bool   `json:"mail_enabled,omitempty" yaml:"mail_enabled"`         // Is mail-enabled (M365)
	SecurityEnabled bool   `json:"security_enabled,omitempty" yaml:"security_enabled"` // Is security-enabled (M365)
	MailNickname    string `json:"mail_nickname,omitempty" yaml:"mail_nickname"`       // Mail alias (M365)
	Mail            string `json:"mail,omitempty" yaml:"mail"`                         // Group email address

	// Directory Structure
	DistinguishedName string   `json:"distinguished_name,omitempty" yaml:"distinguished_name"` // Full DN (for AD)
	OU                string   `json:"ou,omitempty" yaml:"ou"`                                 // Parent OU
	Members           []string `json:"members,omitempty" yaml:"members"`                       // Member user IDs

	// Provider-Specific Attributes (extensibility)
	ProviderAttributes map[string]interface{} `json:"provider_attributes,omitempty" yaml:"provider_attributes"`

	// Metadata
	Created  *time.Time `json:"created,omitempty" yaml:"created"`   // When created
	Modified *time.Time `json:"modified,omitempty" yaml:"modified"` // When last modified
	Source   string     `json:"source" yaml:"source"`               // Source provider name
}

// GroupType represents the type of group
type GroupType string

const (
	GroupTypeSecurity     GroupType = "security"
	GroupTypeDistribution GroupType = "distribution"
	GroupTypeMicrosoft365 GroupType = "microsoft365" // Unified groups in M365
)

// GroupScope represents the scope of a group (AD concept)
type GroupScope string

const (
	GroupScopeDomainLocal GroupScope = "domain_local"
	GroupScopeGlobal      GroupScope = "global"
	GroupScopeUniversal   GroupScope = "universal"
)

// Conversion Methods for Microsoft Graph API

// ToGraphGroup converts DirectoryGroup to Microsoft Graph Group format
func (g *DirectoryGroup) ToGraphGroup() *GraphGroup {
	return &GraphGroup{
		ID:              g.ID,
		DisplayName:     g.DisplayName,
		Description:     g.Description,
		MailEnabled:     g.MailEnabled,
		SecurityEnabled: g.SecurityEnabled,
		MailNickname:    g.MailNickname,
		Mail:            g.Mail,
		CreatedDateTime: g.formatDateTime(g.Created),
	}
}

// FromGraphGroup converts Microsoft Graph Group to DirectoryGroup
func FromGraphGroup(graphGroup *GraphGroup, providerName string) *DirectoryGroup {
	var created *time.Time
	if graphGroup.CreatedDateTime != "" {
		if t, err := time.Parse(time.RFC3339, graphGroup.CreatedDateTime); err == nil {
			created = &t
		}
	}

	// Determine group type from Graph properties
	groupType := GroupTypeSecurity
	if graphGroup.MailEnabled && graphGroup.SecurityEnabled {
		groupType = GroupTypeMicrosoft365
	} else if graphGroup.MailEnabled {
		groupType = GroupTypeDistribution
	}

	return &DirectoryGroup{
		ID:              graphGroup.ID,
		Name:            graphGroup.DisplayName, // Use DisplayName as Name
		DisplayName:     graphGroup.DisplayName,
		Description:     graphGroup.Description,
		GroupType:       groupType,
		MailEnabled:     graphGroup.MailEnabled,
		SecurityEnabled: graphGroup.SecurityEnabled,
		MailNickname:    graphGroup.MailNickname,
		Mail:            graphGroup.Mail,
		Created:         created,
		Modified:        func() *time.Time { now := time.Now(); return &now }(), // Set to current time
		Source:          providerName,
	}
}

// Conversion Methods for M365 Module Configurations

// ToEntraGroupConfig converts DirectoryGroup to Entra Group module configuration format
func (g *DirectoryGroup) ToEntraGroupConfig() *EntraGroupConfig {
	return &EntraGroupConfig{
		DisplayName:     g.DisplayName,
		Description:     g.Description,
		MailEnabled:     g.MailEnabled,
		SecurityEnabled: g.SecurityEnabled,
		MailNickname:    g.MailNickname,
		Members:         g.Members,
		GroupType:       string(g.GroupType),
	}
}

// FromEntraGroupConfig converts Entra Group module configuration to DirectoryGroup
func FromEntraGroupConfig(config *EntraGroupConfig, groupID, providerName string) *DirectoryGroup {
	now := time.Now()
	return &DirectoryGroup{
		ID:              groupID,
		Name:            config.DisplayName,
		DisplayName:     config.DisplayName,
		Description:     config.Description,
		GroupType:       GroupType(config.GroupType),
		MailEnabled:     config.MailEnabled,
		SecurityEnabled: config.SecurityEnabled,
		MailNickname:    config.MailNickname,
		Members:         config.Members,
		Modified:        &now,
		Source:          providerName,
	}
}

// Validation Methods

// Validate performs comprehensive validation of the DirectoryGroup
func (g *DirectoryGroup) Validate() error {
	if g.DisplayName == "" {
		return ErrInvalidGroupDisplayName
	}

	// Validate group type
	switch g.GroupType {
	case GroupTypeSecurity, GroupTypeDistribution, GroupTypeMicrosoft365:
		// Valid types
	default:
		return ErrInvalidGroupType
	}

	// Validate mail-enabled requirements
	if g.MailEnabled && g.MailNickname == "" {
		return ErrInvalidMailNickname
	}

	return nil
}

// Utility Methods

// HasMember checks if the group contains a specific member
func (g *DirectoryGroup) HasMember(memberID string) bool {
	for _, member := range g.Members {
		if member == memberID {
			return true
		}
	}
	return false
}

// AddMember adds a member to the group if not already present
func (g *DirectoryGroup) AddMember(memberID string) {
	if !g.HasMember(memberID) {
		g.Members = append(g.Members, memberID)
		now := time.Now()
		g.Modified = &now
	}
}

// RemoveMember removes a member from the group
func (g *DirectoryGroup) RemoveMember(memberID string) {
	for i, member := range g.Members {
		if member == memberID {
			g.Members = append(g.Members[:i], g.Members[i+1:]...)
			now := time.Now()
			g.Modified = &now
			break
		}
	}
}

// GetMemberCount returns the number of members in the group
func (g *DirectoryGroup) GetMemberCount() int {
	return len(g.Members)
}

// IsSecurityGroup checks if this is a security group
func (g *DirectoryGroup) IsSecurityGroup() bool {
	return g.GroupType == GroupTypeSecurity || g.SecurityEnabled
}

// IsDistributionGroup checks if this is a distribution group
func (g *DirectoryGroup) IsDistributionGroup() bool {
	return g.GroupType == GroupTypeDistribution || (g.MailEnabled && !g.SecurityEnabled)
}

// IsMicrosoft365Group checks if this is a Microsoft 365 group (unified group)
func (g *DirectoryGroup) IsMicrosoft365Group() bool {
	return g.GroupType == GroupTypeMicrosoft365 || (g.MailEnabled && g.SecurityEnabled)
}

// Clone creates a deep copy of the DirectoryGroup
func (g *DirectoryGroup) Clone() *DirectoryGroup {
	// Use JSON marshal/unmarshal for deep copy
	data, _ := json.Marshal(g)
	var clone DirectoryGroup
	_ = json.Unmarshal(data, &clone)
	return &clone
}

// Private helper methods

func (g *DirectoryGroup) formatDateTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.Format(time.RFC3339)
}

// Helper types for conversion

// GraphGroup represents Microsoft Graph Group format
type GraphGroup struct {
	ID              string `json:"id"`
	DisplayName     string `json:"displayName"`
	Description     string `json:"description"`
	MailEnabled     bool   `json:"mailEnabled"`
	SecurityEnabled bool   `json:"securityEnabled"`
	MailNickname    string `json:"mailNickname"`
	Mail            string `json:"mail"`
	CreatedDateTime string `json:"createdDateTime"`
}

// EntraGroupConfig represents M365 Entra Group module configuration format
type EntraGroupConfig struct {
	DisplayName     string   `yaml:"display_name"`
	Description     string   `yaml:"description,omitempty"`
	MailEnabled     bool     `yaml:"mail_enabled"`
	SecurityEnabled bool     `yaml:"security_enabled"`
	MailNickname    string   `yaml:"mail_nickname,omitempty"`
	Members         []string `yaml:"members,omitempty"`
	GroupType       string   `yaml:"group_type,omitempty"`
}
