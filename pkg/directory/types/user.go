// Package types provides unified directory object types and conversion utilities
// to eliminate duplication across CFGMS directory providers and M365 modules.
//
// This package implements the principle of "single source of truth" for directory
// objects while providing seamless conversion between different API formats
// (Microsoft Graph, LDAP, ConfigState YAML).
package types

import (
	"encoding/json"
	"time"
)

// DirectoryUser represents a unified user object across all directory providers.
// This is the canonical representation used internally by CFGMS for all user operations.
//
// Design principle: Contains all possible fields from all providers, with provider-specific
// attributes handled via ProviderAttributes map for extensibility.
type DirectoryUser struct {
	// Core Identity
	ID                string `json:"id" yaml:"id"`                                         // Unique identifier in source directory
	UserPrincipalName string `json:"user_principal_name" yaml:"user_principal_name"`      // UPN (user@domain.com)
	SAMAccountName    string `json:"sam_account_name,omitempty" yaml:"sam_account_name"`  // For AD compatibility
	DisplayName       string `json:"display_name" yaml:"display_name"`                   // Full display name
	MailNickname      string `json:"mail_nickname,omitempty" yaml:"mail_nickname"`       // Mail alias (Graph API)

	// Authentication
	AccountEnabled bool      `json:"account_enabled" yaml:"account_enabled"`             // Is account enabled
	PasswordExpiry *time.Time `json:"password_expiry,omitempty" yaml:"password_expiry"` // When password expires
	LastLogon      *time.Time `json:"last_logon,omitempty" yaml:"last_logon"`           // Last successful logon

	// Contact Information
	EmailAddress string `json:"email_address,omitempty" yaml:"email_address"`          // Primary email
	Mail         string `json:"mail,omitempty" yaml:"mail"`                            // Graph API mail field
	PhoneNumber  string `json:"phone_number,omitempty" yaml:"phone_number"`            // Primary phone
	MobilePhone  string `json:"mobile_phone,omitempty" yaml:"mobile_phone"`            // Mobile phone

	// Organizational Information
	Department      string `json:"department,omitempty" yaml:"department"`               // Department name
	JobTitle        string `json:"job_title,omitempty" yaml:"job_title"`                 // Job title
	Manager         string `json:"manager,omitempty" yaml:"manager"`                     // Manager's ID
	OfficeLocation  string `json:"office_location,omitempty" yaml:"office_location"`     // Office location
	Company         string `json:"company,omitempty" yaml:"company"`                     // Company name
	CompanyName     string `json:"company_name,omitempty" yaml:"company_name"`           // Graph API company field

	// Directory Structure
	DistinguishedName string   `json:"distinguished_name,omitempty" yaml:"distinguished_name"` // Full DN (for AD)
	OU               string   `json:"ou,omitempty" yaml:"ou"`                                 // Parent OU
	Groups           []string `json:"groups,omitempty" yaml:"groups"`                         // Group memberships

	// Provider-Specific Attributes (extensibility)
	ProviderAttributes map[string]interface{} `json:"provider_attributes,omitempty" yaml:"provider_attributes"`

	// Metadata
	Created  *time.Time `json:"created,omitempty" yaml:"created"`     // When created
	Modified *time.Time `json:"modified,omitempty" yaml:"modified"`   // When last modified
	Source   string     `json:"source" yaml:"source"`                 // Source provider name
}

// Conversion Methods for Microsoft Graph API

// ToGraphUser converts DirectoryUser to Microsoft Graph User format
func (u *DirectoryUser) ToGraphUser() *GraphUser {
	return &GraphUser{
		ID:                u.ID,
		UserPrincipalName: u.UserPrincipalName,
		DisplayName:       u.DisplayName,
		MailNickname:      u.MailNickname,
		AccountEnabled:    u.AccountEnabled,
		Mail:              u.getMailField(), // Use unified mail logic
		MobilePhone:       u.MobilePhone,
		OfficeLocation:    u.OfficeLocation,
		JobTitle:          u.JobTitle,
		Department:        u.Department,
		CompanyName:       u.getCompanyField(), // Use unified company logic
		CreatedDateTime:   u.formatDateTime(u.Created),
	}
}

// FromGraphUser converts Microsoft Graph User to DirectoryUser
func FromGraphUser(graphUser *GraphUser, providerName string) *DirectoryUser {
	var created *time.Time
	if graphUser.CreatedDateTime != "" {
		if t, err := time.Parse(time.RFC3339, graphUser.CreatedDateTime); err == nil {
			created = &t
		}
	}

	return &DirectoryUser{
		ID:                graphUser.ID,
		UserPrincipalName: graphUser.UserPrincipalName,
		DisplayName:       graphUser.DisplayName,
		MailNickname:      graphUser.MailNickname,
		AccountEnabled:    graphUser.AccountEnabled,
		EmailAddress:      graphUser.Mail, // Normalize to EmailAddress
		Mail:              graphUser.Mail, // Keep original for compatibility
		MobilePhone:       graphUser.MobilePhone,
		OfficeLocation:    graphUser.OfficeLocation,
		JobTitle:          graphUser.JobTitle,
		Department:        graphUser.Department,
		Company:           graphUser.CompanyName, // Normalize to Company
		CompanyName:       graphUser.CompanyName, // Keep original for compatibility
		Created:           created,
		Modified:          &time.Time{}, // Set to current time
		Source:            providerName,
	}
}

// Conversion Methods for M365 Module Configurations

// ToEntraUserConfig converts DirectoryUser to Entra User module configuration format
func (u *DirectoryUser) ToEntraUserConfig() *EntraUserConfig {
	return &EntraUserConfig{
		UserPrincipalName: u.UserPrincipalName,
		DisplayName:       u.DisplayName,
		MailNickname:      u.MailNickname,
		AccountEnabled:    u.AccountEnabled,
		Mail:              u.getMailField(),
		MobilePhone:       u.MobilePhone,
		OfficeLocation:    u.OfficeLocation,
		JobTitle:          u.JobTitle,
		Department:        u.Department,
		CompanyName:       u.getCompanyField(),
		Groups:            u.Groups,
	}
}

// FromEntraUserConfig converts Entra User module configuration to DirectoryUser
func FromEntraUserConfig(config *EntraUserConfig, userID, providerName string) *DirectoryUser {
	now := time.Now()
	return &DirectoryUser{
		ID:                userID,
		UserPrincipalName: config.UserPrincipalName,
		DisplayName:       config.DisplayName,
		MailNickname:      config.MailNickname,
		AccountEnabled:    config.AccountEnabled,
		EmailAddress:      config.Mail,
		Mail:              config.Mail,
		MobilePhone:       config.MobilePhone,
		OfficeLocation:    config.OfficeLocation,
		JobTitle:          config.JobTitle,
		Department:        config.Department,
		Company:           config.CompanyName,
		CompanyName:       config.CompanyName,
		Groups:            config.Groups,
		Modified:          &now,
		Source:            providerName,
	}
}

// Validation Methods

// Validate performs comprehensive validation of the DirectoryUser
func (u *DirectoryUser) Validate() error {
	if u.UserPrincipalName == "" {
		return ErrInvalidUserPrincipalName
	}
	
	if u.DisplayName == "" {
		return ErrInvalidDisplayName
	}
	
	// Validate UPN format (basic)
	if !isValidUPN(u.UserPrincipalName) {
		return ErrInvalidUserPrincipalNameFormat
	}
	
	return nil
}

// Utility Methods

// GetPrimaryEmail returns the primary email address, preferring EmailAddress over Mail
func (u *DirectoryUser) GetPrimaryEmail() string {
	if u.EmailAddress != "" {
		return u.EmailAddress
	}
	return u.Mail
}

// GetPrimaryCompany returns the primary company name, preferring Company over CompanyName
func (u *DirectoryUser) GetPrimaryCompany() string {
	if u.Company != "" {
		return u.Company
	}
	return u.CompanyName
}

// HasGroup checks if the user is a member of a specific group
func (u *DirectoryUser) HasGroup(groupName string) bool {
	for _, group := range u.Groups {
		if group == groupName {
			return true
		}
	}
	return false
}

// Clone creates a deep copy of the DirectoryUser
func (u *DirectoryUser) Clone() *DirectoryUser {
	// Use JSON marshal/unmarshal for deep copy
	data, _ := json.Marshal(u)
	var clone DirectoryUser
	_ = json.Unmarshal(data, &clone)
	return &clone
}

// Private helper methods

func (u *DirectoryUser) getMailField() string {
	if u.Mail != "" {
		return u.Mail
	}
	return u.EmailAddress
}

func (u *DirectoryUser) getCompanyField() string {
	if u.CompanyName != "" {
		return u.CompanyName
	}
	return u.Company
}

func (u *DirectoryUser) formatDateTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.Format(time.RFC3339)
}

// Helper types for conversion

// GraphUser represents Microsoft Graph User format (matches graph/client.go)
type GraphUser struct {
	ID                string `json:"id"`
	UserPrincipalName string `json:"userPrincipalName"`
	DisplayName       string `json:"displayName"`
	MailNickname      string `json:"mailNickname"`
	AccountEnabled    bool   `json:"accountEnabled"`
	Mail              string `json:"mail"`
	MobilePhone       string `json:"mobilePhone"`
	OfficeLocation    string `json:"officeLocation"`
	JobTitle          string `json:"jobTitle"`
	Department        string `json:"department"`
	CompanyName       string `json:"companyName"`
	CreatedDateTime   string `json:"createdDateTime"`
}

// EntraUserConfig represents M365 Entra User module configuration format
type EntraUserConfig struct {
	UserPrincipalName string   `yaml:"user_principal_name"`
	DisplayName       string   `yaml:"display_name"`
	MailNickname      string   `yaml:"mail_nickname,omitempty"`
	AccountEnabled    bool     `yaml:"account_enabled"`
	Mail              string   `yaml:"mail,omitempty"`
	MobilePhone       string   `yaml:"mobile_phone,omitempty"`
	OfficeLocation    string   `yaml:"office_location,omitempty"`
	JobTitle          string   `yaml:"job_title,omitempty"`
	Department        string   `yaml:"department,omitempty"`
	CompanyName       string   `yaml:"company_name,omitempty"`
	Groups            []string `yaml:"groups,omitempty"`
}