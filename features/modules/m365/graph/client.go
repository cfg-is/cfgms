package graph

import (
	"context"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/features/modules/m365/auth"
)

// Client defines the interface for Microsoft Graph API operations
type Client interface {
	// User operations
	GetUser(ctx context.Context, token *auth.AccessToken, userPrincipalName string) (*User, error)
	CreateUser(ctx context.Context, token *auth.AccessToken, request *CreateUserRequest) (*User, error)
	UpdateUser(ctx context.Context, token *auth.AccessToken, userID string, request *UpdateUserRequest) error
	DeleteUser(ctx context.Context, token *auth.AccessToken, userID string) error
	
	// License operations
	GetUserLicenses(ctx context.Context, token *auth.AccessToken, userID string) ([]LicenseAssignment, error)
	AssignLicense(ctx context.Context, token *auth.AccessToken, userID, skuID string, disabledPlans []string) error
	RemoveLicense(ctx context.Context, token *auth.AccessToken, userID, skuID string) error
	
	// Group operations
	GetUserGroups(ctx context.Context, token *auth.AccessToken, userID string) ([]string, error)
	AddUserToGroup(ctx context.Context, token *auth.AccessToken, userID, groupName string) error
	RemoveUserFromGroup(ctx context.Context, token *auth.AccessToken, userID, groupName string) error
	
	// Conditional Access operations
	GetConditionalAccessPolicy(ctx context.Context, token *auth.AccessToken, policyID string) (*ConditionalAccessPolicy, error)
	CreateConditionalAccessPolicy(ctx context.Context, token *auth.AccessToken, request *CreateConditionalAccessPolicyRequest) (*ConditionalAccessPolicy, error)
	UpdateConditionalAccessPolicy(ctx context.Context, token *auth.AccessToken, policyID string, request *UpdateConditionalAccessPolicyRequest) error
	DeleteConditionalAccessPolicy(ctx context.Context, token *auth.AccessToken, policyID string) error
	
	// Intune operations
	GetDeviceConfiguration(ctx context.Context, token *auth.AccessToken, configurationID string) (*DeviceConfiguration, error)
	CreateDeviceConfiguration(ctx context.Context, token *auth.AccessToken, request *CreateDeviceConfigurationRequest) (*DeviceConfiguration, error)
	UpdateDeviceConfiguration(ctx context.Context, token *auth.AccessToken, configurationID string, request *UpdateDeviceConfigurationRequest) error
	DeleteDeviceConfiguration(ctx context.Context, token *auth.AccessToken, configurationID string) error
}

// User represents a Microsoft Graph user object
type User struct {
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

// CreateUserRequest represents a request to create a new user
type CreateUserRequest struct {
	UserPrincipalName string           `json:"userPrincipalName"`
	DisplayName       string           `json:"displayName"`
	MailNickname      string           `json:"mailNickname"`
	AccountEnabled    bool             `json:"accountEnabled"`
	PasswordProfile   *PasswordProfile `json:"passwordProfile,omitempty"`
	Mail              string           `json:"mail,omitempty"`
	MobilePhone       string           `json:"mobilePhone,omitempty"`
	OfficeLocation    string           `json:"officeLocation,omitempty"`
	JobTitle          string           `json:"jobTitle,omitempty"`
	Department        string           `json:"department,omitempty"`
	CompanyName       string           `json:"companyName,omitempty"`
}

// UpdateUserRequest represents a request to update an existing user
type UpdateUserRequest struct {
	DisplayName    *string `json:"displayName,omitempty"`
	AccountEnabled *bool   `json:"accountEnabled,omitempty"`
	Mail           *string `json:"mail,omitempty"`
	MobilePhone    *string `json:"mobilePhone,omitempty"`
	OfficeLocation *string `json:"officeLocation,omitempty"`
	JobTitle       *string `json:"jobTitle,omitempty"`
	Department     *string `json:"department,omitempty"`
	CompanyName    *string `json:"companyName,omitempty"`
}

// HasChanges returns true if the update request contains any changes
func (r *UpdateUserRequest) HasChanges() bool {
	return r.DisplayName != nil ||
		r.AccountEnabled != nil ||
		r.Mail != nil ||
		r.MobilePhone != nil ||
		r.OfficeLocation != nil ||
		r.JobTitle != nil ||
		r.Department != nil ||
		r.CompanyName != nil
}

// PasswordProfile represents password configuration for a user
type PasswordProfile struct {
	Password                      string `json:"password,omitempty"`
	ForceChangePasswordNextSignIn bool   `json:"forceChangePasswordNextSignIn"`
}

// LicenseAssignment represents a license assignment for a user
type LicenseAssignment struct {
	SkuID         string   `json:"skuId"`
	DisabledPlans []string `json:"disabledPlans,omitempty"`
}

// ConditionalAccessPolicy represents a Conditional Access policy
type ConditionalAccessPolicy struct {
	ID                   string                        `json:"id"`
	DisplayName          string                        `json:"displayName"`
	State                string                        `json:"state"`
	Conditions           ConditionalAccessConditions  `json:"conditions"`
	GrantControls        ConditionalAccessGrantControls `json:"grantControls"`
	SessionControls      ConditionalAccessSessionControls `json:"sessionControls,omitempty"`
	CreatedDateTime      string                        `json:"createdDateTime"`
	ModifiedDateTime     string                        `json:"modifiedDateTime"`
}

// ConditionalAccessConditions represents the conditions for a CA policy
type ConditionalAccessConditions struct {
	Users         ConditionalAccessUsers         `json:"users"`
	Applications  ConditionalAccessApplications  `json:"applications"`
	Locations     ConditionalAccessLocations     `json:"locations,omitempty"`
	Platforms     ConditionalAccessPlatforms     `json:"platforms,omitempty"`
	DeviceStates  ConditionalAccessDeviceStates  `json:"deviceStates,omitempty"`
	ClientAppTypes []string                       `json:"clientAppTypes,omitempty"`
	SignInRiskLevels []string                     `json:"signInRiskLevels,omitempty"`
	UserRiskLevels   []string                     `json:"userRiskLevels,omitempty"`
}

// ConditionalAccessUsers represents user conditions
type ConditionalAccessUsers struct {
	IncludeUsers  []string `json:"includeUsers,omitempty"`
	ExcludeUsers  []string `json:"excludeUsers,omitempty"`
	IncludeGroups []string `json:"includeGroups,omitempty"`
	ExcludeGroups []string `json:"excludeGroups,omitempty"`
	IncludeRoles  []string `json:"includeRoles,omitempty"`
	ExcludeRoles  []string `json:"excludeRoles,omitempty"`
}

// ConditionalAccessApplications represents application conditions
type ConditionalAccessApplications struct {
	IncludeApplications []string `json:"includeApplications,omitempty"`
	ExcludeApplications []string `json:"excludeApplications,omitempty"`
	IncludeUserActions  []string `json:"includeUserActions,omitempty"`
}

// ConditionalAccessLocations represents location conditions
type ConditionalAccessLocations struct {
	IncludeLocations []string `json:"includeLocations,omitempty"`
	ExcludeLocations []string `json:"excludeLocations,omitempty"`
}

// ConditionalAccessPlatforms represents platform conditions
type ConditionalAccessPlatforms struct {
	IncludePlatforms []string `json:"includePlatforms,omitempty"`
	ExcludePlatforms []string `json:"excludePlatforms,omitempty"`
}

// ConditionalAccessDeviceStates represents device state conditions
type ConditionalAccessDeviceStates struct {
	IncludeStates []string `json:"includeStates,omitempty"`
	ExcludeStates []string `json:"excludeStates,omitempty"`
}

// ConditionalAccessGrantControls represents grant controls
type ConditionalAccessGrantControls struct {
	Operator              string   `json:"operator"`
	BuiltInControls       []string `json:"builtInControls,omitempty"`
	CustomAuthenticationFactors []string `json:"customAuthenticationFactors,omitempty"`
	TermsOfUse            []string `json:"termsOfUse,omitempty"`
}

// ConditionalAccessSessionControls represents session controls
type ConditionalAccessSessionControls struct {
	ApplicationEnforcedRestrictions ApplicationEnforcedRestrictions `json:"applicationEnforcedRestrictions,omitempty"`
	CloudAppSecurity                CloudAppSecurity                `json:"cloudAppSecurity,omitempty"`
	PersistentBrowser               PersistentBrowser               `json:"persistentBrowser,omitempty"`
	SignInFrequency                 SignInFrequency                 `json:"signInFrequency,omitempty"`
}

// ApplicationEnforcedRestrictions represents application enforced restrictions
type ApplicationEnforcedRestrictions struct {
	IsEnabled bool `json:"isEnabled"`
}

// CloudAppSecurity represents cloud app security settings
type CloudAppSecurity struct {
	IsEnabled            bool   `json:"isEnabled"`
	CloudAppSecurityType string `json:"cloudAppSecurityType,omitempty"`
}

// PersistentBrowser represents persistent browser settings
type PersistentBrowser struct {
	IsEnabled bool   `json:"isEnabled"`
	Mode      string `json:"mode,omitempty"`
}

// SignInFrequency represents sign-in frequency settings
type SignInFrequency struct {
	IsEnabled         bool   `json:"isEnabled"`
	Type              string `json:"type,omitempty"`
	Value             int    `json:"value,omitempty"`
	FrequencyInterval string `json:"frequencyInterval,omitempty"`
}

// CreateConditionalAccessPolicyRequest represents a request to create a CA policy
type CreateConditionalAccessPolicyRequest struct {
	DisplayName     string                           `json:"displayName"`
	State           string                           `json:"state"`
	Conditions      ConditionalAccessConditions     `json:"conditions"`
	GrantControls   ConditionalAccessGrantControls  `json:"grantControls"`
	SessionControls ConditionalAccessSessionControls `json:"sessionControls,omitempty"`
}

// UpdateConditionalAccessPolicyRequest represents a request to update a CA policy
type UpdateConditionalAccessPolicyRequest struct {
	DisplayName     *string                           `json:"displayName,omitempty"`
	State           *string                           `json:"state,omitempty"`
	Conditions      *ConditionalAccessConditions     `json:"conditions,omitempty"`
	GrantControls   *ConditionalAccessGrantControls  `json:"grantControls,omitempty"`
	SessionControls *ConditionalAccessSessionControls `json:"sessionControls,omitempty"`
}

// DeviceConfiguration represents an Intune device configuration
type DeviceConfiguration struct {
	ID                   string            `json:"id"`
	DisplayName          string            `json:"displayName"`
	Description          string            `json:"description"`
	DeviceConfigurationType string         `json:"@odata.type"`
	CreatedDateTime      string            `json:"createdDateTime"`
	LastModifiedDateTime string            `json:"lastModifiedDateTime"`
	Version              int               `json:"version"`
	Settings             map[string]interface{} `json:"settings,omitempty"`
}

// CreateDeviceConfigurationRequest represents a request to create a device configuration
type CreateDeviceConfigurationRequest struct {
	DeviceConfigurationType string            `json:"@odata.type"`
	DisplayName            string            `json:"displayName"`
	Description            string            `json:"description"`
	Settings               map[string]interface{} `json:"settings,omitempty"`
}

// UpdateDeviceConfigurationRequest represents a request to update a device configuration
type UpdateDeviceConfigurationRequest struct {
	DisplayName *string            `json:"displayName,omitempty"`
	Description *string            `json:"description,omitempty"`
	Settings    map[string]interface{} `json:"settings,omitempty"`
}

// GraphError represents an error response from Microsoft Graph API
type GraphError struct {
	Code       string            `json:"code"`
	Message    string            `json:"message"`
	Details    []GraphErrorDetail `json:"details,omitempty"`
	InnerError map[string]interface{} `json:"innerError,omitempty"`
	StatusCode int               `json:"-"`
}

// GraphErrorDetail represents additional error details
type GraphErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Target  string `json:"target,omitempty"`
}

func (e *GraphError) Error() string {
	return fmt.Sprintf("Microsoft Graph API error [%s]: %s (HTTP %d)", e.Code, e.Message, e.StatusCode)
}

// IsNotFoundError checks if the error is a "not found" error
func IsNotFoundError(err error) bool {
	if graphErr, ok := err.(*GraphError); ok {
		return graphErr.Code == "Request_ResourceNotFound" || graphErr.StatusCode == 404
	}
	return false
}

// IsConflictError checks if the error is a conflict error (resource already exists)
func IsConflictError(err error) bool {
	if graphErr, ok := err.(*GraphError); ok {
		return graphErr.Code == "Request_ResourceAlreadyExists" || graphErr.StatusCode == 409
	}
	return false
}

// IsThrottledError checks if the error is a throttling error
func IsThrottledError(err error) bool {
	if graphErr, ok := err.(*GraphError); ok {
		return graphErr.Code == "TooManyRequests" || graphErr.StatusCode == 429
	}
	return false
}

// RateLimiter defines the interface for rate limiting Graph API calls
type RateLimiter interface {
	// Wait blocks until the rate limiter allows another request
	Wait(ctx context.Context) error
	
	// Allow checks if a request is allowed without blocking
	Allow() bool
}

// RetryConfig defines retry configuration for Graph API calls
type RetryConfig struct {
	MaxRetries      int           `yaml:"max_retries"`
	InitialDelay    time.Duration `yaml:"initial_delay"`
	MaxDelay        time.Duration `yaml:"max_delay"`
	BackoffMultiplier float64     `yaml:"backoff_multiplier"`
}

// DefaultRetryConfig returns a default retry configuration
func DefaultRetryConfig() *RetryConfig {
	return &RetryConfig{
		MaxRetries:        3,
		InitialDelay:      1 * time.Second,
		MaxDelay:          30 * time.Second,
		BackoffMultiplier: 2.0,
	}
}