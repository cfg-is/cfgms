package entra_user

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/features/modules/m365/auth"
	"github.com/cfgis/cfgms/features/modules/m365/graph"
	"gopkg.in/yaml.v3"
)

// entraUserModule implements the Module interface for Entra ID user management
type entraUserModule struct {
	authProvider auth.Provider
	graphClient  graph.Client
}

// New creates a new instance of the Entra User module
func New(authProvider auth.Provider, graphClient graph.Client) modules.Module {
	return &entraUserModule{
		authProvider: authProvider,
		graphClient:  graphClient,
	}
}

// EntraUserConfig represents the configuration for an Entra ID user
type EntraUserConfig struct {
	// Core user properties
	UserPrincipalName string `yaml:"user_principal_name"`
	DisplayName       string `yaml:"display_name"`
	MailNickname      string `yaml:"mail_nickname"`

	// Account settings
	AccountEnabled      bool             `yaml:"account_enabled"`
	PasswordProfile     *PasswordProfile `yaml:"password_profile,omitempty"`
	ForceChangePassword bool             `yaml:"force_change_password,omitempty"`

	// Contact information
	Mail           string `yaml:"mail,omitempty"`
	MobilePhone    string `yaml:"mobile_phone,omitempty"`
	OfficeLocation string `yaml:"office_location,omitempty"`
	JobTitle       string `yaml:"job_title,omitempty"`
	Department     string `yaml:"department,omitempty"`
	CompanyName    string `yaml:"company_name,omitempty"`

	// License assignment
	Licenses []LicenseAssignment `yaml:"licenses,omitempty"`

	// Group memberships
	Groups []string `yaml:"groups,omitempty"`

	// Tenant configuration
	TenantID string `yaml:"tenant_id"`

	// Managed fields - controls which fields Set() will modify
	ManagedFieldsList []string `yaml:"managed_fields,omitempty"`
}

// PasswordProfile represents password configuration for a user
type PasswordProfile struct {
	Password                      string `yaml:"password,omitempty"`
	ForceChangePasswordNextSignIn bool   `yaml:"force_change_password_next_signin"`
}

// LicenseAssignment represents a license assignment for a user
type LicenseAssignment struct {
	SkuID         string   `yaml:"sku_id"`
	DisabledPlans []string `yaml:"disabled_plans,omitempty"`
}

// AsMap returns the configuration as a map for efficient field-by-field comparison
func (c *EntraUserConfig) AsMap() map[string]interface{} {
	result := map[string]interface{}{
		"user_principal_name": c.UserPrincipalName,
		"display_name":        c.DisplayName,
		"mail_nickname":       c.MailNickname,
		"account_enabled":     c.AccountEnabled,
		"tenant_id":           c.TenantID,
	}

	if c.PasswordProfile != nil {
		passwordMap := map[string]interface{}{
			"force_change_password_next_signin": c.PasswordProfile.ForceChangePasswordNextSignIn,
		}
		// Include password if set (needed for user creation)
		if c.PasswordProfile.Password != "" {
			passwordMap["password"] = c.PasswordProfile.Password
		}
		result["password_profile"] = passwordMap
	}

	if c.ForceChangePassword {
		result["force_change_password"] = c.ForceChangePassword
	}

	if c.Mail != "" {
		result["mail"] = c.Mail
	}
	if c.MobilePhone != "" {
		result["mobile_phone"] = c.MobilePhone
	}
	if c.OfficeLocation != "" {
		result["office_location"] = c.OfficeLocation
	}
	if c.JobTitle != "" {
		result["job_title"] = c.JobTitle
	}
	if c.Department != "" {
		result["department"] = c.Department
	}
	if c.CompanyName != "" {
		result["company_name"] = c.CompanyName
	}

	if len(c.Licenses) > 0 {
		result["licenses"] = c.Licenses
	}

	if len(c.Groups) > 0 {
		result["groups"] = c.Groups
	}

	return result
}

// ToYAML serializes the configuration to YAML for export/storage
func (c *EntraUserConfig) ToYAML() ([]byte, error) {
	// Create a copy without sensitive data for export
	exportConfig := *c
	if exportConfig.PasswordProfile != nil {
		// Create a copy without the password field
		exportConfig.PasswordProfile = &PasswordProfile{
			ForceChangePasswordNextSignIn: c.PasswordProfile.ForceChangePasswordNextSignIn,
		}
	}
	return yaml.Marshal(&exportConfig)
}

// FromYAML deserializes YAML data into the configuration
func (c *EntraUserConfig) FromYAML(data []byte) error {
	return yaml.Unmarshal(data, c)
}

// Validate ensures the configuration is valid
func (c *EntraUserConfig) Validate() error {
	if c.UserPrincipalName == "" {
		return fmt.Errorf("user_principal_name is required")
	}

	if c.DisplayName == "" {
		return fmt.Errorf("display_name is required")
	}

	if c.MailNickname == "" {
		return fmt.Errorf("mail_nickname is required")
	}

	if c.TenantID == "" {
		return fmt.Errorf("tenant_id is required")
	}

	// Validate license SKU IDs if provided
	for _, license := range c.Licenses {
		if license.SkuID == "" {
			return fmt.Errorf("license sku_id cannot be empty")
		}
	}

	return nil
}

// GetManagedFields returns the list of fields this configuration manages
func (c *EntraUserConfig) GetManagedFields() []string {
	// If explicitly specified, use those fields
	if len(c.ManagedFieldsList) > 0 {
		return c.ManagedFieldsList
	}

	// Default managed fields based on what's configured
	fields := []string{"display_name", "account_enabled"}

	if c.Mail != "" {
		fields = append(fields, "mail")
	}
	if c.MobilePhone != "" {
		fields = append(fields, "mobile_phone")
	}
	if c.OfficeLocation != "" {
		fields = append(fields, "office_location")
	}
	if c.JobTitle != "" {
		fields = append(fields, "job_title")
	}
	if c.Department != "" {
		fields = append(fields, "department")
	}
	if c.CompanyName != "" {
		fields = append(fields, "company_name")
	}
	if len(c.Licenses) > 0 {
		fields = append(fields, "licenses")
	}
	if len(c.Groups) > 0 {
		fields = append(fields, "groups")
	}
	if c.PasswordProfile != nil {
		fields = append(fields, "password_profile")
	}

	return fields
}

// Set creates or updates an Entra ID user according to the configuration
func (m *entraUserModule) Set(ctx context.Context, resourceID string, config modules.ConfigState) error {
	// Convert ConfigState to EntraUserConfig
	configMap := config.AsMap()
	userConfig := &EntraUserConfig{}

	// Map basic fields
	if upn, ok := configMap["user_principal_name"].(string); ok {
		userConfig.UserPrincipalName = upn
	}
	if displayName, ok := configMap["display_name"].(string); ok {
		userConfig.DisplayName = displayName
	}
	if mailNickname, ok := configMap["mail_nickname"].(string); ok {
		userConfig.MailNickname = mailNickname
	}
	if accountEnabled, ok := configMap["account_enabled"].(bool); ok {
		userConfig.AccountEnabled = accountEnabled
	}
	if tenantID, ok := configMap["tenant_id"].(string); ok {
		userConfig.TenantID = tenantID
	}

	// Map optional fields
	if mail, ok := configMap["mail"].(string); ok {
		userConfig.Mail = mail
	}
	if mobilePhone, ok := configMap["mobile_phone"].(string); ok {
		userConfig.MobilePhone = mobilePhone
	}
	if officeLocation, ok := configMap["office_location"].(string); ok {
		userConfig.OfficeLocation = officeLocation
	}
	if jobTitle, ok := configMap["job_title"].(string); ok {
		userConfig.JobTitle = jobTitle
	}
	if department, ok := configMap["department"].(string); ok {
		userConfig.Department = department
	}
	if companyName, ok := configMap["company_name"].(string); ok {
		userConfig.CompanyName = companyName
	}

	// Handle password profile
	if passwordProfile, ok := configMap["password_profile"].(map[string]interface{}); ok {
		userConfig.PasswordProfile = &PasswordProfile{}
		if forceChange, ok := passwordProfile["force_change_password_next_signin"].(bool); ok {
			userConfig.PasswordProfile.ForceChangePasswordNextSignIn = forceChange
		}
		if password, ok := passwordProfile["password"].(string); ok {
			userConfig.PasswordProfile.Password = password
		}
	}

	// Handle licenses
	if licenses, ok := configMap["licenses"].([]LicenseAssignment); ok {
		userConfig.Licenses = licenses
	}

	// Handle groups
	if groups, ok := configMap["groups"].([]string); ok {
		userConfig.Groups = groups
	}

	// Validate configuration
	if err := userConfig.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// Authenticate with Microsoft Graph
	token, err := m.authProvider.GetAccessToken(ctx, userConfig.TenantID)
	if err != nil {
		return fmt.Errorf("failed to authenticate with Microsoft Graph: %w", err)
	}

	// Check if user exists
	existingUser, err := m.graphClient.GetUser(ctx, token, userConfig.UserPrincipalName)
	if err != nil {
		if !graph.IsNotFoundError(err) {
			return fmt.Errorf("failed to check if user exists: %w", err)
		}
		// User doesn't exist, create it
		return m.createUser(ctx, token, userConfig)
	}

	// User exists, update it with only managed fields
	return m.updateUser(ctx, token, userConfig, existingUser)
}

// Get retrieves the current configuration of an Entra ID user
func (m *entraUserModule) Get(ctx context.Context, resourceID string) (modules.ConfigState, error) {
	// Parse resource ID to extract tenant ID and UPN
	// Format: tenantID:userPrincipalName
	tenantID, upn, err := parseEntraUserResourceID(resourceID)
	if err != nil {
		return nil, fmt.Errorf("invalid resource ID format: %w", err)
	}

	// Authenticate with Microsoft Graph
	token, err := m.authProvider.GetAccessToken(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate with Microsoft Graph: %w", err)
	}

	// Get user from Graph API
	user, err := m.graphClient.GetUser(ctx, token, upn)
	if err != nil {
		return nil, fmt.Errorf("failed to get user from Graph API: %w", err)
	}

	// Get user's license assignments
	graphLicenses, err := m.graphClient.GetUserLicenses(ctx, token, user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user licenses: %w", err)
	}

	// Convert graph.LicenseAssignment to local LicenseAssignment
	licenses := make([]LicenseAssignment, len(graphLicenses))
	for i, gl := range graphLicenses {
		licenses[i] = LicenseAssignment{
			SkuID:         gl.SkuID,
			DisabledPlans: gl.DisabledPlans,
		}
	}

	// Get user's group memberships
	groups, err := m.graphClient.GetUserGroups(ctx, token, user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user groups: %w", err)
	}

	// Convert Graph user to our config format
	config := &EntraUserConfig{
		UserPrincipalName: user.UserPrincipalName,
		DisplayName:       user.DisplayName,
		MailNickname:      user.MailNickname,
		AccountEnabled:    user.AccountEnabled,
		Mail:              user.Mail,
		MobilePhone:       user.MobilePhone,
		OfficeLocation:    user.OfficeLocation,
		JobTitle:          user.JobTitle,
		Department:        user.Department,
		CompanyName:       user.CompanyName,
		TenantID:          tenantID,
		Licenses:          licenses,
		Groups:            groups,
	}

	return config, nil
}

// createUser creates a new Entra ID user
func (m *entraUserModule) createUser(ctx context.Context, token *auth.AccessToken, config *EntraUserConfig) error {
	userRequest := &graph.CreateUserRequest{
		UserPrincipalName: config.UserPrincipalName,
		DisplayName:       config.DisplayName,
		MailNickname:      config.MailNickname,
		AccountEnabled:    config.AccountEnabled,
		Mail:              config.Mail,
		MobilePhone:       config.MobilePhone,
		OfficeLocation:    config.OfficeLocation,
		JobTitle:          config.JobTitle,
		Department:        config.Department,
		CompanyName:       config.CompanyName,
	}

	// Set password profile if provided
	if config.PasswordProfile != nil {
		userRequest.PasswordProfile = &graph.PasswordProfile{
			Password:                      config.PasswordProfile.Password,
			ForceChangePasswordNextSignIn: config.PasswordProfile.ForceChangePasswordNextSignIn,
		}
	}

	// Create the user
	user, err := m.graphClient.CreateUser(ctx, token, userRequest)
	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	// Wait a moment for user creation to propagate
	time.Sleep(2 * time.Second)

	// Assign licenses if specified
	if len(config.Licenses) > 0 {
		for _, license := range config.Licenses {
			if err := m.graphClient.AssignLicense(ctx, token, user.ID, license.SkuID, license.DisabledPlans); err != nil {
				return fmt.Errorf("failed to assign license %s: %w", license.SkuID, err)
			}
		}
	}

	// Add to groups if specified
	if len(config.Groups) > 0 {
		for _, groupName := range config.Groups {
			if err := m.graphClient.AddUserToGroup(ctx, token, user.ID, groupName); err != nil {
				return fmt.Errorf("failed to add user to group %s: %w", groupName, err)
			}
		}
	}

	return nil
}

// updateUser updates an existing Entra ID user with only the managed fields
func (m *entraUserModule) updateUser(ctx context.Context, token *auth.AccessToken, config *EntraUserConfig, existingUser *graph.User) error {
	managedFields := config.GetManagedFields()
	updateRequest := &graph.UpdateUserRequest{}

	// Only update managed fields
	for _, field := range managedFields {
		switch field {
		case "display_name":
			if config.DisplayName != existingUser.DisplayName {
				updateRequest.DisplayName = &config.DisplayName
			}
		case "account_enabled":
			if config.AccountEnabled != existingUser.AccountEnabled {
				updateRequest.AccountEnabled = &config.AccountEnabled
			}
		case "mail":
			if config.Mail != existingUser.Mail {
				updateRequest.Mail = &config.Mail
			}
		case "mobile_phone":
			if config.MobilePhone != existingUser.MobilePhone {
				updateRequest.MobilePhone = &config.MobilePhone
			}
		case "office_location":
			if config.OfficeLocation != existingUser.OfficeLocation {
				updateRequest.OfficeLocation = &config.OfficeLocation
			}
		case "job_title":
			if config.JobTitle != existingUser.JobTitle {
				updateRequest.JobTitle = &config.JobTitle
			}
		case "department":
			if config.Department != existingUser.Department {
				updateRequest.Department = &config.Department
			}
		case "company_name":
			if config.CompanyName != existingUser.CompanyName {
				updateRequest.CompanyName = &config.CompanyName
			}
		}
	}

	// Update the user if there are changes
	if updateRequest.HasChanges() {
		if err := m.graphClient.UpdateUser(ctx, token, existingUser.ID, updateRequest); err != nil {
			return fmt.Errorf("failed to update user: %w", err)
		}
	}

	// Handle license assignments if managed
	if contains(managedFields, "licenses") {
		if err := m.syncUserLicenses(ctx, token, existingUser.ID, config.Licenses); err != nil {
			return fmt.Errorf("failed to sync user licenses: %w", err)
		}
	}

	// Handle group memberships if managed
	if contains(managedFields, "groups") {
		if err := m.syncUserGroups(ctx, token, existingUser.ID, config.Groups); err != nil {
			return fmt.Errorf("failed to sync user groups: %w", err)
		}
	}

	return nil
}

// syncUserLicenses ensures the user has exactly the specified licenses
func (m *entraUserModule) syncUserLicenses(ctx context.Context, token *auth.AccessToken, userID string, desiredLicenses []LicenseAssignment) error {
	// Get current licenses
	currentLicenses, err := m.graphClient.GetUserLicenses(ctx, token, userID)
	if err != nil {
		return fmt.Errorf("failed to get current licenses: %w", err)
	}

	// Create maps for easier comparison
	currentLicenseMap := make(map[string]bool)
	for _, license := range currentLicenses {
		currentLicenseMap[license.SkuID] = true
	}

	desiredLicenseMap := make(map[string]LicenseAssignment)
	for _, license := range desiredLicenses {
		desiredLicenseMap[license.SkuID] = license
	}

	// Remove licenses that are no longer desired
	for skuID := range currentLicenseMap {
		if _, exists := desiredLicenseMap[skuID]; !exists {
			if err := m.graphClient.RemoveLicense(ctx, token, userID, skuID); err != nil {
				return fmt.Errorf("failed to remove license %s: %w", skuID, err)
			}
		}
	}

	// Add new licenses
	for skuID, license := range desiredLicenseMap {
		if !currentLicenseMap[skuID] {
			if err := m.graphClient.AssignLicense(ctx, token, userID, license.SkuID, license.DisabledPlans); err != nil {
				return fmt.Errorf("failed to assign license %s: %w", license.SkuID, err)
			}
		}
	}

	return nil
}

// syncUserGroups ensures the user is a member of exactly the specified groups
func (m *entraUserModule) syncUserGroups(ctx context.Context, token *auth.AccessToken, userID string, desiredGroups []string) error {
	// Get current groups
	currentGroups, err := m.graphClient.GetUserGroups(ctx, token, userID)
	if err != nil {
		return fmt.Errorf("failed to get current groups: %w", err)
	}

	// Create maps for easier comparison
	currentGroupMap := make(map[string]bool)
	for _, group := range currentGroups {
		currentGroupMap[group] = true
	}

	desiredGroupMap := make(map[string]bool)
	for _, group := range desiredGroups {
		desiredGroupMap[group] = true
	}

	// Remove from groups that are no longer desired
	for group := range currentGroupMap {
		if !desiredGroupMap[group] {
			if err := m.graphClient.RemoveUserFromGroup(ctx, token, userID, group); err != nil {
				return fmt.Errorf("failed to remove user from group %s: %w", group, err)
			}
		}
	}

	// Add to new groups
	for group := range desiredGroupMap {
		if !currentGroupMap[group] {
			if err := m.graphClient.AddUserToGroup(ctx, token, userID, group); err != nil {
				return fmt.Errorf("failed to add user to group %s: %w", group, err)
			}
		}
	}

	return nil
}

// parseEntraUserResourceID parses a resource ID into tenant ID and UPN
// Format: tenantID:userPrincipalName
func parseEntraUserResourceID(resourceID string) (tenantID, upn string, err error) {
	parts := strings.SplitN(resourceID, ":", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("resource ID must be in format 'tenantID:userPrincipalName'")
	}
	return parts[0], parts[1], nil
}

// contains checks if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
