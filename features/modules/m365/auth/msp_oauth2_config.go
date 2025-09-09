package auth

import (
	"fmt"
	"strings"
)

// MSPOAuth2Config represents OAuth2 configuration optimized for MSP multi-tenant applications
// This focuses on application permissions and admin consent flow
type MSPOAuth2Config struct {
	// Multi-tenant app registration details (registered in MSP tenant - cfgis.onmicrosoft.com)
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret,omitempty"`
	TenantID     string `yaml:"tenant_id"` // MSP tenant ID (cfgis tenant)
	
	// Client tenant being accessed (dynamic per request)
	ClientTenantID string `yaml:"client_tenant_id,omitempty"`
	
	// Application permissions only (no delegated permissions for MSP)
	ApplicationPermissions []string `yaml:"application_permissions"`
	
	// Admin consent callback URI
	AdminCallbackURI string `yaml:"admin_callback_uri"`
	
	// Optional: Custom authority URL for testing
	AuthorityURL string `yaml:"authority_url,omitempty"`
}

// DefaultMSPApplicationPermissions returns the standard set of application permissions for MSP operations
func DefaultMSPApplicationPermissions() []string {
	return []string{
		// User and directory management
		"User.ReadWrite.All",
		"Directory.ReadWrite.All",
		"Group.ReadWrite.All",
		"GroupMember.ReadWrite.All",
		
		// Security and compliance
		"Policy.ReadWrite.All",                                    // Conditional Access policies
		"Policy.ReadWrite.ConditionalAccess",                     // CA policies (specific)
		"SecurityEvents.ReadWrite.All",                           // Security events
		
		// Device management (Intune)
		"DeviceManagementConfiguration.ReadWrite.All",            // Device configurations
		"DeviceManagementManagedDevices.ReadWrite.All",           // Managed devices
		"DeviceManagementServiceConfig.ReadWrite.All",            // Service configuration
		"DeviceManagementApps.ReadWrite.All",                     // App management
		
		// Organization and reporting
		"Organization.ReadWrite.All",                              // Tenant settings
		"Reports.Read.All",                                        // Usage reports
		"AuditLog.Read.All",                                       // Audit logs
		
		// Optional: Advanced permissions
		// "Application.ReadWrite.All",                            // App registrations (careful!)
		// "RoleManagement.ReadWrite.Directory",                   // Role assignments (careful!)
	}
}

// NewMSPOAuth2Config creates a new MSP OAuth2 configuration with sensible defaults
func NewMSPOAuth2Config(clientID, clientSecret, mspTenantID string) *MSPOAuth2Config {
	return &MSPOAuth2Config{
		ClientID:               clientID,
		ClientSecret:           clientSecret,
		TenantID:               mspTenantID,
		ApplicationPermissions: DefaultMSPApplicationPermissions(),
		AdminCallbackURI:       "https://auth.cfgms.com/admin/callback", // Default production URI
	}
}

// GetTokenURL returns the token endpoint URL for the specified tenant
func (c *MSPOAuth2Config) GetTokenURL(tenantID string) string {
	if c.AuthorityURL != "" {
		return fmt.Sprintf("%s/oauth2/v2.0/token", c.AuthorityURL)
	}
	return fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenantID)
}

// GetAuthorityURL returns the authority URL for the specified tenant
func (c *MSPOAuth2Config) GetAuthorityURL(tenantID string) string {
	if c.AuthorityURL != "" {
		return c.AuthorityURL
	}
	return fmt.Sprintf("https://login.microsoftonline.com/%s", tenantID)
}

// GetApplicationScopeString returns application scopes as Microsoft Graph default scope
// For application permissions, we typically use the .default scope which grants all consented permissions
func (c *MSPOAuth2Config) GetApplicationScopeString() string {
	return "https://graph.microsoft.com/.default"
}

// GetAdminConsentURL generates the admin consent URL for client onboarding
func (c *MSPOAuth2Config) GetAdminConsentURL(state string) string {
	return fmt.Sprintf(
		"https://login.microsoftonline.com/common/adminconsent?client_id=%s&redirect_uri=%s&state=%s",
		c.ClientID,
		c.AdminCallbackURI,
		state,
	)
}

// ToLegacyOAuth2Config converts to the existing OAuth2Config for backward compatibility
func (c *MSPOAuth2Config) ToLegacyOAuth2Config(clientTenantID string) *OAuth2Config {
	return &OAuth2Config{
		ClientID:             c.ClientID,
		ClientSecret:         c.ClientSecret,
		TenantID:             clientTenantID, // Use client tenant ID for token requests
		Scopes:              []string{"https://graph.microsoft.com/.default"},
		UseClientCredentials: true, // Always use client credentials for MSP
		AuthorityURL:         c.GetAuthorityURL(clientTenantID),
		
		// Disable delegated auth features for MSP
		SupportDelegatedAuth:     false,
		FallbackToAppPermissions: false, // Not needed since we only use app permissions
		DelegatedScopes:          []string{}, // Empty for MSP
		RequiredDelegatedScopes:  []string{}, // Empty for MSP
	}
}

// ValidateConfig validates the MSP OAuth2 configuration
func (c *MSPOAuth2Config) ValidateConfig() error {
	if c.ClientID == "" {
		return fmt.Errorf("client_id is required")
	}
	
	if c.ClientSecret == "" {
		return fmt.Errorf("client_secret is required for confidential client")
	}
	
	if c.TenantID == "" {
		return fmt.Errorf("tenant_id (MSP tenant) is required")
	}
	
	if c.AdminCallbackURI == "" {
		return fmt.Errorf("admin_callback_uri is required")
	}
	
	if len(c.ApplicationPermissions) == 0 {
		return fmt.Errorf("application_permissions cannot be empty")
	}
	
	return nil
}

// GetRequiredPermissionsDescription returns a human-readable description of permissions
func (c *MSPOAuth2Config) GetRequiredPermissionsDescription() map[string]string {
	descriptions := map[string]string{
		"User.ReadWrite.All":                           "Manage all user accounts",
		"Directory.ReadWrite.All":                      "Read and modify directory data",
		"Group.ReadWrite.All":                          "Manage all groups and memberships",
		"GroupMember.ReadWrite.All":                    "Manage group memberships",
		"Policy.ReadWrite.All":                         "Manage security and compliance policies",
		"Policy.ReadWrite.ConditionalAccess":           "Manage Conditional Access policies",
		"SecurityEvents.ReadWrite.All":                 "Access security events and alerts",
		"DeviceManagementConfiguration.ReadWrite.All":  "Manage Intune device configurations",
		"DeviceManagementManagedDevices.ReadWrite.All": "Manage Intune enrolled devices",
		"DeviceManagementServiceConfig.ReadWrite.All":  "Manage Intune service configuration",
		"DeviceManagementApps.ReadWrite.All":           "Manage Intune applications",
		"Organization.ReadWrite.All":                    "Manage tenant organization settings",
		"Reports.Read.All":                             "Read usage and activity reports",
		"AuditLog.Read.All":                            "Read audit logs and sign-in reports",
	}
	
	result := make(map[string]string)
	for _, permission := range c.ApplicationPermissions {
		if desc, exists := descriptions[permission]; exists {
			result[permission] = desc
		} else {
			result[permission] = "Custom permission"
		}
	}
	
	return result
}

// GetPermissionsByCategory groups permissions by functional area
func (c *MSPOAuth2Config) GetPermissionsByCategory() map[string][]string {
	categories := map[string][]string{
		"User Management": {
			"User.ReadWrite.All",
			"Directory.ReadWrite.All",
		},
		"Group Management": {
			"Group.ReadWrite.All",
			"GroupMember.ReadWrite.All",
		},
		"Security & Compliance": {
			"Policy.ReadWrite.All",
			"Policy.ReadWrite.ConditionalAccess",
			"SecurityEvents.ReadWrite.All",
		},
		"Device Management": {
			"DeviceManagementConfiguration.ReadWrite.All",
			"DeviceManagementManagedDevices.ReadWrite.All",
			"DeviceManagementServiceConfig.ReadWrite.All",
			"DeviceManagementApps.ReadWrite.All",
		},
		"Reporting & Auditing": {
			"Reports.Read.All",
			"AuditLog.Read.All",
		},
		"Organization Settings": {
			"Organization.ReadWrite.All",
		},
	}
	
	// Filter categories to only include permissions we're requesting
	result := make(map[string][]string)
	for category, permissions := range categories {
		var categoryPerms []string
		for _, permission := range permissions {
			if c.hasPermission(permission) {
				categoryPerms = append(categoryPerms, permission)
			}
		}
		if len(categoryPerms) > 0 {
			result[category] = categoryPerms
		}
	}
	
	return result
}

// hasPermission checks if a specific permission is included
func (c *MSPOAuth2Config) hasPermission(permission string) bool {
	for _, p := range c.ApplicationPermissions {
		if p == permission {
			return true
		}
	}
	return false
}

// GetMinimalPermissions returns a minimal set of permissions for basic MSP operations
func GetMinimalMSPPermissions() []string {
	return []string{
		"User.ReadWrite.All",      // User management
		"Directory.ReadWrite.All", // Directory access
		"Group.ReadWrite.All",     // Group management
		"Reports.Read.All",        // Basic reporting
	}
}

// GetStandardPermissions returns a standard set of permissions for typical MSP operations
func GetStandardMSPPermissions() []string {
	return []string{
		"User.ReadWrite.All",
		"Directory.ReadWrite.All",
		"Group.ReadWrite.All",
		"GroupMember.ReadWrite.All",
		"Policy.ReadWrite.ConditionalAccess",
		"DeviceManagementConfiguration.ReadWrite.All",
		"DeviceManagementManagedDevices.ReadWrite.All",
		"Reports.Read.All",
		"AuditLog.Read.All",
	}
}

// GetAdvancedPermissions returns an extended set of permissions for advanced MSP operations
func GetAdvancedMSPPermissions() []string {
	return DefaultMSPApplicationPermissions()
}

// UpdateApplicationPermissions updates the application permissions and validates the config
func (c *MSPOAuth2Config) UpdateApplicationPermissions(permissions []string) error {
	if len(permissions) == 0 {
		return fmt.Errorf("permissions list cannot be empty")
	}
	
	c.ApplicationPermissions = permissions
	return c.ValidateConfig()
}

// Clone creates a deep copy of the configuration
func (c *MSPOAuth2Config) Clone() *MSPOAuth2Config {
	clone := &MSPOAuth2Config{
		ClientID:         c.ClientID,
		ClientSecret:     c.ClientSecret,
		TenantID:         c.TenantID,
		ClientTenantID:   c.ClientTenantID,
		AdminCallbackURI: c.AdminCallbackURI,
		AuthorityURL:     c.AuthorityURL,
	}
	
	// Deep copy permissions slice
	clone.ApplicationPermissions = make([]string, len(c.ApplicationPermissions))
	copy(clone.ApplicationPermissions, c.ApplicationPermissions)
	
	return clone
}

// String returns a string representation of the configuration (without sensitive data)
func (c *MSPOAuth2Config) String() string {
	return fmt.Sprintf("MSPOAuth2Config{ClientID: %s, TenantID: %s, Permissions: [%s]}",
		c.ClientID,
		c.TenantID,
		strings.Join(c.ApplicationPermissions, ", "))
}