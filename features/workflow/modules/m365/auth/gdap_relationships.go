// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package auth

// Partner-delegated tenant access (GDAP — Granular Delegated Admin Privileges).
//
// An MSP reaches a customer's M365 tenant through a GDAP relationship rather than
// by holding that customer's own app credentials. This file holds the Partner
// Center relationship client (GDAPClient) and the resolver that decides whether a
// relationship grants what an operation needs (GDAPRelationshipResolver).
// OAuth2Provider.GetAccessToken consults the resolver when the CFGMS tenant's own
// stored OAuth2Config is marked partner-delegated (see delegated_token.go).

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
)

// partnerCenterScope is the OAuth2 scope of a Partner Center API token. A token
// carrying it is never valid as a Graph token.
const partnerCenterScope = "https://api.partnercenter.microsoft.com/.default"

// partnerCenterKeyPrefix namespaces Partner Center entries in the CredentialStore.
// CredentialStore keys everything by a tenant ID string, and a CFGMS tenant's Graph
// token and a partner's Partner Center token would otherwise resolve to the same
// key (tokenKey(tenantID)) once both are in this package. GetAccessToken
// additionally refuses any stored token carrying the Partner Center scope, so a
// CFGMS tenant that happens to be named with this prefix still cannot be served a
// Partner Center token as a Graph token.
const partnerCenterKeyPrefix = "partnercenter:"

// partnerCenterTokenKey returns the CredentialStore key under which the Partner
// Center token for partnerTenantID is persisted.
func partnerCenterTokenKey(partnerTenantID string) string {
	return partnerCenterKeyPrefix + partnerTenantID
}

// GDAPRelationshipStatus represents the status of a GDAP relationship.
type GDAPRelationshipStatus string

const (
	GDAPStatusPending    GDAPRelationshipStatus = "pending"
	GDAPStatusActive     GDAPRelationshipStatus = "active"
	GDAPStatusExpired    GDAPRelationshipStatus = "expired"
	GDAPStatusTerminated GDAPRelationshipStatus = "terminated"
)

// GDAPRole represents a role assignment within a GDAP relationship.
type GDAPRole struct {
	RoleDefinitionID string `json:"role_definition_id"`
	RoleName         string `json:"role_name"`
	RoleDescription  string `json:"role_description"`
}

// GDAPRelationship represents a GDAP relationship with a customer tenant.
type GDAPRelationship struct {
	RelationshipID   string                 `json:"relationship_id"`
	CustomerTenantID string                 `json:"customer_tenant_id"`
	CustomerName     string                 `json:"customer_name"`
	Status           GDAPRelationshipStatus `json:"status"`
	Roles            []GDAPRole             `json:"roles"`
	ExpiresAt        time.Time              `json:"expires_at"`
	CreatedAt        time.Time              `json:"created_at"`
	LastModified     time.Time              `json:"last_modified"`
}

// GDAPClient provides methods for interacting with Microsoft Partner Center API
type GDAPClient struct {
	httpClient      *http.Client
	partnerTenantID string
	credStore       CredentialStore
	baseURL         string
	// clientID/clientSecret, when both set, are the Partner Center credentials and
	// the credential store is not consulted for them. OAuth2Provider always sets
	// them from the delegating CFGMS tenant's own stored config, so a stored config
	// can never name another CFGMS tenant's credentials by its partner tenant ID.
	clientID     string
	clientSecret string
	// tokenKeyID, when set, scopes the persisted Partner Center token's
	// credential-store key instead of partnerTenantID, so two CFGMS tenants naming
	// the same partner tenant never share a persisted token.
	tokenKeyID string
	// tokenBaseURL is the Microsoft login base URL used to construct the OAuth2 token
	// endpoint. Defaults to "https://login.microsoftonline.com"; overrideable in tests.
	tokenBaseURL string

	tokenMu     sync.Mutex
	cachedToken *AccessToken
	logger      logging.Logger
}

// NewGDAPClient creates a new GDAP client
func NewGDAPClient(httpClient *http.Client, partnerTenantID string) *GDAPClient {
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: 30 * time.Second,
		}
	}

	return &GDAPClient{
		httpClient:      httpClient,
		partnerTenantID: partnerTenantID,
		baseURL:         "https://api.partnercenter.microsoft.com/v1",
		tokenBaseURL:    "https://login.microsoftonline.com",
		logger:          logging.NewNoopLogger(),
	}
}

// SetCredentialStore sets the credential store for Partner Center authentication
func (c *GDAPClient) SetCredentialStore(credStore CredentialStore) {
	c.credStore = credStore
}

// SetClientCredentials sets the Partner Center client credentials directly. When
// set, they take precedence over any config looked up in the credential store.
func (c *GDAPClient) SetClientCredentials(clientID, clientSecret string) {
	c.clientID = clientID
	c.clientSecret = clientSecret
}

// SetTokenKeyID scopes the persisted Partner Center token key. See tokenKeyID.
func (c *GDAPClient) SetTokenKeyID(id string) {
	c.tokenKeyID = id
}

// persistedTokenKey returns the credential-store key for this client's token.
func (c *GDAPClient) persistedTokenKey() string {
	if c.tokenKeyID != "" {
		return partnerCenterTokenKey(c.tokenKeyID)
	}
	return partnerCenterTokenKey(c.partnerTenantID)
}

// GetGDAPRelationships retrieves all GDAP relationships from Partner Center API
func (c *GDAPClient) GetGDAPRelationships(ctx context.Context) ([]GDAPRelationship, error) {
	// Get Partner Center access token
	token, err := c.getPartnerCenterToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get Partner Center token: %w", err)
	}

	// Build request URL
	reqURL := fmt.Sprintf("%s/customers/relationships/delegatedAdminRelationships", c.baseURL)

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Authorization", token.GetAuthorizationHeader())
	req.Header.Set("Accept", "application/json")
	req.Header.Set("MS-RequestId", c.generateRequestID())
	req.Header.Set("MS-PartnerCenter-Application", "CFGMS-GDAP-Client/1.0")

	// Execute request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("partner center API request failed: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			c.logger.Warn("failed to close Partner Center API response body", "error", logging.SanitizeLogValue(closeErr.Error()))
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("partner center API returned status %d", resp.StatusCode)
	}

	// Parse response
	var apiResponse struct {
		TotalCount int `json:"totalCount"`
		Items      []struct {
			ID          string `json:"id"`
			DisplayName string `json:"displayName"`
			Customer    struct {
				TenantID    string `json:"tenantId"`
				DisplayName string `json:"displayName"`
			} `json:"customer"`
			Details struct {
				UnifiedRoles []struct {
					RoleDefinitionID string `json:"roleDefinitionId"`
					RoleName         string `json:"roleName"`
					Description      string `json:"description"`
				} `json:"unifiedRoles"`
			} `json:"details"`
			Status               string    `json:"status"`
			CreatedDateTime      time.Time `json:"createdDateTime"`
			LastModifiedDateTime time.Time `json:"lastModifiedDateTime"`
			EndDateTime          time.Time `json:"endDateTime"`
		} `json:"items"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&apiResponse); err != nil {
		return nil, fmt.Errorf("failed to parse Partner Center response: %w", err)
	}

	// Convert to our format
	relationships := make([]GDAPRelationship, 0, len(apiResponse.Items))
	for _, item := range apiResponse.Items {
		roles := make([]GDAPRole, 0, len(item.Details.UnifiedRoles))
		for _, role := range item.Details.UnifiedRoles {
			roles = append(roles, GDAPRole{
				RoleDefinitionID: role.RoleDefinitionID,
				RoleName:         role.RoleName,
				RoleDescription:  role.Description,
			})
		}

		relationship := GDAPRelationship{
			RelationshipID:   item.ID,
			CustomerTenantID: item.Customer.TenantID,
			CustomerName:     item.Customer.DisplayName,
			Status:           GDAPRelationshipStatus(strings.ToLower(item.Status)),
			Roles:            roles,
			ExpiresAt:        item.EndDateTime,
			CreatedAt:        item.CreatedDateTime,
			LastModified:     item.LastModifiedDateTime,
		}

		relationships = append(relationships, relationship)
	}

	return relationships, nil
}

// GetGDAPRelationship retrieves a specific GDAP relationship by ID
func (c *GDAPClient) GetGDAPRelationship(ctx context.Context, relationshipID string) (*GDAPRelationship, error) {
	// Get Partner Center access token
	token, err := c.getPartnerCenterToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get Partner Center token: %w", err)
	}

	// Build request URL
	reqURL := fmt.Sprintf("%s/customers/relationships/delegatedAdminRelationships/%s",
		c.baseURL, url.PathEscape(relationshipID))

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Authorization", token.GetAuthorizationHeader())
	req.Header.Set("Accept", "application/json")
	req.Header.Set("MS-RequestId", c.generateRequestID())

	// Execute request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("partner center API request failed: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			c.logger.Warn("failed to close Partner Center API response body", "error", logging.SanitizeLogValue(closeErr.Error()))
		}
	}()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("GDAP relationship not found: %s", relationshipID)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("partner center API returned status %d", resp.StatusCode)
	}

	// Parse single relationship response
	var apiItem struct {
		ID          string `json:"id"`
		DisplayName string `json:"displayName"`
		Customer    struct {
			TenantID    string `json:"tenantId"`
			DisplayName string `json:"displayName"`
		} `json:"customer"`
		Details struct {
			UnifiedRoles []struct {
				RoleDefinitionID string `json:"roleDefinitionId"`
				RoleName         string `json:"roleName"`
				Description      string `json:"description"`
			} `json:"unifiedRoles"`
		} `json:"details"`
		Status               string    `json:"status"`
		CreatedDateTime      time.Time `json:"createdDateTime"`
		LastModifiedDateTime time.Time `json:"lastModifiedDateTime"`
		EndDateTime          time.Time `json:"endDateTime"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&apiItem); err != nil {
		return nil, fmt.Errorf("failed to parse Partner Center response: %w", err)
	}

	// Convert to our format
	roles := make([]GDAPRole, 0, len(apiItem.Details.UnifiedRoles))
	for _, role := range apiItem.Details.UnifiedRoles {
		roles = append(roles, GDAPRole{
			RoleDefinitionID: role.RoleDefinitionID,
			RoleName:         role.RoleName,
			RoleDescription:  role.Description,
		})
	}

	relationship := &GDAPRelationship{
		RelationshipID:   apiItem.ID,
		CustomerTenantID: apiItem.Customer.TenantID,
		CustomerName:     apiItem.Customer.DisplayName,
		Status:           GDAPRelationshipStatus(strings.ToLower(apiItem.Status)),
		Roles:            roles,
		ExpiresAt:        apiItem.EndDateTime,
		CreatedAt:        apiItem.CreatedDateTime,
		LastModified:     apiItem.LastModifiedDateTime,
	}

	return relationship, nil
}

// ValidatePartnerAccess validates that the partner has access to perform operations in a customer tenant
func (c *GDAPClient) ValidatePartnerAccess(ctx context.Context, customerTenantID string) (*PartnerAccessValidation, error) {
	relationships, err := c.GetGDAPRelationships(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get GDAP relationships: %w", err)
	}

	validation := &PartnerAccessValidation{
		CustomerTenantID:    customerTenantID,
		PartnerTenantID:     c.partnerTenantID,
		HasAccess:           false,
		ValidatedAt:         time.Now(),
		ActiveRelationships: make([]string, 0),
		AvailableRoles:      make([]string, 0),
	}

	// Find active relationships for this customer
	for _, rel := range relationships {
		if rel.CustomerTenantID == customerTenantID {
			if rel.Status == GDAPStatusActive && time.Now().Before(rel.ExpiresAt) {
				validation.HasAccess = true
				validation.ActiveRelationships = append(validation.ActiveRelationships, rel.RelationshipID)

				// Collect all available roles
				for _, role := range rel.Roles {
					validation.AvailableRoles = append(validation.AvailableRoles, role.RoleName)
				}
			}
		}
	}

	if !validation.HasAccess {
		validation.Error = fmt.Sprintf("No active GDAP relationship found for customer tenant %s", customerTenantID)
	}

	return validation, nil
}

// GetCustomerInformation retrieves customer tenant information via GDAP
func (c *GDAPClient) GetCustomerInformation(ctx context.Context, customerTenantID string) (*CustomerInfo, error) {
	// First validate access
	validation, err := c.ValidatePartnerAccess(ctx, customerTenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to validate partner access: %w", err)
	}

	if !validation.HasAccess {
		return nil, fmt.Errorf("no GDAP access to customer tenant: %s", customerTenantID)
	}

	// Get Partner Center token
	token, err := c.getPartnerCenterToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get Partner Center token: %w", err)
	}

	// Get customer profile information
	reqURL := fmt.Sprintf("%s/customers/%s", c.baseURL, url.PathEscape(customerTenantID))

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", token.GetAuthorizationHeader())
	req.Header.Set("Accept", "application/json")
	req.Header.Set("MS-RequestId", c.generateRequestID())

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("partner center API request failed: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			c.logger.Warn("failed to close Partner Center API response body", "error", logging.SanitizeLogValue(closeErr.Error()))
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get customer information, status: %d", resp.StatusCode)
	}

	var customerProfile struct {
		ID             string `json:"id"`
		CompanyName    string `json:"companyName"`
		Domain         string `json:"domain"`
		TenantID       string `json:"tenantId"`
		BillingProfile struct {
			CompanyName string `json:"companyName"`
			Address     struct {
				Country string `json:"country"`
				Region  string `json:"region"`
				City    string `json:"city"`
			} `json:"address"`
		} `json:"billingProfile"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&customerProfile); err != nil {
		return nil, fmt.Errorf("failed to parse customer information: %w", err)
	}

	customerInfo := &CustomerInfo{
		TenantID:     customerProfile.TenantID,
		CompanyName:  customerProfile.CompanyName,
		Domain:       customerProfile.Domain,
		Country:      customerProfile.BillingProfile.Address.Country,
		Region:       customerProfile.BillingProfile.Address.Region,
		City:         customerProfile.BillingProfile.Address.City,
		AccessMethod: "gdap",
		Validation:   validation,
	}

	return customerInfo, nil
}

// getPartnerCenterToken returns a valid Partner Center access token, fetching a new
// one via the OAuth2 client-credentials flow when the cached token has expired.
//
// Credentials (client_id, client_secret) are loaded from the credential store using
// the partner tenant ID as the key. The token is cached in memory and also persisted
// back to the credential store for reuse across process restarts.
func (c *GDAPClient) getPartnerCenterToken(ctx context.Context) (*AccessToken, error) {
	if c.credStore == nil {
		return nil, fmt.Errorf("credential store not configured for GDAP client")
	}

	// Check in-memory cache (fastest path — avoids secrets-store I/O on every call).
	c.tokenMu.Lock()
	if c.cachedToken != nil && time.Now().Before(c.cachedToken.ExpiresAt.Add(-60*time.Second)) {
		tok := c.cachedToken
		c.tokenMu.Unlock()
		return tok, nil
	}
	c.tokenMu.Unlock()

	// Check persisted token (valid across process restarts).
	if stored, err := c.credStore.GetToken(c.persistedTokenKey()); err == nil && stored != nil &&
		time.Now().Before(stored.ExpiresAt.Add(-60*time.Second)) {
		c.tokenMu.Lock()
		c.cachedToken = stored
		c.tokenMu.Unlock()
		return stored, nil
	}

	// Partner credentials: explicit credentials win; otherwise they are loaded
	// from the secrets store keyed by the partner tenant ID.
	config := &OAuth2Config{ClientID: c.clientID, ClientSecret: c.clientSecret}
	if c.clientID == "" || c.clientSecret == "" {
		stored, err := c.credStore.GetConfig(c.partnerTenantID)
		if err != nil {
			return nil, fmt.Errorf(
				"partner Center credentials not found for tenant %s: "+
					"partner credentials (client_id and client_secret) must be stored in the "+
					"secrets store before Partner Center token acquisition can proceed: %w",
				c.partnerTenantID, err,
			)
		}
		config = stored
	}
	if config.ClientID == "" {
		return nil, fmt.Errorf(
			"partner Center client_id is not configured for tenant %s: "+
				"store an OAuth2Config with a non-empty ClientID in the secrets store",
			c.partnerTenantID,
		)
	}
	if config.ClientSecret == "" {
		return nil, fmt.Errorf(
			"partner Center client_secret is not configured for tenant %s: "+
				"store an OAuth2Config with a non-empty ClientSecret in the secrets store",
			c.partnerTenantID,
		)
	}

	// Build the tenant-specific token endpoint URL.
	tokenURL := fmt.Sprintf("%s/%s/oauth2/v2.0/token", c.tokenBaseURL, c.partnerTenantID)

	// Prepare client-credentials grant parameters.
	data := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {config.ClientID},
		"client_secret": {config.ClientSecret},
		"scope":         {partnerCenterScope},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create Partner Center token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("partner center token request failed: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			c.logger.Warn("failed to close Partner Center token response body", "error", logging.SanitizeLogValue(closeErr.Error()))
		}
	}()

	var tokenResp struct {
		AccessToken      string `json:"access_token"`
		TokenType        string `json:"token_type"`
		ExpiresIn        int    `json:"expires_in"`
		Scope            string `json:"scope,omitempty"`
		Error            string `json:"error,omitempty"`
		ErrorDescription string `json:"error_description,omitempty"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse Partner Center token response: %w", err)
	}
	if tokenResp.Error != "" {
		return nil, fmt.Errorf("partner center OAuth2 error: %s - %s", tokenResp.Error, tokenResp.ErrorDescription)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("partner center token request failed with status %d", resp.StatusCode)
	}

	token := &AccessToken{
		Token:     tokenResp.AccessToken,
		TokenType: tokenResp.TokenType,
		ExpiresIn: tokenResp.ExpiresIn,
		ExpiresAt: time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
		Scope:     tokenResp.Scope,
		TenantID:  c.partnerTenantID,
	}
	if token.TokenType == "" {
		token.TokenType = "Bearer"
	}

	// Update in-memory cache.
	c.tokenMu.Lock()
	c.cachedToken = token
	c.tokenMu.Unlock()

	// Persist to credential store for cross-process reuse (best-effort).
	if storeErr := c.credStore.StoreToken(c.persistedTokenKey(), token); storeErr != nil {
		c.logger.Warn("failed to persist Partner Center token to credential store",
			"tenant_id", logging.SanitizeLogValue(c.partnerTenantID),
			"error", logging.SanitizeLogValue(storeErr.Error()))
	}

	return token, nil
}

// generateRequestID generates a unique request ID for Partner Center API calls
func (c *GDAPClient) generateRequestID() string {
	return fmt.Sprintf("cfgms-gdap-%d", time.Now().UnixNano())
}

// PartnerAccessValidation represents the result of partner access validation
type PartnerAccessValidation struct {
	CustomerTenantID    string    `json:"customer_tenant_id"`
	PartnerTenantID     string    `json:"partner_tenant_id"`
	HasAccess           bool      `json:"has_access"`
	ActiveRelationships []string  `json:"active_relationships"`
	AvailableRoles      []string  `json:"available_roles"`
	Error               string    `json:"error,omitempty"`
	ValidatedAt         time.Time `json:"validated_at"`
}

// CustomerInfo represents customer tenant information retrieved via GDAP
type CustomerInfo struct {
	TenantID     string                   `json:"tenant_id"`
	CompanyName  string                   `json:"company_name"`
	Domain       string                   `json:"domain"`
	Country      string                   `json:"country"`
	Region       string                   `json:"region"`
	City         string                   `json:"city"`
	AccessMethod string                   `json:"access_method"`
	Validation   *PartnerAccessValidation `json:"validation"`
}

// GDAPRelationshipResolver discovers a partner's GDAP customer relationships and
// validates that one grants what an operation requires. It is the receiver for the
// relationship logic that previously lived on gdap.GDAPProvider.
type GDAPRelationshipResolver struct {
	partnerTenantID string
	gdapClient      *GDAPClient
}

// NewGDAPRelationshipResolver creates a resolver for one partner tenant. The
// httpClient may be nil (a 30s-timeout client is used). Partner Center credentials
// are supplied with SetClientCredentials or, for standalone use, through the
// credential store set with SetCredentialStore.
func NewGDAPRelationshipResolver(httpClient *http.Client, partnerTenantID string) *GDAPRelationshipResolver {
	return &GDAPRelationshipResolver{
		partnerTenantID: partnerTenantID,
		gdapClient:      NewGDAPClient(httpClient, partnerTenantID),
	}
}

// SetCredentialStore sets the credential store used to persist and load the
// Partner Center token (and, absent explicit credentials, the partner config).
func (r *GDAPRelationshipResolver) SetCredentialStore(credStore CredentialStore) {
	r.gdapClient.SetCredentialStore(credStore)
}

// SetEndpoints overrides the Partner Center API base URL and the Microsoft login
// base URL used to reach Partner Center (sovereign clouds, test servers). An empty
// argument keeps the default.
func (r *GDAPRelationshipResolver) SetEndpoints(partnerCenterBaseURL, loginBaseURL string) {
	if partnerCenterBaseURL != "" {
		r.gdapClient.baseURL = partnerCenterBaseURL
	}
	if loginBaseURL != "" {
		r.gdapClient.tokenBaseURL = loginBaseURL
	}
}

// SetTokenKeyID scopes the persisted Partner Center token key (see GDAPClient).
func (r *GDAPRelationshipResolver) SetTokenKeyID(id string) {
	r.gdapClient.SetTokenKeyID(id)
}

// SetClientCredentials sets the Partner Center client credentials directly.
func (r *GDAPRelationshipResolver) SetClientCredentials(clientID, clientSecret string) {
	r.gdapClient.SetClientCredentials(clientID, clientSecret)
}

// DiscoverGDAPCustomers returns the customer relationships that are currently
// active and unexpired.
func (r *GDAPRelationshipResolver) DiscoverGDAPCustomers(ctx context.Context) ([]GDAPRelationship, error) {
	relationships, err := r.gdapClient.GetGDAPRelationships(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get GDAP relationships: %w", err)
	}

	activeRelationships := make([]GDAPRelationship, 0)
	for _, rel := range relationships {
		if rel.Status == GDAPStatusActive && time.Now().Before(rel.ExpiresAt) {
			activeRelationships = append(activeRelationships, rel)
		}
	}

	return activeRelationships, nil
}

// ValidateGDAPAccess validates that the partner has an active, unexpired GDAP
// relationship with customerTenantID that grants every role in requiredRoles. The
// error for a missing role names all of the missing roles.
func (r *GDAPRelationshipResolver) ValidateGDAPAccess(ctx context.Context, customerTenantID string, requiredRoles []string) (*GDAPRelationship, error) {
	relationships, err := r.DiscoverGDAPCustomers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to discover GDAP customers: %w", err)
	}

	var relationship *GDAPRelationship
	for i := range relationships {
		if relationships[i].CustomerTenantID == customerTenantID {
			relationship = &relationships[i]
			break
		}
	}

	if relationship == nil {
		return nil, fmt.Errorf("no active GDAP relationship found for tenant %s", customerTenantID)
	}

	if len(requiredRoles) > 0 {
		availableRoles := make(map[string]bool)
		for _, role := range relationship.Roles {
			availableRoles[role.RoleName] = true
		}

		var missing []string
		for _, requiredRole := range requiredRoles {
			if !availableRoles[requiredRole] {
				missing = append(missing, requiredRole)
			}
		}
		if len(missing) > 0 {
			return nil, fmt.Errorf("GDAP relationship for tenant %s lacks required roles: %s",
				customerTenantID, strings.Join(missing, ", "))
		}
	}

	return relationship, nil
}

// GetGDAPRoleRequirements returns the GDAP roles that satisfy an M365 module
// operation. moduleName is the module's declared name (module.yaml) and operation
// is the modules.Module method, "Set" or "Get". Any one of the returned roles is
// sufficient for the operation; an unmapped module or operation requires Global
// Administrator.
//
// This was keyed by the deleted resource-management framework's resource type and
// CRUD verb. The mapping onto the module contract is:
//
//	users              -> m365-entra-user
//	groups             -> m365-entra-group
//	conditional_access -> m365-conditional-access
//	intune_policies    -> m365-intune-policy
//	create/update/delete -> Set
//	read/list            -> Get
func (r *GDAPRelationshipResolver) GetGDAPRoleRequirements(moduleName, operation string) []string {
	roleMap := map[string]map[string][]string{
		"m365-entra-user": {
			"Set": {"User Administrator", "Global Administrator"},
			"Get": {"User Administrator", "Global Reader", "Directory Readers"},
		},
		"m365-entra-group": {
			"Set": {"Groups Administrator", "Global Administrator"},
			"Get": {"Groups Administrator", "Global Reader", "Directory Readers"},
		},
		"m365-conditional-access": {
			"Set": {"Conditional Access Administrator", "Security Administrator", "Global Administrator"},
			"Get": {"Conditional Access Administrator", "Security Administrator", "Security Reader", "Global Reader"},
		},
		"m365-intune-policy": {
			"Set": {"Intune Administrator", "Global Administrator"},
			"Get": {"Intune Administrator", "Global Reader"},
		},
	}

	if moduleRoles, exists := roleMap[moduleName]; exists {
		if operationRoles, exists := moduleRoles[operation]; exists {
			return operationRoles
		}
	}

	return []string{"Global Administrator"}
}
