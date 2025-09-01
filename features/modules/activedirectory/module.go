package activedirectory

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/pkg/directory/interfaces"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/go-ldap/ldap/v3"
)

// activeDirectoryModule implements the Module interface for Active Directory management
type activeDirectoryModule struct {
	logger logging.Logger
	
	// Connection management
	conn     *ldap.Conn
	connMux  sync.RWMutex
	config   *ADModuleConfig
	
	// Authentication management
	authManager *AuthenticationManager
	
	// Statistics tracking
	stats struct {
		sync.RWMutex
		requestCount int64
		errorCount   int64
		lastRequest  time.Time
		connectedAt  time.Time
	}
}

// New creates a new instance of the Active Directory module
func New(logger logging.Logger) modules.Module {
	if logger == nil {
		logger = logging.NewNoopLogger()
	}
	
	return &activeDirectoryModule{
		logger: logger,
	}
}

// Get retrieves the current state of Active Directory objects
func (m *activeDirectoryModule) Get(ctx context.Context, resourceID string) (modules.ConfigState, error) {
	m.logger.Debug("Getting AD object", "resource_id", resourceID)
	
	// Parse resourceID to determine operation type
	// Format: "query:user:john.doe" or "query:group:Administrators" or "status"
	// Cross-domain: "query:user:john.doe:trusted-domain.com" 
	// Forest: "forest:user:john.doe"
	parts := strings.Split(resourceID, ":")
	if len(parts) < 1 {
		return nil, fmt.Errorf("invalid resource ID format: %s", resourceID)
	}
	
	operation := parts[0]
	
	switch operation {
	case "status":
		return m.getConnectionStatus(ctx)
	case "query":
		if len(parts) < 3 {
			return nil, fmt.Errorf("query requires format 'query:type:id', got: %s", resourceID)
		}
		objectType := parts[1]
		objectID := parts[2]
		
		// Check for cross-domain query
		if len(parts) == 4 {
			targetDomain := parts[3]
			return m.queryTrustedDomain(ctx, targetDomain, objectType, objectID)
		}
		
		return m.queryADObject(ctx, objectType, objectID)
	case "forest":
		if len(parts) < 3 {
			return nil, fmt.Errorf("forest query requires format 'forest:type:id', got: %s", resourceID)
		}
		objectType := parts[1]
		objectID := parts[2]
		return m.queryGlobalCatalog(ctx, objectType, objectID)
	case "list":
		if len(parts) < 2 {
			return nil, fmt.Errorf("list requires format 'list:type', got: %s", resourceID)
		}
		objectType := parts[1]
		return m.listADObjects(ctx, objectType)
	default:
		return nil, fmt.Errorf("unsupported operation: %s", operation)
	}
}

// Set configures the Active Directory module connection and settings
func (m *activeDirectoryModule) Set(ctx context.Context, resourceID string, config modules.ConfigState) error {
	m.logger.Debug("Setting AD module configuration", "resource_id", resourceID)
	
	// Convert ConfigState to ADModuleConfig
	configMap := config.AsMap()
	adConfig := &ADModuleConfig{}
	
	// Extract configuration fields
	if domain, ok := configMap["domain"].(string); ok {
		adConfig.Domain = domain
	}
	if dc, ok := configMap["domain_controller"].(string); ok {
		adConfig.DomainController = dc
	}
	if port, ok := configMap["port"].(int); ok {
		adConfig.Port = port
	}
	if useTLS, ok := configMap["use_tls"].(bool); ok {
		adConfig.UseTLS = useTLS
	}
	if authMethod, ok := configMap["auth_method"].(string); ok {
		adConfig.AuthMethod = authMethod
	}
	if username, ok := configMap["username"].(string); ok {
		adConfig.Username = username
	}
	if password, ok := configMap["password"].(string); ok {
		adConfig.Password = password
	}
	if searchBase, ok := configMap["search_base"].(string); ok {
		adConfig.SearchBase = searchBase
	}
	if pageSize, ok := configMap["page_size"].(int); ok {
		adConfig.PageSize = pageSize
	}
	if opType, ok := configMap["operation_type"].(string); ok {
		adConfig.OperationType = opType
	}
	if objTypes, ok := configMap["object_types"].([]string); ok {
		adConfig.ObjectTypes = objTypes
	}
	if maxConn, ok := configMap["max_connections"].(int); ok {
		adConfig.MaxConnections = maxConn
	}
	if timeout, ok := configMap["request_timeout"].(time.Duration); ok {
		adConfig.RequestTimeout = timeout
	}
	
	// Set defaults
	if adConfig.Port == 0 {
		if adConfig.UseTLS {
			adConfig.Port = 636 // LDAPS
		} else {
			adConfig.Port = 389 // LDAP
		}
	}
	if adConfig.PageSize == 0 {
		adConfig.PageSize = 100
	}
	if adConfig.MaxConnections == 0 {
		adConfig.MaxConnections = 5
	}
	if adConfig.RequestTimeout == 0 {
		adConfig.RequestTimeout = 30 * time.Second
	}
	
	// Validate configuration
	if err := adConfig.Validate(); err != nil {
		return fmt.Errorf("invalid AD configuration: %w", err)
	}
	
	// Store configuration and establish connection
	m.connMux.Lock()
	defer m.connMux.Unlock()
	
	// Close existing connection if any
	if m.conn != nil {
		m.conn.Close()
		m.conn = nil
	}
	
	m.config = adConfig
	
	// Initialize authentication manager
	m.authManager = NewAuthenticationManager(adConfig)
	
	// Establish new connection
	if err := m.connect(ctx); err != nil {
		return fmt.Errorf("failed to connect to AD: %w", err)
	}
	
	m.logger.Info("AD module configured successfully", 
		"domain", adConfig.Domain,
		"domain_controller", adConfig.DomainController,
		"auth_method", adConfig.AuthMethod)
	
	return nil
}

// connect establishes connection to Active Directory
func (m *activeDirectoryModule) connect(ctx context.Context) error {
	if m.config == nil {
		return fmt.Errorf("no configuration set")
	}
	
	// Discover domain controller if not specified
	dcAddress := m.config.DomainController
	if dcAddress == "" {
		var err error
		dcAddress, err = m.discoverDomainController(ctx, m.config.Domain)
		if err != nil {
			return fmt.Errorf("failed to discover domain controller: %w", err)
		}
		m.logger.Info("Discovered domain controller", "dc", dcAddress)
	}
	
	// Build connection URL
	scheme := "ldap"
	if m.config.UseTLS {
		scheme = "ldaps"
	}
	
	url := fmt.Sprintf("%s://%s:%d", scheme, dcAddress, m.config.Port)
	m.logger.Debug("Connecting to AD", "url", url)
	
	// Create LDAP connection
	conn, err := ldap.DialURL(url)
	if err != nil {
		return fmt.Errorf("failed to dial LDAP: %w", err)
	}
	
	// Authenticate using authentication manager
	if err := m.authManager.Authenticate(ctx, conn); err != nil {
		conn.Close()
		return fmt.Errorf("authentication failed: %w", err)
	}
	
	m.conn = conn
	m.stats.Lock()
	m.stats.connectedAt = time.Now()
	m.stats.Unlock()
	
	m.logger.Info("Connected to Active Directory", 
		"domain", m.config.Domain,
		"dc", dcAddress,
		"auth_method", m.config.AuthMethod)
	
	return nil
}

// discoverDomainController discovers a domain controller for the specified domain
func (m *activeDirectoryModule) discoverDomainController(ctx context.Context, domain string) (string, error) {
	m.logger.Debug("Discovering domain controller", "domain", domain)
	
	// Try DNS SRV record lookup for domain controllers
	_, addrs, err := net.LookupSRV("ldap", "tcp", domain)
	if err == nil && len(addrs) > 0 {
		// Use the first available DC
		dcAddress := strings.TrimSuffix(addrs[0].Target, ".")
		m.logger.Debug("Found DC via SRV record", "dc", dcAddress)
		return dcAddress, nil
	}
	
	m.logger.Debug("SRV lookup failed, trying A record", "domain", domain, "srv_error", err)
	
	// Fallback: try direct domain lookup
	ips, err := net.LookupIP(domain)
	if err != nil {
		return "", fmt.Errorf("failed to resolve domain %s: %w", domain, err)
	}
	
	if len(ips) == 0 {
		return "", fmt.Errorf("no IP addresses found for domain %s", domain)
	}
	
	// Use the first IP
	dcAddress := ips[0].String()
	m.logger.Debug("Using domain IP as DC", "dc", dcAddress)
	
	return dcAddress, nil
}

// getConnectionStatus returns the current connection status
func (m *activeDirectoryModule) getConnectionStatus(ctx context.Context) (modules.ConfigState, error) {
	m.connMux.RLock()
	defer m.connMux.RUnlock()
	
	status := &ADConnectionStatus{
		Connected: m.conn != nil,
	}
	
	if m.config != nil {
		status.Domain = m.config.Domain
		status.DomainController = m.config.DomainController
		status.AuthMethod = m.config.AuthMethod
	}
	
	m.stats.RLock()
	status.ConnectedSince = m.stats.connectedAt
	status.RequestCount = m.stats.requestCount
	status.ErrorCount = m.stats.errorCount
	status.LastHealthCheck = time.Now()
	m.stats.RUnlock()
	
	// Test connection health
	if m.conn != nil {
		start := time.Now()
		
		// Simple search to test connectivity
		searchReq := ldap.NewSearchRequest(
			"", // Empty base DN for rootDSE
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			0, 0, false,
			"(objectClass=*)",
			[]string{"defaultNamingContext"},
			nil,
		)
		
		_, err := m.conn.Search(searchReq)
		status.ResponseTime = time.Since(start)
		
		if err != nil {
			status.HealthStatus = "unhealthy"
			m.logger.Warn("AD health check failed", "error", err)
		} else {
			status.HealthStatus = "healthy"
		}
	} else {
		status.HealthStatus = "disconnected"
	}
	
	return status, nil
}

// queryADObject queries a specific Active Directory object
func (m *activeDirectoryModule) queryADObject(ctx context.Context, objectType, objectID string) (modules.ConfigState, error) {
	m.connMux.RLock()
	conn := m.conn
	config := m.config
	m.connMux.RUnlock()
	
	if conn == nil || config == nil {
		return nil, fmt.Errorf("not connected to Active Directory")
	}
	
	m.updateStats(true)
	defer func() {
		// Update error stats in defer to catch any errors
	}()
	
	startTime := time.Now()
	result := &ADQueryResult{
		QueryType:    objectType,
		ObjectID:     objectID,
		ExecutedAt:   startTime,
	}
	
	// Determine search base
	searchBase := config.SearchBase
	if searchBase == "" {
		// Get default naming context
		var err error
		searchBase, err = m.getDefaultNamingContext(ctx)
		if err != nil {
			result.Success = false
			result.Error = fmt.Sprintf("failed to get search base: %v", err)
			result.ResponseTime = time.Since(startTime)
			m.updateStats(false)
			return result, nil
		}
	}
	
	var searchFilter string
	var attributes []string
	
	switch objectType {
	case "user":
		searchFilter = fmt.Sprintf("(&(objectClass=user)(|(sAMAccountName=%s)(userPrincipalName=%s)(distinguishedName=%s)))", 
			ldap.EscapeFilter(objectID), ldap.EscapeFilter(objectID), ldap.EscapeFilter(objectID))
		attributes = []string{
			"objectGUID", "sAMAccountName", "userPrincipalName", "displayName",
			"mail", "telephoneNumber", "mobile", "department", "title", "manager",
			"distinguishedName", "memberOf", "accountExpires", "userAccountControl",
			"whenCreated", "whenChanged", "company", "physicalDeliveryOfficeName",
		}
		
	case "group":
		searchFilter = fmt.Sprintf("(&(objectClass=group)(|(sAMAccountName=%s)(distinguishedName=%s)))", 
			ldap.EscapeFilter(objectID), ldap.EscapeFilter(objectID))
		attributes = []string{
			"objectGUID", "sAMAccountName", "displayName", "description",
			"distinguishedName", "member", "groupType", "managedBy",
			"whenCreated", "whenChanged",
		}
		
	case "organizational_unit", "ou":
		searchFilter = fmt.Sprintf("(&(objectClass=organizationalUnit)(|(name=%s)(distinguishedName=%s)))", 
			ldap.EscapeFilter(objectID), ldap.EscapeFilter(objectID))
		attributes = []string{
			"objectGUID", "name", "displayName", "description",
			"distinguishedName", "managedBy", "whenCreated", "whenChanged",
		}
		
	case "computer":
		searchFilter = fmt.Sprintf("(&(objectClass=computer)(|(sAMAccountName=%s)(dNSHostName=%s)(distinguishedName=%s)))", 
			ldap.EscapeFilter(objectID), ldap.EscapeFilter(objectID), ldap.EscapeFilter(objectID))
		attributes = []string{
			"objectGUID", "sAMAccountName", "dNSHostName", "displayName",
			"distinguishedName", "operatingSystem", "operatingSystemVersion",
			"lastLogonTimestamp", "pwdLastSet", "userAccountControl",
			"whenCreated", "whenChanged", "servicePrincipalName",
		}
		
	case "gpo", "group_policy":
		searchFilter = fmt.Sprintf("(&(objectClass=groupPolicyContainer)(|(displayName=%s)(distinguishedName=%s)))", 
			ldap.EscapeFilter(objectID), ldap.EscapeFilter(objectID))
		attributes = []string{
			"objectGUID", "displayName", "distinguishedName", "gPCFileSysPath",
			"gPCFunctionalityVersion", "gPCMachineExtensionNames", "gPCUserExtensionNames",
			"gPCWQLFilter", "versionNumber", "flags", "whenCreated", "whenChanged",
		}
		
	case "domain_trust", "trust":
		searchFilter = fmt.Sprintf("(&(objectClass=trustedDomain)(|(name=%s)(distinguishedName=%s)))", 
			ldap.EscapeFilter(objectID), ldap.EscapeFilter(objectID))
		attributes = []string{
			"objectGUID", "name", "distinguishedName", "trustDirection", "trustType",
			"trustAttributes", "flatName", "securityIdentifier", "trustPartner",
			"whenCreated", "whenChanged",
		}
		
	default:
		result.Success = false
		result.Error = fmt.Sprintf("unsupported object type: %s", objectType)
		result.ResponseTime = time.Since(startTime)
		m.updateStats(false)
		return result, nil
	}
	
	// Execute LDAP search
	searchReq := ldap.NewSearchRequest(
		searchBase,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1, // Size limit - we want exactly one object
		int(config.RequestTimeout.Seconds()),
		false,
		searchFilter,
		attributes,
		nil,
	)
	
	searchResult, err := conn.Search(searchReq)
	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("LDAP search failed: %v", err)
		result.ResponseTime = time.Since(startTime)
		m.updateStats(false)
		return result, nil
	}
	
	if len(searchResult.Entries) == 0 {
		result.Success = false
		result.Error = fmt.Sprintf("object not found: %s", objectID)
		result.ResponseTime = time.Since(startTime)
		return result, nil
	}
	
	entry := searchResult.Entries[0]
	result.Success = true
	result.ResponseTime = time.Since(startTime)
	
	// Convert LDAP entry to normalized directory object
	switch objectType {
	case "user":
		user := m.ldapEntryToDirectoryUser(entry)
		result.User = user
		
	case "group":
		group := m.ldapEntryToDirectoryGroup(entry)
		result.Group = group
		
	case "organizational_unit", "ou":
		ou := m.ldapEntryToOrganizationalUnit(entry)
		result.OU = ou
		
	case "computer":
		// For now, represent computer as a special user object
		// In a full implementation, we'd have a DirectoryComputer type
		user := m.ldapEntryToDirectoryUser(entry)
		user.ProviderAttributes["object_class"] = "computer"
		// Add computer-specific attributes
		if os := entry.GetAttributeValue("operatingSystem"); os != "" {
			user.ProviderAttributes["operating_system"] = os
		}
		if osVer := entry.GetAttributeValue("operatingSystemVersion"); osVer != "" {
			user.ProviderAttributes["operating_system_version"] = osVer
		}
		if spn := entry.GetAttributeValues("servicePrincipalName"); len(spn) > 0 {
			user.ProviderAttributes["service_principal_names"] = spn
		}
		result.User = user
		
	case "gpo", "group_policy":
		// Convert GPO to generic object for now
		gpo := m.ldapEntryToGenericObject(entry, "groupPolicyContainer")
		result.GenericObject = gpo
		
	case "domain_trust", "trust":
		// Convert trust to generic object for now
		trust := m.ldapEntryToGenericObject(entry, "trustedDomain")
		result.GenericObject = trust
	}
	
	m.logger.Debug("AD query completed successfully", 
		"object_type", objectType,
		"object_id", objectID,
		"response_time", result.ResponseTime)
	
	return result, nil
}

// listADObjects lists Active Directory objects of a specific type
func (m *activeDirectoryModule) listADObjects(ctx context.Context, objectType string) (modules.ConfigState, error) {
	m.connMux.RLock()
	conn := m.conn
	config := m.config
	m.connMux.RUnlock()
	
	if conn == nil || config == nil {
		return nil, fmt.Errorf("not connected to Active Directory")
	}
	
	m.updateStats(true)
	startTime := time.Now()
	
	result := &ADQueryResult{
		QueryType:  "list_" + objectType,
		ExecutedAt: startTime,
	}
	
	// Get search base
	searchBase := config.SearchBase
	if searchBase == "" {
		var err error
		searchBase, err = m.getDefaultNamingContext(ctx)
		if err != nil {
			result.Success = false
			result.Error = fmt.Sprintf("failed to get search base: %v", err)
			result.ResponseTime = time.Since(startTime)
			m.updateStats(false)
			return result, nil
		}
	}
	
	var searchFilter string
	var attributes []string
	
	switch objectType {
	case "user":
		searchFilter = "(&(objectClass=user)(!(objectClass=computer)))"
		attributes = []string{
			"objectGUID", "sAMAccountName", "userPrincipalName", "displayName",
			"mail", "department", "title", "distinguishedName",
		}
		
	case "group":
		searchFilter = "(objectClass=group)"
		attributes = []string{
			"objectGUID", "sAMAccountName", "displayName", "description",
			"distinguishedName", "groupType",
		}
		
	case "organizational_unit", "ou":
		searchFilter = "(objectClass=organizationalUnit)"
		attributes = []string{
			"objectGUID", "name", "displayName", "description", "distinguishedName",
		}
		
	case "computer":
		searchFilter = "(objectClass=computer)"
		attributes = []string{
			"objectGUID", "sAMAccountName", "dNSHostName", "displayName",
			"distinguishedName", "operatingSystem", "servicePrincipalName",
		}
		
	case "gpo", "group_policy":
		searchFilter = "(objectClass=groupPolicyContainer)"
		attributes = []string{
			"objectGUID", "displayName", "distinguishedName", "gPCFileSysPath",
			"gPCFunctionalityVersion", "versionNumber", "flags",
		}
		
	case "domain_trust", "trust":
		searchFilter = "(objectClass=trustedDomain)"
		attributes = []string{
			"objectGUID", "name", "distinguishedName", "trustDirection", "trustType",
			"trustPartner", "flatName",
		}
		
	default:
		result.Success = false
		result.Error = fmt.Sprintf("unsupported object type: %s", objectType)
		result.ResponseTime = time.Since(startTime)
		m.updateStats(false)
		return result, nil
	}
	
	// Execute search with pagination
	searchReq := ldap.NewSearchRequest(
		searchBase,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		config.PageSize,
		int(config.RequestTimeout.Seconds()),
		false,
		searchFilter,
		attributes,
		nil,
	)
	
	searchResult, err := conn.Search(searchReq)
	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("LDAP search failed: %v", err)
		result.ResponseTime = time.Since(startTime)
		m.updateStats(false)
		return result, nil
	}
	
	result.Success = true
	result.TotalCount = len(searchResult.Entries)
	result.HasMore = len(searchResult.Entries) >= config.PageSize
	result.ResponseTime = time.Since(startTime)
	
	// Convert entries to normalized objects
	switch objectType {
	case "user":
		result.Users = make([]interfaces.DirectoryUser, len(searchResult.Entries))
		for i, entry := range searchResult.Entries {
			result.Users[i] = *m.ldapEntryToDirectoryUser(entry)
		}
		
	case "group":
		result.Groups = make([]interfaces.DirectoryGroup, len(searchResult.Entries))
		for i, entry := range searchResult.Entries {
			result.Groups[i] = *m.ldapEntryToDirectoryGroup(entry)
		}
		
	case "organizational_unit", "ou":
		result.OUs = make([]interfaces.OrganizationalUnit, len(searchResult.Entries))
		for i, entry := range searchResult.Entries {
			result.OUs[i] = *m.ldapEntryToOrganizationalUnit(entry)
		}
		
	case "computer":
		result.Users = make([]interfaces.DirectoryUser, len(searchResult.Entries))
		for i, entry := range searchResult.Entries {
			user := m.ldapEntryToDirectoryUser(entry)
			user.ProviderAttributes["object_class"] = "computer"
			// Add computer-specific attributes
			if os := entry.GetAttributeValue("operatingSystem"); os != "" {
				user.ProviderAttributes["operating_system"] = os
			}
			if spn := entry.GetAttributeValues("servicePrincipalName"); len(spn) > 0 {
				user.ProviderAttributes["service_principal_names"] = spn
			}
			result.Users[i] = *user
		}
		
	case "gpo", "group_policy":
		result.GenericObjects = make([]map[string]interface{}, len(searchResult.Entries))
		for i, entry := range searchResult.Entries {
			gpo := m.ldapEntryToGenericObject(entry, "groupPolicyContainer")
			result.GenericObjects[i] = gpo.ProviderAttributes
		}
		
	case "domain_trust", "trust":
		result.GenericObjects = make([]map[string]interface{}, len(searchResult.Entries))
		for i, entry := range searchResult.Entries {
			trust := m.ldapEntryToGenericObject(entry, "trustedDomain")
			result.GenericObjects[i] = trust.ProviderAttributes
		}
	}
	
	m.logger.Debug("AD list completed successfully", 
		"object_type", objectType,
		"count", result.TotalCount,
		"response_time", result.ResponseTime)
	
	return result, nil
}

// getDefaultNamingContext retrieves the default naming context from AD
func (m *activeDirectoryModule) getDefaultNamingContext(ctx context.Context) (string, error) {
	// Search rootDSE for defaultNamingContext
	searchReq := ldap.NewSearchRequest(
		"", // Empty base DN for rootDSE
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"defaultNamingContext"},
		nil,
	)
	
	result, err := m.conn.Search(searchReq)
	if err != nil {
		return "", fmt.Errorf("failed to query rootDSE: %w", err)
	}
	
	if len(result.Entries) == 0 || len(result.Entries[0].Attributes) == 0 {
		return "", fmt.Errorf("defaultNamingContext not found in rootDSE")
	}
	
	namingContext := result.Entries[0].GetAttributeValue("defaultNamingContext")
	if namingContext == "" {
		return "", fmt.Errorf("defaultNamingContext is empty")
	}
	
	return namingContext, nil
}

// Helper method to update statistics
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

// Close cleans up the module and closes connections
func (m *activeDirectoryModule) Close(ctx context.Context) error {
	m.connMux.Lock()
	defer m.connMux.Unlock()
	
	if m.conn != nil {
		m.conn.Close()
		m.conn = nil
		m.logger.Info("Closed Active Directory connection")
	}
	
	return nil
}

// Monitor implements optional real-time monitoring for AD changes
func (m *activeDirectoryModule) Monitor(ctx context.Context, resourceID string, config modules.ConfigState) (<-chan modules.ConfigState, error) {
	// AD monitoring would require DirSync or similar change tracking
	// For initial implementation, return an error indicating it's not supported
	return nil, fmt.Errorf("real-time monitoring not yet implemented for Active Directory")
}

// GetCapabilities returns the capabilities of this module
func (m *activeDirectoryModule) GetCapabilities() map[string]interface{} {
	return map[string]interface{}{
		"supports_read":      true,
		"supports_write":     true,
		"supports_monitor":   false, // Not yet implemented
		"supports_bulk":      true,
		"object_types":       []string{"user", "group", "organizational_unit", "computer", "gpo", "group_policy", "domain_trust", "trust"},
		"auth_methods":       []string{"simple", "kerberos"},
		"platforms":          []string{"windows", "linux"},
		"requires_domain":    true,
		"supports_discovery": true,
		"advanced_features":  []string{"domain_controller_discovery", "computer_objects", "group_policies", "domain_trusts", "multi_domain", "forest_search", "cross_domain_auth"},
	}
}

// Multi-Domain and Multi-Forest Support Methods

// validateDomainTrust validates if a domain trust is properly configured and accessible
func (m *activeDirectoryModule) validateDomainTrust(ctx context.Context, targetDomain string) error {
	if m.config == nil {
		return fmt.Errorf("module not configured")
	}
	
	// Check if target domain is in trusted domains list
	isTrusted := false
	for _, trustedDomain := range m.config.TrustedDomains {
		if strings.EqualFold(trustedDomain, targetDomain) {
			isTrusted = true
			break
		}
	}
	
	if !isTrusted {
		return fmt.Errorf("domain %s is not in trusted domains list", targetDomain)
	}
	
	// Query trusts to verify the trust relationship exists
	trustFilter := fmt.Sprintf("(&(objectClass=trustedDomain)(name=%s))", ldap.EscapeFilter(targetDomain))
	
	// Get default naming context for trust query
	defaultNC, err := m.getDefaultNamingContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to get naming context for trust query: %w", err)
	}
	
	searchReq := ldap.NewSearchRequest(
		fmt.Sprintf("CN=System,%s", defaultNC), // System container for trusts
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1, // Limit to 1 result
		30, // 30 second timeout
		false,
		trustFilter,
		[]string{"name", "trustDirection", "trustType", "trustAttributes"},
		nil,
	)
	
	searchResult, err := m.conn.Search(searchReq)
	if err != nil {
		return fmt.Errorf("failed to query domain trust for %s: %w", targetDomain, err)
	}
	
	if len(searchResult.Entries) == 0 {
		return fmt.Errorf("no trust relationship found for domain %s", targetDomain)
	}
	
	trustEntry := searchResult.Entries[0]
	trustDirection := trustEntry.GetAttributeValue("trustDirection")
	
	// Validate trust direction allows access
	if trustDirection == "" {
		return fmt.Errorf("trust direction not specified for domain %s", targetDomain)
	}
	
	m.logger.Debug("Domain trust validated", 
		"target_domain", targetDomain,
		"trust_direction", trustDirection)
	
	return nil
}

// queryTrustedDomain performs a query in a trusted domain
func (m *activeDirectoryModule) queryTrustedDomain(ctx context.Context, targetDomain, objectType, objectID string) (modules.ConfigState, error) {
	if !m.config.CrossDomainAuth {
		return nil, fmt.Errorf("cross-domain authentication not enabled")
	}
	
	// Validate trust relationship
	if err := m.validateDomainTrust(ctx, targetDomain); err != nil {
		return nil, fmt.Errorf("trust validation failed: %w", err)
	}
	
	// Discover domain controller for target domain
	targetDC, err := m.discoverDomainController(ctx, targetDomain)
	if err != nil {
		return nil, fmt.Errorf("failed to discover DC for trusted domain %s: %w", targetDomain, err)
	}
	
	// Create temporary connection to target domain
	scheme := "ldap"
	if m.config.UseTLS {
		scheme = "ldaps"
	}
	
	targetURL := fmt.Sprintf("%s://%s:%d", scheme, targetDC, m.config.Port)
	targetConn, err := ldap.DialURL(targetURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to trusted domain DC %s: %w", targetDC, err)
	}
	defer targetConn.Close()
	
	// Authenticate to target domain (using same credentials - requires cross-domain trust)
	if err := m.authManager.Authenticate(ctx, targetConn); err != nil {
		return nil, fmt.Errorf("cross-domain authentication failed to %s: %w", targetDomain, err)
	}
	
	// Perform the query in the target domain
	result := m.executeCrossDomainQuery(ctx, targetConn, targetDomain, objectType, objectID)
	
	m.logger.Debug("Cross-domain query completed", 
		"target_domain", targetDomain,
		"object_type", objectType,
		"object_id", objectID)
	
	return result, nil
}

// executeCrossDomainQuery executes a query against a trusted domain
func (m *activeDirectoryModule) executeCrossDomainQuery(ctx context.Context, conn *ldap.Conn, domain, objectType, objectID string) *ADQueryResult {
	startTime := time.Now()
	result := &ADQueryResult{
		QueryType:  objectType,
		ObjectID:   objectID,
		ExecutedAt: startTime,
	}
	
	// Build search base for target domain
	domainParts := strings.Split(domain, ".")
	var dcComponents []string
	for _, part := range domainParts {
		dcComponents = append(dcComponents, fmt.Sprintf("DC=%s", part))
	}
	searchBase := strings.Join(dcComponents, ",")
	
	// Use same search logic but with target domain connection
	var searchFilter string
	var attributes []string
	
	switch objectType {
	case "user":
		searchFilter = fmt.Sprintf("(&(objectClass=user)(|(sAMAccountName=%s)(userPrincipalName=%s)))", 
			ldap.EscapeFilter(objectID), ldap.EscapeFilter(objectID))
		attributes = []string{
			"objectGUID", "sAMAccountName", "userPrincipalName", "displayName",
			"mail", "department", "title", "distinguishedName",
		}
	case "group":
		searchFilter = fmt.Sprintf("(&(objectClass=group)(sAMAccountName=%s))", ldap.EscapeFilter(objectID))
		attributes = []string{
			"objectGUID", "sAMAccountName", "displayName", "distinguishedName",
		}
	default:
		result.Success = false
		result.Error = fmt.Sprintf("cross-domain query not supported for object type: %s", objectType)
		result.ResponseTime = time.Since(startTime)
		return result
	}
	
	// Execute search
	searchReq := ldap.NewSearchRequest(
		searchBase,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1,
		int(m.config.RequestTimeout.Seconds()),
		false,
		searchFilter,
		attributes,
		nil,
	)
	
	searchResult, err := conn.Search(searchReq)
	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("cross-domain LDAP search failed: %v", err)
		result.ResponseTime = time.Since(startTime)
		return result
	}
	
	if len(searchResult.Entries) == 0 {
		result.Success = false
		result.Error = fmt.Sprintf("object not found in domain %s: %s", domain, objectID)
		result.ResponseTime = time.Since(startTime)
		return result
	}
	
	entry := searchResult.Entries[0]
	result.Success = true
	result.ResponseTime = time.Since(startTime)
	
	// Convert entry to appropriate object type
	switch objectType {
	case "user":
		user := m.ldapEntryToDirectoryUser(entry)
		// Mark as cross-domain result
		user.ProviderAttributes["source_domain"] = domain
		user.ProviderAttributes["cross_domain_query"] = true
		result.User = user
		
	case "group":
		group := m.ldapEntryToDirectoryGroup(entry)
		// Mark as cross-domain result
		group.ProviderAttributes["source_domain"] = domain
		group.ProviderAttributes["cross_domain_query"] = true
		result.Group = group
	}
	
	return result
}

// queryGlobalCatalog performs a forest-wide search using Global Catalog
func (m *activeDirectoryModule) queryGlobalCatalog(ctx context.Context, objectType, objectID string) (modules.ConfigState, error) {
	if m.config.GlobalCatalogDC == "" {
		return nil, fmt.Errorf("global catalog DC not configured for forest search")
	}
	
	if m.config.ForestRoot == "" {
		return nil, fmt.Errorf("forest root not configured for forest search")
	}
	
	// Connect to Global Catalog (port 3268 for GC LDAP, 3269 for GC LDAPS)
	gcPort := 3268
	if m.config.UseTLS {
		gcPort = 3269
	}
	
	scheme := "ldap"
	if m.config.UseTLS {
		scheme = "ldaps"
	}
	
	gcURL := fmt.Sprintf("%s://%s:%d", scheme, m.config.GlobalCatalogDC, gcPort)
	gcConn, err := ldap.DialURL(gcURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Global Catalog: %w", err)
	}
	defer gcConn.Close()
	
	// Authenticate to Global Catalog
	if err := m.authManager.Authenticate(ctx, gcConn); err != nil {
		return nil, fmt.Errorf("Global Catalog authentication failed: %w", err)
	}
	
	// Perform forest-wide search
	startTime := time.Now()
	result := &ADQueryResult{
		QueryType:  "forest_" + objectType,
		ObjectID:   objectID,
		ExecutedAt: startTime,
	}
	
	// Build forest-wide search filter
	var searchFilter string
	var attributes []string
	
	switch objectType {
	case "user":
		searchFilter = fmt.Sprintf("(&(objectClass=user)(|(sAMAccountName=%s)(userPrincipalName=%s)))", 
			ldap.EscapeFilter(objectID), ldap.EscapeFilter(objectID))
		attributes = []string{
			"objectGUID", "sAMAccountName", "userPrincipalName", "displayName",
			"mail", "distinguishedName",
		}
	case "group":
		searchFilter = fmt.Sprintf("(&(objectClass=group)(sAMAccountName=%s))", ldap.EscapeFilter(objectID))
		attributes = []string{
			"objectGUID", "sAMAccountName", "displayName", "distinguishedName",
		}
	default:
		result.Success = false
		result.Error = fmt.Sprintf("forest search not supported for object type: %s", objectType)
		result.ResponseTime = time.Since(startTime)
		return result, nil
	}
	
	// Search entire forest (empty search base for GC)
	searchReq := ldap.NewSearchRequest(
		"", // Empty base DN for forest-wide search
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		100, // Allow multiple results from different domains
		int(m.config.RequestTimeout.Seconds()),
		false,
		searchFilter,
		attributes,
		nil,
	)
	
	searchResult, err := gcConn.Search(searchReq)
	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("Global Catalog search failed: %v", err)
		result.ResponseTime = time.Since(startTime)
		return result, nil
	}
	
	result.Success = true
	result.TotalCount = len(searchResult.Entries)
	result.ResponseTime = time.Since(startTime)
	
	// Convert all results
	switch objectType {
	case "user":
		result.Users = make([]interfaces.DirectoryUser, len(searchResult.Entries))
		for i, entry := range searchResult.Entries {
			user := m.ldapEntryToDirectoryUser(entry)
			// Extract source domain from DN
			user.ProviderAttributes["source_domain"] = m.extractDomainFromDN(user.DistinguishedName)
			user.ProviderAttributes["forest_search"] = true
			result.Users[i] = *user
		}
		
	case "group":
		result.Groups = make([]interfaces.DirectoryGroup, len(searchResult.Entries))
		for i, entry := range searchResult.Entries {
			group := m.ldapEntryToDirectoryGroup(entry)
			// Extract source domain from DN
			group.ProviderAttributes["source_domain"] = m.extractDomainFromDN(group.DistinguishedName)
			group.ProviderAttributes["forest_search"] = true
			result.Groups[i] = *group
		}
	}
	
	m.logger.Debug("Forest search completed", 
		"object_type", objectType,
		"object_id", objectID,
		"results_found", result.TotalCount,
		"response_time", result.ResponseTime)
	
	return result, nil
}