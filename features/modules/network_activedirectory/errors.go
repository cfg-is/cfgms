package network_activedirectory

import "errors"

// Module-specific errors
var (
	// Configuration errors
	ErrInvalidDomain      = errors.New("invalid or empty domain")
	ErrInvalidAuthMethod  = errors.New("invalid authentication method")
	ErrInvalidOperation   = errors.New("invalid operation type")
	ErrMissingCredentials = errors.New("username and password required for authentication")
	ErrInvalidObjectType  = errors.New("invalid or unsupported object type")

	// Connection errors
	ErrNotConnected         = errors.New("not connected to Active Directory")
	ErrConnectionFailed     = errors.New("failed to connect to domain controller")
	ErrAuthenticationFailed = errors.New("active Directory authentication failed")
	ErrDCDiscoveryFailed    = errors.New("failed to discover domain controller")

	// Query errors
	ErrObjectNotFound    = errors.New("active Directory object not found")
	ErrInvalidSearchBase = errors.New("invalid search base DN")
	ErrSearchFailed      = errors.New("LDAP search operation failed")
	ErrInvalidFilter     = errors.New("invalid LDAP search filter")

	// Operation errors
	ErrReadOnlyMode      = errors.New("module is in read-only mode")
	ErrInsufficientPrivs = errors.New("insufficient privileges for operation")
	ErrObjectExists      = errors.New("active Directory object already exists")
	ErrInvalidDN         = errors.New("invalid distinguished name")

	// Data conversion errors
	ErrInvalidGUID         = errors.New("invalid or missing object GUID")
	ErrInvalidTimestamp    = errors.New("invalid timestamp format")
	ErrAttributeConversion = errors.New("failed to convert LDAP attribute")

	// Network and timeout errors
	ErrNetworkTimeout      = errors.New("network timeout connecting to domain controller")
	ErrDNSResolutionFailed = errors.New("failed to resolve domain controller address")
	ErrTLSHandshakeFailed  = errors.New("TLS handshake failed with domain controller")
)
