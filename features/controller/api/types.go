package api

import (
	"time"

	"github.com/cfgis/cfgms/api/proto/common"
	controller "github.com/cfgis/cfgms/api/proto/controller"
)

// APIResponse represents a standard API response wrapper
type APIResponse struct {
	Data      interface{} `json:"data"`
	Timestamp time.Time   `json:"timestamp"`
}

// ErrorResponse represents a standard error response
type ErrorResponse struct {
	Error     *APIError `json:"error"`
	Timestamp time.Time `json:"timestamp"`
}

// APIError represents an API error
type APIError struct {
	Code    string                 `json:"code"`
	Message string                 `json:"message"`
	Details map[string]interface{} `json:"details,omitempty"`
}

// StewardInfo represents steward information for API responses
type StewardInfo struct {
	ID          string            `json:"id"`
	Status      string            `json:"status"`
	LastSeen    time.Time         `json:"last_seen"`
	Version     string            `json:"version"`
	ConnectedAt time.Time         `json:"connected_at"`
	Metrics     map[string]string `json:"metrics,omitempty"`
	DNA         *DNAInfo          `json:"dna,omitempty"`
}

// DNAInfo represents DNA information for API responses
type DNAInfo struct {
	Hostname     string            `json:"hostname"`
	OS           string            `json:"os"`
	Architecture string            `json:"architecture"`
	Attributes   map[string]string `json:"attributes,omitempty"`
	CollectedAt  time.Time         `json:"collected_at"`
}

// ConfigurationInfo represents configuration information
type ConfigurationInfo struct {
	StewardID string                 `json:"steward_id"`
	Version   string                 `json:"version"`
	Config    map[string]interface{} `json:"config"`
	UpdatedAt time.Time              `json:"updated_at"`
}

// ConfigValidationRequest represents a config validation request
type ConfigValidationRequest struct {
	Config  map[string]interface{} `json:"config"`
	Version string                 `json:"version,omitempty"`
}

// ConfigValidationResult represents validation results
type ConfigValidationResult struct {
	Valid    bool              `json:"valid"`
	Errors   []ValidationError `json:"errors,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// ValidationError represents a validation error
type ValidationError struct {
	Field      string `json:"field"`
	Message    string `json:"message"`
	Level      string `json:"level"`
	Code       string `json:"code"`
	Suggestion string `json:"suggestion,omitempty"`
}

// ConfigStatusInfo represents configuration status
type ConfigStatusInfo struct {
	StewardID     string         `json:"steward_id"`
	ConfigVersion string         `json:"config_version"`
	Status        string         `json:"status"`
	Modules       []ModuleStatus `json:"modules"`
	UpdatedAt     time.Time      `json:"updated_at"`
}

// ModuleStatus represents the status of a module
type ModuleStatus struct {
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}

// CertificateInfo represents certificate information
type CertificateInfo struct {
	SerialNumber        string    `json:"serial_number"`
	CommonName          string    `json:"common_name"`
	StewardID           string    `json:"steward_id,omitempty"`
	IsValid             bool      `json:"is_valid"`
	ExpiresAt           time.Time `json:"expires_at"`
	DaysUntilExpiration int32     `json:"days_until_expiration"`
	NeedsRenewal        bool      `json:"needs_renewal"`
}

// CertificateProvisionRequest represents a certificate provision request
type CertificateProvisionRequest struct {
	StewardID    string `json:"steward_id"`
	CommonName   string `json:"common_name"`
	Organization string `json:"organization,omitempty"`
	ValidityDays int32  `json:"validity_days,omitempty"`
}

// CertificateProvisionResult represents a certificate provision result
type CertificateProvisionResult struct {
	CertificatePEM   string    `json:"certificate_pem"`
	PrivateKeyPEM    string    `json:"private_key_pem"`
	CACertificatePEM string    `json:"ca_certificate_pem"`
	SerialNumber     string    `json:"serial_number"`
	ExpiresAt        time.Time `json:"expires_at"`
}

// CertificateRevocationRequest represents a certificate revocation request
type CertificateRevocationRequest struct {
	SerialNumber string `json:"serial_number"`
	Reason       string `json:"reason,omitempty"`
}

// RoleInfo represents role information
type RoleInfo struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Permissions []string  `json:"permissions"`
	TenantID    string    `json:"tenant_id"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// SubjectInfo represents subject information
type SubjectInfo struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	TenantID  string    `json:"tenant_id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// PermissionInfo represents permission information
type PermissionInfo struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	ResourceType string   `json:"resource_type"`
	Actions      []string `json:"actions"`
}

// RoleAssignmentRequest represents a role assignment request
type RoleAssignmentRequest struct {
	RoleID   string `json:"role_id"`
	TenantID string `json:"tenant_id,omitempty"`
}

// PermissionCheckRequest represents a permission check request
type PermissionCheckRequest struct {
	SubjectID    string `json:"subject_id"`
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
	Action       string `json:"action"`
	TenantID     string `json:"tenant_id,omitempty"`
}

// PermissionCheckResult represents a permission check result
type PermissionCheckResult struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason,omitempty"`
}

// APIKeyCreateRequest represents an API key creation request
type APIKeyCreateRequest struct {
	Name        string     `json:"name"`
	Permissions []string   `json:"permissions"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	TenantID    string     `json:"tenant_id,omitempty"`
}

// APIKeyInfo represents API key information (without the actual key)
type APIKeyInfo struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Permissions []string   `json:"permissions"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	TenantID    string     `json:"tenant_id"`
}

// APIKeyCreateResult represents the result of API key creation
type APIKeyCreateResult struct {
	APIKeyInfo
	Key string `json:"key"` // Only returned on creation
}

// HealthStatus represents the system health status
type HealthStatus struct {
	Status    string            `json:"status"`
	Version   string            `json:"version"`
	Timestamp time.Time         `json:"timestamp"`
	Services  map[string]string `json:"services"`
}

// Helper functions to convert protobuf messages to API types

// DNAFromProto converts a protobuf DNA message to DNAInfo
func DNAFromProto(dna *common.DNA) *DNAInfo {
	if dna == nil {
		return nil
	}

	// Extract common attributes from the DNA attributes map
	hostname := dna.Attributes["hostname"]
	os := dna.Attributes["os"]
	architecture := dna.Attributes["architecture"]

	return &DNAInfo{
		Hostname:     hostname,
		OS:           os,
		Architecture: architecture,
		Attributes:   dna.Attributes,
		CollectedAt:  dna.LastUpdated.AsTime(),
	}
}

// ValidationErrorFromProto converts a protobuf ValidationError to ValidationError
func ValidationErrorFromProto(err *controller.ValidationError) ValidationError {
	level := "INFO"
	switch err.Level {
	case controller.ValidationError_WARNING:
		level = "WARNING"
	case controller.ValidationError_ERROR:
		level = "ERROR"
	case controller.ValidationError_CRITICAL:
		level = "CRITICAL"
	}

	return ValidationError{
		Field:      err.Field,
		Message:    err.Message,
		Level:      level,
		Code:       err.Code,
		Suggestion: err.Suggestion,
	}
}

// ModuleStatusFromProto converts a protobuf ModuleStatus to ModuleStatus
func ModuleStatusFromProto(status *controller.ModuleStatus) ModuleStatus {
	return ModuleStatus{
		Name:      status.Name,
		Status:    status.Status.Message,
		Message:   status.Message,
		Timestamp: status.Timestamp.AsTime(),
	}
}

// CertificateInfoFromProto converts a protobuf CertificateInfo to CertificateInfo
// Note: This is currently not used as we interface directly with cert manager
func CertificateInfoFromProto(cert interface{}) CertificateInfo {
	// Placeholder - would need to be implemented if gRPC cert service is used
	return CertificateInfo{}
}
