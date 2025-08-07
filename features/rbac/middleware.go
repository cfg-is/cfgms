package rbac

import (
	"context"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/rbac/continuous"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Context key types to avoid collisions
type contextKey string

const (
	authContextKey  contextKey = "auth_context"
	authResponseKey contextKey = "auth_response"
)

// AuthorizationMode defines the authorization mode for the interceptor
type AuthorizationMode string

const (
	AuthorizationModeTraditional  AuthorizationMode = "traditional"   // Session-based authorization
	AuthorizationModeContinuous   AuthorizationMode = "continuous"    // Per-action authorization
)

// AuthorizationInterceptor provides gRPC middleware for RBAC authorization
type AuthorizationInterceptor struct {
	rbacManager           RBACManager
	continuousAuthEngine  *continuous.ContinuousAuthorizationEngine
	permissionMap         map[string]string // Maps gRPC method to required permission
	publicMethods         map[string]bool   // Methods that don't require authorization
	authorizationMode     AuthorizationMode
	enableContinuous      bool
	continuousRequired    map[string]bool   // Methods that require continuous authorization
}

// NewAuthorizationInterceptor creates a new authorization interceptor
func NewAuthorizationInterceptor(rbacManager RBACManager) *AuthorizationInterceptor {
	return &AuthorizationInterceptor{
		rbacManager:        rbacManager,
		permissionMap:      getDefaultPermissionMap(),
		publicMethods:      getDefaultPublicMethods(),
		authorizationMode:  AuthorizationModeTraditional,
		enableContinuous:   false,
		continuousRequired: getDefaultContinuousRequiredMethods(),
	}
}

// NewContinuousAuthorizationInterceptor creates an interceptor with continuous authorization
func NewContinuousAuthorizationInterceptor(rbacManager RBACManager, continuousAuthEngine *continuous.ContinuousAuthorizationEngine) *AuthorizationInterceptor {
	return &AuthorizationInterceptor{
		rbacManager:          rbacManager,
		continuousAuthEngine: continuousAuthEngine,
		permissionMap:        getDefaultPermissionMap(),
		publicMethods:        getDefaultPublicMethods(),
		authorizationMode:    AuthorizationModeContinuous,
		enableContinuous:     true,
		continuousRequired:   getDefaultContinuousRequiredMethods(),
	}
}

// UnaryServerInterceptor returns a gRPC unary interceptor for authorization
func (a *AuthorizationInterceptor) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// Check if method requires authorization
		if a.publicMethods[info.FullMethod] {
			return handler(ctx, req)
		}

		// Extract authorization context from gRPC metadata
		authContext, err := a.extractAuthContext(ctx)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, err.Error())
		}

		// Get required permission for the method
		requiredPermission, exists := a.permissionMap[info.FullMethod]
		if !exists {
			// Default to deny if no permission mapping exists
			return nil, status.Error(codes.PermissionDenied, "no permission mapping for method")
		}

		// Perform authorization based on mode
		if a.enableContinuous && (a.authorizationMode == AuthorizationModeContinuous || a.continuousRequired[info.FullMethod]) {
			// Use continuous authorization
			response, err := a.performContinuousAuth(ctx, authContext, requiredPermission, info.FullMethod)
			if err != nil {
				return nil, status.Error(codes.Internal, fmt.Sprintf("continuous authorization failed: %v", err))
			}

			if !response.Granted {
				return nil, status.Error(codes.PermissionDenied, response.Reason)
			}

			// Add authorization info to context
			ctx = withAuthInfo(ctx, authContext, response)
		} else {
			// Use traditional authorization
			response, err := a.rbacManager.ValidateAccess(ctx, authContext, requiredPermission)
			if err != nil {
				return nil, status.Error(codes.Internal, fmt.Sprintf("authorization check failed: %v", err))
			}

			if !response.Granted {
				return nil, status.Error(codes.PermissionDenied, response.Reason)
			}

			// Add authorization info to context for downstream use
			ctx = withAuthInfo(ctx, authContext, response)
		}

		return handler(ctx, req)
	}
}

// StreamServerInterceptor returns a gRPC stream interceptor for authorization
func (a *AuthorizationInterceptor) StreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		// Check if method requires authorization
		if a.publicMethods[info.FullMethod] {
			return handler(srv, ss)
		}

		// Extract authorization context from gRPC metadata
		authContext, err := a.extractAuthContext(ss.Context())
		if err != nil {
			return status.Error(codes.Unauthenticated, err.Error())
		}

		// Get required permission for the method
		requiredPermission, exists := a.permissionMap[info.FullMethod]
		if !exists {
			return status.Error(codes.PermissionDenied, "no permission mapping for method")
		}

		// Check authorization
		response, err := a.rbacManager.ValidateAccess(ss.Context(), authContext, requiredPermission)
		if err != nil {
			return status.Error(codes.Internal, fmt.Sprintf("authorization check failed: %v", err))
		}

		if !response.Granted {
			return status.Error(codes.PermissionDenied, response.Reason)
		}

		// Add authorization info to context
		ctx := withAuthInfo(ss.Context(), authContext, response)
		wrappedStream := &authorizedServerStream{ServerStream: ss, ctx: ctx}

		return handler(srv, wrappedStream)
	}
}

// extractAuthContext extracts authorization context from gRPC metadata
func (a *AuthorizationInterceptor) extractAuthContext(ctx context.Context) (*common.AuthorizationContext, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, fmt.Errorf("no metadata found in context")
	}

	// Extract subject ID (from certificate or API key)
	subjectID := getMetadataValue(md, "subject-id")
	if subjectID == "" {
		return nil, fmt.Errorf("subject-id not found in metadata")
	}

	// Extract tenant ID
	tenantID := getMetadataValue(md, "tenant-id")
	if tenantID == "" {
		tenantID = "default" // Default tenant if not specified
	}

	// Extract environment attributes
	environment := make(map[string]string)
	if clientIP := getMetadataValue(md, "client-ip"); clientIP != "" {
		environment["client_ip"] = clientIP
	}
	if userAgent := getMetadataValue(md, "user-agent"); userAgent != "" {
		environment["user_agent"] = userAgent
	}

	return &common.AuthorizationContext{
		TenantId:  tenantID,
		SubjectId: subjectID,
		Environment: environment,
		ResourceAttributes: make(map[string]string),
	}, nil
}

// getMetadataValue gets a value from gRPC metadata
func getMetadataValue(md metadata.MD, key string) string {
	values := md.Get(key)
	if len(values) > 0 {
		return values[0]
	}
	return ""
}

// getDefaultPermissionMap returns the default mapping of gRPC methods to required permissions
func getDefaultPermissionMap() map[string]string {
	return map[string]string{
		// Controller Service
		"/cfgms.api.controller.ControllerService/RegisterSteward":   "steward.register",
		"/cfgms.api.controller.ControllerService/Heartbeat":         "steward.heartbeat",
		"/cfgms.api.controller.ControllerService/SyncDNA":           "steward.dna.sync",
		
		// Configuration Service
		"/cfgms.api.controller.ConfigurationService/GetConfiguration":    "config.read",
		"/cfgms.api.controller.ConfigurationService/ValidateConfig":       "config.validate",
		"/cfgms.api.controller.ConfigurationService/ReportConfigStatus":   "config.status.report",
		"/cfgms.api.controller.ConfigurationService/SubscribeConfigChanges": "config.read",
		
		// RBAC Service
		"/cfgms.api.controller.RBACService/GetPermission":        "rbac.permission.read",
		"/cfgms.api.controller.RBACService/ListPermissions":      "rbac.permission.read",
		"/cfgms.api.controller.RBACService/CreateRole":           "rbac.role.manage",
		"/cfgms.api.controller.RBACService/GetRole":              "rbac.role.read",
		"/cfgms.api.controller.RBACService/ListRoles":            "rbac.role.read",
		"/cfgms.api.controller.RBACService/UpdateRole":           "rbac.role.manage",
		"/cfgms.api.controller.RBACService/DeleteRole":           "rbac.role.manage",
		"/cfgms.api.controller.RBACService/CreateSubject":        "rbac.assignment.manage",
		"/cfgms.api.controller.RBACService/GetSubject":           "rbac.role.read",
		"/cfgms.api.controller.RBACService/ListSubjects":         "rbac.role.read",
		"/cfgms.api.controller.RBACService/UpdateSubject":        "rbac.assignment.manage",
		"/cfgms.api.controller.RBACService/DeleteSubject":        "rbac.assignment.manage",
		"/cfgms.api.controller.RBACService/AssignRole":           "rbac.assignment.manage",
		"/cfgms.api.controller.RBACService/RevokeRole":           "rbac.assignment.manage",
		"/cfgms.api.controller.RBACService/GetSubjectRoles":      "rbac.role.read",
		"/cfgms.api.controller.RBACService/CheckPermission":      "rbac.role.read",
		"/cfgms.api.controller.RBACService/GetSubjectPermissions": "rbac.role.read",
	}
}

// getDefaultPublicMethods returns methods that don't require authorization
func getDefaultPublicMethods() map[string]bool {
	return map[string]bool{
		// Health checks and system info
		"/grpc.health.v1.Health/Check": true,
		"/grpc.health.v1.Health/Watch": true,
		
		// Initial steward registration (before RBAC is set up)
		// Note: This might need special handling in real implementation
	}
}

// withAuthInfo adds authorization information to the context
func withAuthInfo(ctx context.Context, authContext *common.AuthorizationContext, response *common.AccessResponse) context.Context {
	ctx = context.WithValue(ctx, authContextKey, authContext)
	ctx = context.WithValue(ctx, authResponseKey, response)
	return ctx
}

// GetAuthContextFromContext extracts authorization context from a context
func GetAuthContextFromContext(ctx context.Context) (*common.AuthorizationContext, bool) {
	authContext, ok := ctx.Value("auth_context").(*common.AuthorizationContext)
	return authContext, ok
}

// GetAuthResponseFromContext extracts authorization response from a context
func GetAuthResponseFromContext(ctx context.Context) (*common.AccessResponse, bool) {
	authResponse, ok := ctx.Value("auth_response").(*common.AccessResponse)
	return authResponse, ok
}

// authorizedServerStream wraps a ServerStream to include authorization context
type authorizedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *authorizedServerStream) Context() context.Context {
	return s.ctx
}

// WithPermissionMapping adds or updates permission mappings
func (a *AuthorizationInterceptor) WithPermissionMapping(method, permission string) *AuthorizationInterceptor {
	a.permissionMap[method] = permission
	return a
}

// WithPublicMethod marks a method as public (no authorization required)
func (a *AuthorizationInterceptor) WithPublicMethod(method string) *AuthorizationInterceptor {
	a.publicMethods[method] = true
	return a
}

// CheckMethodPermission is a helper function to check if a subject has permission for a specific gRPC method
func (a *AuthorizationInterceptor) CheckMethodPermission(ctx context.Context, subjectID, tenantID, method string) (bool, error) {
	requiredPermission, exists := a.permissionMap[method]
	if !exists {
		return false, fmt.Errorf("no permission mapping for method %s", method)
	}

	request := &common.AccessRequest{
		SubjectId:    subjectID,
		PermissionId: requiredPermission,
		TenantId:     tenantID,
	}

	response, err := a.rbacManager.CheckPermission(ctx, request)
	if err != nil {
		return false, err
	}

	return response.Granted, nil
}

// performContinuousAuth performs continuous authorization for a request
func (a *AuthorizationInterceptor) performContinuousAuth(ctx context.Context, authContext *common.AuthorizationContext, permission, method string) (*common.AccessResponse, error) {
	if a.continuousAuthEngine == nil {
		return nil, fmt.Errorf("continuous authorization engine not available")
	}

	// Extract session ID from context or create one
	sessionID := getSessionIDFromContext(ctx)
	if sessionID == "" {
		// Generate a session ID for this request
		sessionID = fmt.Sprintf("grpc-%s-%d", authContext.SubjectId, time.Now().UnixNano())
	}

	// Create continuous authorization request
	continuousRequest := &continuous.ContinuousAuthRequest{
		AccessRequest: &common.AccessRequest{
			SubjectId:    authContext.SubjectId,
			PermissionId: permission,
			TenantId:     authContext.TenantId,
			ResourceId:   method, // Use method as resource ID
		},
		SessionID:       sessionID,
		OperationType:   continuous.OperationTypeAPI,
		ResourceContext: authContext.ResourceAttributes,
		RequestTime:     time.Now(),
	}

	// Perform continuous authorization
	continuousResponse, err := a.continuousAuthEngine.AuthorizeAction(ctx, continuousRequest)
	if err != nil {
		return nil, fmt.Errorf("continuous authorization failed: %w", err)
	}

	return continuousResponse.AccessResponse, nil
}

// getSessionIDFromContext extracts session ID from context
func getSessionIDFromContext(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	return getMetadataValue(md, "session-id")
}

// EnableContinuousMode enables continuous authorization mode
func (a *AuthorizationInterceptor) EnableContinuousMode(continuousAuthEngine *continuous.ContinuousAuthorizationEngine) *AuthorizationInterceptor {
	a.continuousAuthEngine = continuousAuthEngine
	a.enableContinuous = true
	a.authorizationMode = AuthorizationModeContinuous
	return a
}

// SetAuthorizationMode sets the authorization mode
func (a *AuthorizationInterceptor) SetAuthorizationMode(mode AuthorizationMode) *AuthorizationInterceptor {
	a.authorizationMode = mode
	return a
}

// WithContinuousRequired marks a method as requiring continuous authorization
func (a *AuthorizationInterceptor) WithContinuousRequired(method string) *AuthorizationInterceptor {
	a.continuousRequired[method] = true
	return a
}

// getDefaultContinuousRequiredMethods returns methods that require continuous authorization by default
func getDefaultContinuousRequiredMethods() map[string]bool {
	return map[string]bool{
		// Terminal service methods require continuous authorization
		"/cfgms.api.terminal.TerminalService/CreateSession":     true,
		"/cfgms.api.terminal.TerminalService/ExecuteCommand":    true,
		"/cfgms.api.terminal.TerminalService/TerminateSession":  true,
		
		// Sensitive RBAC operations
		"/cfgms.api.controller.RBACService/CreateRole":         true,
		"/cfgms.api.controller.RBACService/DeleteRole":         true,
		"/cfgms.api.controller.RBACService/AssignRole":         true,
		"/cfgms.api.controller.RBACService/RevokeRole":         true,
		
		// Sensitive configuration operations
		"/cfgms.api.controller.ConfigurationService/UpdateConfiguration": true,
		"/cfgms.api.controller.ConfigurationService/DeployConfiguration": true,
	}
}