// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package transport

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/features/controller/credentials"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
)

const (
	// credentialRateLimit is the most IssueInitialCredential requests one steward
	// may make per credentialRateWindow, counted in memory on each node.
	credentialRateLimit  = 60
	credentialRateWindow = time.Minute

	// credentialRefusal is the one message every authorization-class refusal
	// carries, so an undeclared resource, another steward's resource and an
	// unregistered caller cannot be told apart. The reason is logged server-side.
	credentialRefusal = "credential request refused"

	credentialIssueTimeout = 15 * time.Second
)

// CredentialIssuer issues initial passwords. *credentials.Service satisfies it.
type CredentialIssuer interface {
	Issue(ctx context.Context, key credentials.Key) (string, error)
}

// CredentialHandler serves IssueInitialCredential.
//
// # Authorization order
//
//  1. Identity: the verified mTLS peer certificate yields the steward id. The
//     request carries no steward id and no tenant.
//  2. Rate limit: at most credentialRateLimit requests per steward per minute.
//  3. Tenant: resolved from the fleet registry, never from the request.
//  4. Resource: kind must be activedirectory.user and resource_id must name an
//     activedirectory.user resource in THIS steward's own effective configuration.
//     Another steward's cfg, even in the declaring tenant, does not count.
//  5. Issue: the credential service keys everything by (tenant, steward,
//     resource), so a pending record can only ever be replaced or re-issued to the
//     peer that owns it.
//
// Errors carry fixed text only; the password is never logged, audited, or placed
// in an error.
type CredentialHandler struct {
	issuer  CredentialIssuer
	config  EffectiveConfigSource
	tenants ModuleStewardRegistry
	limiter *credentialLimiter
	logger  logging.Logger
}

// NewCredentialHandler creates the handler. All arguments are required.
func NewCredentialHandler(issuer CredentialIssuer, config EffectiveConfigSource, tenants ModuleStewardRegistry, logger logging.Logger) *CredentialHandler {
	return &CredentialHandler{
		issuer:  issuer,
		config:  config,
		tenants: tenants,
		limiter: newCredentialLimiter(credentialRateLimit, credentialRateWindow, time.Now),
		logger:  logger,
	}
}

func (h *CredentialHandler) refuse(stewardID, reason string, err error) error {
	args := []any{"steward_id", logging.SanitizeLogValue(stewardID), "reason", reason}
	if err != nil {
		args = append(args, "error", logging.SanitizeLogValue(err.Error()))
	}
	h.logger.Warn("Initial credential request refused", args...)
	return status.Error(codes.PermissionDenied, credentialRefusal)
}

// HandleGRPC processes one IssueInitialCredential RPC.
func (h *CredentialHandler) HandleGRPC(ctx context.Context, req *transportpb.IssueInitialCredentialRequest) (*transportpb.IssueInitialCredentialResponse, error) {
	stewardID, err := moduleFetchPeerID(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "mTLS certificate required")
	}
	if !h.limiter.allow(stewardID) {
		h.logger.Warn("Initial credential request rate limited", "steward_id", logging.SanitizeLogValue(stewardID))
		return nil, status.Error(codes.ResourceExhausted, "rate limit exceeded")
	}

	info, ok := h.tenants.GetStewardInfo(stewardID)
	if !ok || info == nil || info.TenantID == "" {
		return nil, h.refuse(stewardID, "steward not registered to a tenant", nil)
	}
	key := credentials.Key{TenantID: info.TenantID, StewardID: stewardID, ResourceID: req.GetResourceId()}
	if req.GetKind() != credentials.KindActiveDirectoryUser || key.Validate() != nil {
		return nil, h.refuse(stewardID, "unsupported kind or malformed resource id", nil)
	}

	ctx, cancel := context.WithTimeout(ctx, credentialIssueTimeout)
	defer cancel()
	sysCtx := context.WithValue(ctxkeys.WithSystem(ctx), ctxkeys.TenantID, key.TenantID)
	effective, err := h.config.GetEffectiveConfiguration(sysCtx, key.TenantID, stewardID)
	if err != nil || effective == nil || effective.Config == nil {
		return nil, h.refuse(stewardID, "configuration unavailable", err)
	}
	declared := false
	for _, r := range effective.Config.Resources {
		if r.Module == credentials.KindActiveDirectoryUser && r.Name == key.ResourceID {
			declared = true
			break
		}
	}
	if !declared {
		return nil, h.refuse(stewardID, "resource not declared in the steward's own configuration", nil)
	}

	password, err := h.issuer.Issue(sysCtx, key)
	switch {
	case err == nil:
	case errors.Is(err, credentials.ErrAlreadyIssued):
		return nil, status.Error(codes.FailedPrecondition, "already issued")
	case errors.Is(err, credentials.ErrCapExceeded):
		h.logger.Warn("Initial credential cap reached", "steward_id", logging.SanitizeLogValue(stewardID))
		return nil, status.Error(codes.ResourceExhausted, "pending credential cap reached")
	case errors.Is(err, credentials.ErrNotClusterAtomic):
		h.logger.Error("Initial credential refused: config store is not cluster-atomic")
		return nil, status.Error(codes.Unavailable, "credential service unavailable")
	default:
		h.logger.Error("Initial credential issue failed",
			"steward_id", logging.SanitizeLogValue(stewardID),
			"error", logging.SanitizeLogValue(err.Error()))
		return nil, status.Error(codes.Internal, "credential issue failed")
	}
	h.logger.Info("Initial credential issued",
		"steward_id", logging.SanitizeLogValue(stewardID),
		"resource_id", logging.SanitizeLogValue(key.ResourceID))
	return &transportpb.IssueInitialCredentialResponse{Password: password}, nil
}

// credentialLimiter is a per-key sliding-window limiter held in memory on this
// node only.
type credentialLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	now    func() time.Time
	hits   map[string][]time.Time
}

func newCredentialLimiter(limit int, window time.Duration, now func() time.Time) *credentialLimiter {
	return &credentialLimiter{limit: limit, window: window, now: now, hits: make(map[string][]time.Time)}
}

func (l *credentialLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	cutoff := now.Add(-l.window)
	recent := l.hits[key][:0]
	for _, t := range l.hits[key] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	if len(recent) >= l.limit {
		l.hits[key] = recent
		return false
	}
	l.hits[key] = append(recent, now)
	if len(l.hits) > 4096 {
		for k, ts := range l.hits {
			if len(ts) == 0 || !ts[len(ts)-1].After(cutoff) {
				delete(l.hits, k)
			}
		}
	}
	return true
}

// secretBearingMethods are full gRPC method names whose request or response
// carries a secret. They are excluded from every payload-logging interceptor and
// from tracing span attributes: only the method, status code and duration of
// such a call may be recorded.
var secretBearingMethods = map[string]struct{}{
	transportpb.StewardTransport_IssueInitialCredential_FullMethodName: {},
}

// IsSecretBearingMethod reports whether fullMethod carries a secret in its
// payload. Any interceptor or stats handler that records request or response
// content, or that sets span attributes from it, must skip these methods.
func IsSecretBearingMethod(fullMethod string) bool {
	_, ok := secretBearingMethods[fullMethod]
	return ok
}

// NewUnaryAccessLogInterceptor logs one line per unary RPC with its method,
// status code and duration. It never logs a request or response, and a method
// for which IsSecretBearingMethod is true is logged without even the error text.
func NewUnaryAccessLogInterceptor(logger logging.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		start := time.Now()
		resp, err := handler(ctx, req)
		code := status.Code(err)
		args := []any{
			"method", logging.SanitizeLogValue(info.FullMethod),
			"code", code.String(),
			"duration_ms", time.Since(start).Milliseconds(),
		}
		if err != nil && !IsSecretBearingMethod(info.FullMethod) {
			args = append(args, "error", logging.SanitizeLogValue(strings.TrimSpace(status.Convert(err).Message())))
		}
		logger.Debug("gRPC unary call", args...)
		return resp, err
	}
}
