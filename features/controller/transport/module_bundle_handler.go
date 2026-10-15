// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package transport

import (
	"context"
	"errors"
	"path/filepath"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/features/controller/modules/cache"
	"github.com/cfgis/cfgms/features/controller/service"
	pkgconfig "github.com/cfgis/cfgms/pkg/config"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	dataplaneTypes "github.com/cfgis/cfgms/pkg/dataplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/modules/bundle"
	quictransport "github.com/cfgis/cfgms/pkg/transport/quic"
)

// maxConcurrentModuleStreams bounds how many FetchModuleBundle streams the
// controller serves at once, across all tenants. Each stream holds one platform
// binary (up to bundle.MaxBundleFileBytes) in memory while it is verified and
// sent, so the bound is also the memory ceiling.
const maxConcurrentModuleStreams = 8

// moduleBundleRefusal is the one message every authorization-class refusal of
// FetchModuleBundle carries. Together with codes.NotFound it is all a caller
// learns, so an absent module, one required by someone else's configuration, a
// pending or rejected one, an unknown platform and an unreadable cache entry
// cannot be told apart. The reason is logged server-side only.
const moduleBundleRefusal = "module bundle not found"

// ModuleBundleStore is the part of the controller module cache the handler
// reads. *cache.ModuleCache satisfies it.
type ModuleBundleStore interface {
	Lookup(publisher, name, version string) (bundle.ContentAddress, error)
	GetApprovalStatus(addr bundle.ContentAddress) (cache.ApprovalStatus, error)
	GetPayload(addr bundle.ContentAddress, platform string) (*bundle.Bundle, error)
}

// EffectiveConfigSource resolves a steward's current effective configuration
// (the tenant cascade merged root to leaf). *service.ConfigurationServiceV2
// satisfies it.
type EffectiveConfigSource interface {
	GetEffectiveConfiguration(ctx context.Context, tenantID, stewardID string) (*pkgconfig.EffectiveConfiguration, error)
}

// ModuleStewardRegistry maps an authenticated steward to its registered tenant.
// *service.ControllerService satisfies it.
type ModuleStewardRegistry interface {
	GetStewardInfo(stewardID string) (*service.StewardInfo, bool)
}

// ModuleBundleHandler serves FetchModuleBundle: one approved module bundle to the
// steward whose own configuration requires it.
//
// # Authorization order
//
// Every request is checked in this order and fails closed at the first failure:
//
//  1. Identity: the verified peer certificate yields the steward id
//     (quictransport.PeerStewardID). The request carries no steward id and no
//     content hash; nothing in it names a caller or a bundle by hash.
//  2. Admission: the steward's registered tenant is resolved from the fleet
//     registry; the per-tenant TenantQueue and the global
//     maxConcurrentModuleStreams limit are taken without blocking.
//  3. Requirement: the steward's CURRENT effective configuration (tenant
//     cascade, resolved from the registry's tenant, never from the request) must
//     list exactly this publisher/name at exactly this version in
//     required_modules. Another steward's or tenant's configuration never counts.
//  4. Approval: the cache holds a bundle for the triple and its approval status
//     is approved now. A store error counts as not approved.
//  5. Integrity: the bytes are read through ModuleCache.GetPayload, which
//     re-verifies the binary against its signed digest and the content hash on
//     every call, so altered stored bytes fail before any byte is sent. The
//     served file must also be within bundle.MaxBundleFileBytes.
//
// # Error shape
//
// Failures of 3, 4, 5, an unknown or absent platform and a malformed request
// return codes.NotFound with the single message moduleBundleRefusal. A missing
// or unverified certificate returns codes.Unauthenticated; a full queue or
// stream limit returns codes.ResourceExhausted. No filesystem path, repository
// URL or reason reaches the caller; reasons are logged with sanitized values.
//
// # Stream layout
//
// The first ModuleBundleChunk carries a header (manifest bytes, signatures
// verbatim, the FULL digest list as recorded in bundle.yaml, the content hash,
// and the selected file's name and size) and no data. Each following chunk
// carries a slice of that one platform binary, chunk_index counting from 1; the
// last has final set. The cache holds every platform; the stream carries one.
// Signatures are never re-signed or rewritten.
type ModuleBundleHandler struct {
	store   ModuleBundleStore
	config  EffectiveConfigSource
	tenants ModuleStewardRegistry
	queue   *TenantQueue
	logger  logging.Logger
	// streams is the global concurrent-stream semaphore, capacity
	// maxConcurrentModuleStreams.
	streams chan struct{}
}

// NewModuleBundleHandler creates the handler. All arguments are required.
func NewModuleBundleHandler(
	store ModuleBundleStore,
	config EffectiveConfigSource,
	tenants ModuleStewardRegistry,
	queue *TenantQueue,
	logger logging.Logger,
) *ModuleBundleHandler {
	return &ModuleBundleHandler{
		store:   store,
		config:  config,
		tenants: tenants,
		queue:   queue,
		logger:  logger,
		streams: make(chan struct{}, maxConcurrentModuleStreams),
	}
}

func moduleBundleRefused() error {
	return status.Error(codes.NotFound, moduleBundleRefusal)
}

// refuse logs the server-side reason and returns the uniform refusal.
func (h *ModuleBundleHandler) refuse(stewardID string, req *transportpb.FetchModuleBundleRequest, reason string, err error) error {
	args := []any{
		"steward_id", logging.SanitizeLogValue(stewardID),
		"publisher", logging.SanitizeLogValue(req.GetPublisher()),
		"name", logging.SanitizeLogValue(req.GetName()),
		"version", logging.SanitizeLogValue(req.GetVersion()),
		"platform", logging.SanitizeLogValue(req.GetPlatform()),
		"reason", reason,
	}
	if err != nil {
		args = append(args, "error", logging.SanitizeLogValue(err.Error()))
	}
	h.logger.Warn("Module bundle fetch refused", args...)
	return moduleBundleRefused()
}

// HandleGRPC processes a FetchModuleBundle RPC on the shared gRPC-over-QUIC
// server. See ModuleBundleHandler for the authorization order and stream layout.
func (h *ModuleBundleHandler) HandleGRPC(ctx context.Context, req *transportpb.FetchModuleBundleRequest, stream grpc.ServerStreamingServer[transportpb.ModuleBundleChunk]) error {
	// 1. Identity: the peer certificate only.
	stewardID, err := moduleFetchPeerID(ctx)
	if err != nil {
		return status.Error(codes.Unauthenticated, "mTLS certificate required")
	}

	// 2. Admission. The tenant comes from the fleet registry, never the request.
	info, ok := h.tenants.GetStewardInfo(stewardID)
	if !ok || info == nil || info.TenantID == "" {
		return h.refuse(stewardID, req, "steward not registered to a tenant", nil)
	}
	tenantID := info.TenantID
	if qErr := h.queue.Acquire(tenantID); qErr != nil {
		return status.Error(codes.ResourceExhausted, "tenant queue full")
	}
	defer h.queue.Release(tenantID)
	select {
	case h.streams <- struct{}{}:
		defer func() { <-h.streams }()
	default:
		return status.Error(codes.ResourceExhausted, "too many concurrent module streams")
	}

	if reason := validateModuleBundleRequest(req); reason != "" {
		return h.refuse(stewardID, req, reason, nil)
	}

	// 3. The steward's own current effective configuration must require exactly
	// this publisher/name at exactly this version.
	sysCtx := context.WithValue(ctxkeys.WithSystem(ctx), ctxkeys.TenantID, tenantID)
	effective, err := h.config.GetEffectiveConfiguration(sysCtx, tenantID, stewardID)
	if err != nil || effective == nil || effective.Config == nil {
		return h.refuse(stewardID, req, "configuration unavailable", err)
	}
	wantName := req.GetPublisher() + "/" + req.GetName()
	required := false
	for _, rm := range effective.Config.RequiredModules {
		if rm.Name == wantName && rm.Version == req.GetVersion() {
			required = true
			break
		}
	}
	if !required {
		return h.refuse(stewardID, req, "module not required by the steward's configuration", nil)
	}

	// 4. The bundle exists and is approved now.
	addr, err := h.store.Lookup(req.GetPublisher(), req.GetName(), req.GetVersion())
	if err != nil {
		return h.refuse(stewardID, req, "bundle not in cache", err)
	}
	approval, err := h.store.GetApprovalStatus(addr)
	if err != nil {
		return h.refuse(stewardID, req, "approval status unavailable", err)
	}
	if approval != cache.ApprovalStatusApproved {
		return h.refuse(stewardID, req, "bundle not approved ("+string(approval)+")", nil)
	}

	// 5. Integrity: GetPayload re-verifies the stored bytes against the signed
	// digests and content hash, so altered bytes fail before any send.
	b, err := h.store.GetPayload(addr, req.GetPlatform())
	if err != nil {
		return h.refuse(stewardID, req, "bundle payload unreadable or altered", err)
	}
	data, ok := b.BinaryContent[req.GetPlatform()]
	fileName := filepath.Base(b.Binaries[req.GetPlatform()])
	if !ok || b.Binaries[req.GetPlatform()] == "" || b.ContentHash != addr.ContentHash {
		return h.refuse(stewardID, req, "bundle has no binary for the platform", nil)
	}
	if int64(len(data)) > bundle.MaxBundleFileBytes {
		return h.refuse(stewardID, req, "binary exceeds the file size limit", nil)
	}

	return h.send(stewardID, req, stream, b, fileName, data)
}

// send streams the header then the binary. Everything it sends has already been
// verified by GetPayload.
func (h *ModuleBundleHandler) send(stewardID string, req *transportpb.FetchModuleBundleRequest, stream grpc.ServerStreamingServer[transportpb.ModuleBundleChunk], b *bundle.Bundle, fileName string, data []byte) error {
	header := &transportpb.ModuleBundleHeader{
		Manifest:      b.ManifestBytes,
		BinaryDigests: b.BinaryDigests,
		ContentHash:   b.ContentHash,
		FileName:      fileName,
		FileSize:      int64(len(data)),
	}
	for _, s := range b.Signatures {
		header.Signatures = append(header.Signatures, &transportpb.ModuleBundleSignature{
			Publisher: s.Publisher,
			Algorithm: s.Algorithm,
			Signature: s.Signature,
		})
	}

	// #nosec G115 -- len(data) is bounded by bundle.MaxBundleFileBytes above, so
	// the chunk count is far below MaxInt32.
	total := int32((len(data) + dataplaneTypes.DefaultChunkSize - 1) / dataplaneTypes.DefaultChunkSize)
	if err := stream.Send(&transportpb.ModuleBundleChunk{Header: header, Final: total == 0}); err != nil {
		h.logger.Warn("Module bundle header send failed", "steward_id", logging.SanitizeLogValue(stewardID), "error", logging.SanitizeLogValue(err.Error()))
		return status.Error(codes.Unavailable, "module bundle stream failed")
	}
	for i := int32(0); i < total; i++ {
		if err := stream.Context().Err(); err != nil {
			return status.Error(codes.Canceled, "stream cancelled")
		}
		start := int(i) * dataplaneTypes.DefaultChunkSize
		end := start + dataplaneTypes.DefaultChunkSize
		if end > len(data) {
			end = len(data)
		}
		if err := stream.Send(&transportpb.ModuleBundleChunk{
			Data:       data[start:end],
			ChunkIndex: i + 1,
			Final:      i == total-1,
		}); err != nil {
			h.logger.Warn("Module bundle chunk send failed", "steward_id", logging.SanitizeLogValue(stewardID), "chunk", i+1, "chunks", total, "error", logging.SanitizeLogValue(err.Error()))
			return status.Error(codes.Unavailable, "module bundle stream failed")
		}
	}

	h.logger.Info("Module bundle served",
		"steward_id", logging.SanitizeLogValue(stewardID),
		"publisher", logging.SanitizeLogValue(req.GetPublisher()),
		"name", logging.SanitizeLogValue(req.GetName()),
		"version", logging.SanitizeLogValue(req.GetVersion()),
		"platform", logging.SanitizeLogValue(req.GetPlatform()),
		"bytes", len(data))
	return nil
}

// validateModuleBundleRequest returns a reason when the request cannot name a
// bundle: a path-like or empty component, a non-exact version or a platform
// outside the os-arch allowlist. The platform is a selector only.
func validateModuleBundleRequest(req *transportpb.FetchModuleBundleRequest) string {
	for _, c := range []string{req.GetPublisher(), req.GetName()} {
		if c == "" || len(c) > 128 || strings.ContainsAny(c, `/\`) || strings.Contains(c, "..") {
			return "invalid publisher or name"
		}
	}
	if !bundle.IsExactSemver(req.GetVersion()) {
		return "version is not exact"
	}
	if !bundle.ValidPlatformKey(req.GetPlatform()) {
		return "platform not in the allowlist"
	}
	return ""
}

// moduleFetchPeerID returns the steward id of the verified mTLS peer.
func moduleFetchPeerID(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", errors.New("no peer")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", errors.New("no TLS info")
	}
	return quictransport.PeerStewardID(tlsInfo.State)
}
