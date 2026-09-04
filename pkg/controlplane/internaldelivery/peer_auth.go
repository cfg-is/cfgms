// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package internaldelivery

import (
	"context"
	"crypto/x509"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
)

// StewardCertOrganization is the Subject Organization stamped into every
// steward client certificate at registration
// (features/controller/api/handlers_registration.go). Steward leaves are
// signed by the same controller CA the internal delivery listener trusts, so
// the delivery service must reject them on identity, not on trust anchor.
const StewardCertOrganization = "CFGMS Stewards"

// PeerAuthorizer authorizes inbound internal-delivery RPCs by the verified
// mTLS peer certificate. It exists because the delivery listener's client CA
// pool is necessarily wider than "cluster peer nodes": it inherits the
// controller CA (which also signs every steward client certificate and every
// mTLS admin certificate) and only appends the HA peer CA, so a successful
// TLS handshake proves "holds a controller-CA-signed certificate", not "is a
// peer controller node". Without this application-layer check any registered
// steward that can reach the port could probe which stewards are connected to
// this node (a cross-tenant connectivity oracle) and attempt deliveries to
// arbitrary fleet stewards.
//
// The identity contract is the same one pkg/ha's Raft transport already
// enforces on the sibling internal listener (verifyPeerCN): a peer node
// authenticates with a client certificate whose CommonName is its cluster node
// ID. Anything else — a steward leaf, an admin leaf, an unknown CN — is
// refused with codes.PermissionDenied.
//
// Fails closed: a nil authorizer, a nil node-ID source, or an empty cluster
// membership denies every call rather than admitting anonymous callers.
type PeerAuthorizer struct {
	clusterNodeIDs func() []string
	logger         logging.Logger
}

// NewPeerAuthorizer constructs a PeerAuthorizer. clusterNodeIDs is evaluated on
// every call rather than snapshotted, so nodes joining or leaving the cluster
// take effect without restarting the delivery listener. Pass the IDs of every
// node permitted to forward deliveries to this node, including this node's own
// ID (loopback forwarding is legal and is what a routing-table/self race
// produces).
func NewPeerAuthorizer(clusterNodeIDs func() []string, logger logging.Logger) *PeerAuthorizer {
	if logger == nil {
		logger = logging.NewNoopLogger()
	}
	return &PeerAuthorizer{clusterNodeIDs: clusterNodeIDs, logger: logger}
}

// UnaryInterceptor is the grpc.UnaryServerInterceptor that gates every internal
// delivery RPC on Authorize. Register it with
// grpc.UnaryInterceptor(authorizer.UnaryInterceptor) when constructing the
// delivery gRPC server.
func (a *PeerAuthorizer) UnaryInterceptor(ctx context.Context, req interface{}, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	if err := a.Authorize(ctx); err != nil {
		return nil, err
	}
	return handler(ctx, req)
}

// Authorize reports whether ctx carries a verified mTLS peer identity belonging
// to a known cluster node. The returned error is always a
// codes.PermissionDenied status with a caller-safe message; the specific reason
// is logged, never returned, so the endpoint cannot be used to enumerate
// cluster membership or certificate contents.
func (a *PeerAuthorizer) Authorize(ctx context.Context) error {
	if a == nil {
		return status.Error(codes.PermissionDenied, "caller is not an authorized cluster peer node")
	}

	leaf, reason := verifiedPeerLeaf(ctx)
	if leaf == nil {
		return a.deny(reason, "")
	}

	// An admin mTLS certificate is a controller-CA leaf with full API authority;
	// it is emphatically not a cluster node identity.
	if cert.HasAdminMarker(leaf) {
		return a.deny("admin certificate presented to the internal delivery endpoint", leaf.Subject.CommonName)
	}

	// A steward leaf is signed by the same controller CA as everything else, so
	// it is refused on its Organization marker regardless of its CommonName —
	// this holds even if a steward were somehow registered under an ID that
	// collides with a cluster node ID.
	for _, org := range leaf.Subject.Organization {
		if org == StewardCertOrganization {
			return a.deny("steward certificate presented to the internal delivery endpoint", leaf.Subject.CommonName)
		}
	}

	cn := leaf.Subject.CommonName
	if cn == "" {
		return a.deny("peer certificate has no CommonName", "")
	}
	if a.clusterNodeIDs == nil {
		return a.deny("no cluster membership source configured", cn)
	}
	for _, nodeID := range a.clusterNodeIDs() {
		if nodeID != "" && nodeID == cn {
			return nil
		}
	}
	return a.deny("peer certificate CommonName is not a known cluster node ID", cn)
}

// deny logs the concrete reason (sanitized) and returns the single opaque
// PermissionDenied status every rejection shares.
func (a *PeerAuthorizer) deny(reason, commonName string) error {
	a.logger.Warn("internaldelivery: rejected unauthorized delivery RPC",
		"reason", logging.SanitizeLogValue(reason),
		"peer_common_name", logging.SanitizeLogValue(commonName))
	return status.Error(codes.PermissionDenied, "caller is not an authorized cluster peer node")
}

// verifiedPeerLeaf extracts the leaf of the chain the TLS stack itself
// verified. VerifiedChains — not PeerCertificates — is deliberate: it is only
// populated when the handshake verified the presented chain against the
// listener's ClientCAs, so an unverified or absent chain can never reach the
// identity checks above.
func verifiedPeerLeaf(ctx context.Context) (*x509.Certificate, string) {
	p, ok := peer.FromContext(ctx)
	if !ok || p == nil {
		return nil, "no peer information on the RPC context"
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, "connection is not mTLS"
	}
	if len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.VerifiedChains[0]) == 0 {
		return nil, "no verified client certificate chain"
	}
	return tlsInfo.State.VerifiedChains[0][0], ""
}
