// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package grpc

import (
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
)

// DoS limits applied to every gRPC server created by this package.
//
// Values are set per the product specification to prevent a malicious steward
// from OOM-ing the controller via oversized messages or stream flooding.
const (
	maxRecvMsgSize       = 8 * 1024 * 1024 // 8 MB — caps each inbound message
	maxSendMsgSize       = 8 * 1024 * 1024 // 8 MB — caps each outbound message
	maxConcurrentStreams = 100             // max active streams per connection

	keepalivePingTime = 30 * time.Second // interval between server-initiated pings
	keepaliveTimeout  = 60 * time.Second // time to wait for ping ACK before closing
	keepaliveMinTime  = 10 * time.Second // minimum client ping interval enforced
)

// ServerOptions returns gRPC server options that enforce DoS limits for all
// CFGMS data plane servers.
//
// Both the standalone data plane server (provider.go startServer) and the
// controller's shared gRPC server (server.go Start) must use these options so a
// malicious steward cannot OOM the controller via oversized messages or stream
// flooding. Credentials must be prepended by each call site since they vary.
func ServerOptions() []grpc.ServerOption {
	return []grpc.ServerOption{
		grpc.MaxRecvMsgSize(maxRecvMsgSize),
		grpc.MaxSendMsgSize(maxSendMsgSize),
		grpc.MaxConcurrentStreams(maxConcurrentStreams),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    keepalivePingTime,
			Timeout: keepaliveTimeout,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime: keepaliveMinTime,
		}),
	}
}
