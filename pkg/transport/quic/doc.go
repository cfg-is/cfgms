// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors

// Package quic provides net.Listener and net.Conn adapters that allow gRPC to
// run over QUIC streams.
//
// gRPC requires a net.Listener (server) and net.Conn (both sides) to operate
// its HTTP/2 transport. QUIC provides quic.Listener and quic.Stream. This
// package bridges the two with thin adapters so gRPC can run over QUIC without
// any gRPC-internal modifications.
//
// # Architecture
//
// One QUIC connection maps to one gRPC connection. gRPC handles its own HTTP/2
// stream multiplexing within that single QUIC stream. This is the correct
// mapping: each QUIC connection carries exactly one bidirectional stream, which
// gRPC uses for its entire HTTP/2 connection lifetime.
//
// # Server usage
//
//	lis, err := quic.Listen(addr, tlsConfig, nil)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	grpcServer := grpc.NewServer()
//	grpcServer.Serve(lis)
//
// # Client usage
//
//	dialer := quic.NewDialer(tlsConfig, nil)
//	conn, err := grpc.NewClient(addr,
//	    grpc.WithContextDialer(dialer),
//	    grpc.WithTransportCredentials(insecure.NewCredentials()),
//	)
//
// # TLS
//
// TLS is handled entirely by the QUIC layer. Callers must provide a *tls.Config
// with NextProtos set to a common value on both ends. gRPC should be configured
// with insecure credentials since security is provided by the QUIC transport.
//
// This package contains no CFGMS business logic and may be used independently.
package quic
