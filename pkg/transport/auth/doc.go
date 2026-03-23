// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors

// Package auth provides gRPC interceptors for steward identity enforcement
// in the CFGMS transport layer.
//
// # Security Model
//
// Every steward connects to the controller using mutual TLS (mTLS). The steward's
// identity is the Common Name (CN) of its client certificate. This package
// enforces that the identity embedded in gRPC messages matches the cryptographic
// identity established during the TLS handshake.
//
// This is the gRPC equivalent of the MQTT ACL (features/controller/server/mqtt_acl.go)
// — stewards can only act as themselves; they cannot impersonate other stewards or
// send message types reserved for controllers.
//
// # Usage
//
// Register both interceptors when creating the gRPC server:
//
//	grpc.NewServer(
//	    grpc.ChainUnaryInterceptor(auth.UnaryIdentityInterceptor()),
//	    grpc.ChainStreamInterceptor(auth.StreamIdentityInterceptor()),
//	)
//
// Inside handlers, retrieve the authenticated identity via:
//
//	identity, ok := auth.StewardIDFromContext(ctx)
//
// To validate ControlChannel message content, obtain a validator and call it
// with the authenticated identity and the incoming message:
//
//	validator := auth.ControlChannelValidator()
//	if err := validator(identity, msg); err != nil {
//	    return err
//	}
package auth
