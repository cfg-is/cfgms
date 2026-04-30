// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

// Package registry provides a thread-safe connection registry for mapping
// steward IDs to their active transport connections.
//
// The registry is transport-agnostic — it stores opaque connection wrappers
// that satisfy the MessageSender interface. This allows gRPC streams,
// WebSocket connections, or any bidirectional channel to be stored without
// coupling the registry to any specific transport library.
//
// # Usage
//
// Create a registry and register connections as stewards connect:
//
//	reg := registry.NewRegistry()
//
//	reg.OnConnect(func(stewardID string) {
//	    log.Printf("steward connected: %s", stewardID)
//	})
//
//	reg.OnDisconnect(func(stewardID string) {
//	    log.Printf("steward disconnected: %s", stewardID)
//	})
//
//	conn := &registry.StewardConnection{
//	    StewardID:   "steward-001",
//	    Sender:      stream, // implements MessageSender
//	    ConnectedAt: time.Now(),
//	    RemoteAddr:  "10.0.0.1:50051",
//	}
//	if err := reg.Register(conn); err != nil {
//	    return err
//	}
//
// Send a message to a specific steward:
//
//	conn, ok := reg.Get("steward-001")
//	if !ok {
//	    return errors.New("steward not connected")
//	}
//	if err := conn.Send(msg); err != nil {
//	    reg.Unregister("steward-001")
//	}
//
// Fan-out a message to multiple stewards:
//
//	conns := reg.GetMany([]string{"steward-001", "steward-002", "steward-003"})
//	for stewardID, conn := range conns {
//	    if err := conn.Send(msg); err != nil {
//	        reg.Unregister(stewardID)
//	    }
//	}
//
// # Design Notes
//
// The registry does NOT manage connection lifecycle. It does not perform
// health checks, enforce timeouts, or automatically clean up stale connections.
// The transport server handler is responsible for calling Register when a
// steward connects and Unregister when the connection is lost.
//
// The registry does NOT support querying by tenant path. Fan-out target
// resolution (determining which steward IDs belong to a tenant) is the
// caller's responsibility. The registry is a flat stewardID → connection map.
//
// All methods are safe for concurrent use from multiple goroutines.
package registry
