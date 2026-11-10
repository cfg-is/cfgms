// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package pgopen

import (
	"context"
	"testing"
	"time"
)

func TestOpen_ValidDSNReturnsHandleWithoutDialing(t *testing.T) {
	db, err := Open("postgres://user:pw@127.0.0.1:1/db?sslmode=disable")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err == nil {
		t.Fatal("PingContext succeeded against a closed port")
	}
}

func TestOpen_MalformedDSNFailsOnConnect(t *testing.T) {
	db, err := Open("postgres://user:pw@host:notaport/db")
	if err != nil {
		return // a driver that rejects at Open is equally acceptable
	}
	defer func() { _ = db.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err == nil {
		t.Fatal("PingContext succeeded for a malformed connection string")
	}
}
