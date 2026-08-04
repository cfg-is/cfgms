// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package registration

import (
	"testing"
	"time"
)

func TestCreateTokenDefaultsToShortLifetime(t *testing.T) {
	before := time.Now().Add(DefaultTokenTTL)
	token, err := CreateToken(&TokenCreateRequest{
		TenantID:      "tenant-a",
		ControllerURL: "controller.example.com:4433",
	})
	if err != nil {
		t.Fatal(err)
	}
	if token.ExpiresAt == nil {
		t.Fatal("new registration token has no expiration")
	}
	if token.ExpiresAt.Before(before.Add(-time.Second)) || token.ExpiresAt.After(time.Now().Add(DefaultTokenTTL+time.Second)) {
		t.Fatalf("unexpected default expiration: %s", token.ExpiresAt)
	}
}
