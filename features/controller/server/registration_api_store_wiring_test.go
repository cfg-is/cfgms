// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cfgis/cfgms/features/controller/api"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// The two stubs below embed their interface rather than implementing it method
// by method: this test asserts only that a non-nil store is handed through to
// the API server, never that it behaves. Embedding keeps the test from breaking
// every time a store interface gains a method (same approach as
// pkg/controlplane/providers/grpc/approval_test.go's approvalTestStore).
type stubIPTrustStore struct{ business.IPTrustStore }

type stubPendingStore struct{ business.PendingRegistrationStore }

// TestWireRegistrationAPIStores_WiresIPTrustStore is the regression guard for the
// story #3096 finding: api.Server.SetIPTrustStore existed (Issue #1698), the
// /api/v1/registration/ip-trust routes existed, and the Postgres provider
// implemented CreateIPTrustStore — but NOTHING in production ever called the
// setter. s.ipTrustStore was therefore always nil and all three ip-trust
// endpoints returned 503 "ip-trust store unavailable" on every deployment shape.
// The handler unit tests all call SetIPTrustStore themselves, which is exactly
// why the gap survived: only startup wiring was broken.
//
// Found live on the real 3-node cfg-lab cluster while investigating why no
// steward could enrol (runbook §6): the default ip-trust approval hook
// quarantines any source IP that is not trusted, and an operator had no way to
// mark one trusted because the management API was dead.
//
// Same bug class — and same test shape — as Issue #2548's tag/role store wiring
// (see tag_role_store_wiring_test.go).
func TestWireRegistrationAPIStores_WiresIPTrustStore(t *testing.T) {
	httpServer := &api.Server{}
	logger := logging.NewNoopLogger()

	wireRegistrationAPIStores(httpServer, stubPendingStore{}, stubIPTrustStore{}, logger)

	assert.NotNil(t, httpServer.IPTrustStore(),
		"ip-trust store must be wired into the API server (else /registration/ip-trust 503s)")
	assert.NotNil(t, httpServer.PendingStore(),
		"pending-registration store must be wired into the API server (else /registration/pending 503s)")
}

// TestWireRegistrationAPIStores_NilStoresStayNil proves the wiring keeps the
// "backend does not supply this store" case as an explicit nil rather than
// panicking or installing a typed-nil that would defeat the handlers' own
// nil-checks. The OSS composite (flatfile+SQLite) backend supplies neither
// store, and must keep 503-ing rather than crashing.
func TestWireRegistrationAPIStores_NilStoresStayNil(t *testing.T) {
	httpServer := &api.Server{}
	logger := logging.NewNoopLogger()

	wireRegistrationAPIStores(httpServer, nil, nil, logger)

	assert.Nil(t, httpServer.IPTrustStore(), "unsupplied ip-trust store must stay nil")
	assert.Nil(t, httpServer.PendingStore(), "unsupplied pending store must stay nil")
}
