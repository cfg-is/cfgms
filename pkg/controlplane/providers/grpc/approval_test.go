// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package grpc

import (
	"context"
	"crypto/tls"
	"errors"
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/transport/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// approveAll is a StewardApprovalChecker that always approves.
type approveAll struct{}

func (approveAll) IsApproved(_ context.Context, _ string) (bool, error) { return true, nil }

// rejectAll is a StewardApprovalChecker that always rejects.
type rejectAll struct{}

func (rejectAll) IsApproved(_ context.Context, _ string) (bool, error) { return false, nil }

// errorChecker is a StewardApprovalChecker that always returns an error.
type errorChecker struct{}

func (errorChecker) IsApproved(_ context.Context, _ string) (bool, error) {
	return false, errors.New("checker unavailable")
}

type approvalTestStore struct {
	business.StewardStore
	record *business.StewardRecord
	err    error
}

type nonConsumingRegistrationStore struct {
	business.RegistrationTokenStore
}

func (s *approvalTestStore) GetSteward(_ context.Context, _ string) (*business.StewardRecord, error) {
	return s.record, s.err
}

// newTestEnvWithChecker is like newTestEnv but injects an approval checker into the server.
func newTestEnvWithChecker(t *testing.T, stewardID string, checker StewardApprovalChecker) (*Provider, registry.Registry) {
	t.Helper()

	serverTLS, clientTLS := newTestTLSConfigs(t, stewardID)
	reg := registry.NewRegistry()

	server := New(ModeServer, WithApprovalChecker(checker))
	err := server.Initialize(context.Background(), map[string]interface{}{
		"mode":       "server",
		"addr":       "127.0.0.1:0",
		"tls_config": serverTLS,
		"registry":   reg,
	})
	require.NoError(t, err)
	require.NoError(t, server.Start(context.Background()))
	t.Cleanup(server.ForceStop)

	listenAddr := server.ListenAddr()

	client := New(ModeClient)
	err = client.Initialize(context.Background(), map[string]interface{}{
		"mode":       "client",
		"addr":       listenAddr,
		"tls_config": clientTLS,
		"steward_id": stewardID,
	})
	require.NoError(t, err)
	require.NoError(t, client.Start(context.Background()))
	t.Cleanup(func() { _ = client.Stop(context.Background()) })

	return server, reg
}

// TestApprovalChecker_NilChecker_AdmitsByDefault verifies that the default
// (no checker injected) allows all mTLS-authenticated stewards.
func TestApprovalChecker_NilChecker_AdmitsByDefault(t *testing.T) {
	t.Parallel()
	// newTestEnv creates a server with no approval checker (default).
	env := newTestEnv(t, "steward-approve-default")

	_, ok := env.registry.Get("steward-approve-default")
	assert.True(t, ok, "steward should be admitted by default (no checker)")
}

// TestApprovalChecker_ApproveAll_AdmitsSteward verifies that a checker that
// always returns (true, nil) does not prevent steward admission.
func TestApprovalChecker_ApproveAll_AdmitsSteward(t *testing.T) {
	t.Parallel()
	_, reg := newTestEnvWithChecker(t, "steward-approve-ok", approveAll{})

	require.Eventually(t, func() bool {
		_, ok := reg.Get("steward-approve-ok")
		return ok
	}, 5*time.Second, 10*time.Millisecond, "steward should be admitted by approveAll checker")
}

// TestApprovalChecker_RejectAll_BlocksSteward verifies that a checker returning
// (false, nil) prevents the steward from being admitted to the registry.
func TestApprovalChecker_RejectAll_BlocksSteward(t *testing.T) {
	t.Parallel()
	_, reg := newTestEnvWithChecker(t, "steward-reject", rejectAll{})

	// Give time for connection attempts; the steward should never appear.
	time.Sleep(500 * time.Millisecond)
	_, ok := reg.Get("steward-reject")
	assert.False(t, ok, "steward should be blocked by rejectAll checker")
}

// TestApprovalChecker_ErrorChecker_FailsClosed verifies that authorization
// dependency failures never become implicit approval.
func TestApprovalChecker_ErrorChecker_FailsClosed(t *testing.T) {
	t.Parallel()
	_, reg := newTestEnvWithChecker(t, "steward-checker-err", errorChecker{})

	require.Never(t, func() bool {
		_, ok := reg.Get("steward-checker-err")
		return ok
	}, 500*time.Millisecond, 10*time.Millisecond, "steward must not be admitted when checker errors")
}

// TestWithApprovalChecker_OptionSetsField verifies that WithApprovalChecker
// correctly wires the checker into the Provider struct.
func TestWithApprovalChecker_OptionSetsField(t *testing.T) {
	t.Parallel()
	checker := approveAll{}
	p := New(ModeServer, WithApprovalChecker(checker))
	assert.Equal(t, StewardApprovalChecker(checker), p.approvalChecker)
}

func TestRequiredSecurityStoresFailInitializationClosed(t *testing.T) {
	baseConfig := func(store business.RegistrationTokenStore) map[string]interface{} {
		return map[string]interface{}{
			"mode":                     "server",
			"addr":                     "127.0.0.1:7443",
			"tls_config":               &tls.Config{MinVersion: tls.VersionTLS13},
			"registration_token_store": store,
			"require_security_stores":  true,
		}
	}

	t.Run("missing approval checker", func(t *testing.T) {
		provider := New(ModeServer)
		err := provider.Initialize(context.Background(), baseConfig(newInMemoryTokenStore()))
		require.ErrorContains(t, err, "approval checker")
	})

	t.Run("token store without atomic consumer", func(t *testing.T) {
		provider := New(ModeServer, WithApprovalChecker(approveAll{}))
		err := provider.Initialize(context.Background(), baseConfig(&nonConsumingRegistrationStore{}))
		require.ErrorContains(t, err, "atomic registration token consumption")
	})

	t.Run("complete security services", func(t *testing.T) {
		provider := New(ModeServer, WithApprovalChecker(approveAll{}))
		require.NoError(t, provider.Initialize(context.Background(), baseConfig(newInMemoryTokenStore())))
	})
}

func TestStewardStoreApprovalChecker_StatusPolicy(t *testing.T) {
	allowed := []business.StewardStatus{
		business.StewardStatusRegistered,
		business.StewardStatusActive,
		business.StewardStatusLost,
	}
	for _, stewardStatus := range allowed {
		checker := NewStewardStoreApprovalChecker(&approvalTestStore{
			record: &business.StewardRecord{Status: stewardStatus},
		})
		ok, err := checker.IsApproved(t.Context(), "steward")
		require.NoError(t, err)
		assert.True(t, ok, "status %s should be reconnect-capable", stewardStatus)
	}

	denied := []business.StewardStatus{
		business.StewardStatusDeregistered,
		business.StewardStatusArchived,
		business.StewardStatusDormant,
		business.StewardStatusRevoked,
	}
	for _, stewardStatus := range denied {
		checker := NewStewardStoreApprovalChecker(&approvalTestStore{
			record: &business.StewardRecord{Status: stewardStatus},
		})
		ok, err := checker.IsApproved(t.Context(), "steward")
		require.NoError(t, err)
		assert.False(t, ok, "status %s must be denied", stewardStatus)
	}
}

func TestStewardStoreApprovalChecker_StoreFailureFailsClosed(t *testing.T) {
	checker := NewStewardStoreApprovalChecker(&approvalTestStore{err: errors.New("database unavailable")})
	ok, err := checker.IsApproved(t.Context(), "steward")
	require.ErrorContains(t, err, "database unavailable")
	assert.False(t, ok)
}
