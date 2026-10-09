// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package service_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/features/controller/commands"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/pkg/cert"
	grpcCP "github.com/cfgis/cfgms/pkg/controlplane/providers/grpc"
	"github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/testutil"
	"github.com/cfgis/cfgms/pkg/transport/registry"
)

const clusterTestTenant = "cluster-ca-tenant"

// clusterNodes builds n controller nodes sharing one CA, secret store and
// signing cursor, each with its own certificate directory.
func clusterNodes(t *testing.T, n int) []*cert.Manager {
	t.Helper()
	secrets := testutil.NewMemSecretStore()
	cursor, err := cert.NewFileSigningCursorStore(t.TempDir())
	require.NoError(t, err)
	nodes := make([]*cert.Manager, n)
	for i := range nodes {
		ks, err := cert.NewSecretStoreSigningKeyStore(secrets, clusterTestTenant, "")
		require.NoError(t, err)
		nodes[i], err = cert.NewManagerFromSecretStore(context.Background(), secrets, clusterTestTenant, "cluster-ca", &cert.ManagerConfig{
			StoragePath:        t.TempDir(),
			CAConfig:           &cert.CAConfig{Organization: "Test", Country: "US", ValidityDays: 365, KeySize: 2048},
			SigningCursorStore: cursor,
			SigningKeyStore:    ks,
		})
		require.NoError(t, err)
		require.NoError(t, nodes[i].EnsureSigningCertificate(&cert.SigningCertConfig{CommonName: "cfgms-config-signer", ValidityDays: 365, KeySize: 2048}))
	}
	return nodes
}

func rootCtx() context.Context {
	return context.WithValue(context.Background(), ctxkeys.TenantScopeKey, ctxkeys.NewRootScope())
}

func TestRotate_ReportsNodeIDAndStoresKeyInSharedStore(t *testing.T) {
	t.Parallel()
	nodes := clusterNodes(t, 2)
	svc := service.NewSigningRotationService(nodes[0], logging.NewNoopLogger())
	svc.SetControllerService(service.NewControllerService(logging.NewNoopLogger()))
	svc.SetNodeID("node-a")

	result, err := svc.Rotate(rootCtx(), "operator-serial", 7, false)
	require.NoError(t, err)
	assert.Equal(t, "node-a", result.NodeID)
	assert.NotEqual(t, result.OldSerial, result.NewSerial)

	// The other node resolves the rotated certificate from the shared store.
	cur, err := nodes[1].GetCurrentCertForPurpose(cert.PurposeSigning)
	require.NoError(t, err)
	assert.Equal(t, result.NewSerial, cur.SerialNumber)
}

func TestRotate_ConcurrentRotationOnOtherNodeIsInProgress(t *testing.T) {
	t.Parallel()
	nodes := clusterNodes(t, 2)
	svcA := service.NewSigningRotationService(nodes[0], logging.NewNoopLogger())
	svcA.SetControllerService(service.NewControllerService(logging.NewNoopLogger()))
	svcB := service.NewSigningRotationService(nodes[1], logging.NewNoopLogger())
	svcB.SetControllerService(service.NewControllerService(logging.NewNoopLogger()))

	_, err := svcA.Rotate(rootCtx(), "operator-serial", 7, false)
	require.NoError(t, err)
	_, err = svcB.Rotate(rootCtx(), "operator-serial", 7, false)
	require.ErrorIs(t, err, cert.ErrSigningRotationInProgress)
}

// TestEnsureStewardCurrent_ClusterSignsWithRotatingCertFromSharedStore: a steward
// that missed a rotation performed through node A is served by node B, which must
// sign the push with the rotating certificate resolved from the shared store.
func TestEnsureStewardCurrent_ClusterSignsWithRotatingCertFromSharedStore(t *testing.T) {
	t.Parallel()
	const stewardID = "steward-cluster-missed-rotation"
	nodes := clusterNodes(t, 2)

	original, err := nodes[0].GetCurrentCertForPurpose(cert.PurposeSigning)
	require.NoError(t, err)
	originalPEM, _, err := nodes[0].ExportCertificate(original.SerialNumber, false, false)
	require.NoError(t, err)
	oldVerifier, err := signature.NewVerifier(&signature.VerifierConfig{CertificatePEM: originalPEM})
	require.NoError(t, err)

	logger := logging.NewNoopLogger()
	svcA := service.NewSigningRotationService(nodes[0], logger)
	svcA.SetControllerService(service.NewControllerService(logger))
	// Zero overlap: the rotating cert is the only one a steward that missed the
	// rotation can still verify against.
	result, err := svcA.Rotate(rootCtx(), "operator-serial", 0, false)
	require.NoError(t, err)
	require.NotEqual(t, original.SerialNumber, result.NewSerial)

	svcB := service.NewSigningRotationService(nodes[1], logger)
	serverTLS, clientTLS := tlsForTest(t, stewardID)
	reg := registry.NewRegistry()
	serverProvider := grpcCP.New(grpcCP.ModeServer)
	require.NoError(t, serverProvider.Initialize(context.Background(), map[string]interface{}{
		"mode": "server", "addr": "127.0.0.1:0", "tls_config": serverTLS, "registry": reg,
	}))
	require.NoError(t, serverProvider.Start(context.Background()))
	t.Cleanup(serverProvider.ForceStop)
	publisher, err := commands.New(&commands.Config{ControlPlane: serverProvider, Logger: logger})
	require.NoError(t, err)
	svcB.SetPublisher(publisher)

	clientProvider := grpcCP.New(grpcCP.ModeClient)
	require.NoError(t, clientProvider.Initialize(context.Background(), map[string]interface{}{
		"mode": "client", "addr": serverProvider.ListenAddr(), "tls_config": clientTLS, "steward_id": stewardID,
	}))
	var mu sync.Mutex
	var received []*types.SignedCommand
	require.NoError(t, clientProvider.SubscribeCommands(context.Background(), stewardID, func(_ context.Context, sc *types.SignedCommand) error {
		mu.Lock()
		received = append(received, sc)
		mu.Unlock()
		return nil
	}))
	require.NoError(t, clientProvider.Start(context.Background()))
	t.Cleanup(func() { _ = clientProvider.Stop(context.Background()) })
	require.Eventually(t, func() bool { _, ok := reg.Get(stewardID); return ok }, 5*time.Second, 10*time.Millisecond)

	require.NoError(t, svcB.EnsureStewardCurrent(context.Background(), stewardID))

	var push *types.SignedCommand
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range received {
			if c.Command.Type == types.CommandPushSigningCert {
				push = c
				return true
			}
		}
		return false
	}, 5*time.Second, 10*time.Millisecond, "push_signing_cert must be received")
	require.NotNil(t, push.Signature)

	rawParams := push.RawParams
	if rawParams == nil {
		rawParams = types.InterfaceParamsToStringMap(push.Command.Params)
	}
	cmdBytes, err := types.CommandSigningBytes(&push.Command, rawParams)
	require.NoError(t, err)
	require.NoError(t, oldVerifier.Verify(cmdBytes, push.Signature),
		"the push served by node B must be signed with the rotating cert from the shared store")
}
