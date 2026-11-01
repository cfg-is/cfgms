// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/cmd/steward/service"
	"github.com/cfgis/cfgms/features/steward/client"
	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/pkg/cert"
	grpcCP "github.com/cfgis/cfgms/pkg/controlplane/providers/grpc"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	dataplaneInterfaces "github.com/cfgis/cfgms/pkg/dataplane/interfaces"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/registration/identity"
	quictransport "github.com/cfgis/cfgms/pkg/transport/quic"
	"github.com/cfgis/cfgms/pkg/transport/registry"
)

const unsafeTokenContent = "tok_unsafe_file_content"

func resetStartupReasons(t *testing.T) {
	t.Helper()
	clear := func() {
		startupReasons.Clear(tokenReasonComponent)
		startupReasons.Clear(trustReasonComponent)
	}
	clear()
	t.Cleanup(clear)
}

// tokenDefects maps each token file defect to the file path that produces it
// and the reason code it must report.
func tokenDefects(t *testing.T) map[string]struct{ path, code string } {
	t.Helper()
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty-token")
	writeSafeTokenFile(t, empty, "")
	unsafe := filepath.Join(dir, "unsafe-token")
	writeSafeTokenFile(t, unsafe, unsafeTokenContent)
	makeReadableByOthers(t, unsafe)
	return map[string]struct{ path, code string }{
		"missing":     {filepath.Join(dir, "absent-token"), "token_file.missing"},
		"empty":       {empty, "token_file.empty"},
		"permissions": {unsafe, "token_file.permissions"},
	}
}

func TestTokenFromFile_StoredIdentity_ContinuesWithEmptyTokenAndReason(t *testing.T) {
	newStoredIdentityFixture(t, "127.0.0.1:1")
	for name, d := range tokenDefects(t) {
		t.Run(name, func(t *testing.T) {
			resetStartupReasons(t)
			token, err := tokenFromFile(d.path)
			require.NoError(t, err)
			assert.Empty(t, token, "the unsafe file's content is never used")
			reasons := startupReasons.List()
			require.Len(t, reasons, 1)
			assert.Equal(t, "registration_token", reasons[0].Component)
			assert.Equal(t, d.code, reasons[0].Code)
			assert.NotContains(t, reasons[0].Message, unsafeTokenContent)
		})
	}
}

func TestTokenFromFile_NoStoredIdentity_StillRefuses(t *testing.T) {
	prev := certStoreDirResolver
	certStoreDirResolver = func() string { return t.TempDir() }
	t.Cleanup(func() { certStoreDirResolver = prev })
	for name, d := range tokenDefects(t) {
		t.Run(name, func(t *testing.T) {
			resetStartupReasons(t)
			token, err := tokenFromFile(d.path)
			require.Error(t, err, "without an identity the token is needed, so the defect stops the start")
			assert.Empty(t, token)
			tfe, ok := service.AsTokenFileError(err)
			require.True(t, ok)
			assert.Equal(t, d.code, "token_file."+string(tfe.Kind))
			assert.Empty(t, startupReasons.List())
		})
	}
}

func TestTokenFromFile_ValidTokenIsUsed(t *testing.T) {
	newStoredIdentityFixture(t, "127.0.0.1:1")
	resetStartupReasons(t)
	path := filepath.Join(t.TempDir(), "registration-token")
	writeSafeTokenFile(t, path, "tok_valid_123")
	token, err := tokenFromFile(path)
	require.NoError(t, err)
	assert.Equal(t, "tok_valid_123", token)
	assert.Empty(t, startupReasons.List())
}

func TestRunRoot_TokenDefectWithStoredIdentity_StartsWithEmptyToken(t *testing.T) {
	newStoredIdentityFixture(t, "127.0.0.1:1")
	for name, d := range tokenDefects(t) {
		t.Run(name, func(t *testing.T) {
			resetStartupReasons(t)
			token, started, err := runRootWithSeam(t, "--regtoken-file", d.path)
			require.NoError(t, err)
			assert.True(t, started)
			assert.Empty(t, token)
		})
	}
}

func TestRunRoot_TokenDefectWithoutStoredIdentity_Refused(t *testing.T) {
	prev := certStoreDirResolver
	certStoreDirResolver = func() string { return t.TempDir() }
	t.Cleanup(func() { certStoreDirResolver = prev })
	for name, d := range tokenDefects(t) {
		t.Run(name, func(t *testing.T) {
			resetStartupReasons(t)
			_, started, err := runRootWithSeam(t, "--regtoken-file", d.path)
			require.Error(t, err)
			assert.False(t, started)
		})
	}
}

// TestRunStewardInternal_EmptyTokenWithStoredIdentity_EntersConnectedMode fails
// if the `regToken != ""` gate is restored: with no token and no --config the
// steward would return without connecting.
func TestRunStewardInternal_EmptyTokenWithStoredIdentity_EntersConnectedMode(t *testing.T) {
	t.Setenv("CFGMS_LOG_DIR", t.TempDir())
	resetStartupReasons(t)
	f := newStoredIdentityFixture(t, "127.0.0.1:4433")
	saved := ControllerURL
	ControllerURL = "https://ctrl.test:4433"
	t.Cleanup(func() { ControllerURL = saved })

	var calls atomic.Int32
	var gotToken atomic.Value
	cf := connectFuncT(func(_ context.Context, token, _ string, _ TrustSource, _ string,
		_ identity.KeyStore, _ bool, _ logging.Logger) (*client.TransportClient, error) {
		gotToken.Store(token)
		calls.Add(1)
		return nil, errors.New("controller unreachable")
	})
	_ = f

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runStewardInternal(ctx, "", "", "", cf) }()

	require.Eventually(t, func() bool { return calls.Load() > 0 }, 30*time.Second, 10*time.Millisecond)
	assert.Equal(t, "", gotToken.Load(), "an empty token flows into the connect function")
	select {
	case err := <-done:
		t.Fatalf("steward exited instead of staying connected-mode: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	cancel()
	require.NoError(t, <-done)
}

func TestRunStewardInternal_EmptyTokenNoIdentity_DoesNotConnect(t *testing.T) {
	t.Setenv("CFGMS_LOG_DIR", t.TempDir())
	prev := certStoreDirResolver
	certStoreDirResolver = func() string { return t.TempDir() }
	t.Cleanup(func() { certStoreDirResolver = prev })
	var calls atomic.Int32
	cf := connectFuncT(func(context.Context, string, string, TrustSource, string,
		identity.KeyStore, bool, logging.Logger) (*client.TransportClient, error) {
		calls.Add(1)
		return nil, errors.New("unexpected")
	})
	require.NoError(t, runStewardInternal(context.Background(), "", "", "", cf))
	assert.Zero(t, calls.Load(), "behaviour without an identity is unchanged until the no-identity story")
}

func TestRunStewardInternal_FailedDataDirCheck_DoesNotUseIdentityAddress(t *testing.T) {
	t.Setenv("CFGMS_LOG_DIR", t.TempDir())
	newStoredIdentityFixture(t, "127.0.0.1:4433")
	saved := ControllerURL
	ControllerURL = ""
	t.Cleanup(func() { ControllerURL = saved })
	prev := dataDirCheck
	dataDirCheck = func(logging.Logger) error { return errors.New("data directory is not secure") }
	t.Cleanup(func() { dataDirCheck = prev })

	var calls atomic.Int32
	cf := connectFuncT(func(context.Context, string, string, TrustSource, string,
		identity.KeyStore, bool, logging.Logger) (*client.TransportClient, error) {
		calls.Add(1)
		return nil, errors.New("must not dial")
	})
	resetStartupReasons(t)
	err := runStewardInternal(context.Background(), "", "", "", cf)
	require.Error(t, err)
	assert.Zero(t, calls.Load(), "the identity's address must not be used after a failed check")
	assert.Empty(t, startupReasons.List(), "no controller_url reason: the identity was never consulted")
}

func TestResolveTrustSourceForStart_StoredAddressNeverWeakerThanStoredMode(t *testing.T) {
	for _, mode := range []string{"compile-baked", "install-pinned", "tofu"} {
		t.Run(mode, func(t *testing.T) {
			resetStartupReasons(t)
			id := &StewardIdentity{StewardID: "s", TransportAddress: "10.0.0.1:4433", TrustMode: mode}
			src, url, err := resolveTrustSourceForStart("", "", "", id)
			require.NoError(t, err)
			assert.Equal(t, "10.0.0.1:4433", url)
			assert.Equal(t, trustSourceFromMode(mode), src)
			assert.NoError(t, checkTrustDowngrade(src, "", id), "must not be weaker than the stored mode")
			require.Len(t, startupReasons.List(), 1)
			assert.Equal(t, "trust", startupReasons.List()[0].Component)
			assert.Equal(t, "controller_url.missing", startupReasons.List()[0].Code)
		})
	}
	t.Run("unrecorded mode takes the strictest source", func(t *testing.T) {
		resetStartupReasons(t)
		src, _, err := resolveTrustSourceForStart("", "", "", &StewardIdentity{StewardID: "s", TransportAddress: "10.0.0.1:4433"})
		require.NoError(t, err)
		assert.Equal(t, trustSourceCompileBaked, src)
	})
}

func TestResolveTrustSourceForStart_ConfiguredURLWinsAndNoIdentityStillErrors(t *testing.T) {
	resetStartupReasons(t)
	id := &StewardIdentity{StewardID: "s", TransportAddress: "10.0.0.1:4433", TrustMode: "compile-baked"}
	src, url, err := resolveTrustSourceForStart("", "https://ctrl.example", "", id)
	require.NoError(t, err)
	assert.Equal(t, trustSourceTOFU, src, "a configured URL keeps today's resolution")
	assert.Equal(t, "https://ctrl.example", url)
	assert.Empty(t, startupReasons.List())

	_, _, err = resolveTrustSourceForStart("", "", "", nil)
	require.Error(t, err)
	_, _, err = resolveTrustSourceForStart("", "", "", &StewardIdentity{StewardID: "s"})
	require.Error(t, err)
}

func TestRegisterWithToken_EmptyTokenIsAClearErrorAndKeepsIdentity(t *testing.T) {
	f := newStoredIdentityFixture(t, "127.0.0.1:1")
	logger := logging.NewLogger("error")
	_, err := registerWithToken(context.Background(), f.certStoreDir, "", "https://ctrl.example", trustSourceTOFU, "", "", nil, "", stewardconfig.StewardConfig{}, false, logger)
	require.ErrorIs(t, err, errNoRegistrationToken)
	_, err = registerAsClone(context.Background(), f.certStoreDir, "", "https://ctrl.example", trustSourceTOFU, "", "", nil, stewardconfig.StewardConfig{}, false, logger)
	require.ErrorIs(t, err, errNoRegistrationToken)
	id, lerr := loadIdentity(f.certStoreDir)
	require.NoError(t, lerr)
	assert.NotNil(t, id, "the stored identity must survive a refused re-registration")
}

// TestRunSteward_TokenDefectHeartbeatCarriesReason connects a steward with a
// real stored identity to a real control plane, for each token file defect, and
// checks the heartbeat carries token_file.<kind>.
func TestRunSteward_TokenDefectHeartbeatCarriesReason(t *testing.T) {
	t.Setenv("CFGMS_LOG_DIR", t.TempDir())
	f := newStoredIdentityFixture(t, "placeholder")
	serverCert := f.serverCert(t)
	serverTLS, err := cert.CreateServerTLSConfig(serverCert.CertificatePEM, serverCert.PrivateKeyPEM, []byte(f.caPEM), tls.VersionTLS13)
	require.NoError(t, err)
	serverTLS.NextProtos = []string{quictransport.ALPNProtocol}
	server := grpcCP.New(grpcCP.ModeServer)
	require.NoError(t, server.Initialize(context.Background(), map[string]interface{}{
		"mode": "server", "addr": "127.0.0.1:0", "tls_config": serverTLS, "registry": registry.NewRegistry(),
	}))
	require.NoError(t, server.Start(context.Background()))
	t.Cleanup(server.ForceStop)
	got := make(chan *cpTypes.Heartbeat, 64)
	require.NoError(t, server.SubscribeHeartbeats(context.Background(), func(_ context.Context, hb *cpTypes.Heartbeat) error {
		got <- hb
		return nil
	}))
	id, err := loadIdentity(f.certStoreDir)
	require.NoError(t, err)
	id.TransportAddress = server.ListenAddr()
	id.TrustMode = "install-pinned"
	require.NoError(t, saveIdentity(f.certStoreDir, *id))

	saved := ControllerURL
	ControllerURL = ""
	t.Cleanup(func() { ControllerURL = saved })

	for name, d := range tokenDefects(t) {
		t.Run(name, func(t *testing.T) {
			resetStartupReasons(t)
			// An earlier connect in this process leaves the data plane provider started.
			_ = dataplaneInterfaces.GetProvider("grpc").Stop(context.Background())
			for len(got) > 0 {
				<-got
			}
			token, err := tokenFromFile(d.path)
			require.NoError(t, err)
			require.Empty(t, token)

			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- runStewardInternal(ctx, token, "", "", nil) }()
			t.Cleanup(func() {
				cancel()
				// A cancelled context is a clean shutdown, not an error.
				assert.NoError(t, <-done)
				// The client's Disconnect leaves the process-wide data plane provider
				// started; stop it so the next defect can connect in this process.
				_ = dataplaneInterfaces.GetProvider("grpc").Stop(context.Background())
			})

			deadline := time.After(60 * time.Second)
			for {
				select {
				case hb := <-got:
					for _, r := range hb.Reasons {
						if r.Component == "registration_token" {
							assert.Equal(t, d.code, r.Code)
							assert.Equal(t, cpTypes.StatusDegraded, hb.Status)
							return
						}
					}
				case err := <-done:
					t.Fatalf("steward exited: %v", err)
				case <-deadline:
					t.Fatal("no heartbeat carried the token file reason")
				}
			}
		})
	}
}
