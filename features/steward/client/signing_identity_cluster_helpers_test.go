// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package client

// Three-node harness for the cluster signing identity scenarios (Issue #4798).
//
// This lives in package client, not test/integration/cluster, because the steward's
// push_signing_cert handler and its trust set are unexported TransportClient
// members: the only way to run the real handler is from inside the package, as
// signing_migration_real_handler_test.go already does.
//
// Everything on the controller side is the production code: one cert.Manager per
// node (separate certificate directories), one cluster-atomic SecretStore holding
// the shared signing keys, one cursor store, one acknowledgement store and one
// revocation store shared by all three, and one SigningRotationService,
// SigningRetirementService and StewardSigningMigrationService per node. Each
// simulated steward is a real TransportClient with its real command handler and
// push handler, verifying against its own trust set.

import (
	"context"
	"io/fs"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/features/controller/commands"
	"github.com/cfgis/cfgms/features/controller/service"
	stewardcommands "github.com/cfgis/cfgms/features/steward/commands"
	"github.com/cfgis/cfgms/pkg/cert"
	certinterfaces "github.com/cfgis/cfgms/pkg/cert/interfaces"
	cpinterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/testutil"
	"github.com/cfgis/cfgms/pkg/transport/registry"
)

const (
	clusterSigningTenant = "cluster-ca-tenant"
	clusterSigningCN     = "cfgms-config-signer"
)

// clusterStores are the cluster-visible stores every node shares.
type clusterStores struct {
	cursor     certinterfaces.SigningCursorStore
	acks       certinterfaces.SigningTrustAckStore
	revocation certinterfaces.RevocationStore
}

// fileClusterStores returns real file-backed stores. One instance is shared by all
// three nodes, which is what a cluster-visible store is.
func fileClusterStores(t *testing.T) clusterStores {
	t.Helper()
	cursor, err := cert.NewFileSigningCursorStore(t.TempDir())
	require.NoError(t, err)
	acks, err := cert.NewFileSigningTrustAckStore(t.TempDir())
	require.NoError(t, err)
	rev, err := cert.NewFileRevocationStore(t.TempDir())
	require.NoError(t, err)
	return clusterStores{cursor: cursor, acks: acks, revocation: rev}
}

// countingCursorStore wraps a real cursor store and counts committed transitions,
// so a test can assert a rotation performed one cluster-wide transition.
type countingCursorStore struct {
	certinterfaces.SigningCursorStore
	mu          sync.Mutex
	transitions int
}

func (c *countingCursorStore) TransitionCursor(ctx context.Context, newSerial string, overlapDays int, force bool) (*cert.SigningCertCursor, error) {
	cur, err := c.SigningCursorStore.TransitionCursor(ctx, newSerial, overlapDays, force)
	if err == nil {
		c.mu.Lock()
		c.transitions++
		c.mu.Unlock()
	}
	return cur, err
}

func (c *countingCursorStore) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.transitions
}

// clusterNode is one controller node.
type clusterNode struct {
	idx       int
	dir       string
	mgr       *cert.Manager
	rotation  *service.SigningRotationService
	retire    *service.SigningRetirementService
	migration *service.StewardSigningMigrationService
	local     *service.SigningMigrationService
	pub       *commands.Publisher
	reg       *registry.InMemoryRegistry
	signer    signature.Signer

	// localSerial is the node's own pre-shared-identity signing serial (legacy clusters).
	localSerial string
	localPEM    []byte
}

// signingCluster is three controller nodes over shared stores.
type signingCluster struct {
	t          *testing.T
	nodes      []*clusterNode
	stores     clusterStores
	cursor     *countingCursorStore
	keyStore   certinterfaces.SigningKeyStore
	controller *service.ControllerService
	logger     logging.Logger

	mu       sync.Mutex
	stewards map[string]*clusterSteward
}

// clusterOpts selects how the cluster starts.
type clusterOpts struct {
	// legacy gives each node its own local signing certificate before the shared
	// identity exists, so the cluster starts in LegacyLocal mode.
	legacy bool
	// stores overrides the file-backed stores (PostgreSQL-backed runs).
	stores *clusterStores
}

func newSigningCluster(t *testing.T, opts clusterOpts) *signingCluster {
	t.Helper()
	ctx := context.Background()
	secrets := testutil.NewMemSecretStore()

	stores := clusterStores{}
	if opts.stores != nil {
		stores = *opts.stores
	} else {
		stores = fileClusterStores(t)
	}
	counting := &countingCursorStore{SigningCursorStore: stores.cursor}

	ks, err := cert.NewSecretStoreSigningKeyStore(secrets, clusterSigningTenant, "")
	require.NoError(t, err)

	c := &signingCluster{
		t: t, stores: stores, cursor: counting, keyStore: ks,
		controller: service.NewControllerService(logging.NewNoopLogger()),
		logger:     logging.NewNoopLogger(),
		stewards:   map[string]*clusterSteward{},
	}

	build := func(dir string, withKeys bool) *cert.Manager {
		cfg := &cert.ManagerConfig{
			StoragePath:        dir,
			CAConfig:           &cert.CAConfig{Organization: "Test", Country: "US", ValidityDays: 365, KeySize: 2048},
			SigningCursorStore: counting,
			RevocationStore:    stores.revocation,
		}
		if withKeys {
			nodeKS, kerr := cert.NewSecretStoreSigningKeyStore(secrets, clusterSigningTenant, "")
			require.NoError(t, kerr)
			cfg.SigningKeyStore = nodeKS
		}
		m, merr := cert.NewManagerFromSecretStore(ctx, secrets, clusterSigningTenant, "cluster-ca", cfg)
		require.NoError(t, merr)
		return m
	}
	signingCfg := &cert.SigningCertConfig{CommonName: clusterSigningCN, ValidityDays: 365, KeySize: 2048}

	for i := 0; i < 3; i++ {
		n := &clusterNode{idx: i, dir: t.TempDir()}
		if opts.legacy {
			legacy := build(n.dir, false)
			require.NoError(t, legacy.EnsureSigningCertificate(signingCfg))
			local, lerr := legacy.GetCurrentCertForPurpose(cert.PurposeSigning)
			require.NoError(t, lerr)
			n.localSerial = local.SerialNumber
			n.localPEM = local.CertificatePEM
			n.mgr = build(n.dir, true)
			results, ierr := n.mgr.ImportLocalSigningCertificates(ctx)
			require.NoError(t, ierr)
			require.Len(t, results, 1)
			require.True(t, results[0].Imported, results[0].Reason)
		} else {
			n.mgr = build(n.dir, true)
			require.NoError(t, n.mgr.EnsureSigningCertificate(signingCfg))
		}
		c.wireNode(n)
		c.nodes = append(c.nodes, n)
	}
	return c
}

// wireNode builds the node's services around its Manager.
func (c *signingCluster) wireNode(n *clusterNode) {
	t := c.t
	n.reg = registry.NewRegistry()
	n.signer = signature.NewDynamicSigner(service.NewSigningResolver(n.mgr))

	cp := &clusterControlPlane{cluster: c}
	pub, err := commands.New(&commands.Config{ControlPlane: cp, Logger: c.logger, Signer: n.signer})
	require.NoError(t, err)
	n.pub = pub

	n.rotation = service.NewSigningRotationService(n.mgr, c.logger)
	n.rotation.SetPublisher(pub)
	n.rotation.SetControllerService(c.controller)
	n.rotation.SetNodeID(nodeName(n.idx))

	n.retire = service.NewSigningRetirementService(n.rotation, nil, c.logger)

	n.migration = service.NewStewardSigningMigrationService(n.mgr, c.stores.acks, c.logger)
	n.migration.SetPublisher(pub)
	n.migration.SetConnectedStewards(n.reg)
	n.migration.SetTimings(time.Second, time.Hour, 200*time.Millisecond)
	t.Cleanup(n.migration.Stop)

	n.local = service.NewSigningMigrationService(n.mgr, c.logger)
}

func nodeName(idx int) string { return "node-" + string(rune('1'+idx)) }

// clusterControlPlane is the control plane every node's publisher sends through.
// A command goes to the steward wherever it holds its stream, the way cluster
// delivery routes it; a steward connected to no node is unreachable.
type clusterControlPlane struct {
	cpinterfaces.ControlPlaneProvider
	cluster *signingCluster
}

func (p *clusterControlPlane) SendCommand(ctx context.Context, sc *cpTypes.SignedCommand) error {
	st := p.cluster.connectedSteward(sc.Command.StewardID)
	if st == nil {
		return cpinterfaces.ErrStewardNotConnected
	}
	st.deliver(ctx, sc)
	return nil
}

func (c *signingCluster) connectedSteward(id string) *clusterSteward {
	c.mu.Lock()
	defer c.mu.Unlock()
	st := c.stewards[id]
	if st == nil || st.node() == nil {
		return nil
	}
	return st
}

// rootCtx is a request context for an unscoped (root) operator.
func rootCtx() context.Context {
	return context.WithValue(context.Background(), ctxkeys.TenantScopeKey, ctxkeys.NewRootScope())
}

// ---------------------------------------------------------------------------
// Simulated steward: a real TransportClient and command handler.
// ---------------------------------------------------------------------------

type clusterSteward struct {
	cluster *signingCluster
	id      string
	c       *TransportClient
	handler *stewardcommands.Handler

	mu       sync.Mutex
	conn     *clusterNode
	accepted map[string]bool  // command ID -> reached a handler
	rejected map[string]error // command ID -> verification error
}

type loopbackStream struct{}

func (loopbackStream) SendMsg(interface{}) error { return nil }

func (s *clusterSteward) node() *clusterNode {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn
}

// deliver runs a command through the steward's real command handler. A command
// the steward rejects is dropped, as on a real stream.
func (s *clusterSteward) deliver(ctx context.Context, sc *cpTypes.SignedCommand) {
	err := s.handler.HandleCommand(ctx, sc)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.rejected[sc.Command.ID] = err
	}
}

// newSteward creates a steward pinning the cluster CA and trusting trustedPEMs,
// the signing certificates it was enrolled with.
func (c *signingCluster) newSteward(id string, trustedPEMs ...[]byte) *clusterSteward {
	t := c.t
	t.Helper()
	caPEM, err := c.nodes[0].mgr.GetCACertificate()
	require.NoError(t, err)

	tc := minimalClientForPushTest(t)
	tc.stewardID = id
	pems := make([]string, 0, len(trustedPEMs))
	for _, p := range trustedPEMs {
		pems = append(pems, string(p))
	}
	tc.mu.Lock()
	tc.caCertPEM = string(caPEM)
	tc.signingCertPEMs = pems
	tc.mu.Unlock()

	st := &clusterSteward{
		cluster: c, id: id, c: tc,
		accepted: map[string]bool{}, rejected: map[string]error{},
	}
	handler, err := stewardcommands.New(&stewardcommands.Config{
		StewardID: id,
		Logger:    logging.NewNoopLogger(),
		Verifier:  tc.buildVerifierOnDemand(),
		OnStatus: func(ctx context.Context, ev *cpTypes.Event) {
			if n := st.node(); n != nil {
				_ = n.pub.HandleEventUpdate(ctx, ev)
			}
		},
	})
	require.NoError(t, err)
	handler.RegisterHandler(cpTypes.CommandPushSigningCert, func(ctx context.Context, cmd *cpTypes.Command) error {
		return tc.handlePushSigningCert(ctx, cmd)
	})
	handler.RegisterHandler(cpTypes.CommandSyncConfig, func(_ context.Context, cmd *cpTypes.Command) error {
		st.mu.Lock()
		st.accepted[cmd.ID] = true
		st.mu.Unlock()
		return nil
	})
	st.handler = handler
	tc.mu.Lock()
	tc.commandHandler = handler
	tc.mu.Unlock()

	require.NoError(t, c.controller.RegisterSteward(id, "root", "", "active"))
	c.mu.Lock()
	c.stewards[id] = st
	c.mu.Unlock()
	return st
}

// connect attaches the steward to node idx and runs that node's connect hooks, in
// the order the server runs them: the signing refresh, then the migration queue.
func (c *signingCluster) connect(st *clusterSteward, idx int) {
	c.t.Helper()
	n := c.nodes[idx]
	st.mu.Lock()
	st.conn = n
	st.mu.Unlock()
	require.NoError(c.t, n.reg.Register(&registry.StewardConnection{StewardID: st.id, Sender: loopbackStream{}}))
	require.NoError(c.t, n.rotation.OnConnect(context.Background(), st.id))
	require.NoError(c.t, n.migration.OnConnect(context.Background(), st.id))
}

// disconnect drops the steward's stream.
func (c *signingCluster) disconnect(st *clusterSteward) {
	c.t.Helper()
	st.mu.Lock()
	n := st.conn
	st.conn = nil
	st.mu.Unlock()
	if n != nil {
		n.reg.Unregister(st.id)
	}
}

// sendCommand publishes an ordinary command through node idx and reports whether
// the steward accepted it.
func (c *signingCluster) sendCommand(idx int, st *clusterSteward) bool {
	c.t.Helper()
	id, err := c.nodes[idx].pub.PublishCommand(context.Background(), st.id, cpTypes.CommandSyncConfig, map[string]interface{}{})
	require.NoError(c.t, err)
	// A command that fails authentication is rejected synchronously; an accepted one
	// is dispatched to its handler in the background.
	st.mu.Lock()
	_, rejected := st.rejected[id]
	st.mu.Unlock()
	if rejected {
		return false
	}
	return eventuallyTrue(2*time.Second, func() bool {
		st.mu.Lock()
		defer st.mu.Unlock()
		return st.accepted[id]
	})
}

func eventuallyTrue(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return cond()
}

// acceptsConfig reports whether the steward's verifier accepts a payload signed
// through node idx, the way a config transfer is signed.
func (c *signingCluster) acceptsConfig(idx int, st *clusterSteward) bool {
	c.t.Helper()
	payload := []byte(`{"tenant":"acme-corp","modules":["file"]}`)
	sig, err := c.nodes[idx].signer.Sign(payload)
	require.NoError(c.t, err)
	return st.c.buildVerifierOnDemand().Verify(payload, sig) == nil
}

// trust is the steward's trust set as certificate fingerprints (the same SHA-256
// of the DER the steward dedupes by).
func (s *clusterSteward) trust() []string {
	s.c.mu.RLock()
	defer s.c.mu.RUnlock()
	out := make([]string, 0, len(s.c.signingCertPEMs))
	for _, p := range s.c.signingCertPEMs {
		parsed, err := cert.ParseCertificateFromPEM([]byte(p))
		if err != nil {
			out = append(out, "unparseable")
			continue
		}
		out = append(out, certFingerprint(parsed.Raw))
	}
	sort.Strings(out)
	return out
}

// fingerprintOfPEM is the fingerprint the steward records for a certificate PEM.
func fingerprintOfPEM(t *testing.T, certPEM []byte) string {
	t.Helper()
	parsed, err := cert.ParseCertificateFromPEM(certPEM)
	require.NoError(t, err)
	return certFingerprint(parsed.Raw)
}

// fingerprintOfSerial is the fingerprint of the signing certificate with serial,
// exported from node idx.
func (c *signingCluster) fingerprintOfSerial(idx int, serial string) string {
	c.t.Helper()
	pemBytes, _, err := c.nodes[idx].mgr.ExportCertificate(serial, false, false)
	require.NoError(c.t, err)
	return fingerprintOfPEM(c.t, pemBytes)
}

// certPEM exports the certificate with serial from node idx.
func (c *signingCluster) certPEM(idx int, serial string) []byte {
	c.t.Helper()
	pemBytes, _, err := c.nodes[idx].mgr.ExportCertificate(serial, false, false)
	require.NoError(c.t, err)
	return pemBytes
}

// currentSerial is the signing serial node idx resolves right now.
func (c *signingCluster) currentSerial(idx int) string {
	cur, err := c.nodes[idx].mgr.GetCurrentCertForPurpose(cert.PurposeSigning)
	if err != nil {
		return ""
	}
	return cur.SerialNumber
}

// awaitAllNodesCurrent waits until every node signs with serial. A node caches its
// resolved signing identity for a few seconds, so a rotation performed through one
// node reaches the others within that bound.
func (c *signingCluster) awaitAllNodesCurrent(serial string) {
	c.t.Helper()
	require.Eventually(c.t, func() bool {
		for i := range c.nodes {
			if c.currentSerial(i) != serial {
				return false
			}
		}
		return true
	}, 20*time.Second, 50*time.Millisecond, "every node must resolve signing serial %s", serial)
}

// awaitTrust waits until the steward trusts exactly want (fingerprints).
func (s *clusterSteward) awaitTrust(t *testing.T, what string, want ...string) {
	t.Helper()
	sort.Strings(want)
	require.Eventually(t, func() bool {
		got := s.trust()
		if len(got) != len(want) {
			return false
		}
		for i := range got {
			if got[i] != want[i] {
				return false
			}
		}
		return true
	}, 20*time.Second, 20*time.Millisecond, what)
}

// signingKeyFiles walks dir for signing-certificate key.pem files; the CA's key
// directory is not a signing key.
func signingKeyFiles(t *testing.T, dir string) []string {
	t.Helper()
	var found []string
	require.NoError(t, filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && d.Name() == "key.pem" && filepath.Base(filepath.Dir(p)) != "ca" {
			found = append(found, p)
		}
		return err
	}))
	return found
}
