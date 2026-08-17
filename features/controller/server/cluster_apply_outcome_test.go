// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Tests for cluster-aware apply-outcome EID resolution (Issue #3376).
//
// AC1: a clustered vm resource produces an apply-outcome record under
// cluster:<name>/vm:<name>, returned by GetTimeline for the same EID that carries the
// resource's entity-state observations.
//
// AC2: a resource whose taxonomy kind does not list "cluster" in AuthorityClasses
// resolves host-scoped even when the host is a verified cluster member.
//
// AC3: a cluster-eligible kind on a host with no cluster membership resolves host-scoped
// and does not error.
//
// The remaining tests pin the authority boundary. A steward's own cluster:<name> DNA
// fragment — and any cluster:<name> --contains--> host:<self> edge it declares alongside
// it — is evidence, never proof: both are produced by the peer being judged. Only the
// controller-side ClusterMembership verifier can turn a cluster name into an EID
// authority segment, so an uncorroborated claim must never move a record out of the
// reporting peer's host namespace, even when the named cluster genuinely exists.
//
// Fixtures come from the real emission paths: hyperv.VMConfig.AsMap and
// hyperv.ClusterStatus.AsMap canonicalized by features/steward/dna.NewFragment, ingested
// by the real dnasync writer, and registered through the controller service's real
// registration API. The forged-membership fixture is hand-built on purpose — it models a
// compromised steward, which is not bound to the module's emission code.
package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/features/modules/hyperv"
	stewarddna "github.com/cfgis/cfgms/features/steward/dna"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	eginterfaces "github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	egsqlite "github.com/cfgis/cfgms/pkg/entitygraph/providers/sqlite"
	egtypes "github.com/cfgis/cfgms/pkg/entitygraph/types"
	"github.com/cfgis/cfgms/pkg/entitygraph/writers/dnasync"
	"github.com/cfgis/cfgms/pkg/logging"
)

// clusterDNAFragment builds the cluster:<name> DNA fragment a hyperv node publishes
// after joining a failover cluster, from the module's own ClusterStatus.AsMap output.
// This is the controller-held evidence the resolver draws candidate names from.
func clusterDNAFragment(t *testing.T, clusterName string, memberNodes ...string) *commonpb.Fragment {
	t.Helper()
	status := &hyperv.ClusterStatus{
		Name:            clusterName,
		MemberNodes:     memberNodes,
		CNOOwnerNode:    memberNodes[0],
		Found:           true,
		ClusterAccessOK: true,
	}
	frag, err := stewarddna.NewFragment("cluster:"+clusterName, "observer:hyperv", status)
	require.NoError(t, err, "canonicalize cluster fragment")
	return frag
}

// clusteredVMFragment builds the vm:<name> fragment a hyperv node publishes for a
// clustered (HA-role) VM, from the module's own VMConfig.AsMap output. Its
// ha_role.cluster_name is what the dnasync writer's membership-gated branch reads when
// it mints the cluster-scoped entity-state EID.
func clusteredVMFragment(t *testing.T, vmName, clusterName string) *commonpb.Fragment {
	t.Helper()
	return vmFragment(t, vmName, &hyperv.HARoleConfig{ClusterName: clusterName})
}

// standaloneVMFragment builds the vm:<name> fragment for a node-local VM: no ha_role, so
// the dnasync writer records it under the reporting host's own authority.
func standaloneVMFragment(t *testing.T, vmName string) *commonpb.Fragment {
	t.Helper()
	return vmFragment(t, vmName, nil)
}

func vmFragment(t *testing.T, vmName string, haRole *hyperv.HARoleConfig) *commonpb.Fragment {
	t.Helper()
	vm := &hyperv.VMConfig{
		Name:       vmName,
		MemoryMB:   2048,
		CPUCount:   2,
		Generation: 2,
		State:      "running",
		HARole:     haRole,
	}
	frag, err := stewarddna.NewFragment("vm:"+vmName, "observer:hyperv", vm)
	require.NoError(t, err, "canonicalize vm fragment")
	return frag
}

// forgedMembershipFragment is the fragment a COMPROMISED steward ships to claim a
// cluster it does not belong to: a bare cluster:<name> fragment (whose EID authority the
// dnasync writer takes from the fragment id, by design, because cluster fragments are
// the evidence membership views are built from) declaring a contains edge to the "self"
// sentinel, which resolves to the reporting peer's bare host EID. It is hand-built
// because a compromised host is not bound to the module's emission code.
func forgedMembershipFragment(t *testing.T, clusterName string) *commonpb.Fragment {
	t.Helper()
	frag, err := stewarddna.NewFragment("cluster:"+clusterName, "observer:hyperv", stewarddna.MapState{
		"name":  clusterName,
		"found": "true",
		"__entitygraph_edges": []interface{}{
			map[string]interface{}{"type": "contains", "to": "self"},
		},
	})
	require.NoError(t, err, "canonicalize forged cluster fragment")
	return frag
}

// registerStewardWithDNA registers a steward through the controller service's real
// registration API and attaches DNA fragments, which is the state a prior authenticated
// SyncDNA round-trip leaves behind.
func registerStewardWithDNA(t *testing.T, svc *service.ControllerService, peerID, tenantID string, frags ...*commonpb.Fragment) {
	t.Helper()
	require.NoError(t, svc.RegisterSteward(peerID, tenantID, "", "active"))
	require.True(t, svc.SetStewardDNA(peerID, &commonpb.DNA{Id: peerID, Fragments: frags}),
		"steward %q must be registered before its DNA is set", peerID)
}

// newClusterTestServer returns a minimal Server wired with the entity-graph provider, a
// ControllerService, and the cluster-membership verifier that gates cluster authority.
// Pass a nil verifier to exercise the unwired (deny-everything) default.
func newClusterTestServer(t *testing.T, p *egsqlite.SQLiteEntityGraphProvider, svc *service.ControllerService, membership dnasync.ClusterMembership) *Server {
	t.Helper()
	s := &Server{
		egProvider:        p,
		controllerService: svc,
		logger:            logging.ForModule("cluster-apply-outcome-test"),
	}
	if membership != nil {
		s.SetEntityGraphClusterMembership(membership)
	}
	return s
}

// writeEntityState ingests DNA fragments through the real dnasync writer using the same
// membership verifier the server is given. This is what puts entity state — cluster- or
// host-scoped, according to that one verifier — in the graph.
func writeEntityState(t *testing.T, p *egsqlite.SQLiteEntityGraphProvider, membership dnasync.ClusterMembership, peerID string, frags ...*commonpb.Fragment) {
	t.Helper()
	w, err := dnasync.New(p, dnasync.WithClusterMembership(membership))
	require.NoError(t, err)
	require.NoError(t, w.WriteFragmentDelta(context.Background(), peerID, frags, nil, egtypes.DefaultTaxonomy()))
}

// hasApplyOutcome reports whether the entity graph holds an apply-outcome observation
// for eid within one minute of at.
func hasApplyOutcome(t *testing.T, p *egsqlite.SQLiteEntityGraphProvider, eidStr string, at time.Time) bool {
	t.Helper()
	eid, err := egtypes.ParseEID(eidStr)
	require.NoError(t, err)
	history, err := p.GetHistory(context.Background(), eid, eginterfaces.TimeRange{
		From: at.Add(-time.Minute),
		To:   at.Add(time.Minute),
	})
	require.NoError(t, err)
	for _, hr := range history {
		if hr.Observation.Kind == egtypes.ObservationKindApplyOutcome {
			return true
		}
	}
	return false
}

// applyOutcomeDetails builds the Event.Details payload for a single apply-outcome
// record, through the same proto wire round-trip the control plane performs.
func applyOutcomeDetails(t *testing.T, configVersion, resourceID, moduleName string, at time.Time) map[string]interface{} {
	t.Helper()
	return simulateDetailsRoundTrip(t, map[string]interface{}{
		"config_version": configVersion,
		"apply_outcomes": []controlplaneTypes.ApplyOutcomeRecord{{
			ResourceID: resourceID,
			ModuleName: moduleName,
			Status:     "applied",
			Timestamp:  at,
		}},
	})
}

// TestClusteredApplyOutcomeLandsOnClusterEID is the required AC1 test.
//
// A clustered VM's apply-outcome must land on cluster:<name>/vm:<name> — the same EID
// its entity-state observations use — so GetTimeline for that EID returns both, which is
// the intent-to-outcome join this story exists to deliver.
func TestClusteredApplyOutcomeLandsOnClusterEID(t *testing.T) {
	p := newApplyOutcomeTestEGProvider(t)
	ctx := context.Background()

	const peerID = "node-a"
	const clusterName = "cluster-prod"
	const vmName = "myvm"
	const resourceID = "vm:" + vmName
	const tenantID = "root/tenant-a"
	const configVersion = "v-ac1"
	now := time.Now().UTC()

	// One verifier for both paths: the entity-state writer and the apply-outcome
	// resolver are gated by the same answer, so their EIDs cannot diverge.
	membership := dnasync.NewStaticClusterMembership(map[string][]string{
		clusterName: {peerID},
	})

	svc := service.NewControllerService(logging.ForModule("ac1-svc"))
	registerStewardWithDNA(t, svc, peerID, tenantID, clusterDNAFragment(t, clusterName, peerID))
	writeEntityState(t, p, membership, peerID, clusteredVMFragment(t, vmName, clusterName))

	s := newClusterTestServer(t, p, svc, membership)
	details := applyOutcomeDetails(t, configVersion, resourceID, "hyperv", now)
	require.NoError(t, s.ingestApplyOutcomes(ctx, peerID, configVersion, details))

	clusterEID, err := egtypes.ParseEID("cluster:" + clusterName + "/" + resourceID)
	require.NoError(t, err)

	events, err := p.GetTimeline(ctx, []eginterfaces.EIDRef{clusterEID}, eginterfaces.TimeRange{
		From: now.Add(-time.Hour),
		To:   now.Add(time.Hour),
	})
	require.NoError(t, err)

	var applyOutcomeEvents, stateEvents []*eginterfaces.TimelineEvent
	for _, ev := range events {
		switch ev.Kind {
		case "apply-outcome":
			applyOutcomeEvents = append(applyOutcomeEvents, ev)
		case "state-change":
			stateEvents = append(stateEvents, ev)
		}
	}
	require.NotEmpty(t, applyOutcomeEvents,
		"GetTimeline must return an apply-outcome event for the cluster-scoped EID %s", clusterEID)
	require.NotEmpty(t, stateEvents,
		"the same EID must carry the entity-state observations the outcome joins to")
	assert.Equal(t, clusterEID, applyOutcomeEvents[0].Subject,
		"apply-outcome event subject must be the cluster-scoped EID")

	assert.False(t, hasApplyOutcome(t, p, "host:"+peerID+"/"+resourceID, now),
		"host-scoped EID must NOT have an apply-outcome when the cluster redirect fired")
}

// TestNonClusterKindResolvesHostScoped is the required AC2 test.
//
// A resource whose taxonomy kind does not list "cluster" in AuthorityClasses (e.g.
// "service") must resolve host-scoped even for a verified cluster member.
func TestNonClusterKindResolvesHostScoped(t *testing.T) {
	p := newApplyOutcomeTestEGProvider(t)
	ctx := context.Background()

	const peerID = "node-b"
	const clusterName = "cluster-ac2"
	const resourceID = "service:sshd" // "service" AuthorityClasses == ["host"]
	const tenantID = "root/tenant-a"
	const configVersion = "v-ac2"
	now := time.Now().UTC()

	membership := dnasync.NewStaticClusterMembership(map[string][]string{clusterName: {peerID}})
	svc := service.NewControllerService(logging.ForModule("ac2-svc"))
	registerStewardWithDNA(t, svc, peerID, tenantID, clusterDNAFragment(t, clusterName, peerID))

	s := newClusterTestServer(t, p, svc, membership)
	details := applyOutcomeDetails(t, configVersion, resourceID, "service", now)
	require.NoError(t, s.ingestApplyOutcomes(ctx, peerID, configVersion, details))

	assert.True(t, hasApplyOutcome(t, p, "host:"+peerID+"/"+resourceID, now),
		"apply-outcome for a host-only kind must land on the host-scoped EID")

	clusterEID, err := egtypes.ParseEID("cluster:" + clusterName + "/" + resourceID)
	require.NoError(t, err)
	clusterHistory, err := p.GetHistory(ctx, clusterEID, eginterfaces.TimeRange{
		From: now.Add(-time.Minute),
		To:   now.Add(time.Minute),
	})
	require.NoError(t, err)
	assert.Empty(t, clusterHistory,
		"cluster-scoped EID must have no history for a host-only kind")
}

// TestClusterEligibleKindWithNoMembershipFallsBack is the required AC3 test.
//
// A cluster-eligible kind (e.g. "vm") on a host with no cluster membership must resolve
// host-scoped and must not error.
func TestClusterEligibleKindWithNoMembershipFallsBack(t *testing.T) {
	p := newApplyOutcomeTestEGProvider(t)
	ctx := context.Background()

	const peerID = "standalone-node"
	const vmName = "lonely-vm"
	const resourceID = "vm:" + vmName // "vm" has AuthorityClasses ["cluster", "host"]
	const tenantID = "root/tenant-a"
	const configVersion = "v-ac3"
	now := time.Now().UTC()

	// A verifier is wired, but it knows of no cluster containing this steward.
	membership := dnasync.NewStaticClusterMembership(map[string][]string{"other-cluster": {"other-node"}})
	svc := service.NewControllerService(logging.ForModule("ac3-svc"))
	registerStewardWithDNA(t, svc, peerID, tenantID) // standalone host: no cluster DNA
	writeEntityState(t, p, membership, peerID, standaloneVMFragment(t, vmName))

	s := newClusterTestServer(t, p, svc, membership)
	details := applyOutcomeDetails(t, configVersion, resourceID, "hyperv", now)
	require.NoError(t, s.ingestApplyOutcomes(ctx, peerID, configVersion, details),
		"ingestApplyOutcomes must not error when the steward has no cluster membership")

	assert.True(t, hasApplyOutcome(t, p, "host:"+peerID+"/"+resourceID, now),
		"apply-outcome must fall back to the host-scoped EID when the steward has no cluster membership")
}

// TestSelfAttestedClusterClaimIsNotEnough is the authority-boundary test.
//
// A compromised steward publishes a cluster:<victim> DNA fragment naming a cluster that
// genuinely exists — its entity state was written by a real member — and reports an
// apply-outcome for a VM in that cluster. The membership verifier does not corroborate
// the claim, so the record must stay in the attacker's own host namespace: a cluster EID
// is not tenant-qualified and apply-outcome observations carry no ClaimScope, so a
// record misfiled there could never be retracted.
func TestSelfAttestedClusterClaimIsNotEnough(t *testing.T) {
	p := newApplyOutcomeTestEGProvider(t)
	ctx := context.Background()

	const victimNode = "victim-node"
	const attackerNode = "attacker-node"
	const clusterName = "cluster-victim"
	const vmName = "victim-vm"
	const resourceID = "vm:" + vmName
	const tenantID = "root/tenant-a"
	const configVersion = "v-sec-claim"
	now := time.Now().UTC()

	// The controller corroborates only the genuine member.
	membership := dnasync.NewStaticClusterMembership(map[string][]string{
		clusterName: {victimNode},
	})

	svc := service.NewControllerService(logging.ForModule("sec-claim-svc"))
	registerStewardWithDNA(t, svc, victimNode, tenantID, clusterDNAFragment(t, clusterName, victimNode))
	// The attacker publishes the same cluster fragment: a pure self-attestation.
	registerStewardWithDNA(t, svc, attackerNode, tenantID, clusterDNAFragment(t, clusterName, attackerNode))

	// Cluster-scoped entity state exists, written by the genuine member.
	writeEntityState(t, p, membership, victimNode, clusteredVMFragment(t, vmName, clusterName))

	s := newClusterTestServer(t, p, svc, membership)
	details := applyOutcomeDetails(t, configVersion, resourceID, "hyperv", now)
	require.NoError(t, s.ingestApplyOutcomes(ctx, attackerNode, configVersion, details))

	assert.False(t, hasApplyOutcome(t, p, "cluster:"+clusterName+"/"+resourceID, now),
		"an uncorroborated cluster claim must not place a record in that cluster's namespace")
	assert.True(t, hasApplyOutcome(t, p, "host:"+attackerNode+"/"+resourceID, now),
		"the record must fall back to the reporting peer's host-scoped EID, not be dropped")
}

// TestForgedMembershipEdgeIsNotEnough is the same boundary from the graph side.
//
// A compromised steward can put a cluster:<victim> --contains--> host:<self> edge in the
// entity graph on its own: the writer's bare cluster-kind branch is deliberately
// ungated, because cluster fragments are the evidence membership views are built from.
// A membership signal the judged peer can author must therefore never grant cluster
// authority by itself.
func TestForgedMembershipEdgeIsNotEnough(t *testing.T) {
	p := newApplyOutcomeTestEGProvider(t)
	ctx := context.Background()

	const victimNode = "edge-victim-node"
	const attackerNode = "edge-attacker-node"
	const clusterName = "cluster-edge-victim"
	const vmName = "edge-victim-vm"
	const resourceID = "vm:" + vmName
	const tenantID = "root/tenant-a"
	const configVersion = "v-sec-edge"
	now := time.Now().UTC()

	membership := dnasync.NewStaticClusterMembership(map[string][]string{
		clusterName: {victimNode},
	})

	svc := service.NewControllerService(logging.ForModule("sec-edge-svc"))
	registerStewardWithDNA(t, svc, victimNode, tenantID, clusterDNAFragment(t, clusterName, victimNode))
	forged := forgedMembershipFragment(t, clusterName)
	registerStewardWithDNA(t, svc, attackerNode, tenantID, forged)

	// Genuine member's cluster-scoped VM state, and the attacker's forged membership
	// edge, both reach the graph through the real writer.
	writeEntityState(t, p, membership, victimNode, clusteredVMFragment(t, vmName, clusterName))
	writeEntityState(t, p, membership, attackerNode, forged)

	// The forged edge really is in the graph, anchored on the attacker's own bare host
	// EID — the attack precondition, asserted so this test cannot pass vacuously.
	attackerHost, err := egtypes.NewEID("host", attackerNode, "")
	require.NoError(t, err)
	edges, err := p.GetEdges(ctx, eginterfaces.EdgeFilter{ToEID: &attackerHost, Types: []string{"contains"}})
	require.NoError(t, err)
	require.NotEmpty(t, edges, "forged contains edge must be present for this test to mean anything")

	s := newClusterTestServer(t, p, svc, membership)
	details := applyOutcomeDetails(t, configVersion, resourceID, "hyperv", now)
	require.NoError(t, s.ingestApplyOutcomes(ctx, attackerNode, configVersion, details))

	assert.False(t, hasApplyOutcome(t, p, "cluster:"+clusterName+"/"+resourceID, now),
		"a self-authored membership edge must not grant cluster authority")
	assert.True(t, hasApplyOutcome(t, p, "host:"+attackerNode+"/"+resourceID, now),
		"the record must fall back to the reporting peer's host-scoped EID, not be dropped")
}

// TestUnwiredMembershipVerifierResolvesHostScoped pins the fail-closed default.
//
// With no verifier wired, the dnasync writer records a clustered VM's entity state under
// host:<peer> — so apply-outcome must resolve the same way. Agreeing on the host-scoped
// EID keeps intent and outcome joinable; a redirect here would file outcomes at an EID
// entity-state never uses.
func TestUnwiredMembershipVerifierResolvesHostScoped(t *testing.T) {
	p := newApplyOutcomeTestEGProvider(t)
	ctx := context.Background()

	const peerID = "unwired-node"
	const clusterName = "cluster-unwired"
	const vmName = "unwired-vm"
	const resourceID = "vm:" + vmName
	const tenantID = "root/tenant-a"
	const configVersion = "v-unwired"
	now := time.Now().UTC()

	svc := service.NewControllerService(logging.ForModule("unwired-svc"))
	registerStewardWithDNA(t, svc, peerID, tenantID, clusterDNAFragment(t, clusterName, peerID))
	// Same nil verifier on both paths, which is the production default today.
	writeEntityState(t, p, nil, peerID, clusteredVMFragment(t, vmName, clusterName))

	s := newClusterTestServer(t, p, svc, nil)
	details := applyOutcomeDetails(t, configVersion, resourceID, "hyperv", now)
	require.NoError(t, s.ingestApplyOutcomes(ctx, peerID, configVersion, details))

	hostEID := "host:" + peerID + "/" + resourceID
	assert.True(t, hasApplyOutcome(t, p, hostEID, now),
		"with no verifier wired the record must resolve host-scoped")
	assert.False(t, hasApplyOutcome(t, p, "cluster:"+clusterName+"/"+resourceID, now),
		"with no verifier wired no record may reach a cluster authority")

	// The entity-state observation for the same resource is on that same host EID.
	parsed, err := egtypes.ParseEID(hostEID)
	require.NoError(t, err)
	history, err := p.GetHistory(ctx, parsed, eginterfaces.TimeRange{From: now.Add(-time.Hour), To: now.Add(time.Hour)})
	require.NoError(t, err)
	var sawState bool
	for _, hr := range history {
		if hr.Observation.Kind == egtypes.ObservationKindState {
			sawState = true
		}
	}
	assert.True(t, sawState, "entity-state and apply-outcome must agree on the host-scoped EID")
}

// TestNodeLocalVMOnClusterMemberStaysHostScoped covers the per-resource evidence gate.
//
// A verified cluster member also runs node-local VMs. Their entity state is host-scoped,
// so their apply-outcomes must be too — otherwise same-named local VMs on two nodes
// would collapse onto one cluster-scoped EID.
func TestNodeLocalVMOnClusterMemberStaysHostScoped(t *testing.T) {
	p := newApplyOutcomeTestEGProvider(t)
	ctx := context.Background()

	const peerID = "member-node"
	const clusterName = "cluster-mixed"
	const vmName = "local-vm"
	const resourceID = "vm:" + vmName
	const tenantID = "root/tenant-a"
	const configVersion = "v-local"
	now := time.Now().UTC()

	membership := dnasync.NewStaticClusterMembership(map[string][]string{clusterName: {peerID}})
	svc := service.NewControllerService(logging.ForModule("local-vm-svc"))
	registerStewardWithDNA(t, svc, peerID, tenantID, clusterDNAFragment(t, clusterName, peerID))
	// The VM carries no ha_role, so its entity state is host-scoped.
	writeEntityState(t, p, membership, peerID, standaloneVMFragment(t, vmName))

	s := newClusterTestServer(t, p, svc, membership)
	details := applyOutcomeDetails(t, configVersion, resourceID, "hyperv", now)
	require.NoError(t, s.ingestApplyOutcomes(ctx, peerID, configVersion, details))

	assert.True(t, hasApplyOutcome(t, p, "host:"+peerID+"/"+resourceID, now),
		"a node-local VM's outcome must stay on the host-scoped EID that carries its state")
	assert.False(t, hasApplyOutcome(t, p, "cluster:"+clusterName+"/"+resourceID, now),
		"peer membership alone must not move a node-local VM into the cluster namespace")
}

// TestClusterKindResourceIDCannotNameAuthority verifies that a resourceID carried in the
// ingested event never becomes an EID authority segment. "cluster" is not host-nameable
// in the taxonomy, so a record for cluster:<name> is filed under the mTLS-verified peer
// rather than taking the bare cluster-kind branch.
func TestClusterKindResourceIDCannotNameAuthority(t *testing.T) {
	p := newApplyOutcomeTestEGProvider(t)
	ctx := context.Background()

	const peerID = "kind-node"
	const ownCluster = "cluster-own"
	const targetCluster = "cluster-someone-else"
	const resourceID = "cluster:" + targetCluster
	const tenantID = "root/tenant-a"
	const configVersion = "v-kind"
	now := time.Now().UTC()

	membership := dnasync.NewStaticClusterMembership(map[string][]string{ownCluster: {peerID}})
	svc := service.NewControllerService(logging.ForModule("kind-svc"))
	registerStewardWithDNA(t, svc, peerID, tenantID, clusterDNAFragment(t, ownCluster, peerID))

	s := newClusterTestServer(t, p, svc, membership)
	details := applyOutcomeDetails(t, configVersion, resourceID, "hyperv", now)
	require.NoError(t, s.ingestApplyOutcomes(ctx, peerID, configVersion, details))

	bareCluster, err := egtypes.ParseEID("cluster:" + targetCluster)
	require.NoError(t, err)
	history, err := p.GetHistory(ctx, bareCluster, eginterfaces.TimeRange{
		From: now.Add(-time.Minute),
		To:   now.Add(time.Minute),
	})
	require.NoError(t, err)
	assert.Empty(t, history,
		"a resourceID from the ingested event must never become an EID authority segment")
	assert.True(t, hasApplyOutcome(t, p, "host:"+peerID+"/"+resourceID, now),
		"the record must be filed under the mTLS-verified peer")
}

// TestUnknownStewardFallsBackToHostScoped verifies that an unregistered steward produces
// a host-scoped EID. An unregistered peer has no tenant, so no cluster candidate is
// derived and the record cannot land in any cluster namespace.
func TestUnknownStewardFallsBackToHostScoped(t *testing.T) {
	p := newApplyOutcomeTestEGProvider(t)
	ctx := context.Background()

	const registeredPeer = "known-node"
	const unknownPeer = "unregistered-node"
	const clusterName = "cluster-unknown"
	const vmName = "myvm"
	const resourceID = "vm:" + vmName
	const tenantID = "root/tenant-a"
	const configVersion = "v-sec-unknown"
	now := time.Now().UTC()

	// The verifier would corroborate both peers; the tenant-scoped registry lookup is
	// what stops the unregistered one, so this also pins that the gates are independent.
	membership := dnasync.NewStaticClusterMembership(map[string][]string{
		clusterName: {registeredPeer, unknownPeer},
	})

	svc := service.NewControllerService(logging.ForModule("unknown-svc"))
	registerStewardWithDNA(t, svc, registeredPeer, tenantID, clusterDNAFragment(t, clusterName, registeredPeer))
	writeEntityState(t, p, membership, registeredPeer, clusteredVMFragment(t, vmName, clusterName))

	s := newClusterTestServer(t, p, svc, membership)
	details := applyOutcomeDetails(t, configVersion, resourceID, "hyperv", now)
	require.NoError(t, s.ingestApplyOutcomes(ctx, unknownPeer, configVersion, details))

	assert.False(t, hasApplyOutcome(t, p, "cluster:"+clusterName+"/"+resourceID, now),
		"an unregistered steward must not receive a cluster redirect")
	assert.True(t, hasApplyOutcome(t, p, "host:"+unknownPeer+"/"+resourceID, now),
		"the record must fall back to the host-scoped EID, not be dropped")
}

// TestTenantIsolationPreventsClusterRedirect verifies that cluster DNA from one tenant
// cannot redirect a steward registered in a different tenant, even when the membership
// verifier — which is not tenant-qualified — would corroborate the peer. Cluster EIDs
// are fleet-global, so the tenant cut on the candidate lookup is load-bearing.
func TestTenantIsolationPreventsClusterRedirect(t *testing.T) {
	p := newApplyOutcomeTestEGProvider(t)
	ctx := context.Background()

	const peerID = "node-tenant-a"
	const otherNode = "node-tenant-b"
	const clusterName = "cluster-shared"
	const vmName = "myvm"
	const resourceID = "vm:" + vmName
	const ownTenant = "root/tenant-a"
	const otherTenant = "root/tenant-b"
	const configVersion = "v-sec-tenant"
	now := time.Now().UTC()

	membership := dnasync.NewStaticClusterMembership(map[string][]string{
		clusterName: {peerID, otherNode},
	})

	svc := service.NewControllerService(logging.ForModule("tenant-isolation-svc"))
	// peerID is in ownTenant with NO cluster DNA of its own.
	registerStewardWithDNA(t, svc, peerID, ownTenant)
	// The cluster's DNA lives entirely in the other tenant.
	registerStewardWithDNA(t, svc, otherNode, otherTenant, clusterDNAFragment(t, clusterName, otherNode))
	writeEntityState(t, p, membership, otherNode, clusteredVMFragment(t, vmName, clusterName))

	s := newClusterTestServer(t, p, svc, membership)
	details := applyOutcomeDetails(t, configVersion, resourceID, "hyperv", now)
	require.NoError(t, s.ingestApplyOutcomes(ctx, peerID, configVersion, details))

	assert.False(t, hasApplyOutcome(t, p, "cluster:"+clusterName+"/"+resourceID, now),
		"cluster DNA from another tenant must not redirect this steward's records")
	assert.True(t, hasApplyOutcome(t, p, "host:"+peerID+"/"+resourceID, now),
		"the record must fall back to the host-scoped EID, not be dropped")
}
