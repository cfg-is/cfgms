// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// clusterTestModule builds a hypervModule wired with the given recording
// transport, a fake audit manager, and a fixed node identity/cluster scope so
// the cluster tests exercise the real getCluster / clusterOwnershipHelper paths
// without any mocks of CFGMS components (the recording transport + fakeDetector
// are the established test seams).
func clusterTestModule(t *testing.T, transport *testWinRMTransport) (*hypervModule, *fakeAuditStore) {
	t.Helper()
	mgr, store := newFakeAuditManager(t)
	m := newModuleWithDetector(nil, &fakeDetector{result: true})
	m.transport = transport
	m.auditMgr = mgr
	m.tenantID = "t-cluster"
	m.stewardID = "steward-cluster"
	m.nodeHostname = "NODE1"
	m.clusterName = "lab-hv"
	return m, store
}

// TestClusterConfig_Validate verifies the desired-state ClusterConfig validation:
// Name is required; everything else is optional.
func TestClusterConfig_Validate(t *testing.T) {
	require.Error(t, (&ClusterConfig{}).Validate(), "empty name must be rejected")
	require.Error(t, (&ClusterConfig{Name: "   "}).Validate(), "whitespace-only name must be rejected")

	ok := &ClusterConfig{
		Name:             "lab-hv",
		RoleNames:        []string{"web-01", "db-01"},
		AllowDestructive: false,
		State:            "present",
	}
	require.NoError(t, ok.Validate(), "valid config must pass")

	// AsMap must expose the declared keys for the executor / DNA layer.
	m := ok.AsMap()
	assert.Equal(t, "lab-hv", m["name"])
	assert.Equal(t, []string{"web-01", "db-01"}, m["role_names"])
	assert.Equal(t, false, m["allow_destructive"])
}

// TestClusterScopeCap_UndeclaredCluster verifies S5: getCluster with a cluster
// name that does not match the configured cluster_name returns the sentinel
// ErrClusterNotDeclared WITHOUT invoking any PowerShell cmdlet (zero transport
// calls).
func TestClusterScopeCap_UndeclaredCluster(t *testing.T) {
	transport := &testWinRMTransport{}
	m, _ := clusterTestModule(t, transport) // m.clusterName == "lab-hv"
	defer func() { _ = m.auditMgr.Stop(context.Background()) }()

	_, err := m.getCluster(context.Background(), "other-cluster")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrClusterNotDeclared,
		"an out-of-scope cluster name must return the scope-cap sentinel")

	transport.mu.Lock()
	defer transport.mu.Unlock()
	assert.Len(t, transport.calls, 0,
		"the scope cap must reject BEFORE touching the transport — zero PS calls")
}

// TestClusterOwnershipHelper_CNOAbsent verifies the Technical Decision: when the
// CNO group has no current owner (transient failover), the helper returns
// (false, nil, nil) — no error, no panic — and queries no role owners.
func TestClusterOwnershipHelper_CNOAbsent(t *testing.T) {
	transport := &testWinRMTransport{
		// First (and only) call: the CNO owner query returns no owner.
		perCallOutputs: []string{`{"owner":""}`},
	}
	m, store := clusterTestModule(t, transport)
	defer func() { _ = m.auditMgr.Stop(context.Background()) }()

	ownsCNO, owners, err := m.clusterOwnershipHelper(context.Background(), "lab-hv")
	require.NoError(t, err, "CNO-absent must not be an error")
	assert.False(t, ownsCNO, "a node cannot own a CNO that has no owner")
	assert.Nil(t, owners, "no role owners are queried when the CNO is mid-failover")

	// Only the single owner-node query must have run (no resource-owner query).
	transport.mu.Lock()
	callCount := len(transport.calls)
	transport.mu.Unlock()
	assert.Equal(t, 1, callCount, "CNO-absent path issues exactly one PS query")

	// No ownership audit event should be recorded for a transient CNO.
	require.NoError(t, m.auditMgr.Flush(context.Background()))
	for _, e := range store.captured() {
		assert.NotEqual(t, "cluster-ownership", e.Action,
			"no ownership decision is recorded when the CNO is mid-failover")
	}
}

// TestClusterOwnershipHelper_NonOwner verifies S1/S8: a non-owner node returns
// (false, map, nil) and the ownership decision records a pkg/audit event whose
// Timestamp is within 5s of time.Now() (Go receipt-time) and whose node
// identity is non-empty.
func TestClusterOwnershipHelper_NonOwner(t *testing.T) {
	transport := &testWinRMTransport{
		perCallOutputs: []string{
			`{"owner":"NODE2"}`,                             // CNO owner is NODE2, not this node (NODE1)
			`{"owners":{"web-01":"NODE2","db-01":"NODE1"}}`, // role owners
		},
	}
	m, store := clusterTestModule(t, transport) // m.nodeHostname == "NODE1"
	defer func() { _ = m.auditMgr.Stop(context.Background()) }()

	start := time.Now()
	ownsCNO, owners, err := m.clusterOwnershipHelper(context.Background(), "lab-hv")
	require.NoError(t, err)
	assert.False(t, ownsCNO, "NODE1 is not the CNO owner (NODE2 is) → non-owner")
	require.NotNil(t, owners, "role owners must be returned for a present CNO")
	assert.Equal(t, "NODE2", owners["web-01"])
	assert.Equal(t, "NODE1", owners["db-01"])

	require.NoError(t, m.auditMgr.Flush(context.Background()))
	var ownershipEvt *business.AuditEntry
	for _, e := range store.captured() {
		if e.Action == "cluster-ownership" {
			ownershipEvt = e
		}
	}
	require.NotNil(t, ownershipEvt, "an ownership-decision audit event must be recorded")

	// S8: receipt-time Timestamp within 5s of time.Now() (Go clock).
	assert.WithinDuration(t, start, ownershipEvt.Timestamp, 5*time.Second,
		"ownership audit Timestamp must be Go receipt-time, within 5s")

	// S8: non-empty node identity recorded.
	host, _ := ownershipEvt.Details["host"].(string)
	assert.Equal(t, "NODE1", host, "ownership audit must carry a non-empty node identity")
	assert.NotEmpty(t, host, "node identity must be non-empty")

	// The decision scalars are captured (no live host secrets).
	require.NotNil(t, ownershipEvt.Changes)
	assert.Equal(t, false, ownershipEvt.Changes.After["owns_cno"])
}

// TestGetCluster_NotFound verifies that a cluster the host reports as absent
// (found:false) yields a ClusterStatus{Found:false} with err==nil and issues no
// further ownership queries.
func TestGetCluster_NotFound(t *testing.T) {
	transport := &testWinRMTransport{
		perCallOutputs: []string{`{"found":false}`},
	}
	m, _ := clusterTestModule(t, transport)
	defer func() { _ = m.auditMgr.Stop(context.Background()) }()

	state, err := m.getCluster(context.Background(), "lab-hv")
	require.NoError(t, err)
	require.NotNil(t, state)

	status, ok := state.(*ClusterStatus)
	require.True(t, ok, "getCluster must return a *ClusterStatus")
	assert.False(t, status.Found, "an absent cluster must report Found=false")
	assert.Equal(t, "lab-hv", status.Name)

	// Only the single Get-Cluster query runs; no ownership follow-ups.
	transport.mu.Lock()
	callCount := len(transport.calls)
	transport.mu.Unlock()
	assert.Equal(t, 1, callCount, "an absent cluster issues exactly one PS query")
}

// TestGetCluster_FoundPopulatesDNA verifies the AC: Get("cluster:<name>")
// returns a *ClusterStatus whose AsMap exposes member_nodes, cno_owner_node,
// resource_owner, and csv_paths populated from live cluster state.
func TestGetCluster_FoundPopulatesDNA(t *testing.T) {
	transport := &testWinRMTransport{
		perCallOutputs: []string{
			// Get-Cluster
			`{"found":true,"Name":"lab-hv","MemberNodes":["NODE1","NODE2","NODE3"],"CsvPaths":["C:\\ClusterStorage\\CSV01"]}`,
			// CNO owner (this node owns it)
			`{"owner":"NODE1"}`,
			// role owners
			`{"owners":{"web-01":"NODE1","db-01":"NODE2"}}`,
		},
	}
	m, _ := clusterTestModule(t, transport)
	defer func() { _ = m.auditMgr.Stop(context.Background()) }()

	state, err := m.getCluster(context.Background(), "lab-hv")
	require.NoError(t, err)

	mp := state.AsMap()
	assert.Equal(t, "lab-hv", mp["name"])
	assert.Equal(t, []string{"NODE1", "NODE2", "NODE3"}, mp["member_nodes"])
	assert.Equal(t, []string{`C:\ClusterStorage\CSV01`}, mp["csv_paths"])
	assert.Equal(t, "NODE1", mp["cno_owner_node"], "this node owns the CNO")

	owners, ok := mp["resource_owner"].(map[string]string)
	require.True(t, ok, "resource_owner must be a map[string]string")
	assert.Equal(t, "NODE1", owners["web-01"])
	assert.Equal(t, "NODE2", owners["db-01"])

	// This node owns the CNO, so getCluster issues exactly three PS queries
	// (Get-Cluster, the CNO-owner read, the resource-owner read) and no second
	// CNO-owner read. A regression that adds or drops a PS call is caught here.
	transport.mu.Lock()
	callCount := len(transport.calls)
	transport.mu.Unlock()
	assert.Equal(t, 3, callCount, "owner node issues exactly three PS queries")
}

// TestClusterScopeCap_OwnershipHelper verifies the scope cap is ALSO enforced in
// clusterOwnershipHelper (S5), not just getCluster — an out-of-scope name
// returns the sentinel without any transport call.
func TestClusterScopeCap_OwnershipHelper(t *testing.T) {
	transport := &testWinRMTransport{}
	m, _ := clusterTestModule(t, transport)
	defer func() { _ = m.auditMgr.Stop(context.Background()) }()

	_, _, err := m.clusterOwnershipHelper(context.Background(), "rogue-cluster")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrClusterNotDeclared)

	transport.mu.Lock()
	defer transport.mu.Unlock()
	assert.Len(t, transport.calls, 0, "ownership helper scope cap must not touch the transport")
}

// TestGetCluster_TransportError verifies that a transport failure on the
// Get-Cluster query propagates as a wrapped non-nil error (no silent
// swallowing).
func TestGetCluster_TransportError(t *testing.T) {
	transport := &testWinRMTransport{
		perCallErrors: []error{errors.New("winrm: connection refused")},
	}
	m, _ := clusterTestModule(t, transport)
	defer func() { _ = m.auditMgr.Stop(context.Background()) }()

	state, err := m.getCluster(context.Background(), "lab-hv")
	require.Error(t, err, "a transport failure must surface as an error")
	assert.Nil(t, state, "no status is returned on a transport failure")
	assert.Contains(t, err.Error(), "winrm: connection refused",
		"the underlying transport error must be wrapped, not swallowed")
}

// TestGetCluster_MalformedJSON verifies the json.Unmarshal error branch in
// getCluster (cluster.go ~190): non-JSON Get-Cluster output yields a wrapped
// parse error.
func TestGetCluster_MalformedJSON(t *testing.T) {
	transport := &testWinRMTransport{
		// PowerShell error text instead of JSON.
		perCallOutputs: []string{"Get-Cluster : Cluster service is not running."},
	}
	m, _ := clusterTestModule(t, transport)
	defer func() { _ = m.auditMgr.Stop(context.Background()) }()

	state, err := m.getCluster(context.Background(), "lab-hv")
	require.Error(t, err, "malformed Get-Cluster output must surface a parse error")
	assert.Nil(t, state)
	assert.Contains(t, err.Error(), "parse get-cluster response",
		"the parse error must be wrapped with context")
}

// TestReadResourceOwners_MalformedJSON verifies the json.Unmarshal error branch
// in readResourceOwners (cluster.go ~303): non-JSON resource-owner output yields
// a wrapped parse error. Driven through getCluster so the third PS call returns
// garbage while the prior calls succeed.
func TestReadResourceOwners_MalformedJSON(t *testing.T) {
	transport := &testWinRMTransport{
		perCallOutputs: []string{
			`{"found":true,"Name":"lab-hv","MemberNodes":["NODE1","NODE2"],"CsvPaths":[]}`,
			`{"owner":"NODE1"}`, // CNO owner read (this node)
			"not-json",          // resource-owner read → parse error
		},
	}
	m, _ := clusterTestModule(t, transport)
	defer func() { _ = m.auditMgr.Stop(context.Background()) }()

	state, err := m.getCluster(context.Background(), "lab-hv")
	require.Error(t, err, "malformed resource-owner output must surface a parse error")
	assert.Nil(t, state)
	assert.Contains(t, err.Error(), "parse cluster resource owners",
		"the resource-owner parse error must be wrapped with context")
}

// TestReadCNOOwner_MalformedJSON verifies the json.Unmarshal branch in
// readCNOOwner (cluster.go ~242). readCNOOwner deliberately swallows transient
// errors and returns "" — so a malformed owner response yields an empty owner.
// In the getCluster context, an empty CNO owner is treated as a transient
// failover (clusterOwnershipHelper returns false,nil,nil), so getCluster
// succeeds with an empty cno_owner_node and no role owners.
func TestReadCNOOwner_MalformedJSON(t *testing.T) {
	// Direct unit assertion on readCNOOwner: malformed JSON → "".
	transport := &testWinRMTransport{
		perCallOutputs: []string{"Get-ClusterGroup : The cluster group could not be found."},
	}
	m, _ := clusterTestModule(t, transport)
	defer func() { _ = m.auditMgr.Stop(context.Background()) }()

	owner := m.readCNOOwner(context.Background(), "lab-hv")
	assert.Empty(t, owner, "malformed CNO-owner JSON must be swallowed to an empty owner")
}

// TestGetCluster_FoundNonCNOOwner verifies the else branch in getCluster: the
// cluster is found but this node (NODE1) is NOT the CNO owner (NODE2 is), so
// getCluster re-reads the CNO owner (the 4th transport call) to populate
// cno_owner_node with the live owner. Asserts the resulting CNOOwnerNode is the
// other node and the exact transport call count.
func TestGetCluster_FoundNonCNOOwner(t *testing.T) {
	transport := &testWinRMTransport{
		perCallOutputs: []string{
			// 0: Get-Cluster
			`{"found":true,"Name":"lab-hv","MemberNodes":["NODE1","NODE2"],"CsvPaths":["C:\\ClusterStorage\\CSV01"]}`,
			// 1: CNO owner read inside the ownership helper → NODE2 (not this node)
			`{"owner":"NODE2"}`,
			// 2: resource-owner read
			`{"owners":{"web-01":"NODE2"}}`,
			// 3: second CNO owner read (getCluster else branch) → NODE2
			`{"owner":"NODE2"}`,
		},
	}
	m, _ := clusterTestModule(t, transport) // m.nodeHostname == "NODE1"
	defer func() { _ = m.auditMgr.Stop(context.Background()) }()

	state, err := m.getCluster(context.Background(), "lab-hv")
	require.NoError(t, err)

	mp := state.AsMap()
	assert.Equal(t, "NODE2", mp["cno_owner_node"],
		"a non-owner node must report the live CNO owner (NODE2)")

	owners, ok := mp["resource_owner"].(map[string]string)
	require.True(t, ok)
	assert.Equal(t, "NODE2", owners["web-01"])

	// Non-owner path issues four PS queries: Get-Cluster, the helper's CNO read,
	// the resource-owner read, and the second CNO read in getCluster's else
	// branch.
	transport.mu.Lock()
	callCount := len(transport.calls)
	transport.mu.Unlock()
	assert.Equal(t, 4, callCount, "non-owner path issues exactly four PS queries")
}

// TestGetCluster_NilTransport verifies #7: with no transport wired, getCluster
// returns the distinct ErrTransportNotConfigured sentinel (a misconfiguration),
// NOT the ErrClusterNotDeclared scope-cap sentinel.
func TestGetCluster_NilTransport(t *testing.T) {
	m, _ := clusterTestModule(t, &testWinRMTransport{})
	defer func() { _ = m.auditMgr.Stop(context.Background()) }()
	m.transport = nil

	_, err := m.getCluster(context.Background(), "lab-hv")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTransportNotConfigured,
		"a nil transport is a misconfiguration, not an out-of-scope cluster")
	assert.NotErrorIs(t, err, ErrClusterNotDeclared,
		"the nil-transport path must not masquerade as the scope-cap sentinel")
}

// TestClusterOwnershipHelper_NilTransport verifies #7 for the ownership helper:
// a nil transport returns ErrTransportNotConfigured, not ErrClusterNotDeclared.
func TestClusterOwnershipHelper_NilTransport(t *testing.T) {
	m, _ := clusterTestModule(t, &testWinRMTransport{})
	defer func() { _ = m.auditMgr.Stop(context.Background()) }()
	m.transport = nil

	_, _, err := m.clusterOwnershipHelper(context.Background(), "lab-hv")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTransportNotConfigured,
		"a nil transport is a misconfiguration, not an out-of-scope cluster")
	assert.NotErrorIs(t, err, ErrClusterNotDeclared,
		"the nil-transport path must not masquerade as the scope-cap sentinel")
}
