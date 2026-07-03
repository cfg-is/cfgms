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

	// This node owns the CNO, so getCluster issues exactly four PS queries
	// (Get-Cluster, the CNO-owner read, the resource-owner read, the cluster-access
	// self-check) and no second CNO-owner read. A regression that adds or drops a
	// PS call is caught here.
	transport.mu.Lock()
	callCount := len(transport.calls)
	transport.mu.Unlock()
	assert.Equal(t, 4, callCount, "owner node issues exactly four PS queries")
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

	// Non-owner path issues five PS queries: Get-Cluster, the helper's CNO read,
	// the resource-owner read, the second CNO read in getCluster's else branch,
	// and the cluster-access self-check.
	transport.mu.Lock()
	callCount := len(transport.calls)
	transport.mu.Unlock()
	assert.Equal(t, 5, callCount, "non-owner path issues exactly five PS queries")
}

// TestGetCluster_ClusterAccessOK is the [REQUIRED TEST] (#2306 onboarding): when
// the node's computer account holds cluster access, getCluster reports
// ClusterAccessOK=true, no remediation, and surfaces cluster_access_ok on the DNA.
func TestGetCluster_ClusterAccessOK(t *testing.T) {
	transport := &testWinRMTransport{
		perCallOutputs: []string{
			`{"found":true,"Name":"lab-hv","MemberNodes":["NODE1","NODE2"],"CsvPaths":["C:\\ClusterStorage\\CSV01"]}`,
			`{"owner":"NODE1"}`, // CNO owner (this node)
			`{"owners":{}}`,     // resource owners
			`{"account":"LAB\\NODE1$","access_ok":true,"remediation":"Grant-ClusterAccess -Cluster lab-hv -User 'LAB\\NODE1$' -Full"}`,
		},
	}
	m, _ := clusterTestModule(t, transport)
	defer func() { _ = m.auditMgr.Stop(context.Background()) }()

	state, err := m.getCluster(context.Background(), "lab-hv")
	require.NoError(t, err)
	status := state.(*ClusterStatus)
	assert.True(t, status.ClusterAccessOK, "a granted node reports access OK")
	assert.Empty(t, status.ClusterAccessRemediation, "no remediation when access is OK")
	assert.Equal(t, true, status.AsMap()["cluster_access_ok"], "DNA exposes cluster_access_ok=true")
}

// TestGetCluster_ClusterAccessMissing is the [REQUIRED TEST] (#2306 onboarding):
// when the node lacks cluster access, getCluster reports ClusterAccessOK=false and
// an actionable remediation naming the Grant-ClusterAccess command.
func TestGetCluster_ClusterAccessMissing(t *testing.T) {
	transport := &testWinRMTransport{
		perCallOutputs: []string{
			`{"found":true,"Name":"lab-hv","MemberNodes":["NODE1"],"CsvPaths":[]}`,
			`{"owner":"NODE1"}`,
			`{"owners":{}}`,
			`{"account":"LAB\\NODE1$","access_ok":false,"remediation":"Grant-ClusterAccess -Cluster lab-hv -User 'LAB\\NODE1$' -Full"}`,
		},
	}
	m, _ := clusterTestModule(t, transport)
	defer func() { _ = m.auditMgr.Stop(context.Background()) }()

	state, err := m.getCluster(context.Background(), "lab-hv")
	require.NoError(t, err)
	status := state.(*ClusterStatus)
	assert.False(t, status.ClusterAccessOK, "an ungranted node reports access missing")
	assert.Contains(t, status.ClusterAccessRemediation, "Grant-ClusterAccess", "remediation names the grant command")
	assert.Equal(t, false, status.AsMap()["cluster_access_ok"], "DNA exposes cluster_access_ok=false")
}

// TestGetCluster_Standalone_NoAccessAlert is the [REQUIRED TEST] (#2306
// onboarding): a standalone (non-cluster) host never raises a cluster-access
// alert and skips the probe entirely.
func TestGetCluster_Standalone_NoAccessAlert(t *testing.T) {
	transport := &testWinRMTransport{perCallOutputs: []string{`{"found":false}`}}
	m, _ := clusterTestModule(t, transport)
	defer func() { _ = m.auditMgr.Stop(context.Background()) }()

	state, err := m.getCluster(context.Background(), "lab-hv")
	require.NoError(t, err)
	status := state.(*ClusterStatus)
	assert.False(t, status.Found)
	assert.True(t, status.ClusterAccessOK, "a standalone host never raises a cluster-access alert")
	transport.mu.Lock()
	n := len(transport.calls)
	transport.mu.Unlock()
	assert.Equal(t, 1, n, "a standalone host skips the access probe (one Get-Cluster query only)")
}

// TestComputeClusterAccessReconcile is the [REQUIRED TEST] (#2306 lifecycle): the
// pure reconcile computes the correct grant-set (desired members lacking access)
// and revoke-set (granted nodes no longer members — drift), case-insensitively.
func TestComputeClusterAccessReconcile(t *testing.T) {
	// Desired A,B,C; ACL holds A, c (different case), X (retired drift).
	grants, revokes := computeClusterAccessReconcile(
		[]string{"CFG-A", "CFG-B", "CFG-C"}, []string{"CFG-A", "cfg-c", "CFG-X"})
	assert.ElementsMatch(t, []string{"CFG-B"}, grants, "a desired member absent from the ACL is granted")
	assert.ElementsMatch(t, []string{"CFG-X"}, revokes, "a granted node no longer a member is revoked (drift)")

	// Steady state: desired == current (any case/order) → no changes.
	g, r := computeClusterAccessReconcile([]string{"CFG-A", "CFG-B"}, []string{"cfg-b", "CFG-A"})
	assert.Empty(t, g, "steady state grants nothing")
	assert.Empty(t, r, "steady state revokes nothing")
}

// TestReconcileClusterAccess drives the reconcile through the transport: it reads
// the ACL, grants the missing member and revokes the drift node, exactly once each.
func TestReconcileClusterAccess(t *testing.T) {
	transport := &testWinRMTransport{
		perCallOutputs: []string{
			`{"nodes":["NODE1","NODE3"]}`, // current ACL: NODE1, NODE3
			``,                            // grant NODE2
			``,                            // revoke NODE3
		},
	}
	m, store := clusterTestModule(t, transport)
	defer func() { _ = m.auditMgr.Stop(context.Background()) }()

	res, err := m.ReconcileClusterAccess(context.Background(), "lab-hv", []string{"NODE1", "NODE2"})
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"NODE2"}, res.Granted)
	assert.ElementsMatch(t, []string{"NODE3"}, res.Revoked)
	assert.Equal(t, 1, countCmd(transport, psGrantClusterAccess), "one grant issued")
	assert.Equal(t, 1, countCmd(transport, psRevokeClusterAccess), "one revoke issued")

	require.NoError(t, m.auditMgr.Flush(context.Background()))
	assert.Len(t, auditEntriesByActionCT(store.captured(), "cluster-access-grant"), 1)
	assert.Len(t, auditEntriesByActionCT(store.captured(), "cluster-access-revoke"), 1)
}

// auditEntriesByActionCT counts captured audit entries by action (unit-test copy;
// the integration file has its own auditEntriesByAction under a different tag).
func auditEntriesByActionCT(entries []*business.AuditEntry, action string) []*business.AuditEntry {
	var out []*business.AuditEntry
	for _, e := range entries {
		if e.Action == action {
			out = append(out, e)
		}
	}
	return out
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

// ─── S2: setCluster (create / skip / idempotency / destructive / drift) ────────

// scriptBlocks returns the psCommand (scriptBlock) const string recorded for
// every transport call, in call order. The cluster tests assert on this to
// prove which PS verb was (or was NOT) invoked — the user-supplied role/cluster
// names only ever travel via psArgs, never the scriptBlock text (S3).
func scriptBlocks(tr *testWinRMTransport) []string {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	out := make([]string, len(tr.calls))
	for i, c := range tr.calls {
		out[i] = c.scriptBlock
	}
	return out
}

// countCmd returns how many recorded calls used the given psCommand const.
func countCmd(tr *testWinRMTransport, psCommand string) int {
	n := 0
	for _, sb := range scriptBlocks(tr) {
		if sb == psCommand {
			n++
		}
	}
	return n
}

// psArgsForCmd reconstructs the psArgs key→value map for the first recorded
// call to psCommand. winRMCall stores args as []interface{} in SORTED key order
// (see testWinRMTransport.ExecutePS), so the caller-known sorted key list for
// each cluster verb is zipped back against the recorded values. Returns nil if
// the command was never invoked. Used by W2 to positively assert that the
// user-supplied names travelled via ArgumentList.
func psArgsForCmd(tr *testWinRMTransport, psCommand string) map[string]string {
	// Sorted key order per cluster write verb (matches the dispatch psArgs maps
	// in setCluster).
	var keys []string
	switch psCommand {
	case psAddClusterVMRole:
		keys = []string{"ClusterName", "VMName"} // sorted
	case psRemoveClusterResource:
		keys = []string{"Name"}
	case psSetClusterRolePreferredOwners:
		keys = []string{"ClusterName", "GroupName", "Owners"} // sorted
	case psSetClusterRolePossibleOwners:
		keys = []string{"ClusterName", "Owners", "ResourceName"} // sorted
	case psSetClusterGroupPriority:
		keys = []string{"ClusterName", "GroupName", "Priority"} // sorted
	case psSetClusterGroupAutoStart:
		keys = []string{"AutoStart", "ClusterName", "GroupName"} // sorted
	case psSetClusterGroupAntiAffinity:
		keys = []string{"ClassName", "ClusterName", "GroupName"} // sorted
	default:
		return nil
	}
	tr.mu.Lock()
	defer tr.mu.Unlock()
	for _, c := range tr.calls {
		if c.scriptBlock != psCommand {
			continue
		}
		out := make(map[string]string, len(keys))
		for i, k := range keys {
			if i < len(c.args) {
				if s, ok := c.args[i].(string); ok {
					out[k] = s
				}
			}
		}
		return out
	}
	return nil
}

// intPtr / boolPtr are small helpers for the optional ClusterRoleProperties.
func intPtr(v int) *int    { return &v }
func boolPtr(v bool) *bool { return &v }

// TestSetCluster_EmptyRoles_Noop verifies (#2306) that a present-Set with no
// cfg.Roles entries dispatches ZERO property-set PS consts — properties are left
// at cluster defaults when the operator declares none.
func TestSetCluster_EmptyRoles_Noop(t *testing.T) {
	transport := &testWinRMTransport{
		perCallOutputs: []string{
			`{"owner":"NODE1"}`,             // CNO owner → this node
			`{"owners":{"web-01":"NODE1"}}`, // resource owners → role present
			`{"owner":"NODE1"}`,             // cnoOwner re-read
		},
	}
	m, _ := clusterTestModule(t, transport) // nodeHostname NODE1, clusterName lab-hv
	defer func() { _ = m.auditMgr.Stop(context.Background()) }()

	// Roles is nil.
	cfg := &ClusterConfig{Name: "lab-hv", RoleNames: []string{"web-01"}, State: "present"}
	require.NoError(t, m.setCluster(context.Background(), "cluster:lab-hv", cfg))

	for _, c := range []string{
		psSetClusterRolePreferredOwners, psSetClusterRolePossibleOwners,
		psSetClusterGroupPriority, psSetClusterGroupAutoStart, psSetClusterGroupAntiAffinity,
	} {
		assert.Equal(t, 0, countCmd(transport, c), "no property set must be dispatched when Roles is empty")
	}
}

// TestSetCluster_OwnerReconcileDispatches verifies (#2306) that on the CNO-owner
// node a role with declared properties dispatches exactly the matching property
// PS consts, with the operator values travelling via ArgumentList (never in the
// scriptBlock text).
func TestSetCluster_OwnerReconcileDispatches(t *testing.T) {
	transport := &testWinRMTransport{
		perCallOutputs: []string{
			`{"owner":"NODE1"}`,             // CNO owner → this node
			`{"owners":{"web-01":"NODE1"}}`, // resource owners → role present (no Add)
			`{"owner":"NODE1"}`,             // cnoOwner re-read
			``,                              // preferred_owners set → ok
			``,                              // priority set → ok
		},
	}
	m, store := clusterTestModule(t, transport)
	defer func() { _ = m.auditMgr.Stop(context.Background()) }()

	cfg := &ClusterConfig{
		Name:      "lab-hv",
		RoleNames: []string{"web-01"},
		State:     "present",
		Roles: map[string]ClusterRoleProperties{
			"web-01": {PreferredOwners: []string{"NODE1", "NODE2"}, Priority: intPtr(2000)},
		},
	}
	require.NoError(t, m.setCluster(context.Background(), "cluster:lab-hv", cfg))

	// Exactly the two declared properties dispatched; the others not.
	assert.Equal(t, 1, countCmd(transport, psSetClusterRolePreferredOwners))
	assert.Equal(t, 1, countCmd(transport, psSetClusterGroupPriority))
	assert.Equal(t, 0, countCmd(transport, psSetClusterRolePossibleOwners))
	assert.Equal(t, 0, countCmd(transport, psSetClusterGroupAutoStart))
	assert.Equal(t, 0, countCmd(transport, psSetClusterGroupAntiAffinity))

	// Values travelled via ArgumentList (S3): role name + owners + priority never
	// composed into the scriptBlock text.
	po := psArgsForCmd(transport, psSetClusterRolePreferredOwners)
	require.NotNil(t, po)
	assert.Equal(t, "lab-hv", po["ClusterName"])
	assert.Equal(t, "web-01", po["GroupName"])
	assert.Equal(t, "NODE1,NODE2", po["Owners"])
	pr := psArgsForCmd(transport, psSetClusterGroupPriority)
	require.NotNil(t, pr)
	assert.Equal(t, "2000", pr["Priority"])

	// A property-reconcile audit event is recorded.
	require.NoError(t, m.auditMgr.Flush(context.Background()))
	var found bool
	for _, e := range store.captured() {
		if e.Action == "cluster-set-role-properties" {
			found = true
		}
	}
	assert.True(t, found, "a cluster-set-role-properties audit event must be recorded")
}

// TestSetCluster_NonOwnerSkipsProperties verifies (#2306) that a NON-owner node
// records the ownership-gated skip and dispatches NO property sets (the gate is
// upstream of the property reconcile).
func TestSetCluster_NonOwnerSkipsProperties(t *testing.T) {
	transport := &testWinRMTransport{
		perCallOutputs: []string{
			`{"owner":"NODE2"}`,             // CNO owner → NODE2 (this node is NODE1 → non-owner)
			`{"owners":{"web-01":"NODE2"}}`, // resource owners
			`{"owner":"NODE2"}`,             // cnoOwner re-read
		},
	}
	m, store := clusterTestModule(t, transport)
	defer func() { _ = m.auditMgr.Stop(context.Background()) }()

	cfg := &ClusterConfig{
		Name:      "lab-hv",
		RoleNames: []string{"web-01"},
		State:     "present",
		Roles: map[string]ClusterRoleProperties{
			"web-01": {Priority: intPtr(3000), AutoStart: boolPtr(true)},
		},
	}
	require.NoError(t, m.setCluster(context.Background(), "cluster:lab-hv", cfg))

	for _, c := range []string{
		psSetClusterRolePreferredOwners, psSetClusterRolePossibleOwners,
		psSetClusterGroupPriority, psSetClusterGroupAutoStart, psSetClusterGroupAntiAffinity,
	} {
		assert.Equal(t, 0, countCmd(transport, c), "a non-owner must dispatch no property sets")
	}

	require.NoError(t, m.auditMgr.Flush(context.Background()))
	var skip bool
	for _, e := range store.captured() {
		if e.Action == "cluster-set-skip" {
			skip = true
		}
	}
	assert.True(t, skip, "a non-owner must record cluster-set-skip")
}

// TestClusterSet_CNOOwner_Create verifies the AC: the CNO-owner node calls
// Cfgms-AddClusterVMRole (psAddClusterVMRole) exactly once when the named role
// is absent, and records a create audit event with the owner node identity and
// a Go receipt-time Timestamp (S8).
func TestClusterSet_CNOOwner_Create(t *testing.T) {
	transport := &testWinRMTransport{
		perCallOutputs: []string{
			`{"owner":"NODE1"}`, // helper: CNO owner read → this node (NODE1) owns it
			`{"owners":{}}`,     // helper: resource owners → role absent
			`{"owner":"NODE1"}`, // setCluster: cnoOwner re-read
			``,                  // Add-ClusterVirtualMachineRole → success (empty output)
		},
	}
	m, store := clusterTestModule(t, transport) // m.nodeHostname == "NODE1", clusterName == "lab-hv"
	defer func() { _ = m.auditMgr.Stop(context.Background()) }()

	cfg := &ClusterConfig{Name: "lab-hv", RoleNames: []string{"web-01"}, State: "present"}

	start := time.Now()
	err := m.setCluster(context.Background(), "cluster:lab-hv", cfg)
	require.NoError(t, err)

	// Exactly one Add cmdlet, and the user-supplied role name never appears in the
	// scriptBlock text — only in psArgs (S3 no string composition).
	assert.Equal(t, 1, countCmd(transport, psAddClusterVMRole),
		"the CNO owner must call Add-ClusterVirtualMachineRole exactly once for an absent role")
	for _, sb := range scriptBlocks(transport) {
		assert.NotContains(t, sb, "web-01",
			"role names must travel via ArgumentList, never composed into the scriptBlock")
		assert.NotContains(t, sb, "lab-hv",
			"cluster names must travel via ArgumentList, never composed into the scriptBlock")
	}

	// W2: positive assertion — the recorded Add call carries the cluster + role
	// names via psArgs (ClusterName/VMName), complementing the negative
	// "names absent from scriptBlock text" assertion above. args is sorted by
	// key: ClusterName before VMName.
	addArgs := psArgsForCmd(transport, psAddClusterVMRole)
	require.NotNil(t, addArgs, "the Add call's psArgs must be recorded")
	assert.Equal(t, "lab-hv", addArgs["ClusterName"],
		"Add must carry the cluster name in the ClusterName psArg")
	assert.Equal(t, "web-01", addArgs["VMName"],
		"Add must carry the role name in the VMName psArg")

	require.NoError(t, m.auditMgr.Flush(context.Background()))
	var createEvt *business.AuditEntry
	for _, e := range store.captured() {
		if e.Action == "cluster-set-create" {
			createEvt = e
		}
	}
	require.NotNil(t, createEvt, "a create audit event must be recorded")
	assert.WithinDuration(t, start, createEvt.Timestamp, 5*time.Second,
		"create audit Timestamp must be Go receipt-time")
	host, _ := createEvt.Details["host"].(string)
	assert.Equal(t, "NODE1", host, "create audit must carry the owner node identity")
	require.NotNil(t, createEvt.Changes)
	assert.Equal(t, true, createEvt.Changes.After["created"])
}

// TestClusterSet_NonOwner_Skip verifies S1/S8: a non-owner node issues no PS
// mutation (no Add/Remove cmdlet) and records an ownership-gated-skip audit
// event. Set returns nil — coordination, not authorization.
func TestClusterSet_NonOwner_Skip(t *testing.T) {
	transport := &testWinRMTransport{
		perCallOutputs: []string{
			`{"owner":"NODE2"}`,             // helper: CNO owner is NODE2, not this node (NODE1)
			`{"owners":{"web-01":"NODE2"}}`, // helper: resource owners
			`{"owner":"NODE2"}`,             // setCluster: cnoOwner re-read
		},
	}
	m, store := clusterTestModule(t, transport) // m.nodeHostname == "NODE1"
	defer func() { _ = m.auditMgr.Stop(context.Background()) }()

	cfg := &ClusterConfig{Name: "lab-hv", RoleNames: []string{"web-01"}, State: "present"}
	err := m.setCluster(context.Background(), "cluster:lab-hv", cfg)
	require.NoError(t, err, "a non-owner must return nil — coordination, not authorization")

	assert.Equal(t, 0, countCmd(transport, psAddClusterVMRole),
		"a non-owner must issue no Add-ClusterVirtualMachineRole")
	assert.Equal(t, 0, countCmd(transport, psRemoveClusterResource),
		"a non-owner must issue no Remove-ClusterResource")

	require.NoError(t, m.auditMgr.Flush(context.Background()))
	var skipEvt *business.AuditEntry
	for _, e := range store.captured() {
		if e.Action == "cluster-set-skip" {
			skipEvt = e
		}
	}
	require.NotNil(t, skipEvt, "an ownership-gated-skip audit event must be recorded")
	require.NotNil(t, skipEvt.Changes)
	assert.Equal(t, true, skipEvt.Changes.After["skipped"])
	assert.Equal(t, false, skipEvt.Changes.After["owns_cno"])
}

// TestClusterSet_Idempotent verifies the idempotency Technical Decision two ways:
// (a) when the role already exists, the existence check short-circuits the Add
// (no PS mutation), and (b) when the existence read missed it but Add returns an
// "already registered" error, that error is normalised to nil. Both converges
// succeed and leave no error.
func TestClusterSet_Idempotent(t *testing.T) {
	// (a) Existence-check short-circuit: role already present in the owners map.
	t.Run("existence-check short-circuit", func(t *testing.T) {
		transport := &testWinRMTransport{
			perCallOutputs: []string{
				`{"owner":"NODE1"}`,             // helper CNO owner (this node)
				`{"owners":{"web-01":"NODE1"}}`, // role already exists
				`{"owner":"NODE1"}`,             // cnoOwner re-read
			},
		}
		m, _ := clusterTestModule(t, transport)
		defer func() { _ = m.auditMgr.Stop(context.Background()) }()

		err := m.setCluster(context.Background(), "cluster:lab-hv",
			&ClusterConfig{Name: "lab-hv", RoleNames: []string{"web-01"}, State: "present"})
		require.NoError(t, err)
		assert.Equal(t, 0, countCmd(transport, psAddClusterVMRole),
			"an already-existing role must short-circuit BEFORE the Add (no PS mutation)")
	})

	// (b) Add error normalised: existence read empty, but Add reports already-registered.
	t.Run("already-registered error normalised", func(t *testing.T) {
		transport := &testWinRMTransport{
			perCallOutputs: []string{
				`{"owner":"NODE1"}`, // helper CNO owner (this node)
				`{"owners":{}}`,     // existence read: role absent
				`{"owner":"NODE1"}`, // cnoOwner re-read
				``,                  // Add call (output ignored; error supplied below)
			},
			perCallErrors: []error{
				nil, nil, nil,
				errors.New("Add-ClusterVirtualMachineRole : The resource is already configured for high availability."),
			},
		}
		m, _ := clusterTestModule(t, transport)
		defer func() { _ = m.auditMgr.Stop(context.Background()) }()

		err := m.setCluster(context.Background(), "cluster:lab-hv",
			&ClusterConfig{Name: "lab-hv", RoleNames: []string{"web-01"}, State: "present"})
		require.NoError(t, err,
			"an 'already configured' error from Add must be normalised to nil (idempotent)")
		assert.Equal(t, 1, countCmd(transport, psAddClusterVMRole),
			"the Add was attempted once before the error was normalised")
	})

	// (c) A genuine non-idempotent error is NOT swallowed.
	t.Run("non-idempotent error surfaces", func(t *testing.T) {
		transport := &testWinRMTransport{
			perCallOutputs: []string{
				`{"owner":"NODE1"}`,
				`{"owners":{}}`,
				`{"owner":"NODE1"}`,
				``,
			},
			perCallErrors: []error{
				nil, nil, nil,
				errors.New("Add-ClusterVirtualMachineRole : Access is denied."),
			},
		}
		m, _ := clusterTestModule(t, transport)
		defer func() { _ = m.auditMgr.Stop(context.Background()) }()

		err := m.setCluster(context.Background(), "cluster:lab-hv",
			&ClusterConfig{Name: "lab-hv", RoleNames: []string{"web-01"}, State: "present"})
		require.Error(t, err, "a non-idempotent PS error must surface, not be swallowed")
		assert.Contains(t, err.Error(), "Access is denied")
	})
}

// TestClusterSet_DestructiveGate verifies S6: state: absent with
// allow_destructive: false returns ErrDestructiveOpBlocked WITHOUT invoking any
// PS write cmdlet (zero Add/Remove calls).
func TestClusterSet_DestructiveGate(t *testing.T) {
	transport := &testWinRMTransport{
		perCallOutputs: []string{
			`{"owner":"NODE1"}`,             // helper CNO owner (this node owns it)
			`{"owners":{"web-01":"NODE1"}}`, // role present
			`{"owner":"NODE1"}`,             // cnoOwner re-read
		},
	}
	m, _ := clusterTestModule(t, transport)
	defer func() { _ = m.auditMgr.Stop(context.Background()) }()

	cfg := &ClusterConfig{
		Name:             "lab-hv",
		RoleNames:        []string{"web-01"},
		State:            "absent",
		AllowDestructive: false,
	}
	err := m.setCluster(context.Background(), "cluster:lab-hv", cfg)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDestructiveOpBlocked,
		"state: absent without allow_destructive must return ErrDestructiveOpBlocked")

	assert.Equal(t, 0, countCmd(transport, psRemoveClusterResource),
		"the destructive gate must block BEFORE any Remove-ClusterResource")
	assert.Equal(t, 0, countCmd(transport, psAddClusterVMRole),
		"the destructive gate must issue no Add either")
}

// TestClusterSet_DriftNotAdopted verifies S1: Set on a cfg naming only role A,
// with an undeclared role B also present on the cluster, issues no Add or Remove
// targeting B — only declared roles are mutated. Here role A ("web-01") is
// absent (gets created) while role B ("db-99") is present but undeclared and
// must be left untouched, even though state is the default "present".
func TestClusterSet_DriftNotAdopted(t *testing.T) {
	transport := &testWinRMTransport{
		perCallOutputs: []string{
			`{"owner":"NODE1"}`,            // helper CNO owner (this node)
			`{"owners":{"db-99":"NODE1"}}`, // undeclared role db-99 present; declared web-01 absent
			`{"owner":"NODE1"}`,            // cnoOwner re-read
			``,                             // Add web-01 → success
		},
	}
	m, _ := clusterTestModule(t, transport)
	defer func() { _ = m.auditMgr.Stop(context.Background()) }()

	cfg := &ClusterConfig{Name: "lab-hv", RoleNames: []string{"web-01"}, State: "present"}
	err := m.setCluster(context.Background(), "cluster:lab-hv", cfg)
	require.NoError(t, err)

	// Exactly one Add (for the declared web-01); zero Removes (db-99 is never adopted).
	assert.Equal(t, 1, countCmd(transport, psAddClusterVMRole),
		"only the declared role is created")
	assert.Equal(t, 0, countCmd(transport, psRemoveClusterResource),
		"an undeclared, present role must never be Removed (drift-not-adopted)")

	// The undeclared role name must never appear in any Add psArgs.
	transport.mu.Lock()
	defer transport.mu.Unlock()
	for _, c := range transport.calls {
		if c.scriptBlock == psAddClusterVMRole {
			for _, a := range c.args {
				assert.NotEqual(t, "db-99", a,
					"the undeclared role must never be passed to Add-ClusterVirtualMachineRole")
			}
		}
	}
}

// ─── B2: setCluster destructive REMOVE success path (state: absent + allow_destructive) ─

// TestClusterSet_Remove_Success verifies B2(a): on the CNO-owner node, a
// declared role that EXISTS, with state: absent + allow_destructive: true,
// triggers Remove-ClusterResource exactly once and records a
// cluster-set-remove audit event with removed: true.
func TestClusterSet_Remove_Success(t *testing.T) {
	transport := &testWinRMTransport{
		perCallOutputs: []string{
			`{"owner":"NODE1"}`,             // helper CNO owner → this node (NODE1) owns it
			`{"owners":{"web-01":"NODE1"}}`, // helper resource owners → role present
			`{"owner":"NODE1"}`,             // setCluster cnoOwner re-read
			``,                              // Remove-ClusterResource → success
		},
	}
	m, store := clusterTestModule(t, transport) // m.nodeHostname == "NODE1"
	defer func() { _ = m.auditMgr.Stop(context.Background()) }()

	cfg := &ClusterConfig{
		Name:             "lab-hv",
		RoleNames:        []string{"web-01"},
		State:            "absent",
		AllowDestructive: true,
	}

	start := time.Now()
	err := m.setCluster(context.Background(), "cluster:lab-hv", cfg)
	require.NoError(t, err, "removing an existing role with allow_destructive must succeed")

	// (a) Exactly one Remove cmdlet; zero Adds.
	assert.Equal(t, 1, countCmd(transport, psRemoveClusterResource),
		"an existing declared role must be Removed exactly once")
	assert.Equal(t, 0, countCmd(transport, psAddClusterVMRole),
		"the destructive path must issue no Add")

	// The Remove carries the role via the Name psArg (never the scriptBlock).
	rmArgs := psArgsForCmd(transport, psRemoveClusterResource)
	require.NotNil(t, rmArgs, "the Remove call's psArgs must be recorded")
	assert.Equal(t, "web-01", rmArgs["Name"],
		"Remove must carry the role name in the Name psArg")
	for _, sb := range scriptBlocks(transport) {
		assert.NotContains(t, sb, "web-01",
			"role names must travel via ArgumentList, never composed into the scriptBlock")
	}

	// Audit: a cluster-set-remove event with removed: true and the owner identity.
	require.NoError(t, m.auditMgr.Flush(context.Background()))
	var removeEvt *business.AuditEntry
	for _, e := range store.captured() {
		if e.Action == "cluster-set-remove" {
			removeEvt = e
		}
	}
	require.NotNil(t, removeEvt, "a cluster-set-remove audit event must be recorded")
	assert.WithinDuration(t, start, removeEvt.Timestamp, 5*time.Second,
		"remove audit Timestamp must be Go receipt-time")
	host, _ := removeEvt.Details["host"].(string)
	assert.Equal(t, "NODE1", host, "remove audit must carry the owner node identity")
	require.NotNil(t, removeEvt.Changes)
	assert.Equal(t, true, removeEvt.Changes.After["removed"],
		"the remove audit must record removed: true")
}

// TestClusterSet_Remove_TransportError verifies B2(b): when the
// Remove-ClusterResource transport call FAILS, setCluster wraps and returns the
// error (it does NOT swallow it) — isAlreadyRegistered must NOT be applied to
// the remove path, so even an "already"-bearing error surfaces.
func TestClusterSet_Remove_TransportError(t *testing.T) {
	transport := &testWinRMTransport{
		perCallOutputs: []string{
			`{"owner":"NODE1"}`,             // helper CNO owner (this node owns it)
			`{"owners":{"web-01":"NODE1"}}`, // role present
			`{"owner":"NODE1"}`,             // cnoOwner re-read
			``,                              // Remove call (error supplied below)
		},
		perCallErrors: []error{
			nil, nil, nil,
			// Note the literal "already" substring: the remove path must STILL
			// surface this, proving isAlreadyRegistered is not applied here.
			errors.New("Remove-ClusterResource : The cluster resource could not be deleted; it is already in a pending state."),
		},
	}
	m, store := clusterTestModule(t, transport)
	defer func() { _ = m.auditMgr.Stop(context.Background()) }()

	cfg := &ClusterConfig{
		Name:             "lab-hv",
		RoleNames:        []string{"web-01"},
		State:            "absent",
		AllowDestructive: true,
	}
	err := m.setCluster(context.Background(), "cluster:lab-hv", cfg)
	require.Error(t, err, "a failed Remove must surface, never be swallowed")
	assert.Contains(t, err.Error(), "could not be deleted",
		"the underlying Remove error must be wrapped, not normalised away")

	assert.Equal(t, 1, countCmd(transport, psRemoveClusterResource),
		"the Remove was attempted once before the error surfaced")

	// The remove failure is audited with removed: false.
	require.NoError(t, m.auditMgr.Flush(context.Background()))
	var removeEvt *business.AuditEntry
	for _, e := range store.captured() {
		if e.Action == "cluster-set-remove" {
			removeEvt = e
		}
	}
	require.NotNil(t, removeEvt, "a cluster-set-remove audit event must be recorded for the failure")
	require.NotNil(t, removeEvt.Changes)
	assert.Equal(t, false, removeEvt.Changes.After["removed"],
		"a failed remove must record removed: false")
}

// TestClusterSet_Remove_AlreadyGone verifies B2(c): a declared role that is NOT
// present in the resource-owner map, with state: absent + allow_destructive:
// true, is an idempotent no-op — zero Remove-ClusterResource calls, a
// cluster-set-remove-noop audit event, and no error.
func TestClusterSet_Remove_AlreadyGone(t *testing.T) {
	transport := &testWinRMTransport{
		perCallOutputs: []string{
			`{"owner":"NODE1"}`, // helper CNO owner (this node owns it)
			`{"owners":{}}`,     // resource owners → role already gone
			`{"owner":"NODE1"}`, // cnoOwner re-read
		},
	}
	m, store := clusterTestModule(t, transport)
	defer func() { _ = m.auditMgr.Stop(context.Background()) }()

	cfg := &ClusterConfig{
		Name:             "lab-hv",
		RoleNames:        []string{"web-01"},
		State:            "absent",
		AllowDestructive: true,
	}
	err := m.setCluster(context.Background(), "cluster:lab-hv", cfg)
	require.NoError(t, err, "removing an already-absent role is an idempotent no-op")

	assert.Equal(t, 0, countCmd(transport, psRemoveClusterResource),
		"an already-gone role must issue zero Remove-ClusterResource calls")
	assert.Equal(t, 0, countCmd(transport, psAddClusterVMRole),
		"the destructive no-op path must issue no Add")

	// Audit: a cluster-set-remove-noop event with removed: false.
	require.NoError(t, m.auditMgr.Flush(context.Background()))
	var noopEvt *business.AuditEntry
	for _, e := range store.captured() {
		if e.Action == "cluster-set-remove-noop" {
			noopEvt = e
		}
	}
	require.NotNil(t, noopEvt, "an idempotent remove-noop audit event must be recorded")
	require.NotNil(t, noopEvt.Changes)
	assert.Equal(t, false, noopEvt.Changes.After["removed"],
		"the remove-noop audit must record removed: false")
}

// ─── B3: setCluster scope-cap + nil-transport guards ───────────────────────────

// TestClusterSet_ScopeCap_Undeclared verifies B3: setCluster addressed to a
// cluster name != the configured cluster_name returns ErrClusterNotDeclared and
// makes ZERO transport calls — the scope cap rejects BEFORE the transport, even
// for the write path.
func TestClusterSet_ScopeCap_Undeclared(t *testing.T) {
	transport := &testWinRMTransport{}
	m, _ := clusterTestModule(t, transport) // m.clusterName == "lab-hv"
	defer func() { _ = m.auditMgr.Stop(context.Background()) }()

	cfg := &ClusterConfig{Name: "other-cluster", RoleNames: []string{"web-01"}, State: "present"}
	err := m.setCluster(context.Background(), "cluster:other-cluster", cfg)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrClusterNotDeclared,
		"an out-of-scope cluster name must return the scope-cap sentinel on the write path")

	transport.mu.Lock()
	defer transport.mu.Unlock()
	assert.Len(t, transport.calls, 0,
		"the scope cap must reject BEFORE touching the transport — zero PS calls")
}

// TestClusterSet_NilTransport verifies B3: setCluster with no transport wired
// returns the distinct ErrTransportNotConfigured sentinel (a misconfiguration),
// NOT the ErrClusterNotDeclared scope-cap sentinel.
func TestClusterSet_NilTransport(t *testing.T) {
	m, _ := clusterTestModule(t, &testWinRMTransport{})
	defer func() { _ = m.auditMgr.Stop(context.Background()) }()
	m.transport = nil

	cfg := &ClusterConfig{Name: "lab-hv", RoleNames: []string{"web-01"}, State: "present"}
	err := m.setCluster(context.Background(), "cluster:lab-hv", cfg)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTransportNotConfigured,
		"a nil transport is a misconfiguration, not an out-of-scope cluster")
	assert.NotErrorIs(t, err, ErrClusterNotDeclared,
		"the nil-transport path must not masquerade as the scope-cap sentinel")
}
