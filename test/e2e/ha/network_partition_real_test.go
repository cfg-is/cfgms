// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build e2e

// Fleet-e2e live validation of network partition tolerance and split-brain
// prevention on the real cfg-lab 3-node controller cluster (epic #3090 AC1,
// story #3095), against the genuine 3-node deployment story #3130
// established.
//
// Rewritten for Issue #3763 (ADR-031 Decision 5): leadership authority is no
// longer Raft's CheckQuorum protocol, so a partition can no longer be induced
// by blocking the Raft peer transport port (:9443, deleted along with the
// transport itself). Authority is now the shared database lease (pkg/lease):
// every ClusterMode node periodically calls TryAcquire against the same
// Postgres row (docs/testing/controller-ha-real-cluster-runbook.md §3 names
// the lab's datasvc host and port, 5432). This suite now induces the
// partition by blocking the isolated node's own access to that database
// port — the substrate its lease-backed HasLeadership() depends on — rather
// than to its peers. The property under test is unchanged (ADR-029
// Decision 7's retained intent, carried into ADR-031 Decision 5): no two
// nodes may simultaneously report HasLeadership() == true. What changed is
// only the mechanism inducing the scenario and the surface polled
// (GET /api/v1/ha/status's lease-backed is_leader field, replacing the
// deleted GET /api/v1/raft/status).
//
// This file is deliberately self-contained (its own npNode/npSetup/
// npGetHAStatus/... helpers, `np`-prefixed) rather than reusing this
// package's leader_election_real_test.go helpers, matching that file's own
// stated precedent (two sibling files in one package that intentionally do
// not share package-level declarations — the codebase's hyperv e2e suite
// established the same pattern for the same reason: cluster_cascade_test.go's
// `cc`-prefixed helpers vs. promote_role_test.go's `pr`-prefixed helpers,
// both living in `hyperv_e2e`).
//
// Unlike test/integration/ha's Docker suite (TestNetworkPartition), which
// simulates a partition by stopping/restarting a container — not a real
// network-layer partition — this suite drives a genuine iptables rule on one
// of the 3 real Debian VM hosts. The rule blocks only the shared database
// port (5432, both directions) on the isolated node, leaving the admin REST
// port (:9080) and inter-node traffic open — this suite's own mTLS polling
// keeps observing BOTH sides of the partition throughout, and the majority
// nodes are never touched (matching the AC's own wording, "a real iptables
// rule on ONE cfg-lab host": the isolated node's own INPUT/OUTPUT chains
// block its database traffic in both directions, and nothing else needs a
// rule).
//
// docs/architecture/controller-operating-model.md's "Clustered" section
// documents the production mechanism this suite validates: leadership is the
// shared database lease, bounded by pkg/lease.SafetyMargin
// (ElectionTimeout's derived 0.8× lease duration, minus renewal
// interval/latency margins) — the isolated node's cached local authority
// lapses on its own monotonic clock once it can no longer renew, with no
// live database read required to detect the loss (pkg/lease package doc).
//
// The suite is excluded from CI and `make test-complete` by the e2e build
// tag, and skips cleanly when CFGMS_E2E_HA_CLUSTER_NODES is unset, following
// the same convention story #3094 established.
package ha_e2e

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// Required environment variable (the suite skips when unset):
//
//	CFGMS_E2E_HA_CLUSTER_NODES   comma-separated admin API base URLs of the 3
//	                             real cluster nodes — same variable story
//	                             #3094 uses, so one export covers both suites.
//
// Optional (same names/defaults as #3094's suite):
//
//	CFGMS_E2E_HA_ADMIN_BUNDLE, CFGMS_E2E_HA_SSH_KEY, CFGMS_E2E_HA_SSH_USER
const (
	npEnvClusterNodes = "CFGMS_E2E_HA_CLUSTER_NODES"
	npEnvAdminBundle  = "CFGMS_E2E_HA_ADMIN_BUNDLE"
	npEnvSSHKey       = "CFGMS_E2E_HA_SSH_KEY"
	npEnvSSHUser      = "CFGMS_E2E_HA_SSH_USER"

	npFailoverBound = 90 * time.Second

	// npPartitionChain is a dedicated iptables chain so setup/teardown are
	// idempotent and easy to verify absent afterward, rather than searching
	// INPUT/OUTPUT for exact rule matches.
	npPartitionChain = "CFGMS_E2E_PARTITION"

	// npDatabasePort is the lab's shared Postgres port (the lease substrate,
	// pkg/lease) per docs/testing/controller-ha-real-cluster-runbook.md §3.
	npDatabasePort = "5432"

	// npPartitionStepDownBound and npPartitionObserveWindow are sized off the
	// lease's derived SafetyMargin (pkg/lease.SafetyMargin: ElectionTimeout's
	// 0.8× lease duration, minus renewal-interval/latency margins), not
	// Raft's old CheckQuorum bound of (ElectionTimeout, 2×ElectionTimeout].
	// At production defaults (pkg/ha.DefaultConfig: ElectionTimeout 10s) the
	// isolated node's cached local authority lapses within ~8s of losing the
	// ability to renew — these bounds add headroom for network/polling
	// jitter rather than matching that figure exactly.
	npPartitionStepDownBound = 20 * time.Second
	npPartitionObserveWindow = 40 * time.Second
	npPartitionPollInterval  = 500 * time.Millisecond
)

// npNode is one cluster member's identity: admin REST API base URL (mTLS)
// and the SSH hostname reaching its guest OS.
type npNode struct {
	adminURL string
	sshHost  string
}

// npLabTopology maps each admin API base URL accepted via npEnvClusterNodes
// to the rest of that node's identity — cfg-lab-specific, same data as
// #3094's suite (independently declared per this file's package doc).
var npLabTopology = map[string]npNode{
	"https://192.168.234.103:9080": {adminURL: "https://192.168.234.103:9080", sshHost: "cfgms-ctrl-01.lab.cfg.is"},
	"https://192.168.234.104:9080": {adminURL: "https://192.168.234.104:9080", sshHost: "cfgms-ha-node2.lab.cfg.is"},
	"https://192.168.234.106:9080": {adminURL: "https://192.168.234.106:9080", sshHost: "cfgms-ha-node3.lab.cfg.is"},
}

// ─── setup / gate ───────────────────────────────────────────────────────────

func npSetup(t *testing.T) ([]npNode, *http.Client) {
	t.Helper()
	raw := os.Getenv(npEnvClusterNodes)
	if raw == "" {
		t.Skipf("live real-cluster HA e2e: set %s to the 3 admin API base URLs to run", npEnvClusterNodes)
	}

	var nodes []npNode
	for _, u := range strings.Split(raw, ",") {
		u = strings.TrimSpace(strings.TrimRight(u, "/"))
		n, ok := npLabTopology[u]
		if !ok {
			t.Fatalf("%s lists %q, which is not a known cfg-lab node (known: %v)", npEnvClusterNodes, u, npKnownURLs())
		}
		nodes = append(nodes, n)
	}
	require.Len(t, nodes, 3, "%s must list exactly the 3 real cluster nodes", npEnvClusterNodes)

	client := npMTLSClient(t)
	return nodes, client
}

func npKnownURLs() []string {
	var out []string
	for u := range npLabTopology {
		out = append(out, u)
	}
	return out
}

type npAdminBundle struct {
	CertPEM string `yaml:"cert_pem"`
	KeyPEM  string `yaml:"key_pem"`
	CAPEM   string `yaml:"ca_pem"`
}

func npDefaultBundlePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	if runtime.GOOS == "windows" {
		return filepath.Join(home, "admin.bundle.yaml")
	}
	return filepath.Join(home, ".cfgms", "admin.bundle.yaml")
}

func npMTLSClient(t *testing.T) *http.Client {
	t.Helper()
	path := npGetenvDefault(npEnvAdminBundle, npDefaultBundlePath())
	data, err := os.ReadFile(path) // #nosec G304 -- operator-controlled path via env/default, local test tooling
	if err != nil {
		t.Skipf("live real-cluster HA e2e: cannot read admin bundle at %s (set %s): %v", path, npEnvAdminBundle, err)
	}
	var b npAdminBundle
	require.NoError(t, yaml.Unmarshal(data, &b), "admin bundle at %s must parse", path)

	cert, err := tls.X509KeyPair([]byte(b.CertPEM), []byte(b.KeyPEM))
	require.NoError(t, err, "admin bundle cert/key must parse")
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM([]byte(b.CAPEM)), "admin bundle CA must parse")

	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				RootCAs:      pool,
				MinVersion:   tls.VersionTLS12,
			},
		},
	}
}

func npGetenvDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// ─── ha/status polling ──────────────────────────────────────────────────────

// npHAStatus mirrors features/controller/api/handlers_ha.go's
// HAStatusResponse — the lease-backed status surface (ADR-031 Decision 5)
// that replaced the deleted Raft-protocol raftStatusResponse (Issue #3763).
type npHAStatus struct {
	NodeID   string `json:"node_id"`
	IsLeader bool   `json:"is_leader"`
}

func npGetHAStatus(ctx context.Context, client *http.Client, baseURL string) (npHAStatus, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/api/v1/ha/status", nil)
	if err != nil {
		return npHAStatus{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return npHAStatus{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return npHAStatus{}, fmt.Errorf("ha/status %s: HTTP %d: %s", baseURL, resp.StatusCode, string(body))
	}
	var st npHAStatus
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return npHAStatus{}, err
	}
	return st, nil
}

// npHALeader mirrors features/controller/api/handlers_ha.go's HALeaderResponse.
type npHALeader struct {
	NodeID string `json:"node_id"`
}

func npGetLeaderID(ctx context.Context, client *http.Client, baseURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/api/v1/ha/leader", nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("ha/leader %s: HTTP %d: %s", baseURL, resp.StatusCode, string(body))
	}
	var l npHALeader
	if err := json.NewDecoder(resp.Body).Decode(&l); err != nil {
		return "", err
	}
	return l.NodeID, nil
}

func npWaitForAgreement(ctx context.Context, t *testing.T, client *http.Client, urls []string, notLeader string, bound time.Duration) (string, time.Duration) {
	t.Helper()
	start := time.Now()
	deadline := start.Add(bound)
	for time.Now().Before(deadline) {
		leader := ""
		agree := true
		seen := 0
		for _, u := range urls {
			id, err := npGetLeaderID(ctx, client, u)
			if err != nil {
				agree = false
				continue
			}
			seen++
			if id == "" || id == notLeader {
				agree = false
				continue
			}
			if leader == "" {
				leader = id
			} else if leader != id {
				agree = false
			}
		}
		if agree && seen == len(urls) && leader != "" {
			return leader, time.Since(start)
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("no leader agreement among %v within %v (excluding prior leader %q)", urls, bound, notLeader)
	return "", 0
}

func npNodeIndexByID(ctx context.Context, client *http.Client, nodes []npNode, id string) int {
	for i, n := range nodes {
		st, err := npGetHAStatus(ctx, client, n.adminURL)
		if err == nil && st.NodeID == id {
			return i
		}
	}
	return -1
}

func npURLs(nodes []npNode) []string {
	out := make([]string, len(nodes))
	for i, n := range nodes {
		out[i] = n.adminURL
	}
	return out
}

func npExcept(urls []string, exclude string) []string {
	var out []string
	for _, u := range urls {
		if u != exclude {
			out = append(out, u)
		}
	}
	return out
}

// ─── steward fleet health (constraint: actively poll, don't assume) ───────

type npFleetSnapshot struct {
	total int
	err   error
}

func npFleetHealth(client *http.Client, urls []string) npFleetSnapshot {
	for _, u := range urls {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u+"/api/v1/stewards", nil)
		if err != nil {
			cancel()
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			cancel()
			continue
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			cancel()
			continue
		}
		var body struct {
			Data []json.RawMessage `json:"data"`
		}
		decodeErr := json.NewDecoder(resp.Body).Decode(&body)
		_ = resp.Body.Close()
		cancel()
		if decodeErr == nil {
			return npFleetSnapshot{total: len(body.Data)}
		}
	}
	return npFleetSnapshot{err: fmt.Errorf("no reachable node answered /api/v1/stewards")}
}

// ─── SSH ─────────────────────────────────────────────────────────────────

func npSSHKey() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return npGetenvDefault(npEnvSSHKey, filepath.Join(home, ".ssh", "cfgms_lab_ed25519"))
}

func npSSHRun(host, remoteCmd string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ssh",
		"-i", npSSHKey(),
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "ConnectTimeout=10",
		npGetenvDefault(npEnvSSHUser, "debian")+"@"+host, remoteCmd)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("ssh %s %q: %w: %s", host, remoteCmd, err, stderr.String())
	}
	return strings.TrimSpace(stdout.String()), nil
}

// ─── iptables partition control ─────────────────────────────────────────────

// npApplyPartition blocks all traffic to the shared database port (5432,
// both directions) on node via a dedicated iptables chain — a real firewall
// rule, not a Docker network toggle. The admin REST port (9080) is
// deliberately left open so this suite's own polling keeps observing the
// isolated node. Blocking the database (the lease substrate, pkg/lease)
// rather than a peer-to-peer port is the post-Raft equivalent of the
// original Raft-transport-port block: it is the one dependency whose loss
// makes this node unable to renew its claim to leadership.
func npApplyPartition(t *testing.T, node npNode) {
	t.Helper()
	cmd := "sudo -n iptables -N " + npPartitionChain + " 2>/dev/null; " +
		"sudo -n iptables -F " + npPartitionChain +
		" && sudo -n iptables -A " + npPartitionChain + " -p tcp --dport " + npDatabasePort + " -j DROP" +
		" && sudo -n iptables -A " + npPartitionChain + " -p tcp --sport " + npDatabasePort + " -j DROP" +
		" && (sudo -n iptables -C INPUT -j " + npPartitionChain + " 2>/dev/null || sudo -n iptables -I INPUT -j " + npPartitionChain + ")" +
		" && (sudo -n iptables -C OUTPUT -j " + npPartitionChain + " 2>/dev/null || sudo -n iptables -I OUTPUT -j " + npPartitionChain + ")"
	_, err := npSSHRun(node.sshHost, cmd)
	require.NoError(t, err, "apply network partition on %s", node.sshHost)
}

// npRemovePartition unconditionally removes the partition rule and chain —
// safe to call even if npApplyPartition partially failed or was never
// called (every step is best-effort). Per the story's Constraints, this is
// the automated half of "cleanup must always run, even on assertion failure
// or panic" — paired with t.Cleanup at every call site below.
func npRemovePartition(node npNode) {
	cmd := "sudo -n iptables -D INPUT -j " + npPartitionChain + " 2>/dev/null; " +
		"sudo -n iptables -D OUTPUT -j " + npPartitionChain + " 2>/dev/null; " +
		"sudo -n iptables -F " + npPartitionChain + " 2>/dev/null; " +
		"sudo -n iptables -X " + npPartitionChain + " 2>/dev/null; " +
		"true"
	_, _ = npSSHRun(node.sshHost, cmd)
}

// npManualPartitionRecovery is logged whenever a partition test starts, so a
// failed automated cleanup always has the exact manual command an operator
// needs on hand — this directly affects live lab fleet connectivity, not
// disposable test infrastructure (story #3095 Constraints).
func npManualPartitionRecovery(node npNode) string {
	return "ssh -i <key> " + npGetenvDefault(npEnvSSHUser, "debian") + "@" + node.sshHost +
		" 'sudo iptables -D INPUT -j " + npPartitionChain + "; sudo iptables -D OUTPUT -j " + npPartitionChain +
		"; sudo iptables -F " + npPartitionChain + "; sudo iptables -X " + npPartitionChain + "'"
}

// ─── partition-window observation ───────────────────────────────────────────

// npPartitionSetup resolves the cluster, confirms a healthy 3-way leader
// agreement (the safety precondition — partitioning is only safe to attempt
// from a confirmed-healthy baseline), and returns the current leader's node
// index so callers can isolate it specifically. Using the leader as the
// minority side exercises a REAL lease-expiry step-down (AC's "no longer
// leader" branch), the more meaningful case compared to partitioning an
// already-non-leader node ("was never leader").
func npPartitionSetup(t *testing.T) (nodes []npNode, client *http.Client, urls []string, minorityIdx int) {
	t.Helper()
	nodes, client = npSetup(t)
	ctx := context.Background()
	urls = npURLs(nodes)

	initialLeader, _ := npWaitForAgreement(ctx, t, client, urls, "", 30*time.Second)
	minorityIdx = npNodeIndexByID(ctx, client, nodes, initialLeader)
	require.GreaterOrEqual(t, minorityIdx, 0, "must resolve which node URL currently holds lease-backed leadership %q", initialLeader)
	t.Logf("current leader (isolated as the minority side): node_id=%s (%s / %s)", initialLeader, nodes[minorityIdx].adminURL, nodes[minorityIdx].sshHost)
	t.Logf("manual partition recovery if automated cleanup fails: %s", npManualPartitionRecovery(nodes[minorityIdx]))
	return nodes, client, urls, minorityIdx
}

// npBeginPartition applies the partition and registers its unconditional
// removal via t.Cleanup — every call site gets this pairing so a failed
// assertion or panic can never leave the lab cluster partitioned.
func npBeginPartition(t *testing.T, node npNode) {
	t.Helper()
	npApplyPartition(t, node)
	t.Cleanup(func() { npRemovePartition(node) })
}

// ─── AC (REQUIRED): minority steps down ─────────────────────────────────────

// TestRealClusterPartition_MinorityStepsDown (REQUIRED, #3095) — a real
// iptables rule isolates the current leader from the shared database; the
// minority side's own GET /api/v1/ha/status must stop (or never) report
// is_leader=true during the partition window. Also confirms the Constraints
// requirement: the majority side keeps serving the live steward fleet
// throughout, actively polled rather than assumed.
func TestRealClusterPartition_MinorityStepsDown(t *testing.T) {
	nodes, client, urls, minorityIdx := npPartitionSetup(t)
	ctx := context.Background()
	minority := nodes[minorityIdx]
	majorityURLs := npExcept(urls, minority.adminURL)
	require.Len(t, majorityURLs, 2, "exactly 2 nodes must remain on the majority side")

	t.Logf("partitioning %s from the shared database (real iptables rule, port %s both directions)", minority.sshHost, npDatabasePort)
	npBeginPartition(t, minority)

	// Poll the minority side until it stops claiming leadership, bounded —
	// this is the lease-expiry step-down the AC exists to prove.
	steppedDown := false
	deadline := time.Now().Add(npPartitionStepDownBound)
	for time.Now().Before(deadline) {
		st, err := npGetHAStatus(ctx, client, minority.adminURL)
		if err == nil && !st.IsLeader {
			steppedDown = true
			break
		}
		time.Sleep(npPartitionPollInterval)
	}
	assert.True(t, steppedDown, "minority side %s did not step down from leadership within %v of partition", minority.sshHost, npPartitionStepDownBound)

	// Continue observing for the rest of the window: it must never reclaim
	// leadership while still isolated.
	remaining := npPartitionObserveWindow - npPartitionStepDownBound
	if remaining > 0 {
		reclaimed := false
		obsDeadline := time.Now().Add(remaining)
		for time.Now().Before(obsDeadline) {
			st, err := npGetHAStatus(ctx, client, minority.adminURL)
			if err == nil && st.IsLeader {
				reclaimed = true
				break
			}
			// Majority side must keep serving the live fleet throughout —
			// actively polled, not assumed (story #3095 Constraints).
			fh := npFleetHealth(client, majorityURLs)
			assert.NoError(t, fh.err, "majority side must remain reachable for fleet health during the partition")
			time.Sleep(npPartitionPollInterval)
		}
		assert.False(t, reclaimed, "minority side %s reclaimed leadership while still partitioned from the database", minority.sshHost)
	}
	t.Logf("MINORITY STEP-DOWN: %s stepped down and stayed down for the %v observation window", minority.sshHost, npPartitionObserveWindow)
}

// ─── AC (REQUIRED): no dual leader ──────────────────────────────────────────

// TestRealClusterPartition_NoDualLeader (REQUIRED, #3095) — polls both sides
// of the partition in tight paired sequence (minimal skew between the two
// reads — a paired sequential read is a stricter same-instant check than two
// independently-scheduled goroutines, which would introduce MORE skew, not
// less) every 500ms throughout the partition window, asserting no poll round
// ever finds both sides simultaneously claiming leadership.
//
// Originally written and validated against the Raft-backed mechanism
// (2026-08-15 through 2026-08-26; see docs/testing/controller-ha-real-cluster-runbook.md
// section 5 for that history). Rewritten for Issue #3763 (ADR-031 Decision
// 5): leadership is now the shared database lease, so the partition target
// changed from the Raft peer transport port to the database port, and the
// polled surface changed from GET /api/v1/raft/status to
// GET /api/v1/ha/status's is_leader field. The property under test — no
// instant exists where both sides report leadership — and its underlying
// guarantee (pkg/lease.SafetyMargin: the isolated node's cached local
// authority is bounded by its own monotonic clock, independent of whether
// the database itself is reachable) are unchanged.
//
// This rewrite has not been executed against live cfg-lab infrastructure
// (agent container, no lab network access) — see the runbook's history
// section for the last real measurement (Raft-backed mechanism) and update
// it with a fresh run once this rewrite executes against the live cluster.
func TestRealClusterPartition_NoDualLeader(t *testing.T) {
	nodes, client, urls, minorityIdx := npPartitionSetup(t)
	ctx := context.Background()
	minority := nodes[minorityIdx]
	// Majority "side" for this check is represented by whichever majority
	// node currently holds/acquires leadership — poll all majority URLs each
	// round, not just one, so a majority-side leader handoff mid-window is
	// still caught.
	majorityURLs := npExcept(urls, minority.adminURL)
	require.Len(t, majorityURLs, 2, "exactly 2 nodes must remain on the majority side")

	t.Logf("partitioning %s from the shared database (real iptables rule, port %s both directions)", minority.sshHost, npDatabasePort)
	npBeginPartition(t, minority)

	violations := 0
	rounds := 0
	deadline := time.Now().Add(npPartitionObserveWindow)
	for time.Now().Before(deadline) {
		rounds++
		minoritySt, minorityErr := npGetHAStatus(ctx, client, minority.adminURL)
		minorityIsLeader := minorityErr == nil && minoritySt.IsLeader

		for _, u := range majorityURLs {
			st, err := npGetHAStatus(ctx, client, u)
			if err == nil && st.IsLeader && minorityIsLeader {
				violations++
				t.Errorf("DUAL LEADER at round %d: minority %s (node_id=%s) AND majority %s (node_id=%s) both report is_leader=true",
					rounds, minority.adminURL, minoritySt.NodeID, u, st.NodeID)
			}
		}
		time.Sleep(npPartitionPollInterval)
	}

	assert.Zero(t, violations, "dual-leader window(s) observed during the partition — see individual round failures above")
	t.Logf("NO DUAL LEADER: %d paired poll rounds across %v (interval %v), 0 dual-leader instants", rounds, npPartitionObserveWindow, npPartitionPollInterval)
}

// ─── AC (REQUIRED): heals to single leader ─────────────────────────────────

// TestRealClusterPartition_HealsToSingleLeader (REQUIRED, #3095) — removes
// the firewall rule and asserts the cluster reconverges to exactly one
// agreed leader across all 3 nodes within a bounded timeout.
func TestRealClusterPartition_HealsToSingleLeader(t *testing.T) {
	nodes, client, urls, minorityIdx := npPartitionSetup(t)
	ctx := context.Background()
	minority := nodes[minorityIdx]

	t.Logf("partitioning %s from the shared database (real iptables rule, port %s both directions)", minority.sshHost, npDatabasePort)
	npApplyPartition(t, minority)
	partitioned := true
	t.Cleanup(func() {
		if partitioned {
			npRemovePartition(minority)
		}
	})

	// Brief settle so the partition is genuinely in effect before healing —
	// this test's focus is recovery, not re-proving step-down (covered above).
	time.Sleep(10 * time.Second)

	t.Logf("healing partition: removing iptables rule on %s", minority.sshHost)
	npRemovePartition(minority)
	partitioned = false

	leader, elapsed := npWaitForAgreement(ctx, t, client, urls, "", npFailoverBound)
	t.Logf("HEALED: all 3 nodes reconverged on leader node_id=%s in %v (bound %v) after partition removal", leader, elapsed, npFailoverBound)
}
