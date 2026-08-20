// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build e2e

// Fleet-e2e live validation of leader election and automatic failover on the
// real cfg-lab 3-node controller cluster (epic #3090 AC1, story #3094), built
// on top of the genuine 3-node ha.mode: cluster deployment story #3130
// established (cfgms-ctrl-01, cfgms-ha-node2, cfgms-ha-node3; see
// docs/testing/controller-ha-real-cluster-runbook.md §3).
//
// Unlike test/integration/ha's Docker-Compose suite (local containers,
// FastElectionConfig-adjacent timing), this suite drives the real hosts over
// the network: mTLS admin REST calls to GET /api/v1/raft/status on all 3
// nodes, SSH to abruptly kill the leader's controller process, and remote
// Hyper-V PowerShell to power off the leader's VM outright. It measures both
// failure modes' real wall-clock re-election time against production
// defaults (pkg/ha.DefaultConfig: ElectionTimeout 10s, HeartbeatInterval 2s
// — this suite deliberately does NOT use FastElectionConfig, which exists
// only to keep CPU-contended unit tests fast and would invalidate the
// real-world comparison this suite exists to produce).
//
// Safety (this cluster serves the real lab fleet — see the story's
// Constraints): every kill is preceded by a live 3-way leader-agreement
// check (proving quorum is currently healthy) and only ever removes ONE of
// the 3 nodes, which cannot drop the cluster below pkg/ha.DefaultConfig's
// MinQuorum of 2. Recovery is the delicate part: pkg/ha's Raft state is
// entirely raft.MemoryStorage (never persisted to disk — runbook §3), so a
// killed node that comes back while its two peers are still running
// re-bootstraps as a fresh, self-elected single-node cluster and can
// diverge/panic a peer that later tries to reconcile logs with it
// (reproduced live during #3130: "panic: tocommit(4) is out of range
// [lastIndex(3)]"). This suite never restarts a node solo: haRestoreQuorum
// always stops the still-running peers first, brings the downed node back,
// then starts the peers together — the same stop-all/start-all discipline
// #3130's rollback drill used. The controller process's Restart=on-failure
// systemd property (RestartSec=5) is also a landmine here — an unattended
// kill would auto-respawn the node mid-test, 5 seconds into the very window
// this suite is measuring, hitting the same solo-restart divergence risk
// with no operator awareness. `systemctl set-property Restart=...` turned out
// NOT to be settable at runtime on this unit (verified live against systemd
// 257: "Cannot set property Restart, or unknown property" — Restart=
// governs process lifecycle, not resource control, and isn't in the D-Bus
// runtime-settable set), so haKillProcess instead races RestartSec's 5s
// window directly: the SIGKILL and a `systemctl stop` are sent back-to-back
// over one SSH connection, well inside 5s — `systemctl stop` cancels any
// pending auto-restart job regardless of the unit's current state. This is a
// genuine operational gap this story surfaces, not a simulation artifact —
// see the runbook appendix this suite feeds.
//
// The suite is excluded from CI and `make test-complete` by the e2e build
// tag, and skips cleanly when CFGMS_E2E_HA_CLUSTER_NODES is unset, following
// the convention in test/e2e/hyperv/promote_role_test.go:35-37.
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
//	                             real cluster nodes, e.g.
//	                             "https://192.168.234.103:9080,https://192.168.234.104:9080,https://192.168.234.106:9080"
//
// Optional:
//
//	CFGMS_E2E_HA_ADMIN_BUNDLE    path to the admin.bundle.yaml mTLS credential
//	                             used for GET /api/v1/raft/status and
//	                             /api/v1/stewards (default: platform admin
//	                             bundle path, matching cmd/cfg/cmd's own
//	                             default lookup for a user-level bundle).
//	CFGMS_E2E_HA_SSH_KEY         private key for reaching the node VMs
//	                             (default: <home>/.ssh/cfgms_lab_ed25519).
//	CFGMS_E2E_HA_SSH_USER        SSH user on the node VMs (default: "debian").
const (
	envClusterNodes = "CFGMS_E2E_HA_CLUSTER_NODES"
	envAdminBundle  = "CFGMS_E2E_HA_ADMIN_BUNDLE"
	envSSHKey       = "CFGMS_E2E_HA_SSH_KEY"
	envSSHUser      = "CFGMS_E2E_HA_SSH_USER"

	haPollInterval  = 2 * time.Second
	haFailoverBound = 90 * time.Second
)

// haNode is one cluster member's full identity: its admin REST API base URL
// (mTLS), the SSH hostname reaching its guest OS, and the Hyper-V host + VM
// name needed to power off its VM for the "host killed" scenario.
type haNode struct {
	adminURL string
	sshHost  string
	hvHost   string
	vmName   string
}

// haLabTopology maps each admin API base URL accepted via envClusterNodes to
// the rest of that node's identity. This suite is tied to the one real
// cluster it validates against (cfg-lab, story #3130) — the same hardcoded
// pattern the sibling hyperv e2e suites use for their lab defaults
// (HVSwitch_1G, CSV01, "cfg-lab", etc. in cluster_cascade_test.go).
var haLabTopology = map[string]haNode{
	"https://192.168.234.103:9080": {
		adminURL: "https://192.168.234.103:9080",
		sshHost:  "cfgms-ctrl-01.lab.cfg.is",
		hvHost:   "CFG-70-02",
		vmName:   "cfgms-ctrl-01",
	},
	"https://192.168.234.104:9080": {
		adminURL: "https://192.168.234.104:9080",
		sshHost:  "cfgms-ha-node2.lab.cfg.is",
		hvHost:   "CFG-AB-02",
		vmName:   "cfgms-ha-node2",
	},
	"https://192.168.234.106:9080": {
		adminURL: "https://192.168.234.106:9080",
		sshHost:  "cfgms-ha-node3.lab.cfg.is",
		hvHost:   "CFG-C3-02",
		vmName:   "cfgms-ha-node3",
	},
}

// ─── setup / gate ───────────────────────────────────────────────────────────

// haSetup resolves the environment and skips cleanly when the suite cannot
// run live: CFGMS_E2E_HA_CLUSTER_NODES unset, an unrecognized URL, or the
// admin bundle credential missing/unparseable.
func haSetup(t *testing.T) ([]haNode, *http.Client) {
	t.Helper()
	raw := os.Getenv(envClusterNodes)
	if raw == "" {
		t.Skipf("live real-cluster HA e2e: set %s to the 3 admin API base URLs to run", envClusterNodes)
	}

	var nodes []haNode
	for _, u := range strings.Split(raw, ",") {
		u = strings.TrimSpace(strings.TrimRight(u, "/"))
		n, ok := haLabTopology[u]
		if !ok {
			t.Fatalf("%s lists %q, which is not a known cfg-lab node (known: %v)", envClusterNodes, u, haKnownURLs())
		}
		nodes = append(nodes, n)
	}
	require.Len(t, nodes, 3, "%s must list exactly the 3 real cluster nodes", envClusterNodes)

	client := haMTLSClient(t)
	return nodes, client
}

func haKnownURLs() []string {
	var out []string
	for u := range haLabTopology {
		out = append(out, u)
	}
	return out
}

type haAdminBundle struct {
	CertPEM string `yaml:"cert_pem"`
	KeyPEM  string `yaml:"key_pem"`
	CAPEM   string `yaml:"ca_pem"`
}

// haDefaultBundlePath mirrors cmd/cfg/cmd's defaultSystemBundlePath, but for
// this suite the operator's own admin.bundle.yaml (not the system-wide one)
// is the realistic credential source, so it prefers the user's home
// directory on both platforms.
func haDefaultBundlePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	if runtime.GOOS == "windows" {
		return filepath.Join(home, "admin.bundle.yaml")
	}
	return filepath.Join(home, ".cfgms", "admin.bundle.yaml")
}

// haMTLSClient builds an mTLS http.Client from the admin bundle, skipping
// cleanly when the bundle is missing.
func haMTLSClient(t *testing.T) *http.Client {
	t.Helper()
	path := getenvDefault(envAdminBundle, haDefaultBundlePath())
	data, err := os.ReadFile(path) // #nosec G304 -- operator-controlled path via env/default, local test tooling
	if err != nil {
		t.Skipf("live real-cluster HA e2e: cannot read admin bundle at %s (set %s): %v", path, envAdminBundle, err)
	}
	var b haAdminBundle
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

func getenvDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// ─── raft/status polling ────────────────────────────────────────────────────

// haRaftStatus mirrors pkg/ha/raft_transport.go's raftStatusResponse. Fields
// are concretely typed (not interface{}), so encoding/json preserves full
// uint64 precision for the FNV node-ID hashes — the same precision-loss bug
// class #3130 found and fixed (RaftCommand.Data) does not apply here because
// this decodes directly into typed struct fields, never through interface{}.
type haRaftStatus struct {
	NodeID   uint64 `json:"node_id"`
	IsLeader bool   `json:"is_leader"`
	Leader   uint64 `json:"leader"`
	Term     uint64 `json:"term"`
	Nodes    int    `json:"nodes"`
}

func haGetRaftStatus(ctx context.Context, client *http.Client, baseURL string) (haRaftStatus, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/api/v1/raft/status", nil)
	if err != nil {
		return haRaftStatus{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return haRaftStatus{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return haRaftStatus{}, fmt.Errorf("raft/status %s: HTTP %d: %s", baseURL, resp.StatusCode, string(body))
	}
	var st haRaftStatus
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return haRaftStatus{}, err
	}
	return st, nil
}

// haWaitForAgreement polls urls until every one of them reports the SAME
// nonzero leader that is not notLeader (the prior leader, when re-electing
// after a kill — pass 0 for "no exclusion" on an initial baseline check).
// A url that errors (e.g. the node just killed, briefly unreachable during a
// VM stop) is simply not counted this poll — only currently-reachable nodes
// need to agree, and all of urls must be reachable and agreeing to succeed.
// Returns the agreed leader's raft node ID and elapsed wall-clock time.
func haWaitForAgreement(ctx context.Context, t *testing.T, client *http.Client, urls []string, notLeader uint64, bound time.Duration) (uint64, time.Duration) {
	t.Helper()
	start := time.Now()
	deadline := start.Add(bound)
	for time.Now().Before(deadline) {
		leader := uint64(0)
		agree := true
		seen := 0
		for _, u := range urls {
			st, err := haGetRaftStatus(ctx, client, u)
			if err != nil {
				agree = false
				continue
			}
			seen++
			if st.Leader == 0 || st.Leader == notLeader {
				agree = false
				continue
			}
			if leader == 0 {
				leader = st.Leader
			} else if leader != st.Leader {
				agree = false
			}
		}
		if agree && seen == len(urls) && leader != 0 {
			return leader, time.Since(start)
		}
		time.Sleep(haPollInterval)
	}
	t.Fatalf("no leader agreement among %v within %v (excluding prior leader %d)", urls, bound, notLeader)
	return 0, 0
}

// haNodeIndexByRaftID finds which nodes[] entry currently reports raftID as
// its OWN node_id, resolving a raft node ID (opaque FNV hash) back to the
// concrete node identity (SSH host, VM name) the rest of this suite acts on.
func haNodeIndexByRaftID(ctx context.Context, client *http.Client, nodes []haNode, raftID uint64) int {
	for i, n := range nodes {
		st, err := haGetRaftStatus(ctx, client, n.adminURL)
		if err == nil && st.NodeID == raftID {
			return i
		}
	}
	return -1
}

func haURLs(nodes []haNode) []string {
	out := make([]string, len(nodes))
	for i, n := range nodes {
		out[i] = n.adminURL
	}
	return out
}

func haExcept(urls []string, exclude string) []string {
	var out []string
	for _, u := range urls {
		if u != exclude {
			out = append(out, u)
		}
	}
	return out
}

// ─── steward fleet health (constraint: monitor throughout, not just at the end) ──

type haFleetSnapshot struct {
	total int
	err   error
}

// haFleetHealth queries GET /api/v1/stewards against the first reachable URL
// in urls and returns the enrolled-steward count. Best-effort: a fleet
// snapshot is diagnostic context for this suite, not itself an acceptance
// criterion, so a failure to reach any node here is reported, not fatal.
func haFleetHealth(client *http.Client, urls []string) haFleetSnapshot {
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
			return haFleetSnapshot{total: len(body.Data)}
		}
	}
	return haFleetSnapshot{err: fmt.Errorf("no reachable node answered /api/v1/stewards")}
}

// haCheckFleetUnchanged logs both snapshots (the runbook's "captured...not
// silently absorbed" requirement) and asserts the enrolled count didn't
// regress when both snapshots were actually taken successfully.
func haCheckFleetUnchanged(t *testing.T, label string, before, after haFleetSnapshot) {
	t.Helper()
	t.Logf("fleet health %s: before=%d (err=%v) after=%d (err=%v)", label, before.total, before.err, after.total, after.err)
	if before.err == nil && after.err == nil {
		assert.Equal(t, before.total, after.total, "steward fleet enrolled count changed during %s — investigate before treating as expected", label)
	}
}

// ─── SSH (leader process control) ───────────────────────────────────────────

func haSSHKey() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return getenvDefault(envSSHKey, filepath.Join(home, ".ssh", "cfgms_lab_ed25519"))
}

func haSSHRun(host, remoteCmd string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ssh",
		"-i", haSSHKey(),
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "ConnectTimeout=10",
		getenvDefault(envSSHUser, "debian")+"@"+host, remoteCmd)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("ssh %s %q: %w: %s", host, remoteCmd, err, stderr.String())
	}
	return strings.TrimSpace(stdout.String()), nil
}

func haWaitSSHReachable(t *testing.T, host string, bound time.Duration) {
	t.Helper()
	deadline := time.Now().Add(bound)
	for time.Now().Before(deadline) {
		if _, err := haSSHRun(host, "true"); err == nil {
			return
		}
		time.Sleep(5 * time.Second)
	}
	t.Fatalf("node %s did not become SSH-reachable within %v", host, bound)
}

// haKillProcess abruptly kills the leader's cfgms-controller process
// (SIGKILL — simulating a crash, not a graceful `systemctl stop`, so the
// OS/network stack resets in-flight TCP connections immediately per the
// story's Implementation Notes). `systemctl set-property Restart=...` is NOT
// among the properties this unit accepts at runtime (verified live: "Cannot
// set property Restart, or unknown property" against systemd 257 — Restart=
// governs process lifecycle, not resource control, and isn't in the D-Bus
// runtime-settable set), so this instead races RestartSec=5s directly: the
// kill and a `systemctl stop` are sent back-to-back over one SSH connection,
// well inside the 5s window. `systemctl stop` cancels any pending auto-
// restart job regardless of unit state, which is what actually prevents the
// solo-restart divergence risk documented in the package doc comment.
func haKillProcess(t *testing.T, node haNode) {
	t.Helper()
	_, err := haSSHRun(node.sshHost, "sudo -n systemctl kill --kill-who=main -s SIGKILL cfgms-controller.service; sudo -n systemctl stop cfgms-controller.service")
	require.NoError(t, err, "kill leader process on %s", node.sshHost)
}

// haRestoreQuorum is the only safe way this suite brings a solo-downed node
// back into a live quorum: stop the still-running peers first, discard every
// node's persisted Raft WAL, bring the downed node back via bringUp, then
// start the peers together.
//
// The stop-all/start-all discipline is because a node that rejoins while its
// peers keep running can diverge instead of catching up cleanly.
//
// The WAL wipe is newer and is what makes this function work at all today.
// Raft state used to be memory-only (as the package doc comment describes),
// so a cold start re-bootstrapped membership from the configured peer list.
// Since Issue #3284 the log is persisted to <data>/raft-log/raft.db, and
// NewRaftConsensus takes raft.RestartNode whenever that file has data — but
// nothing restores the ConfState, and config.Applied is set to the recovered
// applied index so the original ConfChange entries are never re-delivered
// either. Every node therefore comes back with an empty voter set
// ("newRaft <id> [peers: [], term: N, ...]") and no election ever happens:
// GET /api/v1/raft/status reports leader 0 forever.
//
// Reproduced deterministically on the real cfg-lab cluster on 2026-08-20
// (story #3096, runbook §6 finding F1) — twice, across a full stop/start of
// all three nodes, with terms diverging (t3/commit8 vs t2/commit7). Wiping the
// WAL restores the StartNode path and quorum forms in seconds. Until that
// defect is fixed, a restore that does not wipe leaves the lab cluster
// leaderless, so this helper wipes rather than pretending the restart works.
func haRestoreQuorum(t *testing.T, allNodes []haNode, downIdx int, bringUp func()) {
	t.Helper()
	var up []haNode
	for i, n := range allNodes {
		if i != downIdx {
			up = append(up, n)
		}
	}

	t.Log("restoring 3-node quorum: stopping remaining peers, wiping persisted Raft WALs, bringing the downed node back, then starting all together")
	for _, n := range up {
		_, err := haSSHRun(n.sshHost, "sudo -n systemctl stop cfgms-controller.service")
		assert.NoError(t, err, "stop peer %s during quorum restore", n.sshHost)
	}

	// Wipe on every node, including the downed one — a partial wipe leaves the
	// wiped nodes bootstrapping a fresh term while the un-wiped node sits at
	// its old term with no voters, which does not converge either.
	for _, n := range allNodes {
		_, err := haSSHRun(n.sshHost, "sudo -n find /var/lib/cfgms -name raft.db -delete")
		assert.NoError(t, err, "wipe persisted raft WAL on %s during quorum restore", n.sshHost)
	}

	bringUp()

	for _, n := range up {
		_, err := haSSHRun(n.sshHost, "sudo -n systemctl start cfgms-controller.service")
		assert.NoError(t, err, "start peer %s during quorum restore", n.sshHost)
	}
}

// ─── Hyper-V host control (leader VM control) ───────────────────────────────

func haPowerShell(script string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("%w: %s", err, stderr.String())
	}
	return strings.TrimSpace(stdout.String()), nil
}

// haIsLocalHVHost reports whether node's Hyper-V host is this machine — the
// Hyper-V cmdlets' -ComputerName parameter targets a *remote* host over
// WSMan/CIM using the caller's ambient domain identity, but a *local* Stop-VM
// needs this process's own token to hold local admin/Hyper-V-Administrators
// rights, which a deliberately non-admin session (this repo's Windows
// dev-host convention) does not have. See haStopVMHost's error message.
func haIsLocalHVHost(node haNode) bool {
	local, err := os.Hostname()
	return err == nil && strings.EqualFold(local, node.hvHost)
}

func haStopVMHost(t *testing.T, node haNode) {
	t.Helper()
	var script string
	if haIsLocalHVHost(node) {
		script = fmt.Sprintf(`Stop-VM -Name '%s' -TurnOff -Force -ErrorAction Stop`, node.vmName)
	} else {
		script = fmt.Sprintf(`Stop-VM -ComputerName '%s' -Name '%s' -TurnOff -Force -ErrorAction Stop`, node.hvHost, node.vmName)
	}
	out, err := haPowerShell(script)
	require.NoErrorf(t, err, "Stop-VM %s on %s (if this is a local-host permission error, run this suite from a session with local Hyper-V admin rights on %s): %s", node.vmName, node.hvHost, node.hvHost, out)
}

func haStartVMHost(t *testing.T, node haNode) {
	t.Helper()
	var script string
	if haIsLocalHVHost(node) {
		script = fmt.Sprintf(`Start-VM -Name '%s' -ErrorAction Stop`, node.vmName)
	} else {
		script = fmt.Sprintf(`Start-VM -ComputerName '%s' -Name '%s' -ErrorAction Stop`, node.hvHost, node.vmName)
	}
	out, err := haPowerShell(script)
	assert.NoErrorf(t, err, "Start-VM %s on %s: %s", node.vmName, node.hvHost, out)
}

// ─── AC (REQUIRED): baseline leader agreement ──────────────────────────────

// TestRealClusterLeaderAgreement (REQUIRED, #3094) — all 3 real nodes agree
// on the same leader via GET /api/v1/raft/status under normal operation.
func TestRealClusterLeaderAgreement(t *testing.T) {
	nodes, client := haSetup(t)
	ctx := context.Background()
	urls := haURLs(nodes)

	leader, elapsed := haWaitForAgreement(ctx, t, client, urls, 0, 30*time.Second)
	t.Logf("all %d real nodes agree on leader node_id=%d (confirmed in %v)", len(urls), leader, elapsed)
}

// ─── AC (REQUIRED): process-kill failover ──────────────────────────────────

// TestRealClusterFailover_ProcessKilled (REQUIRED, #3094) — kills the
// leader's controller process and asserts the remaining 2 nodes converge on
// a new, different leader within a bounded timeout, logging the measured
// wall-clock re-election time.
func TestRealClusterFailover_ProcessKilled(t *testing.T) {
	nodes, client := haSetup(t)
	ctx := context.Background()
	urls := haURLs(nodes)

	initialLeader, _ := haWaitForAgreement(ctx, t, client, urls, 0, 30*time.Second)
	leaderIdx := haNodeIndexByRaftID(ctx, client, nodes, initialLeader)
	require.GreaterOrEqual(t, leaderIdx, 0, "must resolve which node URL currently holds raft leader %d", initialLeader)
	leaderNode := nodes[leaderIdx]
	t.Logf("current leader: node_id=%d (%s / %s)", initialLeader, leaderNode.adminURL, leaderNode.sshHost)

	// Quorum-safety constraint: a healthy 3-way agreement (just confirmed above)
	// with MinQuorum=2 (pkg/ha.DefaultConfig) means killing exactly ONE node
	// leaves the required majority intact — never test a scenario that would
	// drop below quorum.
	remaining := haExcept(urls, leaderNode.adminURL)
	require.Len(t, remaining, 2, "exactly 2 nodes must remain after excluding the leader")

	before := haFleetHealth(client, remaining)
	t.Logf("live steward fleet before test: %d enrolled (err=%v) — monitored throughout, not just at the end", before.total, before.err)

	t.Logf("killing leader process on %s (SIGKILL)", leaderNode.sshHost)
	haKillProcess(t, leaderNode)
	t.Cleanup(func() {
		haRestoreQuorum(t, nodes, leaderIdx, func() {
			_, err := haSSHRun(leaderNode.sshHost, "sudo -n systemctl start cfgms-controller.service")
			assert.NoError(t, err, "restart killed leader %s during cleanup", leaderNode.sshHost)
		})
		finalLeader, elapsed := haWaitForAgreement(ctx, t, client, urls, 0, 90*time.Second)
		t.Logf("post-test quorum restored: all 3 nodes agree on leader node_id=%d (%v after restart)", finalLeader, elapsed)
	})

	newLeader, elapsed := haWaitForAgreement(ctx, t, client, remaining, initialLeader, haFailoverBound)
	t.Logf("PROCESS-KILL FAILOVER: remaining %d nodes converged on new leader node_id=%d in %v (bound %v)", len(remaining), newLeader, elapsed, haFailoverBound)
	assert.NotEqual(t, initialLeader, newLeader, "new leader must differ from the killed leader")

	after := haFleetHealth(client, remaining)
	haCheckFleetUnchanged(t, "process-kill failover", before, after)
}

// ─── AC (REQUIRED): host-kill failover ─────────────────────────────────────

// TestRealClusterFailover_HostKilled (REQUIRED, #3094) — stops the leader's
// VM outright (not just its process) and asserts the same convergence,
// logging the measured wall-clock time separately from the process-kill
// figure. A host kill is a materially different recovery curve: in-flight
// TCP connections time out rather than reset immediately (Implementation
// Notes), which this suite runs as an independent scenario against a fresh
// 3-way agreement rather than assuming ordering with the process-kill test.
func TestRealClusterFailover_HostKilled(t *testing.T) {
	nodes, client := haSetup(t)
	ctx := context.Background()
	urls := haURLs(nodes)

	initialLeader, _ := haWaitForAgreement(ctx, t, client, urls, 0, 30*time.Second)
	leaderIdx := haNodeIndexByRaftID(ctx, client, nodes, initialLeader)
	require.GreaterOrEqual(t, leaderIdx, 0, "must resolve which node URL currently holds raft leader %d", initialLeader)
	leaderNode := nodes[leaderIdx]
	t.Logf("current leader: node_id=%d (%s / VM %s on %s)", initialLeader, leaderNode.adminURL, leaderNode.vmName, leaderNode.hvHost)

	remaining := haExcept(urls, leaderNode.adminURL)
	require.Len(t, remaining, 2, "exactly 2 nodes must remain after excluding the leader")

	before := haFleetHealth(client, remaining)
	t.Logf("live steward fleet before test: %d enrolled (err=%v) — monitored throughout, not just at the end", before.total, before.err)

	t.Logf("stopping leader's VM %s on %s (hard power-off, not a guest shutdown)", leaderNode.vmName, leaderNode.hvHost)
	haStopVMHost(t, leaderNode)
	t.Cleanup(func() {
		haRestoreQuorum(t, nodes, leaderIdx, func() {
			haStartVMHost(t, leaderNode)
			haWaitSSHReachable(t, leaderNode.sshHost, 3*time.Minute)
			_, err := haSSHRun(leaderNode.sshHost, "sudo -n systemctl start cfgms-controller.service")
			assert.NoError(t, err, "restart controller on %s during cleanup", leaderNode.sshHost)
		})
		finalLeader, elapsed := haWaitForAgreement(ctx, t, client, urls, 0, 90*time.Second)
		t.Logf("post-test quorum restored: all 3 nodes agree on leader node_id=%d (%v after VM restart)", finalLeader, elapsed)
	})

	newLeader, elapsed := haWaitForAgreement(ctx, t, client, remaining, initialLeader, haFailoverBound)
	t.Logf("HOST-KILL FAILOVER: remaining %d nodes converged on new leader node_id=%d in %v (bound %v)", len(remaining), newLeader, elapsed, haFailoverBound)
	assert.NotEqual(t, initialLeader, newLeader, "new leader must differ from the killed leader")

	after := haFleetHealth(client, remaining)
	haCheckFleetUnchanged(t, "host-kill failover", before, after)
}
