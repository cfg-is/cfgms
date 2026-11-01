// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build e2e

// Fleet-e2e live validation of steward continuity through a real controller
// leader failover on the cfg-lab 3-node cluster (epic #3090, story #3096),
// building on story #3094's failover suite in leader_election_real_test.go —
// this file reuses that file's setup, mTLS client, kill and quorum-restore
// helpers rather than duplicating them (same package, same build tag).
//
// The question this suite answers is narrower than #3094's: not "does a new
// leader get elected" (that is #3094's, already measured), but "does an
// enrolled steward keep heartbeating while it happens".
//
// Live findings that shaped this suite (full evidence in
// docs/testing/controller-ha-real-cluster-runbook.md §6):
//
//  1. Continuity through a leader failover is REAL and clean. Measured
//     2026-08-20 against the live cluster: leader cfgms-ha-node3 SIGKILLed,
//     cfgms-ha-node2 elected, and a steward attached to the surviving
//     follower cfgms-ctrl-01 missed ZERO heartbeats (cadence ~25s held
//     straight through) and logged zero reconnects. The steward's transport
//     is unaffected by a leader change because its node never went away.
//
//  2. A steward's fleet record is NODE-LOCAL, not cluster-wide.
//     GET /api/v1/stewards is served from ControllerService's in-process map
//     (features/controller/service/controller_service.go:979), so the very
//     steward that is actively heartbeating through one node is invisible on
//     the other two — including the leader. This suite therefore reads the
//     steward's heartbeat from the node that SERVES it, not from the leader,
//     and asserts the node-local view explicitly rather than pretending the
//     fleet view is shared.
//
//  3. Keeping a steward enrolled across a controller restart does not work
//     today (RLS policy bug, runbook §6 finding F3): the controller's own DB
//     role cannot read back steward_records it just wrote, so after any
//     controller restart every steward is denied admission. That is why this
//     suite SKIPS rather than fails when no active steward is present — it
//     refuses to assert continuity it cannot observe, and refuses to pass
//     vacuously.
package ha_e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Optional environment variable for this suite:
//
//	CFGMS_E2E_HA_STEWARD_ID   pin the steward to observe. When unset, the
//	                          suite uses the first steward reporting status
//	                          "active" on any node.
const envStewardID = "CFGMS_E2E_HA_STEWARD_ID"

// haContinuityBound is how long a heartbeat may take to land after the
// failover before continuity is considered broken. The measured live cadence
// is ~25s, so this allows roughly three beats — generous enough not to flake
// on a slow beat, tight enough that a steward which actually stopped
// heartbeating (the failure this asserts against) is still caught.
const haContinuityBound = 90 * time.Second

// haStewardView is the subset of GET /api/v1/stewards this suite reads.
type haStewardView struct {
	ID       string    `json:"id"`
	TenantID string    `json:"tenant_id"`
	Status   string    `json:"status"`
	LastSeen time.Time `json:"last_seen"`
}

// haListStewards returns one node's view of the fleet. Deliberately per-node:
// finding (2) above means the three nodes do NOT agree, and this suite exists
// partly to record that.
func haListStewards(ctx context.Context, client *http.Client, baseURL string) ([]haStewardView, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/api/v1/stewards", nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("stewards %s: HTTP %d: %s", baseURL, resp.StatusCode, string(body))
	}
	var envelope struct {
		Data []haStewardView `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, err
	}
	return envelope.Data, nil
}

// haFindActiveSteward locates a steward reporting "active" and the node whose
// API reports it. Returns ok=false when the fleet has no active steward on any
// node, which is the documented-gap case the caller turns into a skip.
func haFindActiveSteward(ctx context.Context, client *http.Client, nodes []haNode) (steward haStewardView, servingNode haNode, ok bool) {
	want := os.Getenv(envStewardID)
	for _, n := range nodes {
		list, err := haListStewards(ctx, client, n.adminURL)
		if err != nil {
			continue
		}
		for _, s := range list {
			if want != "" && s.ID != want {
				continue
			}
			if s.Status == "active" {
				return s, n, true
			}
		}
	}
	return haStewardView{}, haNode{}, false
}

// haStewardOn re-reads one steward's record from one specific node.
func haStewardOn(ctx context.Context, client *http.Client, node haNode, stewardID string) (haStewardView, bool) {
	list, err := haListStewards(ctx, client, node.adminURL)
	if err != nil {
		return haStewardView{}, false
	}
	for _, s := range list {
		if s.ID == stewardID {
			return s, true
		}
	}
	return haStewardView{}, false
}

// ─── AC (REQUIRED): steward continuity through a real leader failover ───────

// TestRealClusterStewardContinuity_LeaderFailover (REQUIRED, #3096) kills the
// current leader and asserts that a steward attached to a SURVIVING node keeps
// heartbeating across the re-election — a fresh heartbeat must land after the
// new leader is agreed, and the steward must never leave "active".
//
// It skips (never fails, never passes vacuously) when the cluster has no active
// steward to observe, because enrolling one is currently blocked by the
// registration gaps recorded in runbook §6.
func TestRealClusterStewardContinuity_LeaderFailover(t *testing.T) {
	nodes, client := haSetup(t)
	ctx := context.Background()
	urls := haURLs(nodes)

	steward, serving, ok := haFindActiveSteward(ctx, client, nodes)
	if !ok {
		t.Skipf("no active steward enrolled against the real cluster — cannot observe continuity. "+
			"Enrolling one currently requires an operator-added trusted CIDR "+
			"(POST /api/v1/registration/ip-trust) and does not survive a controller restart, "+
			"per the registration findings in docs/testing/controller-ha-real-cluster-runbook.md §6. "+
			"Set %s once a steward is enrolled to pin which one this suite observes.", envStewardID)
	}
	t.Logf("observing steward %s (tenant %s) as served by %s", steward.ID, steward.TenantID, serving.sshHost)

	// Baseline: the cluster must be healthy before we break it, and we need to
	// know which node is leader so we can kill the right one.
	leader, _ := haWaitForAgreement(ctx, t, client, urls, "", 30*time.Second)
	leaderIdx := haNodeIndexByID(ctx, client, nodes, leader)
	require.GreaterOrEqual(t, leaderIdx, 0, "elected leader %s must map to a known cfg-lab node", leader)
	leaderNode := nodes[leaderIdx]

	// The scenario under test is "the steward's own node survives, the LEADER
	// dies". If the steward happens to be served by the leader itself, killing
	// it would test something else entirely (losing your own controller — the
	// single-controller-URL Non-Goal), so skip rather than mis-report.
	if leaderNode.adminURL == serving.adminURL {
		t.Skipf("steward %s is served by the current leader (%s); this test covers leader failover with the "+
			"steward attached to a SURVIVING node. Re-run once the leader has moved, or pin a steward on another node.",
			steward.ID, leaderNode.sshHost)
	}

	before, found := haStewardOn(ctx, client, serving, steward.ID)
	require.True(t, found, "steward %s must be readable on its serving node before the kill", steward.ID)
	t.Logf("baseline: last_seen=%s status=%s", before.LastSeen.Format(time.RFC3339), before.Status)

	// Kill the leader. Only ever one of three nodes — quorum (MinQuorum 2) holds.
	t.Logf("killing leader %s (node id %s)", leaderNode.sshHost, leader)
	killedAt := time.Now()
	haKillProcess(t, leaderNode)

	survivors := haExcept(urls, leaderNode.adminURL)
	newLeader, electionTime := haWaitForAgreement(ctx, t, client, survivors, leader, haFailoverBound)
	require.NotEqual(t, leader, newLeader, "a NEW leader must be elected after the old one is killed")
	t.Logf("re-elected: leader %s -> %s in %v", leader, newLeader, electionTime)

	// Continuity: a heartbeat that post-dates the kill must land on the
	// steward's serving node. Comparing against killedAt (not against the
	// baseline last_seen) is what makes this a continuity assertion rather
	// than a "record still exists" assertion — a stale record would satisfy
	// the latter, so it must not satisfy this.
	var latest haStewardView
	deadline := time.Now().Add(haContinuityBound)
	beat := false
	for time.Now().Before(deadline) {
		s, present := haStewardOn(ctx, client, serving, steward.ID)
		if present {
			latest = s
			assert.Equal(t, "active", s.Status,
				"steward must stay active through the failover (observed %q)", s.Status)
			if s.LastSeen.After(killedAt) {
				beat = true
				break
			}
		}
		time.Sleep(haPollInterval)
	}

	require.Truef(t, beat,
		"steward %s did not heartbeat within %v of the leader being killed "+
			"(last_seen=%s, kill=%s) — continuity through leader failover is broken",
		steward.ID, haContinuityBound,
		latest.LastSeen.Format(time.RFC3339), killedAt.Format(time.RFC3339))

	t.Logf("CONTINUITY OK: heartbeat at %s landed %v after the leader was killed (re-election took %v)",
		latest.LastSeen.Format(time.RFC3339), latest.LastSeen.Sub(killedAt).Round(time.Second), electionTime)

	// The fleet view must now agree across the cluster. This was a recorded
	// observation rather than an assertion while the list was node-local: a
	// steward heartbeating through one node was invisible on its peers,
	// including the leader (runbook §6 finding F4). Issue #3480 made the list
	// read the shared store, so every node is expected to see it.
	for _, n := range nodes {
		_, present := haStewardOn(ctx, client, n, steward.ID)
		assert.Truef(t, present,
			"%s does not see steward %s — the fleet view is node-local again (Issue #3480)",
			n.sshHost, steward.ID)
	}

	haRestoreQuorum(t, nodes, leaderIdx, func() {
		_, err := haSSHRun(leaderNode.sshHost, "sudo -n systemctl start cfgms-controller.service")
		assert.NoError(t, err, "restart killed leader %s", leaderNode.sshHost)
	})
}
