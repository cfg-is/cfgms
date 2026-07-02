// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package hyperv

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/pkg/logging"
)

// defaultClusterPollInterval is the default cadence for the cluster DNA poller.
// There is no FailoverCluster event channel (unlike the Hyper-V VMMS Event Log),
// so ownership / membership is polled on a ticker.
const defaultClusterPollInterval = 30 * time.Second

// monitorClusterLoop is the per-cluster DNA polling loop (S4 of epic #2198). On
// each tick it reads the cluster status via the S1 read consts and emits a
// ChangeTypeModified ChangeEvent carrying the *ClusterStatus whenever ownership
// or membership changes — but only after a stability dwell (S8 anti-flap): a
// change must be observed on two consecutive polls before it is emitted, which
// suppresses mid-failover CNO-transient churn. The first poll establishes the
// baseline and emits nothing (consumers read the initial state via Get).
//
// The tick channel is injected so the production caller passes a real
// time.Ticker while tests drive the cadence deterministically. The loop returns
// when stop is closed.
func (m *hypervModule) monitorClusterLoop(clusterName string, tick <-chan time.Time, stop <-chan struct{}) {
	var lastEmitted, pending string
	var baselineSet bool

	for {
		select {
		case <-stop:
			return
		case <-tick:
			status := m.pollClusterStatus(clusterName)
			if status == nil {
				continue // poll failed — skip this tick, retry on the next
			}
			sig := clusterSignature(status)

			if !baselineSet {
				lastEmitted = sig
				baselineSet = true
				pending = ""
				continue
			}
			if sig == lastEmitted {
				// No net change (a transient may have reverted) — drop any pending.
				pending = ""
				continue
			}
			// sig differs from the last emitted state.
			if pending == sig {
				// Stable across two consecutive polls (S8 dwell) → emit.
				m.dispatchCluster(clusterName, modules.ChangeTypeModified, status)
				lastEmitted = sig
				pending = ""
			} else {
				// First sighting of this change — confirm on the next poll.
				pending = sig
			}
		}
	}
}

// pollClusterStatus reads the current cluster status via getCluster (the S1
// read-only PowerShell envelope). Returns nil on error so the loop simply
// retries on the next tick.
func (m *hypervModule) pollClusterStatus(clusterName string) *ClusterStatus {
	cs, err := m.getCluster(context.Background(), clusterName)
	if err != nil {
		if logger, ok := m.GetLogger(); ok {
			logger.Warn("hyperv: cluster DNA poll failed",
				"cluster", logging.SanitizeLogValue(clusterName),
				"error", logging.SanitizeLogValue(err.Error()))
		}
		return nil
	}
	status, _ := cs.(*ClusterStatus)
	return status
}

// dispatchCluster emits a cluster ChangeEvent on the shared monitor channel.
// Unlike dispatch() (VM events, Details: nil), the cluster event carries the
// *ClusterStatus as Details — the epic #415 DNA contract. The send is
// non-blocking and gated on registered interest + open channel, exactly like
// dispatch(), so a wedged consumer never blocks the polling goroutine.
func (m *hypervModule) dispatchCluster(clusterName string, ct modules.ChangeType, status *ClusterStatus) {
	resourceID := "cluster:" + clusterName

	m.monMu.Lock()
	if m.monClosed || m.monChanges == nil {
		m.monMu.Unlock()
		return
	}
	if _, watched := m.monClusterInterest[resourceID]; !watched {
		m.monMu.Unlock()
		return
	}
	ch := m.monChanges
	m.monMu.Unlock()

	ev := modules.ChangeEvent{
		ResourceID: resourceID,
		Timestamp:  time.Now().Unix(), // S8: Go receipt-time, never a cluster-reported timestamp
		ChangeType: ct,
		Details:    status,
	}
	// Non-blocking send: a wedged consumer must not block the polling goroutine.
	select {
	case ch <- ev:
	default:
	}
}

// clusterSignature renders the change-relevant fields of a ClusterStatus into a
// stable string for equality comparison across polls. Ownership (resource_owner
// + cno_owner) and membership (member_nodes) drive change detection; CSV paths
// and transient fields do not.
func clusterSignature(s *ClusterStatus) string {
	if s == nil {
		return ""
	}
	members := append([]string(nil), s.MemberNodes...)
	sort.Strings(members)

	ownerKeys := make([]string, 0, len(s.RoleOwners))
	for k := range s.RoleOwners {
		ownerKeys = append(ownerKeys, k)
	}
	sort.Strings(ownerKeys)

	var b strings.Builder
	b.WriteString("found=")
	b.WriteString(strconv.FormatBool(s.Found))
	b.WriteString(";access=")
	// cluster_access_ok is part of the signature so a grant/revoke transition
	// emits a DNA change and the onboarding alert clears/raises (#2306).
	b.WriteString(strconv.FormatBool(s.ClusterAccessOK))
	b.WriteString(";cno=")
	b.WriteString(s.CNOOwnerNode)
	b.WriteString(";members=")
	b.WriteString(strings.Join(members, ","))
	b.WriteString(";owners=")
	for _, k := range ownerKeys {
		b.WriteString(k)
		b.WriteString("=")
		b.WriteString(s.RoleOwners[k])
		b.WriteString(",")
	}
	return b.String()
}
