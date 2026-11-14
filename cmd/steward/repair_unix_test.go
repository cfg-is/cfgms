// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
)

// unreadableLog makes a log file the steward cannot read. A user with root reads
// every file, so the test cannot construct one there.
func unreadableLog(t *testing.T, f *repairFixture, name string) string {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root reads every file; an unreadable log cannot be made")
	}
	path := filepath.Join(f.paths.logDir, name)
	require.NoError(t, os.WriteFile(path, []byte("unreadable contents"), 0o600))
	require.NoError(t, os.Chmod(path, 0o000))
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
	return path
}

func TestRepair_Loss_UnreadableLogIsAssessedAndPublishedBeforeAnyRequest(t *testing.T) {
	f := newRepairFixture(t, repairFixtureOpts{})
	bad := unreadableLog(t, f, "bad.log")

	a := assessRepairLoss(f.paths, nil)
	assert.Equal(t, []string{cpTypes.ReasonCodeRepairLossLocalLogs}, a.Codes)
	assert.Equal(t, []string{bad}, a.items[cpTypes.ReasonCodeRepairLossLocalLogs], "only the unreadable file is at risk")

	f.start()
	// One component per code, on the heartbeat, with no request sent.
	repairReason(t, f.env.f.srv, cpTypes.ReasonCodeRepairLossLocalLogs, cpTypes.ReasonCodeRepairLossLocalLogs)
}

func TestRepair_Loss_EmptyApprovalDeletesNothing(t *testing.T) {
	f := newRepairFixture(t, repairFixtureOpts{})
	unreadableLog(t, f, "bad.log")
	f.start()
	before := shallowSnapshot(t, f.paths.dataDir, f.paths.logDir, f.env.f.dir)

	f.ctrl.allow("repair-noapproval")
	f.send(f.request("repair-noapproval", requestOpts{}))
	awaitOutcome(t, f, cpTypes.ReasonCodeRepairRefusedDataLoss)

	assert.Empty(t, f.removedPaths(), "not one delete or truncate call is made")
	assert.Equal(t, before, shallowSnapshot(t, f.paths.dataDir, f.paths.logDir, f.env.f.dir), "the tree is untouched")
	assert.Empty(t, f.ctrl.callList())
	assert.True(t, f.latch.isLatched())
}

func TestRepair_Loss_ExactApprovalRemovesOnlyThatItemAfterFlushingReadableLogs(t *testing.T) {
	f := newRepairFixture(t, repairFixtureOpts{})
	bad := unreadableLog(t, f, "bad.log")
	history := readFile(t, f.paths.actionHistory())
	f.start()
	f.env.dirBad.Store(false)
	srv := f.env.f.srv

	// When the delete happens, the readable log has already reached the
	// controller: the hook records what the controller had received by then.
	// The hook runs on the steward goroutine, so what it records is guarded.
	var mu sync.Mutex
	var deletes int
	var flushedBeforeDelete bool
	repairRemoveItem = func(path string) error {
		arrived := srv.receivedRepairFlush("steward.log")
		mu.Lock()
		deletes++
		flushedBeforeDelete = arrived
		mu.Unlock()
		return removeRepairItem(path)
	}
	approved := []string{cpTypes.ReasonCodeRepairLossLocalLogs}
	f.ctrl.allow("repair-approved")
	f.send(f.request("repair-approved", requestOpts{approved: approved}))
	awaitOutcome(t, f, cpTypes.ReasonCodeRepairCompleted)

	mu.Lock()
	assert.Equal(t, 1, deletes, "exactly the approved item is deleted")
	assert.True(t, flushedBeforeDelete, "the repair_flush entry for steward.log reached the controller before the delete")
	mu.Unlock()
	var flushed []string
	for _, e := range srv.logEntries() {
		if e.GetFields()["source"] == "repair_flush" {
			flushed = append(flushed, e.GetFields()["file"]+": "+e.GetMessage())
		}
	}
	assert.Contains(t, flushed, "steward.log: log line one\nlog line two\n")

	assert.NoFileExists(t, bad, "the approved item is removed")
	assert.FileExists(t, filepath.Join(f.paths.logDir, "steward.log"), "readable logs are kept")
	assert.Equal(t, history, readFile(t, f.paths.actionHistory()), "the action history is kept")
}

func TestRepair_Loss_UndeliverableFlushDeletesNothingAndReportsFailure(t *testing.T) {
	f := newRepairFixture(t, repairFixtureOpts{})
	bad := unreadableLog(t, f, "bad.log")
	f.start()
	f.env.dirBad.Store(false)
	srv := f.env.f.srv
	before := shallowSnapshot(t, f.paths.dataDir, f.paths.logDir, f.env.f.dir)

	// The controller refuses the log stream: the readable logs cannot leave the host.
	srv.refuseLogs.Store(true)
	f.ctrl.allow("repair-undeliverable")
	f.send(f.request("repair-undeliverable", requestOpts{approved: []string{cpTypes.ReasonCodeRepairLossLocalLogs}}))
	awaitOutcome(t, f, cpTypes.ReasonCodeRepairFailed)

	assert.Empty(t, f.removedPaths(), "not one delete is made when the flush is not confirmed")
	assert.False(t, srv.receivedRepairFlush("steward.log"))
	assert.FileExists(t, bad)
	assert.Equal(t, before, shallowSnapshot(t, f.paths.dataDir, f.paths.logDir, f.env.f.dir), "the tree is untouched")
	assert.Empty(t, f.ctrl.callList(), "no completion is requested")
	assert.True(t, f.latch.isLatched())
}

func TestRepair_Loss_SetChangedBetweenRequestAndExecution_DeletesNothing(t *testing.T) {
	f := newRepairFixture(t, repairFixtureOpts{})
	bad := unreadableLog(t, f, "bad.log")
	f.start()
	// The request is made against the loss set the console showed: local logs.
	req := f.request("repair-toctou", requestOpts{approved: []string{cpTypes.ReasonCodeRepairLossLocalLogs}})
	// By the time it executes, the log is readable again: the set changed.
	require.NoError(t, os.Chmod(bad, 0o600))

	f.ctrl.allow("repair-toctou")
	f.send(req)
	awaitOutcome(t, f, cpTypes.ReasonCodeRepairLossSetChanged)
	assert.Empty(t, f.removedPaths())
	assert.FileExists(t, bad)
	assert.Empty(t, f.ctrl.callList())
	assert.True(t, f.latch.isLatched())
}

func TestRepair_Loss_ApprovalWiderThanTheAssessmentDeletesNothingExtra(t *testing.T) {
	f := newRepairFixture(t, repairFixtureOpts{})
	bad := unreadableLog(t, f, "bad.log")
	f.start()
	wide := []string{cpTypes.ReasonCodeRepairLossLocalLogs, cpTypes.ReasonCodeRepairLossActionHistory}

	f.ctrl.allow("repair-wide")
	f.send(f.request("repair-wide", requestOpts{approved: wide}))
	awaitOutcome(t, f, cpTypes.ReasonCodeRepairLossSetChanged)

	assert.Empty(t, f.removedPaths(), "neither the unreadable log nor the healthy action history is deleted")
	assert.FileExists(t, bad)
	assert.FileExists(t, f.paths.actionHistory())
}

func TestRepair_ReportsPlantedLinksAndNeverFollowsThem(t *testing.T) {
	f := newRepairFixture(t, repairFixtureOpts{})
	outside := filepath.Join(t.TempDir(), "outside-target")
	require.NoError(t, os.WriteFile(outside, []byte("not ours"), 0o644))
	require.NoError(t, os.Chmod(outside, 0o644))
	link := filepath.Join(f.paths.logDir, "planted.log")
	require.NoError(t, os.Symlink(outside, link))
	f.start()
	f.env.dirBad.Store(false)

	f.ctrl.allow("repair-links")
	f.send(f.request("repair-links", requestOpts{}))
	awaitOutcome(t, f, cpTypes.ReasonCodeRepairCompleted)

	_, err := os.Lstat(link)
	assert.True(t, os.IsNotExist(err), "the planted link is removed")
	info, err := os.Stat(outside)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o644), info.Mode().Perm(), "the link target was not touched")
	assert.Equal(t, "not ours", readFile(t, outside))

	// The removal reaches the controller as a log entry on the new link.
	srv := f.env.f.srv
	require.Eventually(t, func() bool {
		for len(srv.logs) > 0 {
			if e := <-srv.logs; e.GetFields()["source"] == "repair" && e.GetFields()["path"] == link {
				return true
			}
		}
		return false
	}, 20*1e9, 50*1e6)
}

func TestRepair_ExposedTreeModesAreResetAndContentKept(t *testing.T) {
	f := newRepairFixture(t, repairFixtureOpts{})
	loose := filepath.Join(f.paths.dataDir, "loose.dat")
	require.NoError(t, os.WriteFile(loose, []byte("keep me"), 0o666))
	require.NoError(t, os.Chmod(loose, 0o666))
	require.NoError(t, os.Chmod(f.paths.actionHistory(), 0o666))
	history := readFile(t, f.paths.actionHistory())
	f.start()
	f.env.dirBad.Store(false)

	f.ctrl.allow("repair-modes")
	f.send(f.request("repair-modes", requestOpts{}))
	awaitOutcome(t, f, cpTypes.ReasonCodeRepairCompleted)

	for _, p := range []string{loose, f.paths.actionHistory()} {
		info, err := os.Stat(p)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), p)
	}
	assert.Equal(t, "keep me", readFile(t, loose))
	assert.Equal(t, history, readFile(t, f.paths.actionHistory()))
	assert.Empty(t, f.removedPaths())
}

// A link planted in a parent directory of an approved item must not lead the
// delete out of the declared directories: the steward acts as root and the tree
// is not trusted yet.
func TestRepair_RemoveItemNeverFollowsAPlantedParentLink(t *testing.T) {
	f := newRepairFixture(t, repairFixtureOpts{})
	outside := t.TempDir()
	victim := filepath.Join(outside, "victim.conf")
	require.NoError(t, os.WriteFile(victim, []byte("system file"), 0o600))
	link := filepath.Join(f.paths.logDir, "x")
	require.NoError(t, os.Symlink(outside, link))

	err := removeRepairItem(filepath.Join(link, "victim.conf"))
	assert.Error(t, err, "a path through a link that leaves the directory is refused")
	assert.Equal(t, "system file", readFile(t, victim), "the file outside was not touched")

	assert.Error(t, removeRepairItem(victim), "a path outside the declared directories is refused")
	assert.Error(t, removeRepairItem(f.paths.logDir), "a declared directory itself is never an item")
	assert.FileExists(t, victim)
}

// A link planted in a parent directory is refused even when it points at another
// directory inside the same declared root: the delete reaches only the entry the
// assessment named, never a file it was redirected to.
func TestRepair_RemoveItemRefusesAnInRootParentLink(t *testing.T) {
	f := newRepairFixture(t, repairFixtureOpts{})
	inside := filepath.Join(f.paths.logDir, "kept")
	require.NoError(t, os.Mkdir(inside, 0o700))
	victim := filepath.Join(inside, "steward.log")
	require.NoError(t, os.WriteFile(victim, []byte("kept log"), 0o600))
	link := filepath.Join(f.paths.logDir, "x")
	require.NoError(t, os.Symlink(inside, link))

	assert.Error(t, removeRepairItem(filepath.Join(link, "steward.log")), "a parent link is refused")
	assert.Equal(t, "kept log", readFile(t, victim), "the file the link leads to is not touched")
}

// The approved delete runs only after the rights reset has made the tree the
// steward's own: an exposed parent directory is no longer writable by anyone
// else when the delete happens, and a special file the reset refuses is still
// removed because it is the approved item.
func TestRepair_ApprovedDeleteRunsAfterTheTakeover(t *testing.T) {
	f := newRepairFixture(t, repairFixtureOpts{})
	exposed := filepath.Join(f.paths.logDir, "x")
	require.NoError(t, os.Mkdir(exposed, 0o700))
	require.NoError(t, os.Chmod(exposed, 0o777))
	pipe := filepath.Join(exposed, "pipe.log")
	require.NoError(t, syscall.Mkfifo(pipe, 0o600))
	f.start()
	f.env.dirBad.Store(false)

	var modesAtDelete []os.FileMode
	repairRemoveItem = func(path string) error {
		info, err := os.Lstat(exposed)
		require.NoError(t, err)
		modesAtDelete = append(modesAtDelete, info.Mode().Perm())
		return removeRepairItem(path)
	}
	f.ctrl.allow("repair-order")
	f.send(f.request("repair-order", requestOpts{approved: []string{cpTypes.ReasonCodeRepairLossLocalLogs}}))
	awaitOutcome(t, f, cpTypes.ReasonCodeRepairCompleted)

	require.NotEmpty(t, modesAtDelete, "the approved item was deleted")
	for _, m := range modesAtDelete {
		assert.Equal(t, os.FileMode(0o700), m, "the parent was taken over before the delete")
	}
	_, err := os.Lstat(pipe)
	assert.True(t, os.IsNotExist(err), "the approved special file is removed")
}
