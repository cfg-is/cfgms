// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package atomicfile replaces and reads files so that a reader and a writer
// working on the same path never block each other.
//
// It keeps only a process-local queue map (see QueuedLockFile) and is not a
// central provider: it has no interfaces, backends or registry.
//
// ReadFile never prevents a concurrent replace of the file it reads, and
// AtomicReplace swaps src over dst in one operation, so a reader sees either
// the whole old file or the whole new file. On POSIX these are os.ReadFile and
// os.Rename. On Windows, ReadFile opens with FILE_SHARE_DELETE and
// AtomicReplace uses a POSIX-semantics rename, because Go's os.ReadFile omits
// FILE_SHARE_DELETE and os.Rename (MoveFileEx) fails with Access is denied
// whenever any other handle to the destination is open.
//
// AtomicReplace does not remove src on failure; the caller does.
//
// LockFile takes an exclusive cross-process advisory lock on a lock file:
// flock(2) on Unix, LockFileEx on Windows. It opens the file (creating it with
// mode 0600 if missing) and never deletes it, because unlinking a lock file that
// another process has open would split the lock across two inodes. The kernel
// releases the lock when the holder exits, so a crashed holder never leaves a
// stale lock behind. The lock is retried without blocking until the context
// ends, so a cancelled or expired context returns ctx.Err() and takes nothing.
// The returned unlock function unlocks and closes the file and is safe to call
// more than once.
//
// QueuedLockFile is LockFile with an in-process FIFO queue in front of it.
// Goroutines of one process queue by lock path in arrival order, and only the
// head calls LockFile, so waiters never touch the filesystem. The wait is bounded
// by lack of progress, not total time: a waiter fails with ErrLockNoProgress when
// the head of its queue has not changed for the given duration, or when the head
// cannot take the OS lock within it. Waiting behind holders that keep releasing
// is not a timeout. A cancelled context returns ctx.Err(), and empty queues are
// removed from the map.
package atomicfile
