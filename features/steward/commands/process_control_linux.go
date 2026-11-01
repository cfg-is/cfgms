// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

//go:build linux

package commands

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// systemProcessPIDs are refused on Linux: init.
var systemProcessPIDs = []int{1}

const (
	// processTermGrace is how long a process gets after SIGTERM before SIGKILL.
	processTermGrace = 5 * time.Second
	// processKillWait is how long to wait for the process to disappear after SIGKILL.
	processKillWait = 2 * time.Second
	processPoll     = 50 * time.Millisecond
)

type signalProcessController struct{}

// newPlatformProcessController returns the signal-based controller (no kill binary).
func newPlatformProcessController() ProcessController { return signalProcessController{} }

func (signalProcessController) Control(ctx context.Context, op ProcessOp, pid int, image string) error {
	if err := verifyProcessImage(pid, image); err != nil {
		return err
	}
	switch op {
	case ProcessOpSuspend:
		return signalPID(pid, syscall.SIGSTOP)
	case ProcessOpResume:
		return signalPID(pid, syscall.SIGCONT)
	case ProcessOpEnd:
		return endProcess(ctx, pid, image)
	default:
		return errors.New("unknown process operation")
	}
}

func endProcess(ctx context.Context, pid int, image string) error {
	if err := signalPID(pid, syscall.SIGTERM); err != nil {
		return err
	}
	if waitProcessGone(ctx, pid, image, processTermGrace) {
		return nil
	}
	// Re-verified inside waitProcessGone's last check: a PID reused during the grace
	// period reads as gone, so SIGKILL never reaches a stranger.
	if err := signalPID(pid, syscall.SIGKILL); err != nil {
		if errors.Is(err, ErrProcessNotFound) {
			return nil
		}
		return err
	}
	if !waitProcessGone(ctx, pid, image, processKillWait) {
		return errors.New("process did not exit after SIGKILL")
	}
	return nil
}

func signalPID(pid int, sig syscall.Signal) error {
	switch err := syscall.Kill(pid, sig); {
	case err == nil:
		return nil
	case errors.Is(err, syscall.ESRCH):
		return ErrProcessNotFound
	case errors.Is(err, syscall.EPERM):
		return ErrProcessPermissionDenied
	default:
		return err
	}
}

// waitProcessGone polls until the process has exited (gone, a zombie, or reused by a
// process with another image) or the timeout or ctx ends.
func waitProcessGone(ctx context.Context, pid int, image string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if processGone(pid, image) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		select {
		case <-ctx.Done():
			return processGone(pid, image)
		case <-time.After(processPoll):
		}
	}
}

func processGone(pid int, image string) bool {
	if verifyProcessImage(pid, image) != nil {
		return true
	}
	return processIsZombie(pid)
}

// readProcFile reads <pid>/<name> through an os.Root scoped to /proc, so the read can
// never resolve outside procfs regardless of the path segments.
func readProcFile(pid int, name string) ([]byte, error) {
	root, err := os.OpenRoot("/proc")
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }() // read-only directory handle; close error carries no data
	return root.ReadFile(strconv.Itoa(pid) + "/" + name)
}

// readProcLink reads the symlink <pid>/<name> through an os.Root scoped to /proc.
func readProcLink(pid int, name string) (string, error) {
	root, err := os.OpenRoot("/proc")
	if err != nil {
		return "", err
	}
	defer func() { _ = root.Close() }() // read-only directory handle; close error carries no data
	return root.Readlink(strconv.Itoa(pid) + "/" + name)
}

func processIsZombie(pid int) bool {
	b, err := readProcFile(pid, "stat")
	if err != nil {
		return true
	}
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 || i+2 >= len(s) {
		return false
	}
	return s[i+2] == 'Z' || s[i+2] == 'X'
}

// verifyProcessImage requires the live image name of pid to equal image. The image is
// the executable's base name, or the kernel's (15 character) comm name.
func verifyProcessImage(pid int, image string) error {
	comm, err := readProcFile(pid, "comm")
	if err != nil {
		switch {
		case errors.Is(err, os.ErrNotExist):
			return ErrProcessNotFound
		case errors.Is(err, os.ErrPermission):
			return ErrProcessPermissionDenied
		default:
			return err
		}
	}
	if strings.TrimSuffix(string(comm), "\n") == image {
		return nil
	}
	if exe, err := readProcLink(pid, "exe"); err == nil {
		if filepath.Base(strings.TrimSuffix(exe, " (deleted)")) == image {
			return nil
		}
	}
	return ErrProcessChanged
}
