// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package security

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// repairOwnerUID is the owner TakeOverForRepair assigns. It is a variable only
// so tests can run without root; production always uses root.
var repairOwnerUID = 0

// TakeOverForRepair resets the owner (root) and mode (directories 0700, files
// 0600) of every entry under roots. It is called only by an accepted repair,
// never by startup or install checks, which keep refusing a tampered tree.
//
// Every entry is reached through a descriptor opened with O_NOFOLLOW relative
// to its already-opened parent, and changed through that descriptor, so a link
// planted anywhere under a root is never followed out of it. A symlink, and a
// regular file with more than one hard link (whose inode is shared with a path
// the root does not control), is unlinked and reported as quarantined; the
// target is not touched. Special files and a root that is itself a link are
// refused. Paths outside roots are never opened.
func TakeOverForRepair(roots []string) (TakeoverReport, error) {
	var rep TakeoverReport
	if len(roots) == 0 {
		return rep, errors.New("repair takeover needs at least one root")
	}
	abs := make([]string, 0, len(roots))
	for _, r := range roots {
		if r == "" {
			return rep, errors.New("repair takeover root is empty")
		}
		a, err := filepath.Abs(r)
		if err != nil {
			return rep, fmt.Errorf("resolve root %q: %w", r, err)
		}
		abs = append(abs, a)
	}
	for _, root := range abs {
		takeOverRoot(root, &rep)
	}
	if len(rep.Refused) > 0 {
		return rep, ErrTakeoverIncomplete
	}
	return rep, nil
}

func takeOverRoot(root string, rep *TakeoverReport) {
	// The root is opened by path, but without following a final symlink. A
	// symlinked ancestor is the caller's declared layout, not a link under the
	// root.
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	switch {
	case errors.Is(err, unix.ENOENT):
		return // nothing to take over
	case err != nil:
		rep.Refused = append(rep.Refused, fmt.Sprintf("%s: root is not a plain directory: %v", root, err))
		return
	}
	defer func() { _ = unix.Close(fd) }()
	takeOverDir(fd, root, rep)
}

// takeOverDir secures the directory behind fd, then every entry in it.
func takeOverDir(fd int, path string, rep *TakeoverReport) {
	secureFD(fd, path, 0700, rep)

	dupFD, err := unix.Dup(fd)
	if err != nil {
		rep.Refused = append(rep.Refused, fmt.Sprintf("%s: list directory: %v", path, err))
		return
	}
	dir := os.NewFile(uintptr(dupFD), path)
	names, err := dir.Readdirnames(-1)
	_ = dir.Close()
	if err != nil {
		rep.Refused = append(rep.Refused, fmt.Sprintf("%s: list directory: %v", path, err))
		return
	}
	for _, name := range names {
		takeOverEntry(fd, path, name, rep)
	}
}

func takeOverEntry(dirFD int, dirPath, name string, rep *TakeoverReport) {
	path := filepath.Join(dirPath, name)
	var st unix.Stat_t
	if err := unix.Fstatat(dirFD, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		rep.Refused = append(rep.Refused, fmt.Sprintf("%s: stat: %v", path, err))
		return
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFLNK:
		quarantine(dirFD, name, path, rep)
	case unix.S_IFDIR:
		takeOverSubdir(dirFD, name, path, rep)
	case unix.S_IFREG:
		takeOverFile(dirFD, name, path, st.Nlink > 1, rep)
	default:
		rep.Refused = append(rep.Refused, path+": special file")
	}
}

func takeOverSubdir(dirFD int, name, path string, rep *TakeoverReport) {
	fd, err := unix.Openat(dirFD, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		rep.Refused = append(rep.Refused, fmt.Sprintf("%s: open directory: %v", path, err))
		return
	}
	defer func() { _ = unix.Close(fd) }()
	takeOverDir(fd, path, rep)
}

// takeOverFile secures a regular file, or quarantines it when it has more than
// one hard link.
func takeOverFile(dirFD int, name, path string, hardLinked bool, rep *TakeoverReport) {
	if hardLinked {
		quarantine(dirFD, name, path, rep)
		return
	}
	fd, err := unix.Openat(dirFD, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		rep.Refused = append(rep.Refused, fmt.Sprintf("%s: open file: %v", path, err))
		return
	}
	defer func() { _ = unix.Close(fd) }()
	// The entry may have been swapped for a hard-linked file since the stat
	// in the caller; the descriptor is what counts.
	var fst unix.Stat_t
	if err := unix.Fstat(fd, &fst); err != nil || fst.Mode&unix.S_IFMT != unix.S_IFREG || fst.Nlink > 1 {
		rep.Refused = append(rep.Refused, path+": changed while being secured")
		return
	}
	secureFD(fd, path, 0600, rep)
}

// quarantine unlinks name from dirFD. unlinkat removes the directory entry
// and never follows it, so the link target is not touched.
func quarantine(dirFD int, name, path string, rep *TakeoverReport) {
	if err := unix.Unlinkat(dirFD, name, 0); err != nil {
		rep.Refused = append(rep.Refused, fmt.Sprintf("%s: remove link: %v", path, err))
		return
	}
	rep.Quarantined = append(rep.Quarantined, path)
}

// secureFD sets owner and mode through the descriptor and records the entry as
// secured when anything had to change.
func secureFD(fd int, path string, mode uint32, rep *TakeoverReport) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		rep.Refused = append(rep.Refused, fmt.Sprintf("%s: stat: %v", path, err))
		return
	}
	changed := false
	if int(st.Uid) != repairOwnerUID {
		if err := unix.Fchown(fd, repairOwnerUID, -1); err != nil {
			rep.Refused = append(rep.Refused, fmt.Sprintf("%s: set owner: %v", path, err))
			return
		}
		changed = true
	}
	// Stat_t.Mode is uint16 on darwin and uint32 on linux; compare as int so
	// the conversion is meaningful on every platform.
	if int(st.Mode&0o7777) != int(mode) {
		if err := unix.Fchmod(fd, mode); err != nil {
			rep.Refused = append(rep.Refused, fmt.Sprintf("%s: set mode: %v", path, err))
			return
		}
		changed = true
	}
	if changed {
		rep.Secured = append(rep.Secured, path)
	}
}
