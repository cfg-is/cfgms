// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package main

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// errShallow is returned when merge-base cannot be trusted.
var errShallow = errors.New("history too shallow to compute merge-base; fetch full history (actions/checkout fetch-depth: 0 or git fetch --unshallow)")

// baseRefs are tried in order as the branch a change is measured against.
var baseRefs = []string{"origin/develop", "develop"}

// maxTreeFileBytes bounds one materialised file, as a guard on archive input.
const maxTreeFileBytes = 64 << 20

// gitCleanEnv returns the process environment without the variables git
// exports to hooks (GIT_DIR, GIT_INDEX_FILE, ...), which would otherwise make
// every git call act on the calling repository instead of the -C directory.
func gitCleanEnv() []string {
	drop := map[string]bool{"GIT_COMMON_DIR": true, "GIT_PREFIX": true}
	// #nosec G204 -- fixed git binary and arguments.
	if out, err := exec.Command("git", "rev-parse", "--local-env-vars").Output(); err == nil {
		for _, n := range strings.Fields(string(out)) {
			drop[n] = true
		}
	}
	for _, n := range []string{"GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_CONFIG", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT",
		"GIT_OBJECT_DIRECTORY", "GIT_DIR", "GIT_WORK_TREE", "GIT_IMPLICIT_WORK_TREE", "GIT_GRAFT_FILE", "GIT_INDEX_FILE",
		"GIT_NO_REPLACE_OBJECTS", "GIT_REPLACE_REF_BASE", "GIT_SHALLOW_FILE"} {
		drop[n] = true
	}
	var env []string
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if !drop[name] {
			env = append(env, kv)
		}
	}
	return env
}

// git runs git in dir and returns stdout. Failures carry git's stderr text.
func git(dir string, args ...string) ([]byte, error) {
	// #nosec G204 -- fixed argv, no shell; callers pass literal subcommands; refs are rejected if they start with "-" (see materializeRef).
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = gitCleanEnv()
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git %s: %v: %s", args[0], err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// MergeBase resolves the merge-base of HEAD and the first of baseRefs that
// exists. It fails closed: a shallow repository, an unresolvable ref or a
// failing merge-base is an error, never "nothing touched".
func MergeBase(dir string) (string, error) {
	out, err := git(dir, "rev-parse", "--is-shallow-repository")
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(string(out)) == "true" {
		return "", errShallow
	}
	ref := ""
	for _, r := range baseRefs {
		if _, err := git(dir, "rev-parse", "--verify", "--quiet", r+"^{commit}"); err == nil {
			ref = r
			break
		}
	}
	if ref == "" {
		return "", fmt.Errorf("neither %s resolves; fetch the base branch", strings.Join(baseRefs, " nor "))
	}
	out, err = git(dir, "merge-base", "HEAD", ref)
	if err != nil {
		return "", fmt.Errorf("%w (%v)", errShallow, err)
	}
	return strings.TrimSpace(string(out)), nil
}

// TouchedFiles returns repo-root-relative, forward-slash paths changed since
// mergeBase: committed, staged and unstaged tracked changes plus untracked
// files that are not ignored.
func TouchedFiles(dir, mergeBase string) ([]string, error) {
	top, err := git(dir, "rev-parse", "--show-toplevel")
	if err != nil {
		return nil, err
	}
	root := strings.TrimSpace(string(top))
	seen := map[string]bool{}
	var files []string
	for _, args := range [][]string{
		{"diff", "--name-only", "-z", mergeBase, "--"},
		{"ls-files", "--others", "--exclude-standard", "-z"},
	} {
		out, err := git(root, args...)
		if err != nil {
			return nil, err
		}
		for _, name := range strings.Split(string(out), "\x00") {
			name = filepath.ToSlash(name)
			if name != "" && !seen[name] {
				seen[name] = true
				files = append(files, name)
			}
		}
	}
	return files, nil
}

// MaterializeRef extracts the tree of ref from the repository in the current
// directory into a temporary directory and returns it as an fs.FS. The
// working tree and index are never touched. cleanup removes the temp dir.
func MaterializeRef(ref string) (fs.FS, func(), error) { return materializeRef(".", ref) }

func materializeRef(repo, ref string) (fs.FS, func(), error) {
	if strings.HasPrefix(ref, "-") {
		return nil, nil, fmt.Errorf("invalid ref %q", ref)
	}
	out, err := git(repo, "archive", "--format=tar", ref, "--")
	if err != nil {
		return nil, nil, err
	}
	dir, err := os.MkdirTemp("", "complexity-tree-")
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	if err := extractTar(bytes.NewReader(out), dir); err != nil {
		cleanup()
		return nil, nil, err
	}
	return os.DirFS(dir), cleanup, nil
}

func extractTar(r io.Reader, dir string) error {
	// All writes go through an os.Root scoped to dir, so the OS enforces that
	// no archive entry (including via a symlinked parent) lands outside it.
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read git archive: %w", err)
		}
		// Only regular files matter for analysis; directories are implied,
		// symlinks and git's pax header are skipped.
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if !filepath.IsLocal(filepath.FromSlash(hdr.Name)) {
			return fmt.Errorf("git archive entry escapes the tree: %q", hdr.Name)
		}
		dst := filepath.FromSlash(hdr.Name)
		if parent := filepath.Dir(dst); parent != "." {
			if err := root.MkdirAll(parent, 0o750); err != nil {
				return err
			}
		}
		f, err := root.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		n, err := io.Copy(f, io.LimitReader(tr, maxTreeFileBytes+1))
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
		if n > maxTreeFileBytes {
			return fmt.Errorf("git archive entry too large: %q", hdr.Name)
		}
	}
}
