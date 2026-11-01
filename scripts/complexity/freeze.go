// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package main

import (
	"bytes"
	"errors"
	"flag"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/cfgis/cfgms/scripts/complexity/metrics"
)

// freezeCmd writes the frozen baseline: the hotspot-only measurement of the
// tree at enablement. It refuses to replace an existing file; replacing one
// takes deleting it in a reviewed diff.
func freezeCmd(args []string, stdout, stderr io.Writer) int {
	fset := flag.NewFlagSet("freeze", flag.ContinueOnError)
	fset.SetOutput(stderr)
	var o reportOptions
	fset.StringVar(&o.root, "root", ".", "repository root to analyse")
	fset.StringVar(&o.manifest, "manifest", "scripts/complexity/manifest.json", "population manifest")
	fset.StringVar(&o.out, "out", "scripts/complexity/baselines/frozen.json", "frozen baseline to write")
	fset.StringVar(&o.baseCommit, "base-commit", "", "base commit SHA recorded in the file (default: git rev-parse origin/develop)")
	if err := fset.Parse(args); err != nil {
		return exitError
	}
	out, errOut := &printer{w: stdout}, &printer{w: stderr}
	code := freezeTo(o, out, errOut)
	if out.err != nil || errOut.err != nil {
		return exitError
	}
	return code
}

func freezeTo(o reportOptions, stdout, stderr *printer) int {
	if _, err := os.Stat(o.out); err == nil {
		stderr.printf("complexity: %s already exists; delete it in a reviewed diff to replace it\n", filepath.ToSlash(o.out))
		return exitViolation
	} else if !errors.Is(err, fs.ErrNotExist) {
		stderr.printf("complexity: stat %s: %v\n", filepath.ToSlash(o.out), ioReason(err))
		return exitError
	}
	tmp, err := os.MkdirTemp("", "complexity-freeze-")
	if err != nil {
		stderr.printf("complexity: %v\n", err)
		return exitError
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	measured := o
	measured.out = filepath.Join(tmp, "frozen.json")
	measured.compact = true
	if code := reportTo(measured, stdout, stderr); code != exitOK {
		return code
	}
	m, err := readMetricFile(measured.out)
	if err != nil {
		stderr.printf("complexity: %v\n", err)
		return exitError
	}
	if m.BaseCommit == "" || m.BaseCommit == "unknown" {
		stderr.printf("complexity: cannot freeze without a base commit; fetch origin/develop or pass -base-commit\n")
		return exitError
	}
	var buf bytes.Buffer
	if err := metrics.Write(&buf, m); err != nil {
		stderr.printf("complexity: encode frozen baseline: %v\n", err)
		return exitError
	}
	if err := os.MkdirAll(filepath.Dir(o.out), 0o750); err != nil {
		stderr.printf("complexity: create %s: %v\n", filepath.ToSlash(filepath.Dir(o.out)), ioReason(err))
		return exitError
	}
	// O_EXCL makes the refusal race-free: a file created since the check wins.
	f, err := os.OpenFile(o.out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- operator-supplied -out flag of a local dev tool
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			stderr.printf("complexity: %s already exists; delete it in a reviewed diff to replace it\n", filepath.ToSlash(o.out))
			return exitViolation
		}
		stderr.printf("complexity: write %s: %v\n", filepath.ToSlash(o.out), ioReason(err))
		return exitError
	}
	if _, err := f.Write(buf.Bytes()); err != nil {
		_ = f.Close()
		stderr.printf("complexity: write %s: %v\n", filepath.ToSlash(o.out), ioReason(err))
		return exitError
	}
	if err := f.Close(); err != nil {
		stderr.printf("complexity: write %s: %v\n", filepath.ToSlash(o.out), ioReason(err))
		return exitError
	}
	stdout.printf("frozen baseline written: %s (base %s)\n", filepath.ToSlash(o.out), m.BaseCommit)
	return exitOK
}
