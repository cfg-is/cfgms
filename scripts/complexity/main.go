// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package main is the CFGMS complexity command. It measures cyclomatic
// complexity and Halstead metrics per production function.
//
// With no subcommand it prints the record count followed by one JSON line per
// function. The report subcommand partitions the measured population into the
// manifest's segments and writes the versioned metric file.
//
// Exit codes: 0 = ok, 1 = partition or duplicate-identity violation,
// 2 = usage, IO or parse error.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/cfgis/cfgms/scripts/complexity/analyzer"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "report" {
		os.Exit(reportCmd(os.Args[2:], os.Stdout, os.Stderr))
	}
	root := flag.String("root", ".", "repository root to analyse")
	flag.Parse()
	if err := run(*root, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "complexity: %v\n", err)
		os.Exit(2)
	}
}

func run(root string, w io.Writer) error {
	fns, err := analyzer.Analyze(os.DirFS(root), []string{"."})
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "%d\n", len(fns)); err != nil {
		return err
	}
	enc := json.NewEncoder(w)
	for _, fn := range fns {
		if err := enc.Encode(fn); err != nil {
			return err
		}
	}
	return nil
}
