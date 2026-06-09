// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// cfgms-steward-launcher is the OS service entry point for the CFGMS
// steward. It supervises the actual steward binary (kept in a versioned
// subdirectory) and auto-rolls-back to the previous version when a new
// one fails its startup window.
//
// # Subcommands
//
//	cfgms-steward-launcher run              Supervise the current version (the default; what the OS service manager invokes).
//	cfgms-steward-launcher swap <ver> <exe> Stage <exe> as version <ver> and make it current. Used by the operator (or by `cfg steward upgrade`) to push a new binary.
//	cfgms-steward-launcher rollback         Restore the previous-recorded version as current.
//	cfgms-steward-launcher status           Print the current and previous version names.
//
// The launcher does NOT verify bundle signatures in this Phase-1 cut;
// signature verification is a follow-up under epic #1917. Operators are
// expected to stage from trusted sources for now.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

func main() {
	// On Windows, the SCM invokes us with no console and expects the
	// process to RegisterServiceCtrlHandler + report SERVICE_RUNNING.
	// tryRunAsService detects that environment and dispatches into the
	// svc.Run loop; on non-Windows or when invoked interactively it's a
	// no-op and we fall through to the regular CLI handling.
	if tryRunAsService() {
		return
	}
	if len(os.Args) < 2 {
		// Default behaviour: supervise. The OS service manager invokes
		// the launcher without args.
		os.Exit(runRun([]string{}))
	}
	switch os.Args[1] {
	case "run":
		os.Exit(runRun(os.Args[2:]))
	case "swap":
		os.Exit(runSwap(os.Args[2:]))
	case "rollback":
		os.Exit(runRollback(os.Args[2:]))
	case "status":
		os.Exit(runStatus(os.Args[2:]))
	case "-h", "--help", "help":
		printUsage()
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "launcher: unknown subcommand %q\n", os.Args[1])
		printUsage()
		os.Exit(2)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, "Usage: cfgms-steward-launcher [run|swap|rollback|status] [flags]\n")
	fmt.Fprintf(os.Stderr, "Run with --help on each subcommand for details.\n")
}

// runRun is the interactive entry point (`cfgms-steward-launcher run`).
// It parses the `run` flag set, then delegates to runSuperviseWithCtx
// after wiring up signal handling on os.Interrupt / SIGTERM.
func runRun(args []string) int {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()
	return runSuperviseWithCtx(ctx, args)
}

// runSuperviseWithCtx parses the `run` flag set and starts the
// supervision loop. Shared by the interactive runRun() entry point and
// the Windows-service Execute() handler (which cancels ctx on SCM
// Stop / Shutdown instead of via signal).
func runSuperviseWithCtx(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	root := fs.String("root", defaultRoot(), "Install root holding current.txt + versions/")
	startupWindow := fs.Duration("startup-window", 30*time.Second, "How long a child must run to be considered healthy")
	maxRollbacks := fs.Int("max-rollbacks", 1, "Cap on auto-rollback attempts per Supervise call")
	childArgs := fs.String("child-args", "", "Space-separated args forwarded to the supervised steward (e.g. \"--regtoken xxx\")")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "launcher run: %v\n", err)
		return 2
	}

	sup := &Supervisor{
		Layout:            Layout{Root: *root, StewardBinaryName: defaultStewardBinaryName()},
		StartupWindow:     *startupWindow,
		MaxRollbackCycles: *maxRollbacks,
		Stdout:            os.Stdout,
		Stderr:            os.Stderr,
		ExtraArgs:         strings.Fields(*childArgs),
	}

	if err := sup.Supervise(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "launcher run: %v\n", err)
		return 1
	}
	return 0
}

func runSwap(args []string) int {
	fs := flag.NewFlagSet("swap", flag.ExitOnError)
	root := fs.String("root", defaultRoot(), "Install root holding current.txt + versions/")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "launcher swap: %v\n", err)
		return 2
	}
	if fs.NArg() != 2 {
		fmt.Fprintf(os.Stderr, "launcher swap: usage: cfgms-steward-launcher swap <version> <source-exe>\n")
		return 2
	}

	layout := Layout{Root: *root, StewardBinaryName: defaultStewardBinaryName()}
	version := fs.Arg(0)
	sourceExe := fs.Arg(1)

	dst, err := layout.StageBinary(version, sourceExe)
	if err != nil {
		fmt.Fprintf(os.Stderr, "launcher swap: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(os.Stdout, "launcher: staged %q as version %q at %q\n", sourceExe, version, dst)
	_, _ = fmt.Fprintf(os.Stdout, "launcher: next steward restart will exec the new version\n")
	return 0
}

func runRollback(args []string) int {
	fs := flag.NewFlagSet("rollback", flag.ExitOnError)
	root := fs.String("root", defaultRoot(), "Install root holding current.txt + versions/")
	if err := fs.Parse(args); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "launcher rollback: %v\n", err)
		return 2
	}

	layout := Layout{Root: *root, StewardBinaryName: defaultStewardBinaryName()}
	newCurrent, err := layout.Rollback()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "launcher rollback: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(os.Stdout, "launcher: rolled back; new active version is %q\n", newCurrent)
	_, _ = fmt.Fprintf(os.Stdout, "launcher: next steward restart will exec the rolled-back version\n")
	return 0
}

func runStatus(args []string) int {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	root := fs.String("root", defaultRoot(), "Install root holding current.txt + versions/")
	if err := fs.Parse(args); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "launcher status: %v\n", err)
		return 2
	}

	layout := Layout{Root: *root, StewardBinaryName: defaultStewardBinaryName()}
	current, _ := layout.ReadCurrent()
	previous, _ := layout.ReadPrevious()
	if current == "" {
		current = "<none>"
	}
	if previous == "" {
		previous = "<none>"
	}
	_, _ = fmt.Fprintf(os.Stdout, "Root:     %s\n", *root)
	_, _ = fmt.Fprintf(os.Stdout, "Current:  %s\n", current)
	_, _ = fmt.Fprintf(os.Stdout, "Previous: %s\n", previous)
	return 0
}

// defaultRoot returns the OS-conventional install root for the steward.
// Operators can override with --root on any subcommand for testing.
func defaultRoot() string {
	switch runtime.GOOS {
	case "windows":
		programFiles := os.Getenv("ProgramFiles")
		if programFiles == "" {
			programFiles = `C:\Program Files`
		}
		return filepath.Join(programFiles, "CFGMS")
	default:
		return "/opt/cfgms"
	}
}

// defaultStewardBinaryName returns the OS-conventional name of the steward
// binary inside each versions/<name>/ directory.
func defaultStewardBinaryName() string {
	if runtime.GOOS == "windows" {
		return "cfgms-steward.exe"
	}
	return "cfgms-steward"
}
