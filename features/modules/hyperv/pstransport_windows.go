// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package hyperv

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/security"
)

// psHostTransport is the post-#1894 in-host transport for the Hyper-V module.
//
// It runs powershell.exe as a long-lived subprocess of the steward and
// dispatches each Hyper-V
// primitive (Get-VM, Start-VM, New-VMSwitch, etc.) as a function call sent
// over stdin. Functions are defined once at session startup via a hardcoded
// preamble.
//
// # Architectural shape
//
// Idempotency, drift detection, and operation sequencing all live in Go
// (vm.go / vswitch.go). The PS host knows nothing about
// "should this memory change?" or "is the VM running?" — its functions are
// thin wrappers around single cmdlets, returning either nothing (for
// effects) or a JSON document (for reads). The Go orchestration decides
// what primitives to invoke and in what order.
//
// # Protocol
//
// Each call is a single line on stdin of the form:
//
//	Cfgms-Invoke -Verb 'VerbName' -ArgsFile '<temp path>'; Write-Output '<<<END:nonce>>>'
//
// The parameter values are never in that line: they are in the per-call JSON
// args file (pstransport_args_windows.go), which Cfgms-Invoke parses and binds
// to the named parameters of Cfgms-VerbName. PowerShell never parses a value
// as code.
//
// The transport reads stdout line-by-line until it sees the matching nonce
// sentinel, then returns the captured lines (joined with newlines) as the
// command output. Errors are surfaced via a separate stderr drain — the
// preamble sets `$ErrorActionPreference = 'Stop'` and the per-call
// invocation is wrapped in `try { ... } catch { Write-Error $_; throw }` so
// stderr always has the failure reason.
//
// Mutex-serialized: one PS host can only do one Hyper-V op at a time. That
// matches the way the host's WMI providers serialise too — there's no
// throughput win from parallel invocations against the same host.
//
// # Why a local subprocess
//
// Same-host steward + Hyper-V: a local subprocess needs no network listener,
// remote authentication, TLS cert, or service-level ACL — the steward already
// runs as LocalSystem on the Hyper-V host (#1853 + #1854 install path) which
// has full Hyper-V admin rights natively.
//
// # Why not WMI
//
// Hyper-V's WMI provider expresses VM lifecycle as instance methods on
// singleton management services (Msvm_VirtualSystemManagementService.
// DefineSystem, Msvm_ComputerSystem.RequestStateChange, etc.). The
// github.com/yusufpapurcu/wmi package handles WQL queries but not instance
// method invocations on services that return WMI job handles. Wiring each
// verb correctly with job polling for async completion would be ~50–200
// lines of careful COM code per verb plus extensive edge-case testing.
// Persistent PS is one cmdlet per verb and the cmdlets are themselves the
// battle-tested wrappers Microsoft already maintains.
type psHostTransport struct {
	// cmd is the running powershell.exe subprocess. Nil only between
	// construction and start; never nil after newPSHostTransport returns
	// successfully.
	cmd *exec.Cmd

	// stdin is the write side of the PS subprocess. Each call sends one
	// line ending in a sentinel and reads stdout until the sentinel comes
	// back.
	stdin io.WriteCloser

	// stdout is wrapped in a bufio.Reader so we can read sentinel-delimited
	// lines without losing the trailing newline at EOF.
	stdout *bufio.Reader

	// stderrBuf accumulates anything the PS host writes to stderr while we
	// wait for the current call to complete. Drained per call.
	stderrBuf *threadSafeBuffer

	// mu serialises Run calls. powershell.exe is single-threaded under
	// our usage; one call must complete before the next is sent.
	mu sync.Mutex

	// closed is set true once Close has been called. Subsequent Run calls
	// return errSessionClosed without touching stdin/stdout.
	closed bool
}

// hypervStagingBase is the directory every file handed to an elevated
// powershell.exe is staged in: the runFresh / runFreshNoCleanup / runDetached
// scripts and the writeArgsFile call-arguments file. stageFile secures it with
// security.EnsureAdminOnlyDir before every stage, so only SYSTEM and
// Administrators can write it, unlike the system temporary directory.
// Overridable for testing.
var hypervStagingBase = defaultHypervStagingBase()

// stagingMu serializes securing the base, creating a file in it, and the
// Go-side removal of staged files: EnsureAdminOnlyDir walks the whole tree
// below the base, and a concurrent removal would race that walk.
var stagingMu sync.Mutex

// stagingVanishedRetries bounds how often stageFile re-runs EnsureAdminOnlyDir
// when its walk failed because an entry disappeared. A detached move script
// deletes itself from its own powershell.exe process, which stagingMu cannot
// serialize; re-running the full check after such a removal does not weaken it.
const stagingVanishedRetries = 3

// defaultHypervStagingBase returns %ProgramData%\cfgms\hyperv-staging, falling
// back to C:\ProgramData when the ProgramData environment variable is unset. It
// is a sibling of cert_trust's staging directory, not inside it, so the two
// packages' tree walks never share a tree.
func defaultHypervStagingBase() string {
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	return filepath.Join(programData, "cfgms", "hyperv-staging")
}

// stageFile secures hypervStagingBase and writes body to a new file in it,
// created exclusively from pattern. It returns the path and a remove function
// that is safe to call more than once. If the base cannot be secured nothing
// is staged and the error names the staging step.
func stageFile(pattern string, body []byte) (string, func(), error) {
	noop := func() {}
	stagingMu.Lock()
	defer stagingMu.Unlock()

	base := hypervStagingBase
	var err error
	for attempt := 0; attempt <= stagingVanishedRetries; attempt++ {
		if err = security.EnsureAdminOnlyDir(base); err == nil || !errors.Is(err, os.ErrNotExist) {
			break
		}
	}
	if err != nil {
		return "", noop, fmt.Errorf("hyperv-ps-host: secure staging directory: %w", err)
	}

	f, err := os.CreateTemp(base, pattern)
	if err != nil {
		return "", noop, fmt.Errorf("hyperv-ps-host: create staged file: %w", err)
	}
	path := f.Name()
	if _, werr := f.Write(body); werr != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return "", noop, fmt.Errorf("hyperv-ps-host: write staged file: %w", werr)
	}
	if cerr := f.Close(); cerr != nil {
		_ = os.Remove(path)
		return "", noop, fmt.Errorf("hyperv-ps-host: close staged file: %w", cerr)
	}
	remove := func() {
		stagingMu.Lock()
		defer stagingMu.Unlock()
		_ = os.Remove(path)
	}
	return path, remove, nil
}

// errSessionClosed is returned when Run is called after Close.
var errSessionClosed = errors.New("hyperv: PS host transport is closed")

// newPSHostTransport spawns powershell.exe, loads the preamble defining the
// Cfgms-* verb functions, and returns a ready-to-use transport.
//
// The PS host stays alive until Close is called or the process exits. On
// unexpected exit the next Run call will surface the exit reason in its
// error.
//
// Currently no parameters are required — the transport is host-agnostic.
// Future arguments (e.g. a custom $env:PSModulePath override) would be added
// here.
func newPSHostTransport(_ context.Context) (*psHostTransport, error) {
	// -Command - reads commands from stdin in a REPL-like loop. Each
	// command is parsed and executed; output goes to stdout. We rely on
	// this rather than -File - (which would read once and exit) so the
	// host can serve many calls.
	//
	// -NoProfile skips loading the user's PowerShell profile (which would
	// add unpredictable startup time and could redefine our verb names).
	// -NonInteractive prevents any prompt (e.g. for credentials) from
	// blocking us forever.
	//
	// CLAUDE.md banned-pattern note: the literal `-Command -` is the
	// canonical "read commands from stdin" marker (see PowerShell docs);
	// it is not a `-Command <user-supplied-script>` invocation. No user
	// input ever appears in argv — every command goes over the stdin
	// pipe where it can be sentinel-delimited and is structurally
	// isolated from program arguments.
	cmd := exec.Command(
		"powershell.exe",
		"-NoProfile",
		"-NonInteractive",
		"-Command",
		"-",
	) //#nosec G204 -- fixed args; user values flow over stdin, never via argv

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("hyperv-ps-host: open stdin pipe: %w", err)
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, fmt.Errorf("hyperv-ps-host: open stdout pipe: %w", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, fmt.Errorf("hyperv-ps-host: open stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		return nil, fmt.Errorf("hyperv-ps-host: start powershell.exe: %w", err)
	}

	t := &psHostTransport{
		cmd:       cmd,
		stdin:     stdin,
		stdout:    bufio.NewReader(stdoutPipe),
		stderrBuf: newThreadSafeBuffer(),
	}

	// Drain stderr continuously in the background so it doesn't block the
	// child. Buffered for the next Run to inspect on error.
	go func() {
		_, _ = io.Copy(t.stderrBuf, stderrPipe)
	}()

	if err := t.loadPreamble(); err != nil {
		_ = t.Close()
		return nil, fmt.Errorf("hyperv-ps-host: load preamble: %w", err)
	}

	return t, nil
}

// Close terminates the PS host subprocess and releases its pipes. Idempotent.
func (t *psHostTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	// Closing stdin tells `-Command -` to exit. We then wait for the
	// process so the OS releases its handles.
	_ = t.stdin.Close()
	if t.cmd != nil && t.cmd.Process != nil {
		_ = t.cmd.Wait()
	}
	return nil
}

// loadPreamble runs the verb-defining preamble in the live PS host and
// waits for the synthetic Cfgms-Preamble-Ready sentinel to confirm it
// parsed cleanly. Called once during newPSHostTransport.
func (t *psHostTransport) loadPreamble() error {
	const readySentinel = "<<<CFGMS-PREAMBLE-READY>>>"
	body := psHostPreamble + "\nWrite-Output '" + readySentinel + "'\n"
	if _, err := io.WriteString(t.stdin, body); err != nil {
		return fmt.Errorf("write preamble: %w", err)
	}
	if err := t.readUntilSentinel(readySentinel); err != nil {
		// Drain stderr so the caller can see what blew up during preamble parsing.
		stderrText := strings.TrimSpace(t.stderrBuf.String())
		if stderrText != "" {
			return fmt.Errorf("preamble sentinel not seen: %w; stderr: %s", err, stderrText)
		}
		return fmt.Errorf("preamble sentinel not seen: %w", err)
	}
	return nil
}

// run sends a single PS expression to the host and returns the captured
// stdout for that expression (stripped of the trailing sentinel and its
// newline). Per-call stderr is checked after the sentinel is seen and
// surfaced as an error if non-empty.
//
// Holds the transport mutex for the duration of the round trip.
// runFresh executes a single Cfgms-* expression in a FRESH powershell.exe
// process via -File, instead of the persistent `-Command -` host. This is
// REQUIRED for the seed VHDX disk operations (New/Mount/Copy/Detach): Mount-VHD
// and Dismount-VHD attach the VHD via the async Virtual Disk Service, which
// DEADLOCKS in the persistent stdin-REPL host — and so do Start-Job and
// Start-Process -Wait launched from inside it. A fresh `powershell -File`
// process runs the disk cmdlets directly with no deadlock (proven on cfg-lab).
//
// The temp script is the full preamble (Cfgms-* defs + safe defaults) followed
// by the expression (freshScriptBody), so the verb resolves exactly as in the
// persistent host. The script is removed after the run. Unlike run(), this does
// not serialise on t.mu (it spawns an independent process) and is unaffected by
// t.closed.
//
// verb names the Cfgms-* verb for the failure message. onKill, when non-nil,
// runs after a deadline kill, before the error returns.
func (t *psHostTransport) runFresh(ctx context.Context, verb, expression string, onKill func()) (string, error) {
	tmpPath, removeScript, err := stageFile("cfgms-seedop-*.ps1", []byte(freshScriptBody(expression)))
	if err != nil {
		return "", fmt.Errorf("stage seed script: %w", err)
	}
	defer removeScript()

	cmd := exec.CommandContext(ctx, "powershell.exe",
		"-NoProfile", "-NonInteractive", "-File", tmpPath,
	) //#nosec G204 -- fixed flags; the temp script path is generated, not user-supplied
	start := time.Now()
	out, runErr := cmd.CombinedOutput()
	elapsed := time.Since(start)
	if runErr != nil {
		// A deadline kill leaks a host-attached VHD, so clean up BEFORE returning.
		// exec.CommandContext kills powershell.exe when ctx expires, and a killed
		// process never runs its finally block — so the try/finally inside
		// Cfgms-MountSeedVHD / Cfgms-CopyToSeedVHD (#3766) cannot help here. Mount-VHD
		// attaches host-wide, so the VHD stays attached after the process dies and the
		// NEXT VM's Add-VMHardDiskDrive fails with a 0x80070020 sharing violation —
		// one timeout silently breaks seed provisioning for every later VM on the host.
		// Observed live on cfg-lab: a seed left Attached=True after a 30s module.Set
		// deadline kill, on a steward already carrying the #3766 fix.
		if ctx.Err() != nil && onKill != nil {
			onKill()
		}
		// Distinguish a module-call deadline kill from a genuine non-zero exit.
		// When the module-call context is cancelled/expired, CommandContext kills
		// the process, so runErr is a bare "signal: killed"/"exit status 1" and
		// `out` is typically empty — the generic path below would surface an
		// uninformative `fresh seed op failed: exit status 1: ` with no clue that
		// WE killed it at the deadline. Check ctx.Err() explicitly (reliable after
		// a CommandContext kill) rather than pattern-matching the error string, and
		// name the phase + elapsed time so a log reader — and any future
		// retry-classification logic — can tell "killed at the deadline" from "the
		// op ran and failed" (#2467).
		if ctxErr := ctx.Err(); ctxErr != nil {
			return string(out), fmt.Errorf(
				"hyperv-ps-host: seed op killed by deadline after %s (ctx: %w)", elapsed, ctxErr)
		}
		return string(out), freshSeedOpError(runErr, string(out), verb, elapsed)
	}
	return string(out), nil
}

// seedCleanupDismountTimeout bounds the post-kill dismount. It is deliberately
// short: the caller has already blown its deadline and is returning an error, so
// cleanup must not extend the stall. Cfgms-DismountAndVerify's own retry loop is
// ~6s worst case, so this leaves ample headroom.
const seedCleanupDismountTimeout = 30 * time.Second

// freshScriptBody is the temp .ps1 body for a fresh-process call: the
// preamble, then the expression.
func freshScriptBody(expression string) string {
	return psHostPreamble + "\n" + expression + "\n"
}

// mountedSeedPathForCleanup returns the seed VHD path a killed call may have
// left ATTACHED to the host, or "" when the call cannot leak a mount.
//
// Only the two verbs that call Mount-VHD can leak: Cfgms-MountSeedVHD (Path)
// and Cfgms-CopyToSeedVHD (SeedPath). Cfgms-NewSeedVHD only creates a file, and
// Cfgms-AttachSeedDisk attaches to the VM rather than mounting host-side, so
// neither needs cleanup — dismounting for them would be a no-op at best and, if
// the VM legitimately holds the disk, misleading noise in the audit trail.
//
// The path is read from the call's structured args, never parsed back out of
// script text.
func mountedSeedPathForCleanup(verb string, psArgs map[string]string) string {
	switch verb {
	case "MountSeedVHD":
		return psArgs["Path"]
	case "CopyToSeedVHD":
		return psArgs["SeedPath"]
	}
	return ""
}

// dismountAfterKill best-effort dismounts a seed VHD left attached by a killed
// runFresh process.
//
// It runs on a FRESH context: the caller's context is already cancelled, which is
// precisely why cleanup is needed, so reusing it would kill this process too and
// leave the mount exactly as it was.
//
// Best-effort by design: the caller is already returning the real failure (the
// deadline kill), and a cleanup error must not replace or mask it. The transport
// has no logger, so a failed cleanup is not reported here — it surfaces as the
// next seed attach failing on 0x80070020, which is the pre-fix behaviour and no
// worse than not having tried.
func (t *psHostTransport) dismountAfterKill(verb string, psArgs map[string]string) {
	seedPath := mountedSeedPathForCleanup(verb, psArgs)
	if seedPath == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), seedCleanupDismountTimeout)
	defer cancel()
	// Cfgms-DismountAndVerify throws when the VHD is still attached after its
	// retry loop, so a non-nil error here genuinely means the leak survived.
	_, _ = t.runFreshNoCleanup(ctx, psCall{
		Verb: "DismountAndVerify",
		Mode: psModeFresh,
		Args: []psArg{{Param: "Path", Value: seedPath}},
	})
}

// runFreshNoCleanup is runFresh without the post-kill dismount, used by
// dismountAfterKill itself so a failing cleanup cannot recurse. The path
// travels through the same args-file channel as every other call.
func (t *psHostTransport) runFreshNoCleanup(ctx context.Context, call psCall) (string, error) {
	argsPath, remove, err := writeArgsFile(call)
	if err != nil {
		return "", err
	}
	defer remove()
	expression, err := invokeExpression(call.Verb, argsPath)
	if err != nil {
		return "", err
	}
	tmpPath, removeScript, err := stageFile("cfgms-seedcleanup-*.ps1", []byte(freshScriptBody(expression)))
	if err != nil {
		return "", fmt.Errorf("stage cleanup script: %w", err)
	}
	defer removeScript()
	cmd := exec.CommandContext(ctx, "powershell.exe",
		"-NoProfile", "-NonInteractive", "-File", tmpPath,
	) //#nosec G204 -- fixed flags; the temp script path is generated, not user-supplied
	out, runErr := cmd.CombinedOutput()
	if runErr != nil {
		return string(out), fmt.Errorf("hyperv-ps-host: post-kill seed dismount failed: %w: %s",
			runErr, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// freshSeedOpError formats the failure of a runFresh seed op.
//
// It exists as a separate function because the message it produces is the ONLY
// diagnostic a caller gets, and the previous form —
// `fresh seed op failed: exit status 1: ` with an empty tail — was actively
// misleading in production: it looks like a truncated message rather than
// "PowerShell exited non-zero and printed nothing at all". That ambiguity cost
// days of misdirected investigation on a real incident, so the empty case now
// says so explicitly and names the verb that failed.
//
// combined is the merged stdout+stderr (exec.CombinedOutput), so an empty value
// genuinely means the process produced NO output on either stream.
func freshSeedOpError(runErr error, combined, verb string, elapsed time.Duration) error {
	trimmed := strings.TrimSpace(combined)
	if trimmed != "" {
		return fmt.Errorf("hyperv-ps-host: fresh seed op failed: %w: %s", runErr, trimmed)
	}
	return fmt.Errorf(
		"hyperv-ps-host: fresh seed op failed: %w: powershell exited non-zero after %s and produced NO output on stdout or stderr (verb: Cfgms-%s)",
		runErr, elapsed, verb)
}

// runDetached launches a single Cfgms-* expression in a DETACHED fresh
// powershell.exe -File process and returns as soon as the process has
// started — it never waits for completion. This is REQUIRED for the live
// storage migration (Cfgms-MoveVMStorage): the move can run for minutes to
// hours, far past the executor's per-module-call deadline (ADR-012 §7), so
// the module call must not hold it open. The MoveRecord written by the Go
// caller is the source of truth for "started"; the detached function writes
// a per-VM error marker on failure, and completion is judged by the converge
// loop re-observing the VM's location.
//
// The temp script is preamble + expression, exactly like runFresh, with a
// trailing self-delete (Go cannot remove the file while the child holds it
// open; PowerShell parses the whole script before executing, so the script
// deleting itself on its last line is safe). A background goroutine reaps
// the process handle and removes the script if the self-delete never ran
// (e.g. a parse-stage failure). No ctx: cancelling the dispatching call must
// not kill an already-started migration — Windows children outlive their
// parent, which is also what lets the move survive a steward restart.
//
// onExit, when non-nil, runs in that goroutine after the process exits; the
// caller uses it to remove the call's args file. It does not run when the
// process fails to start.
func (t *psHostTransport) runDetached(expression string, onExit func()) (string, error) {
	body := freshScriptBody(expression) +
		"Remove-Item -LiteralPath $PSCommandPath -Force -ErrorAction SilentlyContinue\n"
	tmpPath, removeScript, err := stageFile("cfgms-moveop-*.ps1", []byte(body))
	if err != nil {
		return "", fmt.Errorf("stage move script: %w", err)
	}

	cmd := exec.Command("powershell.exe",
		"-NoProfile", "-NonInteractive", "-File", tmpPath,
	) //#nosec G204 -- fixed flags; the temp script path is generated, not user-supplied
	if serr := cmd.Start(); serr != nil {
		removeScript()
		return "", fmt.Errorf("hyperv-ps-host: start detached move process: %w", serr)
	}
	go func() {
		_ = cmd.Wait()
		removeScript() // no-op when the script already self-deleted
		if onExit != nil {
			onExit()
		}
	}()
	return "", nil
}

func (t *psHostTransport) run(_ context.Context, expression string) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return "", errSessionClosed
	}

	nonce, err := generatePSNonce()
	if err != nil {
		return "", fmt.Errorf("hyperv-ps-host: generate nonce: %w", err)
	}
	sentinel := "<<<CFGMS-END:" + nonce + ">>>"

	// Snapshot stderr length BEFORE the call so we can return only the
	// new stderr produced by this expression.
	stderrAtStart := t.stderrBuf.Len()

	// Wrap the expression in a try/catch that emits the failure reason to
	// stderr and rethrows. The sentinel is always written so the read loop
	// terminates even on failure.
	wrapped := "try { " + expression + " } catch { [Console]::Error.WriteLine($_.Exception.Message); throw }\n" +
		"Write-Output '" + sentinel + "'\n"

	if _, err := io.WriteString(t.stdin, wrapped); err != nil {
		return "", fmt.Errorf("hyperv-ps-host: write expression: %w", err)
	}

	output, err := readUntilSentinelFrom(t.stdout, sentinel)
	if err != nil {
		return "", err
	}

	// Check stderr for new content produced by this call.
	stderrTail := t.stderrBuf.SliceFrom(stderrAtStart)
	if stderrText := strings.TrimSpace(stderrTail); stderrText != "" {
		return "", fmt.Errorf("hyperv-ps-host: %s", stderrText)
	}

	return strings.TrimRight(output, "\r\n"), nil
}

// readUntilSentinel is the method form of readUntilSentinelFrom, used by
// loadPreamble before t.stdout is fully wired through the run path.
func (t *psHostTransport) readUntilSentinel(sentinel string) error {
	_, err := readUntilSentinelFrom(t.stdout, sentinel)
	return err
}

// readUntilSentinelFrom reads lines from r until one of them is exactly the
// sentinel (after CRLF trimming). Returns all lines before the sentinel
// joined with newlines (no trailing newline on the final captured line).
func readUntilSentinelFrom(r *bufio.Reader, sentinel string) (string, error) {
	var sb strings.Builder
	for {
		line, err := r.ReadString('\n')
		if err != nil && err != io.EOF {
			return "", fmt.Errorf("read PS stdout: %w", err)
		}
		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed == sentinel {
			return sb.String(), nil
		}
		if line != "" {
			sb.WriteString(line)
		}
		if err == io.EOF {
			// Sentinel never arrived — PS exited before completing the round
			// trip. The caller will surface this as a transport failure.
			return "", fmt.Errorf("PS host exited before sentinel %q arrived", sentinel)
		}
	}
}

// generatePSNonce returns a 16-hex-character random nonce. Used to build a
// per-call sentinel so concurrent calls (if we ever allow them) can't read
// each other's output.
func generatePSNonce() (string, error) {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf[:]), nil
}

// threadSafeBuffer is a minimal append-only string buffer the stderr drain
// goroutine writes into and the per-call code reads from. bytes.Buffer
// isn't safe for concurrent Write + Read.
type threadSafeBuffer struct {
	mu  sync.Mutex
	buf []byte
}

func newThreadSafeBuffer() *threadSafeBuffer { return &threadSafeBuffer{} }

func (b *threadSafeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	return len(p), nil
}

func (b *threadSafeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.buf)
}

func (b *threadSafeBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.buf)
}

func (b *threadSafeBuffer) SliceFrom(offset int) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if offset < 0 || offset > len(b.buf) {
		return ""
	}
	return string(b.buf[offset:])
}
