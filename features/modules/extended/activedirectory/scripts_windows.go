//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package activedirectory

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"unicode"

	"github.com/cfgis/cfgms/pkg/security"
)

// readScript is the module's only PowerShell: a fixed, read-only inventory
// script. It is never composed or modified at runtime.
//
//go:embed scripts/read.ps1
var readScript []byte

// readScriptSHA256 is the SHA-256 of scripts/read.ps1. The staged copy is
// checked against it before every run; TestReadScript_EmbeddedHashMatchesConstant
// keeps it in step with the embedded file.
const readScriptSHA256 = "bd496cfb2f966fe4f85075d886472b00cbd721d942db56c517d579c6e9bf457d"

const (
	// maxLineBytes bounds one line of script output (one directory object).
	// The script cuts each membership list at maxListEntries, so a legitimate
	// object stays well below it.
	maxLineBytes = 4 << 20

	// maxStderrTail bounds how much of the script's stderr an error carries.
	maxStderrTail = 2048

	// maxStagedScriptBytes bounds how much of the staged file is read back for
	// the integrity check.
	maxStagedScriptBytes = 1 << 20
)

// stagingMu serializes securing the script directory and staging the script.
var stagingMu sync.Mutex

// powershellExe returns the absolute path of Windows PowerShell under
// %SystemRoot% (then %windir%, then C:\Windows), so a powershell.exe planted
// earlier on PATH can never run the read. It returns "" when the result is not
// an absolute path; callers refuse to run rather than fall back to a bare name.
func powershellExe() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = os.Getenv("windir")
	}
	if root == "" {
		root = `C:\Windows`
	}
	p := filepath.Join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	if !filepath.IsAbs(p) {
		return ""
	}
	return p
}

// scriptArgv is the complete, fixed argv of every read: the absolute
// powershell.exe path and nothing variable but the staged script path, which
// the module builds itself.
func scriptArgv(exe, scriptPath string) []string {
	return []string{exe, "-NoProfile", "-NonInteractive", "-File", scriptPath}
}

// execScript runs argv with stdin and streams the child's stdout and stderr.
// It returns the exit code (-1 when the process did not run to an exit code).
// Tests replace it to observe the argv without running PowerShell.
var execScript = func(ctx context.Context, argv []string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) // #nosec G204 -- fixed argv from scriptArgv; the only variable is the module-built staged script path
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), err
	}
	if err != nil {
		return -1, err
	}
	return 0, nil
}

// defaultScriptDir returns %ProgramData%\cfgms\activedirectory-scripts,
// falling back to C:\ProgramData when the ProgramData environment variable is
// unset.
func defaultScriptDir() string {
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	return filepath.Join(programData, "cfgms", "activedirectory-scripts")
}

// psScriptRunner stages the embedded read script in an admin-only directory,
// verifies it, and runs it with -File.
type psScriptRunner struct {
	// dir is the script directory, secured with security.EnsureAdminOnlyDir
	// before every stage. Tests point it at their own directory.
	dir string
}

func newPlatformRunner() scriptRunner {
	return &psScriptRunner{dir: defaultScriptDir()}
}

// Run implements scriptRunner.
func (r *psScriptRunner) Run(ctx context.Context, request []byte, onLine func(line []byte) error) error {
	path, err := r.stage()
	if err != nil {
		return err
	}
	if err := verifyStagedScript(path); err != nil {
		return err
	}
	return invoke(ctx, path, request, onLine)
}

// stage secures the script directory and writes the embedded script into it
// unless it is already there. The file name carries the script's hash prefix,
// so a module upgrade stages a new file rather than finding a mismatch.
func (r *psScriptRunner) stage() (string, error) {
	stagingMu.Lock()
	defer stagingMu.Unlock()

	if err := security.EnsureAdminOnlyDir(r.dir); err != nil {
		return "", fmt.Errorf("activedirectory: secure script directory: %w", err)
	}
	path := filepath.Join(r.dir, "read-"+readScriptSHA256[:12]+".ps1")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- module-built path inside the secured script directory
	if errors.Is(err, os.ErrExist) {
		return path, nil
	}
	if err != nil {
		return "", fmt.Errorf("activedirectory: stage read script: %w", err)
	}
	if _, werr := f.Write(readScript); werr != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return "", fmt.Errorf("activedirectory: write read script: %w", werr)
	}
	if cerr := f.Close(); cerr != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("activedirectory: close read script: %w", cerr)
	}
	return path, nil
}

// verifyStagedScript refuses to run unless the staged file's SHA-256 equals
// readScriptSHA256. A mismatch is never repaired by overwriting: it means the
// file was changed after staging and is left in place for investigation.
func verifyStagedScript(path string) error {
	f, err := os.Open(path) // #nosec G304 -- module-built path inside the secured script directory
	if err != nil {
		return fmt.Errorf("activedirectory: open staged read script: %w", err)
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, maxStagedScriptBytes+1))
	if err != nil {
		return fmt.Errorf("activedirectory: read staged read script: %w", err)
	}
	if n > maxStagedScriptBytes || hex.EncodeToString(h.Sum(nil)) != readScriptSHA256 {
		return fmt.Errorf("activedirectory: staged read script does not match the embedded script; refusing to run it")
	}
	return nil
}

// invoke runs the staged script with request on stdin and calls onLine for
// every non-empty stdout line. A line longer than maxLineBytes ends the run.
// Errors never contain the request: the stderr tail they carry has every
// request value redacted.
func invoke(ctx context.Context, scriptPath string, request []byte, onLine func(line []byte) error) error {
	exe := powershellExe()
	if exe == "" {
		return fmt.Errorf("activedirectory: cannot resolve an absolute powershell.exe path")
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	pr, pw := io.Pipe()
	stderr := &tailBuffer{max: maxStderrTail}
	type result struct {
		code int
		err  error
	}
	done := make(chan result, 1)
	go func() {
		code, err := execScript(ctx, scriptArgv(exe, scriptPath), bytes.NewReader(request), pw, stderr)
		_ = pw.Close()
		done <- result{code, err}
	}()

	scanErr := scanLines(pr, onLine)
	if scanErr != nil {
		cancel()
		_, _ = io.Copy(io.Discard, pr)
	}
	res := <-done
	_ = pr.Close()

	if scanErr != nil {
		return scanErr
	}
	if res.err != nil {
		tail := redactRequest(stderr.String(), request)
		if tail == "" {
			return fmt.Errorf("activedirectory: read script failed with exit code %d", res.code)
		}
		return fmt.Errorf("activedirectory: read script failed with exit code %d: %s", res.code, tail)
	}
	return nil
}

// scanLines calls onLine for every non-empty line of r.
func scanLines(r io.Reader, onLine func(line []byte) error) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), maxLineBytes)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		if err := onLine(line); err != nil {
			return err
		}
	}
	if errors.Is(sc.Err(), bufio.ErrTooLong) {
		return fmt.Errorf("activedirectory: object output exceeds bound of %d bytes", maxLineBytes)
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("activedirectory: read script output: %w", err)
	}
	return nil
}

// redactRequest removes the raw request and every string value in it from
// text, then strips control characters, so even a script that echoed its
// stdin cannot leak the request through an error.
func redactRequest(text string, request []byte) string {
	secrets := []string{string(request), strings.TrimSpace(string(request))}
	var doc interface{}
	if json.Unmarshal(request, &doc) == nil {
		secrets = append(secrets, collectStrings(doc)...)
	}
	for _, s := range secrets {
		if s != "" {
			text = strings.ReplaceAll(text, s, "[redacted]")
		}
	}
	text = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, text)
	return strings.TrimSpace(text)
}

// collectStrings returns every string key and value in a decoded JSON value.
func collectStrings(v interface{}) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case map[string]interface{}:
		var out []string
		for k, val := range t {
			out = append(out, k)
			out = append(out, collectStrings(val)...)
		}
		return out
	case []interface{}:
		var out []string
		for _, val := range t {
			out = append(out, collectStrings(val)...)
		}
		return out
	}
	return nil
}

// tailBuffer keeps the last max bytes written to it.
type tailBuffer struct {
	mu  sync.Mutex
	max int
	buf []byte
}

func (b *tailBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	if len(b.buf) > b.max {
		b.buf = append([]byte(nil), b.buf[len(b.buf)-b.max:]...)
	}
	return len(p), nil
}

func (b *tailBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.buf)
}
