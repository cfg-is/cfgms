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

// readScript is the module's fixed, read-only inventory and lookup script.
// writeScript is its fixed write script. Neither is ever composed or modified
// at runtime.
//
//go:embed scripts/read.ps1
var readScript []byte

//go:embed scripts/write.ps1
var writeScript []byte

// readScriptSHA256 and writeScriptSHA256 are the SHA-256 of scripts/read.ps1
// and scripts/write.ps1. The staged copy is checked against them before every
// run; TestReadScript_EmbeddedHashMatchesConstant and
// TestWriteScript_EmbeddedHashMatchesConstant keep them in step with the
// embedded files.
const (
	readScriptSHA256  = "64b52c9459fc2bd74e00a19205b9c50343978f8bcacb5a09d875eb3071271c76"
	writeScriptSHA256 = "cc3fcecb43bd2b4a6cec377fa555b21a301418824936e52c00d5cc43c45ddaed"
)

// embeddedScript is one fixed script and its expected hash.
type embeddedScript struct {
	name   string // file name prefix: "read" or "write"
	body   []byte
	sha256 string
	// quiet keeps the script's stderr out of errors entirely. The write
	// script's stdin can carry a password, so nothing it prints is returned.
	quiet bool
}

var (
	readEmbedded  = embeddedScript{name: "read", body: readScript, sha256: readScriptSHA256}
	writeEmbedded = embeddedScript{name: "write", body: writeScript, sha256: writeScriptSHA256, quiet: true}
)

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

// psScriptRunner stages one embedded script in an admin-only directory,
// verifies it, and runs it with -File.
type psScriptRunner struct {
	// dir is the script directory, secured with security.EnsureAdminOnlyDir
	// before every stage. Tests point it at their own directory.
	dir string
	// script is the embedded script this runner runs. The zero value is the
	// read script.
	script embeddedScript
}

func newPlatformRunner() scriptRunner {
	return &psScriptRunner{dir: defaultScriptDir(), script: readEmbedded}
}

func newPlatformWriteRunner() scriptRunner {
	return &psScriptRunner{dir: defaultScriptDir(), script: writeEmbedded}
}

func (r *psScriptRunner) embedded() embeddedScript {
	if r.script.body == nil {
		return readEmbedded
	}
	return r.script
}

// Run implements scriptRunner.
func (r *psScriptRunner) Run(ctx context.Context, request []byte, onLine func(line []byte) error) error {
	path, err := r.stage()
	if err != nil {
		return err
	}
	if err := verifyStaged(path, r.embedded()); err != nil {
		return err
	}
	return invokeScript(ctx, path, r.embedded(), request, onLine)
}

// stage secures the script directory and writes the embedded script into it
// unless it is already there. The file name carries the script's hash prefix,
// so a module upgrade stages a new file rather than finding a mismatch.
func (r *psScriptRunner) stage() (string, error) {
	stagingMu.Lock()
	defer stagingMu.Unlock()

	s := r.embedded()
	if err := security.EnsureAdminOnlyDir(r.dir); err != nil {
		return "", fmt.Errorf("activedirectory: secure script directory: %w", err)
	}
	path := filepath.Join(r.dir, s.name+"-"+s.sha256[:12]+".ps1")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- module-built path inside the secured script directory
	if errors.Is(err, os.ErrExist) {
		return path, nil
	}
	if err != nil {
		return "", fmt.Errorf("activedirectory: stage %s script: %w", s.name, err)
	}
	if _, werr := f.Write(s.body); werr != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return "", fmt.Errorf("activedirectory: write %s script: %w", s.name, werr)
	}
	if cerr := f.Close(); cerr != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("activedirectory: close %s script: %w", s.name, cerr)
	}
	return path, nil
}

// verifyStagedScript checks a staged read script.
func verifyStagedScript(path string) error { return verifyStaged(path, readEmbedded) }

// verifyStaged refuses to run unless the staged file's SHA-256 equals the
// script's embedded hash. A mismatch is never repaired by overwriting: it
// means the file was changed after staging and is left in place for
// investigation.
func verifyStaged(path string, s embeddedScript) error {
	f, err := os.Open(path) // #nosec G304 -- module-built path inside the secured script directory
	if err != nil {
		return fmt.Errorf("activedirectory: open staged %s script: %w", s.name, err)
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, maxStagedScriptBytes+1))
	if err != nil {
		return fmt.Errorf("activedirectory: read staged %s script: %w", s.name, err)
	}
	if n > maxStagedScriptBytes || hex.EncodeToString(h.Sum(nil)) != s.sha256 {
		return fmt.Errorf("activedirectory: staged %s script does not match the embedded script; refusing to run it", s.name)
	}
	return nil
}

// invoke runs a staged read script.
func invoke(ctx context.Context, scriptPath string, request []byte, onLine func(line []byte) error) error {
	return invokeScript(ctx, scriptPath, readEmbedded, request, onLine)
}

// invokeScript runs the staged script with request on stdin and calls onLine
// for every non-empty stdout line. A line longer than maxLineBytes ends the
// run. Errors never contain the request: the stderr tail a read script's
// error carries has every request value redacted, and a quiet script's errors
// carry no stderr at all.
func invokeScript(ctx context.Context, scriptPath string, s embeddedScript, request []byte, onLine func(line []byte) error) error {
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
		tail := ""
		if !s.quiet {
			tail = redactRequest(stderr.String(), request)
		}
		if tail == "" {
			return fmt.Errorf("activedirectory: %s script failed with exit code %d", s.name, res.code)
		}
		return fmt.Errorf("activedirectory: %s script failed with exit code %d: %s", s.name, res.code, tail)
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
