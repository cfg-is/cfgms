//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package activedirectory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"

	"github.com/cfgis/cfgms/pkg/testutil/winacct"
)

// requireElevated skips t unless the test runs elevated. Securing the script
// directory assigns BUILTIN\Administrators as owner, which needs an elevated
// administrator, as the steward (a SYSTEM service) and the native Windows CI
// runners are.
func requireElevated(t *testing.T) {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated administrator: securing the script directory assigns BUILTIN\\Administrators as owner")
	}
}

// recordExec replaces execScript with a recorder that captures argv and stdin
// and plays back stdout, stderr and an exit code. PowerShell never runs.
type execCall struct {
	argv  []string
	stdin []byte
}

func recordExec(t *testing.T, stdout, stderr string, code int) *[]execCall {
	t.Helper()
	var calls []execCall
	prev := execScript
	execScript = func(_ context.Context, argv []string, stdin io.Reader, out, errOut io.Writer) (int, error) {
		in, err := io.ReadAll(stdin)
		require.NoError(t, err)
		calls = append(calls, execCall{argv: append([]string(nil), argv...), stdin: in})
		_, _ = io.WriteString(out, stdout)
		_, _ = io.WriteString(errOut, stderr)
		if code != 0 {
			return code, errors.New("exit status")
		}
		return 0, nil
	}
	t.Cleanup(func() { execScript = prev })
	return &calls
}

func TestReadScript_EmbeddedHashMatchesConstant(t *testing.T) {
	sum := sha256.Sum256(readScript)
	assert.Equal(t, readScriptSHA256, hex.EncodeToString(sum[:]),
		"readScriptSHA256 must be updated whenever scripts/read.ps1 changes")
	assert.NotContains(t, string(readScript), "-"+"Command", "the read script never passes an inline command")
	assert.NotContains(t, string(readScript), "Invoke-Expression")
}

func TestScriptIntegrity_TamperedScriptRefused(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.ps1")
	require.NoError(t, os.WriteFile(good, readScript, 0o600))
	require.NoError(t, verifyStagedScript(good), "the embedded script verifies")

	tampered := filepath.Join(dir, "tampered.ps1")
	require.NoError(t, os.WriteFile(tampered, append(append([]byte(nil), readScript...), []byte("\nRemove-Item C:\\important\n")...), 0o600))
	err := verifyStagedScript(tampered)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing to run")

	// An oversized file is refused too, without hashing it whole.
	huge := filepath.Join(dir, "huge.ps1")
	require.NoError(t, os.WriteFile(huge, make([]byte, maxStagedScriptBytes+1), 0o600))
	assert.Error(t, verifyStagedScript(huge))
}

func TestRunner_NoUserDataInArgv(t *testing.T) {
	calls := recordExec(t, "", "", 0)
	scriptPath := `C:\ProgramData\cfgms\activedirectory-scripts\read-0123456789ab.ps1`

	for _, hostile := range []string{"-" + "Command", "; Remove-Item C:\\ -Recurse", `"quoted"`, "'single'", "line1\nline2", "$(Get-Process)", "-" + "EncodedCommand AAAA"} {
		request, err := json.Marshal(readRequest{Operation: hostile, PageSize: 1000, Domain: hostile})
		require.NoError(t, err)
		require.NoError(t, invoke(context.Background(), scriptPath, request, func([]byte) error { return nil }))
	}

	require.NotEmpty(t, *calls)
	want := []string{powershellExe(), "-NoProfile", "-NonInteractive", "-File", scriptPath}
	for _, c := range *calls {
		assert.Equal(t, want, c.argv, "argv is fixed; request values only travel on stdin")
	}
	assert.Equal(t, want, scriptArgv(powershellExe(), scriptPath))
}

// TestPowershellExe_AbsoluteUnderSystemRoot: the read never resolves
// powershell.exe through PATH, so a planted binary earlier on PATH cannot run.
func TestPowershellExe_AbsoluteUnderSystemRoot(t *testing.T) {
	exe := powershellExe()
	require.True(t, filepath.IsAbs(exe), "powershell.exe path %q must be absolute", exe)
	assert.True(t, strings.HasSuffix(strings.ToLower(exe),
		strings.ToLower(filepath.Join("System32", "WindowsPowerShell", "v1.0", "powershell.exe"))))

	t.Setenv("SystemRoot", `D:\Win`)
	assert.Equal(t, filepath.Join(`D:\Win`, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"), powershellExe())
}

func TestRunner_ErrorNeverEchoesStdin(t *testing.T) {
	const marker = "zz-secret-marker-domain.example"
	request, err := json.Marshal(readRequest{Operation: "users", PageSize: 1000, Domain: marker})
	require.NoError(t, err)

	// A script that echoed its whole stdin and every value to stderr, then
	// failed: the runner's error must still not carry the request.
	echo := string(request) + "\n" + marker + " operation users\n"
	recordExec(t, "", echo, 1)
	err = invoke(context.Background(), `C:\x\read.ps1`, request, func([]byte) error { return nil })
	require.Error(t, err)
	assert.NotContains(t, err.Error(), marker)
	assert.NotContains(t, err.Error(), string(request))
	assert.Contains(t, err.Error(), "exit code 1")

	// A script error record carries only its fixed code.
	recordExec(t, `{"type":"error","code":"invalid_domain","detail":""}`+"\n", "", 1)
	m := newWithRunner(nil, runnerFunc(func(ctx context.Context, req []byte, onLine func([]byte) error) error {
		return invoke(ctx, `C:\x\read.ps1`, req, onLine)
	}))
	_, err = m.Get(context.Background(), kindDirectoryUser)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid_domain")
	assert.NotContains(t, err.Error(), marker)
}

func TestRunner_OversizedObjectLineRejected(t *testing.T) {
	recordExec(t, strings.Repeat("x", maxLineBytes+10)+"\n", "", 0)
	err := invoke(context.Background(), `C:\x\read.ps1`, []byte(`{}`), func([]byte) error { return nil })
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds bound")
}

// runnerFunc adapts a function to scriptRunner.
type runnerFunc func(ctx context.Context, request []byte, onLine func(line []byte) error) error

func (f runnerFunc) Run(ctx context.Context, request []byte, onLine func(line []byte) error) error {
	return f(ctx, request, onLine)
}

// TestScriptStaging_StagesVerifiedScriptInAdminOnlyDir stages the embedded
// script in a real admin-owned directory and runs it through the recorder.
func TestScriptStaging_StagesVerifiedScriptInAdminOnlyDir(t *testing.T) {
	requireElevated(t)
	dir := filepath.Join(t.TempDir(), "activedirectory-scripts")
	require.NoError(t, os.Mkdir(dir, 0o700))
	sd, err := windows.SecurityDescriptorFromString("O:BA")
	require.NoError(t, err)
	owner, _, err := sd.Owner()
	require.NoError(t, err)
	winacct.SetOwner(t, dir, owner)

	calls := recordExec(t, `{"type":"status","domain":"acme-corp.example"}`+"\n", "", 0)
	r := &psScriptRunner{dir: dir}
	var lines int
	require.NoError(t, r.Run(context.Background(), []byte(`{"operation":"status"}`), func([]byte) error { lines++; return nil }))
	assert.Equal(t, 1, lines)
	require.Len(t, *calls, 1)

	staged := (*calls)[0].argv[4]
	assert.True(t, strings.EqualFold(filepath.Dir(staged), dir))
	content, err := os.ReadFile(staged) // #nosec G304 - test reads the script it staged
	require.NoError(t, err)
	assert.Equal(t, readScript, content)

	// Tampering with the staged file makes the next run refuse.
	require.NoError(t, os.WriteFile(staged, append(content, []byte("\n# changed\n")...), 0o600))
	err = r.Run(context.Background(), []byte(`{"operation":"status"}`), func([]byte) error { return nil })
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing to run")
	assert.Len(t, *calls, 1, "PowerShell must not run a tampered script")
}

// TestRunner_RealScriptValidatesRequestWithoutEcho runs the embedded script
// with the real powershell.exe through invoke. Request validation happens
// before the ActiveDirectory module loads, so it needs no domain controller.
func TestRunner_RealScriptValidatesRequestWithoutEcho(t *testing.T) {
	path := filepath.Join(t.TempDir(), "read.ps1")
	require.NoError(t, os.WriteFile(path, readScript, 0o600))
	require.NoError(t, verifyStagedScript(path))

	const marker = "zz-secret-marker; Remove-Item"
	cases := map[string]readRequest{
		"invalid_operation": {Operation: marker, PageSize: 1000},
		"invalid_domain":    {Operation: "users", PageSize: 1000, Domain: marker},
		"invalid_page_size": {Operation: "users", PageSize: 0},
	}
	for code, req := range cases {
		request, err := json.Marshal(req)
		require.NoError(t, err)
		var stdout []string
		err = invoke(context.Background(), path, request, func(line []byte) error {
			stdout = append(stdout, string(line))
			var rec readRecord
			require.NoError(t, json.Unmarshal(line, &rec))
			if rec.Type == "error" {
				return errors.New(rec.Code)
			}
			return nil
		})
		require.Error(t, err, code)
		assert.Equal(t, code, err.Error())
		for _, line := range stdout {
			assert.NotContains(t, line, "zz-secret-marker", "the script never echoes request values")
		}
	}
}

func TestWriteScript_EmbeddedHashMatchesConstant(t *testing.T) {
	sum := sha256.Sum256(writeScript)
	assert.Equal(t, writeScriptSHA256, hex.EncodeToString(sum[:]),
		"writeScriptSHA256 must be updated whenever scripts/write.ps1 changes")
	onDisk, err := os.ReadFile(filepath.Join("scripts", "write.ps1"))
	require.NoError(t, err)
	assert.Equal(t, onDisk, writeScript, "the embedded write script is scripts/write.ps1")
	assert.NotContains(t, string(writeScript), "-"+"Command", "the write script never passes an inline command")
	assert.NotContains(t, string(writeScript), "Invoke-Expression")
}

// TestWriteRunner_ErrorCarriesNoStderr: the write script's stdin can carry a
// password, so its errors never include anything the script printed.
func TestWriteRunner_ErrorCarriesNoStderr(t *testing.T) {
	const password = "Zq7#tP2m-Lw9xR4v"
	stdin := []byte(`{"operation":"create_user","sam_account_name":"jdoe"}` + "\n" + password)
	recordExec(t, "", "echo: "+string(stdin)+"\n"+password+"\n", 1)
	err := invokeScript(context.Background(), `C:\x\write.ps1`, writeEmbedded, stdin, func([]byte) error { return nil })
	require.Error(t, err)
	assert.NotContains(t, err.Error(), password)
	assert.NotContains(t, err.Error(), "echo")
	assert.Equal(t, "activedirectory: write script failed with exit code 1", err.Error())
}

// TestWriteScript_RealPowerShellNeverEchoesPassword runs the embedded write
// script with the real powershell.exe. Every request is validated, and a new
// user's password read into a SecureString, before the ActiveDirectory module
// loads, so no domain controller is needed: on this host the run ends with a
// validation error, ad_module_unavailable or ad_write_failed. In every case
// the password and request values appear on neither stdout nor stderr.
func TestWriteScript_RealPowerShellNeverEchoesPassword(t *testing.T) {
	path := filepath.Join(t.TempDir(), "write.ps1")
	require.NoError(t, os.WriteFile(path, writeScript, 0o600))
	require.NoError(t, verifyStaged(path, writeEmbedded))
	exe := powershellExe()

	const password = "Zq7#tP2m-Lw9xR4v"
	const marker = "zz-secret-marker"
	cases := []struct {
		name    string
		request string
		codes   []string
	}{
		{"hostile name", `{"operation":"create_user","sam_account_name":"` + marker + `; Remove-Item"}`, []string{"invalid_sam_account_name"}},
		{"leading dash", `{"operation":"create_user","sam_account_name":"-` + marker + `"}`, []string{"invalid_sam_account_name"}},
		{"unknown field", `{"operation":"create_user","password":"` + marker + `"}`, []string{"request_unknown_field"}},
		{"bad ou", `{"operation":"create_user","sam_account_name":"jdoe","ou":"OU=` + marker + `\\,x,DC=a"}`, []string{"invalid_ou"}},
		{"bad id", `{"operation":"set_user_enabled","id":"` + marker + `","enabled":true}`, []string{"invalid_id"}},
		{"delete is not an operation", `{"operation":"delete_user","id":"00000000-0000-4000-8000-000000000001"}`, []string{"invalid_operation"}},
		{"valid create", `{"operation":"create_user","sam_account_name":"jdoe` + `","display_name":"J Doe"}`, []string{"ad_module_unavailable", "ad_write_failed"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr strings.Builder
			stdin := strings.NewReader(tc.request + "\n" + password + "\n")
			_, err := execScript(context.Background(), scriptArgv(exe, path), stdin, &stdout, &stderr)
			require.Error(t, err, "every case ends in an error record and exit code 1")

			var codes []string
			for _, line := range strings.Split(strings.TrimSpace(stdout.String()), "\n") {
				var rec readRecord
				require.NoError(t, json.Unmarshal([]byte(line), &rec), "stdout is NDJSON: %q", line)
				codes = append(codes, rec.Code)
			}
			require.Len(t, codes, 1)
			assert.Contains(t, tc.codes, codes[0])
			for _, out := range []string{stdout.String(), stderr.String()} {
				assert.NotContains(t, out, password)
				assert.NotContains(t, out, marker)
			}
		})
	}
}
