// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

//go:build windows

package contract_test

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// dialPlatform dials a named pipe, the transport contract.Listen uses on this
// platform.
func dialPlatform(ctx context.Context, addr string) (net.Conn, error) {
	return winio.DialPipeContext(ctx, addr)
}

// sidOwnerRights is SDDL "OW" — the OWNER RIGHTS SID, which an access check
// resolves to whichever principal owns the object. contract.Listen's DACL
// names it so that the pipe is reachable only by the runtime account that
// fork/exec'd the module.
const sidOwnerRights = "S-1-3-4"

// readPipeSecurityDescriptor reads addr's security descriptor, waiting out
// ERROR_PIPE_BUSY.
//
// GetNamedSecurityInfo on an SE_FILE_OBJECT opens a client handle to the pipe,
// and a go-winio listener has no connectable instance until its caller reaches
// Accept (its first instance is created without read/write access, which leaves
// it disconnected). The caller therefore starts an accept loop before calling
// here, but that goroutine may not have entered Accept yet, so a busy result is
// a startup race rather than a permanent state. Waiting it out is what any real
// client does — WaitNamedPipe, or winio.DialPipeContext's own ERROR_PIPE_BUSY
// retry. Any other error, and busy past the deadline, fail the test.
func readPipeSecurityDescriptor(t *testing.T, addr string) *windows.SECURITY_DESCRIPTOR {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for {
		sd, err := windows.GetNamedSecurityInfo(addr, windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err == nil {
			return sd
		}
		if !errors.Is(err, windows.ERROR_PIPE_BUSY) || time.Now().After(deadline) {
			require.NoError(t, err, "read security descriptor of %s", addr)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// assertOwnerOnlyAccess reads the named pipe's real security descriptor and
// asserts it grants the owner and nobody else.
//
// go-winio's default descriptor (selected by a nil PipeConfig) comes from
// rtlDefaultNpAcl and grants Everyone and ANONYMOUS LOGON read/write, so the
// checks below are specifically a regression test for that default coming
// back: the DACL must be protected, hold exactly one allow ACE, and that ACE
// must name the owner rather than a world-readable well-known SID.
func assertOwnerOnlyAccess(t *testing.T, addr string) {
	t.Helper()

	sd := readPipeSecurityDescriptor(t, addr)
	sddl := sd.String()

	control, _, err := sd.Control()
	require.NoError(t, err)
	assert.NotZero(t, control&windows.SE_DACL_PROTECTED,
		"pipe DACL must be protected so the default NPFS ACL cannot apply; got %s", sddl)

	dacl, defaulted, err := sd.DACL()
	require.NoError(t, err, "read DACL of %s", addr)
	require.NotNil(t, dacl, "pipe must carry an explicit DACL; got %s", sddl)
	require.False(t, defaulted, "pipe must not use the default named-pipe DACL; got %s", sddl)
	require.EqualValues(t, 1, dacl.AceCount,
		"pipe DACL must hold exactly one ACE (owner only); got %s", sddl)

	owner, _, err := sd.Owner()
	require.NoError(t, err, "read owner of %s", addr)
	ownerRights, err := windows.StringToSid(sidOwnerRights)
	require.NoError(t, err)
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	require.NoError(t, err)
	anonymous, err := windows.CreateWellKnownSid(windows.WinAnonymousSid)
	require.NoError(t, err)

	var ace *windows.ACCESS_ALLOWED_ACE
	require.NoError(t, windows.GetAce(dacl, 0, &ace), "read ACE 0 of %s", addr)
	// The SID is stored inline at the end of the ACE; SidStart is its first
	// dword. This is the documented layout and the same access x/sys/windows
	// uses in its own tests.
	sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))

	assert.EqualValues(t, windows.ACCESS_ALLOWED_ACE_TYPE, ace.Header.AceType,
		"pipe DACL's only ACE must be an allow ACE; got %s", sddl)
	assert.False(t, sid.Equals(everyone),
		"pipe DACL must not grant Everyone; got %s", sddl)
	assert.False(t, sid.Equals(anonymous),
		"pipe DACL must not grant ANONYMOUS LOGON; got %s", sddl)
	assert.True(t, sid.Equals(ownerRights) || sid.Equals(owner),
		"pipe DACL's only ACE must name the owner (%s or %s); got %s",
		sidOwnerRights, owner, sddl)

	// GENERIC_ALL is mapped through the file generic mapping when the ACE is
	// stored, so assert on the mapped rights: the owner must retain enough
	// access for the runtime to dial and for the server to open further pipe
	// instances.
	const needed = windows.FILE_GENERIC_READ | windows.FILE_GENERIC_WRITE
	assert.EqualValues(t, needed, uint32(ace.Mask)&needed,
		"owner ACE must grant read and write on the pipe; got %s", sddl)
}
