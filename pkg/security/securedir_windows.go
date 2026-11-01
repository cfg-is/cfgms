// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package security

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// adminOnlyDACLSDDL is a protected DACL (P: no inherited ACEs) granting full
// control to SYSTEM and BUILTIN\Administrators only, inheritable to all child
// files and directories (OICI).
const adminOnlyDACLSDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

// adminOwnedSDDL is adminOnlyDACLSDDL with BUILTIN\Administrators as owner. It
// is the descriptor a new directory is created with, so the directory never
// exists, even briefly, with the inherited (user-writable) %ProgramData% ACL.
const adminOwnedSDDL = "O:BA" + adminOnlyDACLSDDL

// openFlags opens the object itself, never the target of a junction or
// symbolic link, and allows directories to be opened.
const openFlags = windows.FILE_FLAG_BACKUP_SEMANTICS | windows.FILE_FLAG_OPEN_REPARSE_POINT

// shareAll lets the security handle coexist with any other open of the object.
const shareAll = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE

// EnsureAdminOnlyDir ensures path exists and is readable and writable by SYSTEM
// and BUILTIN\Administrators only.
//
// A missing directory is created atomically with its final security descriptor
// (owner BUILTIN\Administrators, protected admin-only DACL), so there is no
// window in which it is a directory someone else planted or carries the
// inherited parent ACL. If the directory already exists (including one that
// appeared concurrently), every check and the DACL write happen on one handle
// opened without following reparse points:
//
//   - a link, junction or other reparse point, or a non-directory, is refused;
//   - a directory whose owner is neither SYSTEM nor BUILTIN\Administrators is
//     refused with ErrUntrustedDirOwner, and nothing is changed;
//   - every existing entry below it is checked without following reparse
//     points. A reparse point or an entry owned by an untrusted principal is
//     refused before anything is changed.
//
// Otherwise the directory gets a protected DACL (no inherited ACEs) with full
// control for SYSTEM and Administrators, inheritable by children; Windows
// propagates it to existing children that inherit. The tree is then checked
// again, and any entry that is not owned by a trusted principal, is a reparse
// point, or still grants access to any principal other than SYSTEM and
// Administrators is refused (ErrUntrustedDirOwner / ErrUntrustedDirEntry).
// Uses in-process Win32 security APIs only.
func EnsureAdminOnlyDir(path string) error {
	_, err := ensureAdminOnlyDir(path, false)
	return err
}

// AdoptAdminOnlyDir is EnsureAdminOnlyDir for the steward's own data directory,
// run by the installer and at every steward start. Before the checks, every
// existing entry (path itself and everything below it, never following reparse
// points) whose owner is a member of the local BUILTIN\Administrators group,
// directly or through nested groups, is taken over: its owner becomes
// BUILTIN\Administrators and it gets the protected admin-only DACL. Windows makes
// an administrator's own account the owner of what it creates ("Object
// creator"), so files an installer or an administrator wrote would otherwise be
// refused by the SYSTEM steward. An Administrators member can already take
// ownership of anything on the host, so adopting its entries hands control to
// no one new. An entry owned by any other principal (a standard user, a
// non-admin group, an account whose groups cannot be computed) is refused with
// ErrUntrustedDirOwner, as EnsureAdminOnlyDir refuses it.
//
// It returns the paths it took over, for the caller to log.
func AdoptAdminOnlyDir(path string) (adopted []string, err error) {
	return ensureAdminOnlyDir(path, true)
}

func ensureAdminOnlyDir(path string, adopt bool) ([]string, error) {
	path = filepath.Clean(path)
	created, err := createAdminOnlyDir(path)
	if err != nil {
		return nil, err
	}
	var adopted []string
	if adopt && !created {
		a := &adopter{members: map[string]bool{}}
		err := a.adoptTree(path)
		if err != nil {
			return a.adopted, err
		}
		adopted = a.adopted
	}
	return adopted, secureExistingOrCreated(path, created)
}

func secureExistingOrCreated(path string, created bool) error {

	access := uint32(windows.READ_CONTROL | windows.WRITE_DAC)
	if created {
		access |= windows.WRITE_OWNER
	}
	h, err := openHandleNoFollow(path, access)
	if err != nil {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) && !created {
			// The handle we could not open is never written through; this
			// read-only open only decides which refusal to report.
			if rootOwnerIsUntrusted(path) {
				return fmt.Errorf("%s: %w", path, ErrUntrustedDirOwner)
			}
		}
		return fmt.Errorf("open directory %s: %w", path, err)
	}
	defer func() { _ = windows.CloseHandle(h) }()

	if err := requirePlainDir(h, path); err != nil {
		return err
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read security descriptor of %s: %w", path, err)
	}
	trusted, err := ownerIsTrusted(sd)
	if err != nil {
		return fmt.Errorf("read owner of %s: %w", path, err)
	}

	secInfo := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	var owner *windows.SID
	if !trusted {
		if !created {
			return fmt.Errorf("%s: %w", path, ErrUntrustedDirOwner)
		}
		// This call created the directory with an admin-only DACL, so
		// assigning it to Administrators cannot hand control to anyone who did
		// not already have it.
		owner, err = windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
		if err != nil {
			return fmt.Errorf("build Administrators SID: %w", err)
		}
		secInfo |= windows.OWNER_SECURITY_INFORMATION
	}

	// Refuse planted entries before changing anything.
	if !created {
		if err := checkTree(path, false); err != nil {
			return err
		}
	}

	dacl, err := adminOnlyDACL()
	if err != nil {
		return err
	}
	if err := windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, secInfo, owner, nil, dacl, nil); err != nil {
		return fmt.Errorf("apply admin-only security descriptor to %s: %w", path, err)
	}

	// Verify the locked-down tree: catches entries planted before the DACL
	// landed and children whose explicit ACEs the propagation left in place.
	return checkTree(path, true)
}

// createAdminOnlyDir creates path with the admin-only security descriptor. It
// reports created=false when path already exists (as anything); the caller
// then treats it as an existing object and verifies it on a handle.
func createAdminOnlyDir(path string) (created bool, err error) {
	parent := filepath.Dir(path)
	if parent != path {
		if err := os.MkdirAll(parent, 0700); err != nil {
			return false, fmt.Errorf("create parent directory of %s: %w", path, err)
		}
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false, fmt.Errorf("invalid directory path %s: %w", path, err)
	}

	err = createDirWithSDDL(p, adminOwnedSDDL)
	if errors.Is(err, windows.ERROR_INVALID_OWNER) {
		// The token cannot name Administrators as owner (not elevated). Create
		// the directory with the same protected DACL and the caller's default
		// owner; EnsureAdminOnlyDir then assigns the owner or fails.
		err = createDirWithSDDL(p, adminOnlyDACLSDDL)
	}
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, windows.ERROR_ALREADY_EXISTS):
		return false, nil
	default:
		return false, fmt.Errorf("create directory %s: %w", path, err)
	}
}

func createDirWithSDDL(path *uint16, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("build admin-only security descriptor: %w", err)
	}
	sa := windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(sa))
	return windows.CreateDirectory(path, &sa)
}

func adminOnlyDACL() (*windows.ACL, error) {
	dsd, err := windows.SecurityDescriptorFromString(adminOnlyDACLSDDL)
	if err != nil {
		return nil, fmt.Errorf("build admin-only security descriptor: %w", err)
	}
	dacl, _, err := dsd.DACL()
	if err != nil {
		return nil, fmt.Errorf("read admin-only DACL: %w", err)
	}
	return dacl, nil
}

// openHandleNoFollow opens path itself (never a reparse target) for access.
func openHandleNoFollow(path string, access uint32) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	return windows.CreateFile(p, access, shareAll, nil, windows.OPEN_EXISTING, openFlags, 0)
}

// attributesOf returns the file attributes of the object behind h.
func attributesOf(h windows.Handle) (uint32, error) {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return 0, err
	}
	return info.FileAttributes, nil
}

// requirePlainDir refuses a reparse point or a non-directory behind h.
func requirePlainDir(h windows.Handle, path string) error {
	attrs, err := attributesOf(h)
	if err != nil {
		return fmt.Errorf("stat directory %s: %w", path, err)
	}
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("%s is a link or reparse point, refusing to secure it", path)
	}
	if attrs&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return fmt.Errorf("%s exists and is not a directory", path)
	}
	return nil
}

// rootOwnerIsUntrusted reports whether the existing path can be read and is
// owned by an untrusted principal, so a directory the caller cannot open for
// WRITE_DAC is still reported as the ownership refusal it is. It returns false
// when the owner cannot be determined; the caller then reports its own open
// error instead.
func rootOwnerIsUntrusted(path string) bool {
	h, err := openHandleNoFollow(path, windows.READ_CONTROL)
	if err != nil {
		return false
	}
	defer func() { _ = windows.CloseHandle(h) }()
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return false
	}
	trusted, err := ownerIsTrusted(sd)
	return err == nil && !trusted
}

// adminOnlyFileDACLSDDL is adminOnlyDACLSDDL for a file, which has no children
// to pass ACEs on to.
const adminOnlyFileDACLSDDL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)"

// adopter takes over the Administrators-owned entries of one tree. members
// caches the Administrators-membership answer per owner SID, since a tree is
// usually owned by one or two accounts.
type adopter struct {
	members map[string]bool
	adopted []string
}

// adoptTree walks path and everything below it without following reparse
// points and takes over each entry whose owner is an Administrators member. A
// reparse point, or an entry owned by anyone else who is not SYSTEM or
// BUILTIN\Administrators, is refused.
func (a *adopter) adoptTree(path string) error {
	isDir, err := a.adoptEntry(path)
	if err != nil || !isDir {
		return err
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return fmt.Errorf("list directory %s: %w", path, err)
	}
	for _, e := range entries {
		if err := a.adoptTree(filepath.Join(path, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

// adoptEntry inspects one entry, and if an Administrators member owns it sets
// its owner to BUILTIN\Administrators and its DACL to the protected admin-only
// DACL, reading and writing on one handle that does not follow reparse points.
// It reports whether the entry is a plain directory to descend into.
func (a *adopter) adoptEntry(path string) (isDir bool, err error) {
	writable := true
	h, err := openHandleNoFollow(path, windows.READ_CONTROL|windows.WRITE_OWNER|windows.WRITE_DAC)
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		// Not ours to reassign. If the owner is already trusted the checks
		// that follow decide whether the entry is acceptable as it is.
		writable = false
		h, err = openHandleNoFollow(path, windows.READ_CONTROL)
	}
	if err != nil {
		return false, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = windows.CloseHandle(h) }()

	attrs, err := attributesOf(h)
	if err != nil {
		return false, fmt.Errorf("stat %s: %w", path, err)
	}
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return false, fmt.Errorf("%s is a link or reparse point: %w", path, ErrUntrustedDirEntry)
	}
	isDir = attrs&windows.FILE_ATTRIBUTE_DIRECTORY != 0

	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return false, fmt.Errorf("read security descriptor of %s: %w", path, err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return false, fmt.Errorf("read owner of %s: %w", path, err)
	}
	if owner != nil && (owner.IsWellKnown(windows.WinLocalSystemSid) ||
		owner.IsWellKnown(windows.WinBuiltinAdministratorsSid)) {
		return isDir, nil
	}
	if owner == nil || !a.isMember(owner) {
		return false, fmt.Errorf("%s is owned by a principal that is not SYSTEM or a member of Administrators: %w", path, ErrUntrustedDirOwner)
	}
	if !writable {
		return false, fmt.Errorf("%s is owned by a member of Administrators but cannot be reassigned: %w", path, ErrUntrustedDirOwner)
	}

	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return false, fmt.Errorf("build Administrators SID: %w", err)
	}
	daclSDDL := adminOnlyFileDACLSDDL
	if isDir {
		daclSDDL = adminOnlyDACLSDDL
	}
	dsd, err := windows.SecurityDescriptorFromString(daclSDDL)
	if err != nil {
		return false, fmt.Errorf("build admin-only security descriptor: %w", err)
	}
	dacl, _, err := dsd.DACL()
	if err != nil {
		return false, fmt.Errorf("read admin-only DACL: %w", err)
	}
	secInfo := windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION |
		windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	if err := windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, secInfo, admins, nil, dacl, nil); err != nil {
		return false, fmt.Errorf("assign %s to Administrators: %w", path, err)
	}
	a.adopted = append(a.adopted, path)
	return isDir, nil
}

// isMember reports whether owner is the elevated caller or a member of the
// local Administrators group. A membership that cannot be computed counts as
// not a member, so the entry is refused.
func (a *adopter) isMember(owner *windows.SID) bool {
	if ownerIsElevatedCaller(owner) {
		return true
	}
	key := owner.String()
	if m, ok := a.members[key]; ok {
		return m
	}
	m, err := isAdministratorsMember(owner)
	m = m && err == nil
	a.members[key] = m
	return m
}

// checkTree verifies every entry below root without following reparse points.
// Each entry must not be a reparse point and must be owned by a trusted
// principal. With checkDACL, each entry's DACL must also grant access to no
// principal other than SYSTEM and Administrators.
func checkTree(root string, checkDACL bool) error {
	entries, err := os.ReadDir(root)
	if err != nil {
		return fmt.Errorf("list directory %s: %w", root, err)
	}
	for _, e := range entries {
		p := filepath.Join(root, e.Name())
		isDir, err := checkEntry(p, checkDACL)
		if err != nil {
			return err
		}
		if isDir {
			if err := checkTree(p, checkDACL); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkEntry inspects one entry on a handle that does not follow reparse
// points and reports whether it is a (plain) directory to descend into.
func checkEntry(path string, checkDACL bool) (isDir bool, err error) {
	h, err := openHandleNoFollow(path, windows.READ_CONTROL)
	if err != nil {
		return false, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = windows.CloseHandle(h) }()

	attrs, err := attributesOf(h)
	if err != nil {
		return false, fmt.Errorf("stat %s: %w", path, err)
	}
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return false, fmt.Errorf("%s is a link or reparse point: %w", path, ErrUntrustedDirEntry)
	}

	info := windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION)
	if checkDACL {
		info |= windows.DACL_SECURITY_INFORMATION
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, info)
	if err != nil {
		return false, fmt.Errorf("read security descriptor of %s: %w", path, err)
	}
	trusted, err := ownerIsTrusted(sd)
	if err != nil {
		return false, fmt.Errorf("read owner of %s: %w", path, err)
	}
	if !trusted {
		return false, fmt.Errorf("%s: %w", path, ErrUntrustedDirOwner)
	}
	if checkDACL {
		ok, err := daclIsAdminOnly(sd)
		if err != nil {
			return false, fmt.Errorf("read DACL of %s: %w", path, err)
		}
		if !ok {
			return false, fmt.Errorf("%s grants access to a principal other than SYSTEM or BUILTIN\\Administrators: %w", path, ErrUntrustedDirEntry)
		}
	}
	return attrs&windows.FILE_ATTRIBUTE_DIRECTORY != 0, nil
}

// daclIsAdminOnly reports whether every allow ACE in the descriptor's DACL
// names SYSTEM or BUILTIN\Administrators. Deny ACEs only remove access and are
// accepted; a NULL DACL (everyone full control) and any ACE type other than a
// plain allow or deny ACE are refused.
func daclIsAdminOnly(sd *windows.SECURITY_DESCRIPTOR) (bool, error) {
	acl, _, err := sd.DACL()
	if err != nil {
		return false, err
	}
	if acl == nil {
		return false, nil
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return false, err
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if !sid.IsWellKnown(windows.WinLocalSystemSid) &&
				!sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
				return false, nil
			}
		default:
			return false, nil
		}
	}
	return true, nil
}

// ownerIsTrusted reports whether the descriptor's owner is SYSTEM or
// BUILTIN\Administrators.
func ownerIsTrusted(sd *windows.SECURITY_DESCRIPTOR) (bool, error) {
	owner, _, err := sd.Owner()
	if err != nil {
		return false, err
	}
	if owner == nil {
		return false, nil
	}
	if owner.IsWellKnown(windows.WinLocalSystemSid) ||
		owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return true, nil
	}
	return ownerIsElevatedCaller(owner), nil
}

// ownerIsElevatedCaller reports whether owner is the user of the current
// process and that process is elevated (an administrator's token). An elevated
// administrator account may own a directory it created, e.g. one under its own
// profile or temp directory; a non-admin principal still never qualifies.
func ownerIsElevatedCaller(owner *windows.SID) bool {
	token := windows.GetCurrentProcessToken()
	if !token.IsElevated() {
		return false
	}
	user, err := token.GetTokenUser()
	if err != nil {
		return false
	}
	return user.User.Sid.Equals(owner)
}

// VerifyAdminOnlyPath reports whether path (a file or a directory, given as an
// absolute path) can be trusted as data that only administrators may touch.
// It returns nil only when:
//
//   - path is not a link or other reparse point, is owned by SYSTEM,
//     BUILTIN\Administrators or an account that is a member of local
//     Administrators (an account whose groups cannot be computed is refused),
//     and its DACL grants access to SYSTEM and BUILTIN\Administrators only;
//   - the directories that contain it pass the checks described in
//     VerifyAdminOnlyWritablePath, so no other principal can replace path or
//     rename any directory on the way to it.
//
// Because no other principal can change what path names, a later open of the
// same path reaches the object that was checked unless an administrator moves
// it. The check proves who controls the object, not that it holds the
// expected content.
//
// The parent rule refuses a directory that lies directly in %ProgramData% or
// at a volume root, since those let users add entries; verify the files inside
// the data directory instead, after securing it with AdoptAdminOnlyDir or
// EnsureAdminOnlyDir.
//
// An owner that is an Administrators member is accepted because Windows makes
// the creating administrator's account the owner. A non-elevated process of
// that account holds the owner's implicit rights too, so writers should hand
// such files to BUILTIN\Administrators (as AdoptAdminOnlyDir does).
//
// It only reads: the owner and DACL of path and of its directories are never
// changed, and no privilege beyond read access to their security descriptors
// is needed. A wrong owner wraps ErrUntrustedDirOwner; a reparse point or a
// grant to another principal wraps ErrUntrustedDirEntry; a relative path or a
// path that cannot be inspected is an error.
func VerifyAdminOnlyPath(path string) error {
	path, err := absoluteForVerify(path)
	if err != nil {
		return err
	}
	a := &adopter{members: map[string]bool{}}
	sd, err := inspectNoFollow(path)
	if err != nil {
		return err
	}
	if err := requireTrustedOwner(sd, path, a); err != nil {
		return err
	}
	ok, err := daclIsAdminOnly(sd)
	if err != nil {
		return fmt.Errorf("read DACL of %s: %w", path, err)
	}
	if !ok {
		return fmt.Errorf("%s grants access to a principal other than SYSTEM or BUILTIN\\Administrators: %w", path, ErrUntrustedDirEntry)
	}
	return verifyContainers(path, a)
}

// VerifyAdminOnlyWritablePath reports whether path (an absolute path) can be
// trusted as an executable: other principals may read and execute it, but only
// administrators may change it or what it names. The owner and reparse-point
// rules of VerifyAdminOnlyPath apply to path. In addition:
//
//   - on path, a principal other than SYSTEM, BUILTIN\Administrators,
//     NT SERVICE\TrustedInstaller or a member of local Administrators may hold
//     read and execute rights only (anything else, such as write, append,
//     delete, WRITE_DAC, WRITE_OWNER or write-attributes, is refused);
//   - the parent directory must not be a reparse point, must be owned by one of
//     those principals, and may grant other principals list and traverse
//     rights only (add-file, add-subdirectory and delete-child are refused);
//   - every further directory up to the volume root must not be a reparse
//     point, must be owned by one of those principals, and must not grant
//     another principal DELETE, delete-child, WRITE_DAC, WRITE_OWNER or full
//     control, so no directory on the way to path can be renamed and replaced.
//
// ACEs that are inherit-only do not apply to the object and are ignored. The
// check proves who controls the binary, not that it is the expected binary;
// callers that launch it should also verify its signature or hash. Like
// VerifyAdminOnlyPath it only reads and returns the same errors.
func VerifyAdminOnlyWritablePath(path string) error {
	path, err := absoluteForVerify(path)
	if err != nil {
		return err
	}
	a := &adopter{members: map[string]bool{}}
	sd, err := inspectNoFollow(path)
	if err != nil {
		return err
	}
	if err := requireTrustedOwner(sd, path, a); err != nil {
		return err
	}
	if err := refuseUntrustedGrants(sd, path, a, outsideReadExecute); err != nil {
		return err
	}
	return verifyContainers(path, a)
}

// Access rights an untrusted principal may hold on a verified object or its
// parent directory: read and execute (on a directory, list and traverse),
// specific or generic.
const readExecuteMask = windows.FILE_GENERIC_READ | windows.FILE_GENERIC_EXECUTE |
	windows.GENERIC_READ | windows.GENERIC_EXECUTE

// fileDeleteChild is FILE_DELETE_CHILD.
const fileDeleteChild = 0x40

// ancestorReplaceMask is the access rights that let a principal rename or
// replace a directory above the parent, or grant itself the right to.
const ancestorReplaceMask = windows.DELETE | fileDeleteChild | windows.WRITE_DAC |
	windows.WRITE_OWNER | windows.GENERIC_ALL

// outsideReadExecute reports whether mask holds any right beyond read and
// execute.
func outsideReadExecute(mask uint32) bool { return mask&^readExecuteMask != 0 }

// replacesAncestor reports whether mask lets the holder rename or replace a
// directory entry.
func replacesAncestor(mask uint32) bool { return mask&ancestorReplaceMask != 0 }

// sidTrustedInstaller is NT SERVICE\TrustedInstaller, which owns and has full
// control of much of the operating system, including %ProgramFiles%.
const sidTrustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

// absoluteForVerify cleans path and refuses a relative one, whose directories
// would depend on the current directory.
func absoluteForVerify(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("%s is not an absolute path", path)
	}
	return filepath.Clean(path), nil
}

// verifyContainers checks every directory from path's parent up to the volume
// root: none may be a reparse point and each must be owned by a trusted
// principal. The parent may grant other principals read and execute only;
// every directory above it must not let them rename or replace an entry.
func verifyContainers(path string, a *adopter) error {
	refused := outsideReadExecute
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		sd, err := inspectNoFollow(dir)
		if err != nil {
			return err
		}
		owner, _, err := sd.Owner()
		if err != nil {
			return fmt.Errorf("read owner of %s: %w", dir, err)
		}
		if owner == nil || !a.isTrustedPrincipal(owner) {
			return fmt.Errorf("%s is owned by a principal that is not trusted to control %s: %w", dir, path, ErrUntrustedDirOwner)
		}
		if err := refuseUntrustedGrants(sd, dir, a, refused); err != nil {
			return err
		}
		if filepath.Dir(dir) == dir {
			return nil
		}
		refused = replacesAncestor
	}
}

// inspectNoFollow reads the owner and DACL of path on a handle that does not
// follow reparse points, and refuses a reparse point.
func inspectNoFollow(path string) (*windows.SECURITY_DESCRIPTOR, error) {
	h, err := openHandleNoFollow(path, windows.READ_CONTROL)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = windows.CloseHandle(h) }()
	attrs, err := attributesOf(h)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return nil, fmt.Errorf("%s is a link or reparse point: %w", path, ErrUntrustedDirEntry)
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return nil, fmt.Errorf("read security descriptor of %s: %w", path, err)
	}
	return sd, nil
}

// requireTrustedOwner refuses sd unless its owner is SYSTEM,
// BUILTIN\Administrators or a member of local Administrators.
func requireTrustedOwner(sd *windows.SECURITY_DESCRIPTOR, path string, a *adopter) error {
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("read owner of %s: %w", path, err)
	}
	if owner != nil && (owner.IsWellKnown(windows.WinLocalSystemSid) ||
		owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) || a.isMember(owner)) {
		return nil
	}
	return fmt.Errorf("%s is owned by a principal that is not SYSTEM or a member of Administrators: %w", path, ErrUntrustedDirOwner)
}

// isTrustedPrincipal reports whether sid may control a verified object or the
// directories that contain it: SYSTEM, BUILTIN\Administrators,
// NT SERVICE\TrustedInstaller, or an account that is a member of local
// Administrators.
func (a *adopter) isTrustedPrincipal(sid *windows.SID) bool {
	if sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) ||
		sid.String() == sidTrustedInstaller {
		return true
	}
	return a.isMember(sid)
}

// refuseUntrustedGrants refuses sd when an allow ACE that applies to the
// object grants rights that refused reports to a principal that is not
// trusted. Deny ACEs only remove access and are skipped; a NULL DACL and any
// ACE type other than a plain allow or deny ACE are refused.
func refuseUntrustedGrants(sd *windows.SECURITY_DESCRIPTOR, path string, a *adopter, refused func(mask uint32) bool) error {
	acl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("read DACL of %s: %w", path, err)
	}
	if acl == nil {
		return fmt.Errorf("%s has no DACL and grants everyone full access: %w", path, ErrUntrustedDirEntry)
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return fmt.Errorf("read DACL of %s: %w", path, err)
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
		default:
			return fmt.Errorf("%s has an access control entry of a type that cannot be checked: %w", path, ErrUntrustedDirEntry)
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || !refused(uint32(ace.Mask)) {
			continue
		}
		if !a.isTrustedPrincipal((*windows.SID)(unsafe.Pointer(&ace.SidStart))) {
			return fmt.Errorf("%s grants write access to a principal other than an administrator: %w", path, ErrUntrustedDirEntry)
		}
	}
	return nil
}
