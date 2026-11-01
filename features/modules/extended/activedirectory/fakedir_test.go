// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package activedirectory

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/pkg/logging"
)

// FakeDirectory is an in-memory directory behind test implementations of the
// read and write script runners. It answers the same request documents the
// fixed scripts accept and keeps every write and every password it received,
// so tests can assert on exactly what reached the scripts. It is exported for
// the external test package (factory and executor tests).
type FakeDirectory struct {
	mu        sync.Mutex
	domain    string
	objects   map[string]*fakeObject // by objectGUID
	next      int
	writes    []writeRequest
	passwords []string
	reads     []readRequest
}

type fakeObject struct {
	kind     string // "user" or "group"
	id       string
	sam      string
	upn      string
	display  string
	mail     string
	ou       string
	enabled  bool
	scope    string
	category string
	memberOf map[string]bool // group objectGUIDs
}

// NewFakeDirectory returns an empty directory for domain acme-corp.example.
func NewFakeDirectory() *FakeDirectory {
	return &FakeDirectory{domain: "acme-corp.example", objects: map[string]*fakeObject{}}
}

func (d *FakeDirectory) newID(kind string) string {
	d.next++
	prefix := byte('a')
	if kind == "group" {
		prefix = 'b'
	}
	return guid(prefix, 1000+d.next)
}

// AddUser adds an enabled user and returns its objectGUID.
func (d *FakeDirectory) AddUser(sam string) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	id := d.newID("user")
	d.objects[id] = &fakeObject{kind: "user", id: id, sam: sam, enabled: true, memberOf: map[string]bool{}}
	return id
}

// AddGroup adds a global security group and returns its objectGUID.
func (d *FakeDirectory) AddGroup(sam string) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	id := d.newID("group")
	d.objects[id] = &fakeObject{kind: "group", id: id, sam: sam, scope: "Global", category: "Security", memberOf: map[string]bool{}}
	return id
}

// Rename changes an object's sAMAccountName.
func (d *FakeDirectory) Rename(id, sam string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.objects[id].sam = sam
}

// AddMember makes member a direct member of group.
func (d *FakeDirectory) AddMember(group, member string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.objects[member].memberOf[group] = true
}

// IsMember reports whether member is a direct member of group.
func (d *FakeDirectory) IsMember(group, member string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.objects[member].memberOf[group]
}

// Lookup returns the objectGUID of the object named sam.
func (d *FakeDirectory) Lookup(sam string) (string, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	o := d.byName("", sam)
	if o == nil {
		return "", false
	}
	return o.id, true
}

// Enabled reports whether the user is enabled.
func (d *FakeDirectory) Enabled(id string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.objects[id].enabled
}

// WriteOps returns the operation of every write the write runner received.
func (d *FakeDirectory) WriteOps() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	ops := make([]string, 0, len(d.writes))
	for _, w := range d.writes {
		ops = append(ops, w.Operation)
	}
	return ops
}

// Passwords returns every password the write runner received on stdin.
func (d *FakeDirectory) Passwords() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.passwords...)
}

func (d *FakeDirectory) byName(kind, sam string) *fakeObject {
	for _, o := range d.objects {
		if (kind == "" || o.kind == kind) && strings.EqualFold(o.sam, sam) {
			return o
		}
	}
	return nil
}

func (d *FakeDirectory) dn(o *fakeObject) string {
	parent := o.ou
	if parent == "" {
		parent = "CN=Users," + domainDN(d.domain)
	}
	return "CN=" + o.sam + "," + parent
}

func (d *FakeDirectory) record(o *fakeObject, match string) map[string]interface{} {
	rec := map[string]interface{}{
		"type": o.kind, "id": o.id, "sam_account_name": o.sam, "display_name": o.display,
		"distinguished_name": d.dn(o), "directory_domain": d.domain,
	}
	if match != "" {
		rec["match"] = match
	}
	memberOf := []string{}
	for g := range o.memberOf {
		memberOf = append(memberOf, g)
	}
	rec["member_of"] = memberOf
	if o.kind == "user" {
		rec["user_principal_name"] = o.upn
		rec["mail"] = o.mail
		rec["enabled"] = o.enabled
	} else {
		rec["group_scope"] = o.scope
		rec["group_category"] = o.category
	}
	return rec
}

// ReadRunner returns the test implementation of the read script runner.
func (d *FakeDirectory) ReadRunner() scriptRunner { return fakeReadRunner{d} }

// WriteRunner returns the test implementation of the write script runner.
func (d *FakeDirectory) WriteRunner() scriptRunner { return fakeWriteRunner{d} }

type fakeReadRunner struct{ d *FakeDirectory }

func emitJSON(onLine func([]byte) error, rec interface{}) error {
	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return onLine(line)
}

func (r fakeReadRunner) Run(_ context.Context, request []byte, onLine func([]byte) error) error {
	var req readRequest
	if err := json.Unmarshal(request, &req); err != nil {
		return err
	}
	d := r.d
	d.mu.Lock()
	d.reads = append(d.reads, req)
	var out []interface{}
	switch req.Operation {
	case "status":
		out = append(out, map[string]interface{}{"type": "status", "domain": d.domain, "domain_controller": "dc01." + d.domain, "forest_root": d.domain, "netbios_name": "ACME"})
	case "find_user", "find_group":
		kind := strings.TrimPrefix(req.Operation, "find_")
		var byID, byName *fakeObject
		if o, ok := d.objects[req.ID]; ok && req.ID != "" && o.kind == kind {
			byID = o
			out = append(out, d.record(o, "id"))
		}
		if req.SamAccountName != "" {
			if o := d.byName(kind, req.SamAccountName); o != nil {
				byName = o
				out = append(out, d.record(o, "name"))
			}
		}
		target := byID
		if target == nil {
			target = byName
		}
		for i, name := range req.Members {
			o := d.byName("", name)
			if o == nil {
				out = append(out, map[string]interface{}{"type": "member", "index": i, "found": false})
				continue
			}
			isMember := target != nil && o.memberOf[target.id]
			out = append(out, map[string]interface{}{"type": "member", "index": i, "found": true, "id": o.id, "is_member": isMember})
		}
	case "users", "groups":
		kind := strings.TrimSuffix(req.Operation, "s")
		for _, o := range d.objects {
			if o.kind == kind {
				out = append(out, d.record(o, ""))
			}
		}
	default:
		d.mu.Unlock()
		return fmt.Errorf("fake read script: invalid operation %q", req.Operation)
	}
	d.mu.Unlock()
	for _, rec := range out {
		if err := emitJSON(onLine, rec); err != nil {
			return err
		}
	}
	return nil
}

type fakeWriteRunner struct{ d *FakeDirectory }

func (r fakeWriteRunner) Run(_ context.Context, stdin []byte, onLine func([]byte) error) error {
	line, password, _ := bytes.Cut(stdin, []byte("\n"))
	var req writeRequest
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return err
	}
	d := r.d
	d.mu.Lock()
	defer d.mu.Unlock()
	d.writes = append(d.writes, req)
	fail := func(code string) error {
		return emitJSON(onLine, map[string]interface{}{"type": "error", "code": code})
	}
	var id string
	switch req.Operation {
	case opCreateUser:
		if len(password) == 0 {
			return fail("password_missing")
		}
		d.passwords = append(d.passwords, string(password))
		if d.byName("", req.SamAccountName) != nil {
			return fail("ad_write_failed")
		}
		id = d.newID("user")
		o := &fakeObject{kind: "user", id: id, sam: req.SamAccountName, upn: req.UserPrincipalName, ou: req.OU, enabled: true, memberOf: map[string]bool{}}
		if req.DisplayName != nil {
			o.display = *req.DisplayName
		}
		if req.Mail != nil {
			o.mail = *req.Mail
		}
		if req.Enabled != nil {
			o.enabled = *req.Enabled
		}
		d.objects[id] = o
	case opSetUserEnabled:
		o, ok := d.objects[req.ID]
		if !ok || req.Enabled == nil {
			return fail("ad_write_failed")
		}
		o.enabled = *req.Enabled
		id = o.id
	case opSetUserAttributes:
		o, ok := d.objects[req.ID]
		if !ok {
			return fail("ad_write_failed")
		}
		if req.DisplayName != nil {
			o.display = *req.DisplayName
		}
		if req.Mail != nil {
			o.mail = *req.Mail
		}
		id = o.id
	case opCreateGroup:
		if d.byName("", req.SamAccountName) != nil {
			return fail("ad_write_failed")
		}
		id = d.newID("group")
		d.objects[id] = &fakeObject{kind: "group", id: id, sam: req.SamAccountName, ou: req.OU, scope: req.GroupScope, category: req.GroupCategory, memberOf: map[string]bool{}}
	case opAddGroupMember, opRemoveGroupMember:
		g, ok := d.objects[req.ID]
		member, ok2 := d.objects[req.MemberID]
		if !ok || !ok2 || g.kind != "group" {
			return fail("ad_write_failed")
		}
		if req.Operation == opAddGroupMember {
			member.memberOf[g.id] = true
		} else {
			delete(member.memberOf, g.id)
		}
		id = g.id
	default:
		return fail("invalid_operation")
	}
	return emitJSON(onLine, map[string]interface{}{"type": "done", "id": id})
}

// UseFakeDirectory makes every module New creates for the rest of the test
// run against d instead of PowerShell.
func UseFakeDirectory(t *testing.T, d *FakeDirectory) {
	t.Helper()
	prev := platformRunners
	platformRunners = func() (scriptRunner, scriptRunner) { return d.ReadRunner(), d.WriteRunner() }
	t.Cleanup(func() { platformRunners = prev })
}

// newTestBindingStore returns a binding store in dir that does not apply the
// admin-only directory check, which needs an elevated process on Windows.
func newTestBindingStore(dir string) BindingStore {
	return &fileBindingStore{dir: dir}
}

// NewTestModule returns a module running against d, with its bindings in
// stateDir (without the admin-only directory check) and the shared holder.
func NewTestModule(logger logging.Logger, d *FakeDirectory, stateDir string, holder *DeclaredSet) modules.Module {
	return newWithRunners(logger, d.ReadRunner(), d.WriteRunner(),
		WithBindingStore(newTestBindingStore(stateDir)), WithDeclaredSet(holder))
}

// BindingFileName is the name of the bindings file in the state directory.
const BindingFileName = bindingFileName
