# Active Directory Module (System Context)

**Kind:** steward

## Purpose and scope

The Active Directory module reads and manages a local Active Directory domain
from a Windows domain controller through the steward's system context. It needs
no stored credentials: the steward runs as SYSTEM on the domain controller,
which can read and write the directory.

The module reports every user and group of the domain, with direct group
membership, as per-object DNA. The inventory activates on exactly one domain
controller per domain: the holder of the PDC-emulator role.

It also manages the users and groups declared in the steward's configuration
(see [Declared users and groups](#declared-users-and-groups)). It never changes
an object that is not declared, and it never deletes.

## Activation

```yaml
observe_when:
  - fact: ad_pdc_emulator
    equals: "true"
```

`ad_pdc_emulator` is a baseline steward DNA fact. It is `"true"` only on the
domain controller that holds the PDC-emulator role, so one host per domain
reports the inventory. When the role holder cannot be resolved, no host reports
for that cycle and the previously reported inventory stays in place.

## Per-object inventory

The module owns two per-object kinds:

```yaml
owns:
  - kind: directory_user
    per_object: true
  - kind: directory_group
    per_object: true
```

`Get("directory_user")` and `Get("directory_group")` return the object list under
the reserved `__cfgms_objects` key. Each entry has an `id` (the objectGUID) and an
`attrs` map. The steward emits one DNA fragment per object, with fragment ID
`<kind>:<objectGUID>`. Both IDs are reserved: a declared resource named
`directory_user` or `directory_group` is rejected.

### User attributes

| Attribute | Description |
|-----------|-------------|
| `sam_account_name` | SAM account name |
| `user_principal_name` | User principal name |
| `display_name` | Display name |
| `mail` | Mail address |
| `enabled` | Whether the account is enabled |
| `distinguished_name` | Distinguished name |
| `object_sid` | Security identifier |
| `when_created` | Creation time, ISO-8601 UTC |
| `directory_domain` | DNS name of the domain |
| `managed` | `true` when the object is bound to a declared resource (by objectGUID), or matches the `sam_account_name` of a declared resource not yet bound; otherwise `false` |
| `member_of` | Sorted objectGUIDs of the user's direct groups |

### Group attributes

| Attribute | Description |
|-----------|-------------|
| `sam_account_name` | SAM account name |
| `display_name` | Display name |
| `distinguished_name` | Distinguished name |
| `group_scope` | `DomainLocal`, `Global` or `Universal` |
| `group_category` | `Security` or `Distribution` |
| `directory_domain` | DNS name of the domain |
| `managed` | `true` when the object is bound to a declared resource (by objectGUID), or matches the `sam_account_name` of a declared resource not yet bound; otherwise `false` |
| `member_of` | Sorted objectGUIDs of the groups this group is a direct member of |
| `other_members` | Direct members that are neither users nor groups, sorted by type then id, each `{type, id, name}`; `type` is `computer`, `contact`, `foreign_security_principal` or `other` |

These other members do not become inventory objects of their own.

### How membership is read

A group's own member list is never read. AD Web Services returns at most
`MaxGroupOrMemberEntries` values of a membership attribute per object (5,000 by
default), so reading a large group's members would silently drop some of them.
Membership comes from the `memberOf` back-link instead:

- A user's and a group's direct memberships are their own `member_of`. A large
  group's membership is therefore carried on its members' `member_of`, not on
  the group.
- `other_members` is built from one paged query per member class (computers,
  contacts and foreign security principals, then any other non-user, non-group
  object) for objects that are members of something; each such object is listed
  under every group in its `memberOf`.
- The same limit can cap a single object's `memberOf`. When a `memberOf` list
  reaches 5,000 values it may be incomplete, so the object's
  `member_of_truncated` is set. When a contributing object's `memberOf` reached
  the limit, the groups it lists get `other_members_truncated`. A possibly
  incomplete list is always flagged, never reported as complete.

### Bounds

- `member_of` and `other_members` hold at most 10,000 entries per object. A
  longer list keeps its first 10,000 entries in sorted order and sets
  `member_of_truncated: true` or `other_members_truncated: true`; the module logs
  the number of truncated objects, never names.
- One read holds at most 200,000 objects. A larger domain fails the read rather
  than reporting a partial inventory. One `Get` holds up to that many objects
  (about 1 KB each) in memory once.
- No volatile attributes (no last-changed or last-logon times) are reported, so
  an unchanged directory produces unchanged fragment hashes.

## Declared users and groups

Three resource types, declared only in the domain controller steward's own
device-level configuration:

```yaml
resources:
  - name: acme-domain
    module: activedirectory.domain
    config:
      domain: acme-corp.example
  - name: jdoe
    module: activedirectory.user
    config:
      sam_account_name: jdoe
      user_principal_name: jdoe@acme-corp.example
      display_name: J Doe
      mail: jdoe@acme-corp.example
      ou: OU=Staff,DC=acme-corp,DC=example
      enabled: true
  - name: finance
    module: activedirectory.group
    config:
      sam_account_name: finance
      ou: OU=Groups,DC=acme-corp,DC=example
      group_scope: Global          # DomainLocal, Global or Universal
      group_category: Security     # Security or Distribution
      members_present: [jdoe, finance-leads]
      members_absent: [former-staff]
```

| Type | Fields | `Set` does |
|------|--------|------------|
| `activedirectory.user` | `sam_account_name` (required), `user_principal_name`, `display_name`, `mail`, `ou`, `enabled` (default `true`), `adopt` (default `false`) | Creates the user, then keeps `display_name`, `mail` and `enabled` converged |
| `activedirectory.group` | `sam_account_name` (required), `ou`, `group_scope`, `group_category`, `members_present`, `members_absent`, `adopt` | Creates the group, then adds the `members_present` that are missing and removes the `members_absent` that are present |
| `activedirectory.domain` | `domain` | Only verifies the declared domain is the machine's domain |

### Binding and adoption

- When no object with the declared `sam_account_name` exists, `Set` creates it and
  binds the resource to the new object's objectGUID. Later cycles find the object
  by that objectGUID, not by name, so a rename outside CFGMS does not break the
  binding.
- The bindings are steward-side module state in
  `%ProgramData%\cfgms\steward\activedirectory\bindings.json` (admin-only
  directory, replaced atomically). They hold no secret, are never part of a
  configuration, and survive a steward restart.
- When an object with the declared name already exists and is not bound to the
  resource, `Set` fails and changes nothing, unless the resource sets
  `adopt: true`. With `adopt: true` it binds to that object and converges only
  `display_name`, `mail` and `enabled`.
- When the declared name later resolves to a different objectGUID than the bound
  one, or the bound object no longer exists, `Set` refuses and changes nothing.
- Names, the OU and the scope and category are set at creation only; the module
  never renames or moves an object.
- Membership is additive: only the listed members are added or removed. A member
  that is not listed is never touched. Users and groups are members alike. A
  membership that cannot be verified (the member's `memberOf` reached the AD Web
  Services cap) fails `Set` for that member.

### No delete

There is no delete operation. Removing a resource from the configuration leaves
its object in place; the inventory then reports it `managed: false`.

### New-user password

- Before creating a user, the module asks the controller for a one-time initial
  password through the steward's credential client. The user is created with
  "must change password at next logon".
- The password is held in memory only. It goes to the write script on stdin,
  after the request line, and the module clears its buffer after the run.
- `write.ps1` reads it one character at a time into a `SecureString`
  (`AppendChar`); no PowerShell string ever holds it, it is never a string
  argument to a cmdlet or function, and it is never written to output, error or a
  transcript, so PowerShell module logging cannot record it.
- If the controller cannot issue the password, no account is created and `Set`
  fails with an error that carries no secret.
- The password never appears in argv, script text, module state, logs, errors or
  DNA fragments.

### Validation

- `sam_account_name`, `user_principal_name`, `display_name`, `mail` and member
  names may contain only letters, digits, `.`, `_`, `@`, `-` and spaces, may not
  start with `-` or a space, and are length-bounded (a user's
  `sam_account_name` at most 20 characters).
- `ou` is a distinguished name of plain `OU`, `CN` and `DC` components and must be
  inside the machine's domain.
- A declared resource named `directory_user` or `directory_group` is rejected, so
  inventory IDs and declared IDs cannot be confused.
- In monitor drift mode `Set` never runs: a missing or drifted object is reported
  as drift and left alone.

### How the steward hands the declared set over

The executor's module instance and the observe sweep's instance are different
objects. The steward factory gives every activedirectory instance one shared
declared-set holder; before every full configuration pass the executor hands
the declared `activedirectory.*` resources to its instance through
`modules.DeclaredResourceAware.SetDeclared`, and the sweep's instance reads the
same holder to set `managed`.

## Fixed scripts

All PowerShell runs as:

```text
powershell.exe -NoProfile -NonInteractive -File <staged script>
```

- Two scripts are embedded in the steward binary: `scripts/read.ps1` (inventory
  and the lookup of one declared object) and `scripts/write.ps1` (one write per
  run). Nothing is composed at runtime: there is no inline command string, no
  encoded command and no string formatting of PowerShell.
- The scripts are staged in `%ProgramData%\cfgms\activedirectory-scripts`, which
  is secured to SYSTEM and Administrators before every stage. A script's SHA-256
  is compared with its embedded constant before every run, and a mismatch refuses
  to run.
- The operation and its parameters go in as one JSON document on stdin. The
  scripts validate them and use them only as typed cmdlet parameters or as
  variables an ActiveDirectory `-Filter` refers to by name; nothing user-derived
  reaches argv or script text. The write script validates its whole request, and
  reads a new user's password, before it loads the ActiveDirectory module.
- The scripts write one JSON object per line. On failure they write a fixed error
  code and never echo request values. A read error carries at most a bounded
  stderr tail with every request value removed; a write error carries no stderr
  at all.
- Reads page through the directory (default page size 1000).
- The execution policy is not changed. Hosts that enforce `AllSigned` need the
  scripts Authenticode-signed, which is a release-signing concern.

## Configuration options

```yaml
operation_type: read
object_types:
  - user
  - group
```

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `operation_type` | string | Yes | "read" | Type of operations |
| `object_types` | array | Yes | - | AD object types |
| `search_base` | string | No | Auto-detected | Search base DN |
| `page_size` | integer | No | 1000 | Directory paging size (1-5000) |
| `request_timeout` | duration | No | 30s | Timeout for reads |
| `enable_dna_collection` | boolean | No | true | Enable directory inventory |

## Supported operations

| Resource ID | Description |
|-------------|-------------|
| `status` | Domain, domain controller and forest summary, plus module counters |
| `directory_user` | Per-object user inventory |
| `directory_group` | Per-object group inventory |
| `user:<name>`, `group:<name>`, `domain:<name>` | A declared `activedirectory.user`, `.group` or `.domain` resource |

Write operations, as listed in `module.yaml`: `create_user`, `set_user_enabled`,
`set_user_attributes` (`display_name`, `mail`), `create_group`,
`add_group_member`, `remove_group_member`. Each writes exactly one object bound
to a declared resource.

## Security considerations

- **No stored credentials**: the module relies on the steward's SYSTEM context.
  A new user's password is issued by the controller per account and held in
  memory only.
- **Required permissions**: "Log on as a service" and the local system account
  context. SYSTEM on a domain controller needs no further rights.
- **Behavioral envelope**: the module shells out only to `powershell.exe`, and
  reads and writes only its script directory and its bindings directory.

## Requirements

- Windows Server domain controller with the Active Directory PowerShell module
- Steward running as a service under SYSTEM

## Development and testing

Unit tests drive the module through a test implementation of the script runner
that serves canned and generated script output:

```bash
go test -v ./features/modules/extended/activedirectory/...
```

The declared-resource tests run against an in-memory directory behind the same
request documents the scripts accept; `steward_wiring_test.go` runs them
through the real executor, module factory and steward credential client. The
runner tests (fixed argv, no request values in errors, script integrity, the
real `powershell.exe` refusing hostile requests without echoing a password) run
on Windows. The staging test needs an elevated administrator. The integration
tests under `tests/` need a domain controller and skip elsewhere.

## Troubleshooting

**`read script reported ad_module_unavailable`**
- The Active Directory PowerShell module is not installed:
  `Get-Module -ListAvailable ActiveDirectory`

**`secure script directory`**
- The steward could not secure `%ProgramData%\cfgms\activedirectory-scripts`;
  it must run as SYSTEM or an elevated administrator.

**`staged read script does not match the embedded script`** (or `write script`)
- The staged script was changed after staging. The module refuses to run it and
  leaves the file in place for investigation.

**`an object named "<name>" already exists and is not managed by "<resource>"`**
- Set `adopt: true` on the resource to manage the existing object, or choose
  another name.

**`now names a different object than the one bound`** / **`no longer exists`**
- The bound object was renamed and replaced, or deleted, outside CFGMS. Nothing
  is changed until an administrator resolves it.

**`the controller did not issue an initial password; no account was created`**
- The controller was unreachable or refused the request; the next convergence
  run tries again.

## Known limitations

- Windows domain controllers only.
- Users and groups only; computers, OUs and GPOs are neither inventoried nor
  managed.
- No delete and no password reset.
- The steward records bindings locally only; the controller's credential service
  is not told that an account now exists.
- Group membership is direct membership; nested membership is not expanded.
- `member_of` lists only groups of the domain being read; membership in a group
  of another domain is not listed.
