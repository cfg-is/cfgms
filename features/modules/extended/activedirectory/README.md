# Active Directory Module (System Context)

**Kind:** steward

## Purpose and scope

The Active Directory module reads a local Active Directory domain from a Windows
domain controller through the steward's system context. It needs no stored
credentials: the steward runs as SYSTEM on the domain controller, which can read
the directory.

The module reports every user and group of the domain, with direct group
membership, as per-object DNA. It activates on exactly one domain controller per
domain: the holder of the PDC-emulator role.

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
| `managed` | Whether CFGMS manages the object (always `false` for now) |
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
| `managed` | Whether CFGMS manages the object (always `false` for now) |
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

## Fixed read script

All PowerShell runs as:

```text
powershell.exe -NoProfile -NonInteractive -File <staged read script>
```

- The read script (`scripts/read.ps1`) is embedded in the steward binary. Nothing
  is composed at runtime: there is no inline command string, no encoded command
  and no string formatting of PowerShell.
- The script is staged in `%ProgramData%\cfgms\activedirectory-scripts`, which is
  secured to SYSTEM and Administrators before every stage. Its SHA-256 is compared
  with the embedded constant before every run, and a mismatch refuses to run.
- The operation and its parameters (operation, page size, domain) go in as one
  JSON document on stdin. The script validates them and uses them only as typed
  cmdlet parameters; nothing user-derived reaches argv or script text.
- The script writes one JSON object per line. On failure it writes a fixed error
  code and never echoes request values. The module's errors carry at most a
  bounded stderr tail with every request value removed.
- Reads page through the directory (default page size 1000).
- The execution policy is not changed. Hosts that enforce `AllSigned` need the
  script Authenticode-signed, which is a release-signing concern.

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

No write operations are implemented.

## Security considerations

- **No stored credentials**: the module relies on the steward's SYSTEM context.
- **Required permissions**: "Log on as a service" and the local system account
  context. SYSTEM on a domain controller needs no further rights to read the
  directory.
- **Behavioral envelope**: the module shells out only to `powershell.exe`, and
  reads and writes only its script directory.

## Requirements

- Windows Server domain controller with the Active Directory PowerShell module
- Steward running as a service under SYSTEM

## Development and testing

Unit tests drive the module through a test implementation of the script runner
that serves canned and generated script output:

```bash
go test -v ./features/modules/extended/activedirectory/...
```

The runner tests (fixed argv, no request values in errors, script integrity)
run on Windows. The staging test needs an elevated administrator. The
integration tests under `tests/` need a domain controller and skip elsewhere.

## Troubleshooting

**`read script reported ad_module_unavailable`**
- The Active Directory PowerShell module is not installed:
  `Get-Module -ListAvailable ActiveDirectory`

**`secure script directory`**
- The steward could not secure `%ProgramData%\cfgms\activedirectory-scripts`;
  it must run as SYSTEM or an elevated administrator.

**`staged read script does not match the embedded script`**
- The staged script was changed after staging. The module refuses to run it and
  leaves the file in place for investigation.

## Known limitations

- Windows domain controllers only.
- Users and groups only; computers, OUs and GPOs are not inventoried.
- Group membership is direct membership; nested membership is not expanded.
- `member_of` lists only groups of the domain being read; membership in a group
  of another domain is not listed.
