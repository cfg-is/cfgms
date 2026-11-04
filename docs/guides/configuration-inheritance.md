# Configuration Inheritance

Use this guide to explain why a steward received a resource or setting and to
change the correct source document. The current resolver is
[`pkg/config/inheritance.go`](../../pkg/config/inheritance.go); field definitions
belong in the [configuration schema](../reference/config-schema.md).

## Resolution order

The controller resolves the steward's tenant ancestry from root to leaf, then
applies matching cluster and role configuration, and finally device overrides:

1. Tenant root (depth 0): MSP policies.
2. Depth 1: client policies.
3. Every tenant at depth 2 **and deeper**: group-policy layer, in ancestry order.
4. Matching cluster policies, using the steward's own tenant and sorted cluster names.
5. Matching role fragments selected from DNA and tags, in alphabetical role-name order.
6. Device-specific configuration, last.

Deeper tenants are not skipped. The numeric group level is reused at each deeper
tenant; it is not a depth limit. Matching a DNA/tag role is also distinct from
being a descendant tenant in the hierarchy.

The tenant-policy naming rule is shared by readers and writers:

| Tenant depth | Namespace | Config name |
|---|---|---|
| 0 | `msp-policies` | `global` |
| 1 | `client-policies` | tenant leaf name |
| 2 or deeper | `group-policies` | `<tenant-leaf>-groups` |

Use the supported controller configuration interface to store documents at the
intended scope. A similarly named document in another namespace does not
participate in this cascade.

## Merge behavior

Resources are keyed by their exact `name`. A later resource with the same name
**replaces the entire earlier resource**, rather than merging nested config
fields. The replacement retains the original resource's position in the list;
new resource names append in declaration order. This preserves dependency order.

For matching roles, later alphabetical names win a resource-name conflict.
Changing a resource name creates another resource; it does not override the old
one. Do not interpret this rule as arbitrary alphabetical precedence for every
policy or setting: non-resource settings have their own merge rules.

Some security controls can only tighten down the cascade. In particular, a child
cannot weaken an inherited script-signing requirement from `required` to
`optional` or `none`. See the schema and
[`MergeScriptSigningConfig`](../../features/config/stewardtypes/validation.go).

## Example: override a complete file resource

An ancestor document can declare:

```yaml
resources:
  - name: application-settings
    module: file
    config:
      allowed_base_path: /etc/cfgms
      path: /etc/cfgms/application.conf
      state: present
      content: "log_level=info\n"
```

A descendant overrides it by repeating the complete desired resource, including
required path restrictions:

```yaml
resources:
  - name: application-settings
    module: file
    config:
      allowed_base_path: /etc/cfgms
      path: /etc/cfgms/application.conf
      state: present
      content: "log_level=debug\n"
```

These are desired-state document fragments, not controller or steward boot
config. The [file reference](../modules/file.md) owns file field semantics.

## Diagnose an unexpected result

1. Inspect authenticated `GET /api/v1/stewards/{id}/config/effective` with an
   operator authorized to read that steward's configuration. It resolves using
   the steward's tenant; a device label is not a permission grant.
2. Inspect the effective config and `sources`. Resource provenance uses keys
   such as `resource.application-settings`, recording tenant, document and version.
3. Compare the exact resource names and complete replacement blocks across the
   contributing tenant, cluster, role and device layers.
4. Confirm the source document was stored at the correct tenant and namespace,
   and that the steward's current DNA/tags and cluster membership match the intended rules.
5. Check resolution errors and controller logs. Missing documents, failed reads
   and invalid configuration are not interchangeable; do not assume an absent
   layer means the controller silently ignored it.
6. After correcting the intended source, inspect the effective config again and
   verify delivery and convergence on the steward. A resolved document alone
   does not establish successful endpoint application.

If desired state is wrong, change the policy through its review/approval path.
If desired state is right but enforcement failed, investigate restoring compliance
without changing that policy. The [product vision](../product/vision.md) describes
this operator distinction; it does not replace current authorization contracts.
