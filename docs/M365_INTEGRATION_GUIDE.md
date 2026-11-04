# Microsoft 365 Integration

Connect an existing CFGMS client tenant to Microsoft 365 and understand which
operations the controller performs. Connections and observed inventory are not
proof of full onboarding/offboarding or licensing delivery; the
[roadmap](product/roadmap.md) owns those release requirements.

## Registration and permissions

Create an app registration in the client directory for direct access or the MSP
partner directory for the supported partner path. Grant consent in the required
directories and use only the permissions needed by the operations you enable:

- Read-only directory inventory: `User.Read.All`, `Group.Read.All` and
  `GroupMember.Read.All`, or `Directory.Read.All`.
- Declared user/group writes: the corresponding Graph user/group write
  permissions and consent. Validate them against the actual Graph methods used;
  a role label or portal registration alone does not establish effective access.
- Partner mode additionally needs an active, unexpired GDAP relationship granting
  the required roles. A relationship does not bypass Graph consent or token authority.

Do not create a plaintext `.env` file for application secrets. Supply them from
an approved secret store or an in-memory shell variable, pass through the CLI's
stdin interface below, and clear temporary variables afterward. The controller
stores the connection through its encrypted secret provider.

## Connecting Client Tenants

An M365 connection exists **only on an existing CFGMS client tenant**: a tenant whose parent is an MSP tenant (a direct child of the root tenant). The root tenant, an MSP tenant, a tenant that does not exist and a tenant below a client tenant (for example `root/msp-a/client-1/servers`) are refused before anything is written. No `cfg tenant m365` command creates a tenant, an account or a consent record, so create the client tenant first.

A client secret is never accepted as a flag value and is never echoed, logged or audited. Pass `--client-secret-stdin` and write the secret as one line on standard input. A command that asks for confirmation has no terminal left to ask on when the secret is piped, so it needs `--yes`. `--json` prints the API response data.

Connecting needs `tenant:manage` (`tenant:read` for `get`). A root-scoped operator needs an active crossing into the MSP first (see [Tenant Management](administration/tenant-management.md#tenant-crossings)).

### Direct mode: one client, its own app registration

1. In the **client's** Entra tenant, register an application, add the application permissions the modules need (see permissions below), grant admin consent in that tenant, and create a client secret.
2. Connect the client tenant:

   ```bash
   printf '%s\n' "$CLIENT_SECRET" | cfg tenant m365 set client-1 \
     --app-id <application-client-id> \
     --m365-tenant <client-directory-tenant-id> \
     --client-secret-stdin
   ```

   The stored connection holds the application ID, the directory tenant ID and the secret, and nothing else.
3. Check it (the secret is never printed):

   ```bash
   cfg tenant m365 get client-1
   ```

   `get` prints the mode, app ID, M365 tenant, partner tenant and GDAP roles for a partner connection, and `client secret: set`. A tenant without a connection reports that it has none.

A tenant that already has a connection is refused. Re-run `set` with `--replace` to overwrite it; the command prints what it will change and asks `Proceed? [y/N]`. With no terminal and no `--yes` it refuses and exits non-zero:

```bash
printf '%s\n' "$NEW_SECRET" | cfg tenant m365 set client-1 --app-id <id> --m365-tenant <directory-id> --client-secret-stdin --replace --yes
```

Remove a connection and its stored token with `cfg tenant m365 delete client-1` (also confirm-gated; `--yes` skips the prompt).

### Partner mode: many customers through GDAP

In the **MSP's** M365 tenant, register one partner application with Partner Center access and the application permissions the modules need, and create a client secret. Each customer must have an active GDAP relationship with the MSP.

1. List the MSP's active GDAP customers and see which are already linked:

   ```bash
   printf '%s\n' "$PARTNER_SECRET" | cfg tenant m365 gdap-customers msp-a \
     --partner-tenant <msp-m365-tenant-id> --app-id <partner-app-id> --client-secret-stdin
   ```

   The table has the columns `CUSTOMER TENANT`, `NAME`, `STATUS`, `EXPIRES` and `LINKED TO`. `LINKED TO` is the client tenant of that MSP whose stored connection names the customer, or `unlinked`. It is computed on demand and never stored. Nothing is written.
2. Link many customers to existing client tenants in one command:

   ```bash
   printf '%s\n' "$PARTNER_SECRET" | cfg tenant m365 gdap-link msp-a \
     --partner-tenant <msp-m365-tenant-id> --app-id <partner-app-id> --client-secret-stdin \
     --link <customer-1-m365-tenant>=client-1 \
     --link <customer-2-m365-tenant>=client-2 \
     --gdap-role "User Administrator" --yes
   ```

   The command prints the planned links and asks `Proceed? [y/N]` (`--yes` skips the prompt). Each linked client tenant gets a partner connection holding the partner tenant ID, the customer tenant ID, the required GDAP roles and the partner app's ID and secret.

The partner credentials are supplied on every `gdap-customers` and `gdap-link` call. They are copied only into the connections of the client tenants being linked and are never stored on the MSP tenant or under any other key.

`gdap-link` validates the whole request before it writes anything. If any check fails, nothing is written:

- every `--link` target must be a client tenant of `msp-a`;
- every customer must be in the partner's active GDAP list;
- no customer and no target may appear twice;
- no customer may already be linked to a different client tenant;
- a target that already has a connection is refused unless `--replace` is set.

A customer M365 tenant is linked to at most one client tenant under an MSP, and a client tenant holds at most one connection. Use `cfg tenant m365 get <client-tenant>` and `cfg tenant m365 delete <client-tenant>` to inspect or unlink.

Each write emits one audit event per affected client tenant (`m365.connection.set`, `m365.connection.delete`, `m365.gdap.link`) carrying the mode, the app ID and the M365 tenant IDs, never the secret.

### Using the connection from workflows

A connection made with `cfg tenant m365 set` or `cfg tenant m365 gdap-link` is used by the M365 workflow modules (`m365-entra-user`, `m365-entra-group`, `m365-entra-application`, `m365-entra-admin-unit`, `m365-conditional-access`, `m365-intune-policy`) with no other setup. When a workflow step runs one of them, the controller reads the client tenant's connection from its secret store, mints a short-lived Microsoft Graph access token and hands only that token to the module process. The client secret never leaves the controller. If the tenant has no connection, the step fails with an error that names the tenant and points back to `cfg tenant m365 set` or `cfg tenant m365 gdap-link`. A replaced or deleted connection takes effect on the next step. A step that outlives its token fails; start it again.

**Signature binding by build.** In a signed build (one carrying a real CFGMS publisher key), the controller issues the token only to a module bundle carrying a valid `cfgms` publisher signature, checked every time a token is issued; a bundle without one fails the step with an error naming the module and tenant. In unsigned OSS release builds (placeholder key) the token is issued on the bundle's manifest name and publisher alone, and the controller logs a warning at engine start that M365 module credentials are not signature-bound.

## Tenant Inventory

The controller reads every user and group of each CFGMS tenant that has an M365 connection on a schedule and records them in the entity graph under `m365:<entra-tenant-guid>/...`. Nothing is installed on a device and nothing is written to M365.

- **Schedule and freshness.** Each tenant is re-read every 60 minutes by default (`directory.m365_inventory_interval` in the controller config). Only changed objects are written; an unchanged tenant writes nothing, and a controller restart does not rewrite the inventory. In a cluster, one controller (the lease holder) does the reading.
- **What is recorded.** Per user: display name, user principal name, mail, enabled state, department, job title, office location and company name. Per group: display name, description, mail, and mail- and security-enabled flags. Each object carries `source: m365`, `managed` (false until declared configuration names it) and `member_of`: the object ids of its direct groups, at most 10,000, with `member_of_truncated` set when there are more. Group membership, including members that are devices, service principals or contacts, is logged as added and removed events.
- **Removals.** An object that no longer appears in a complete read is retracted.
- **Failures.** If Graph throttles the controller or rejects the connection's credentials, that tenant keeps its previous inventory, marked stale, with a short error; other tenants are unaffected and nothing is retracted.
- **Permissions.** The connection needs the Graph application permissions `User.Read.All`, `Group.Read.All` and `GroupMember.Read.All` (or `Directory.Read.All`).
- **One Entra tenant, one CFGMS tenant.** If two CFGMS tenants have connections to the same Entra tenant, that Entra tenant is collected for neither, and a security event naming both CFGMS tenants is written to the root administrators' audit stream. Remove the connection from one of them to resume collection. The tenant that first recorded an object remains its owner.

## Declaring Users and Groups

A tenant's `m365-entra-user` and `m365-entra-group` resources in its cfg are converged by the controller, not by a steward. They are removed from the cfg delivered to stewards, so no steward ever receives or runs them. Objects that are not declared are never written, and the controller never deletes anything.

```yaml
steward:
  drift_mode: monitor                 # report only; apply to correct
  module_drift_modes:
    m365-entra-user: apply            # a per-module mode wins over drift_mode
resources:
  - name: alice
    module: m365-entra-user
    config:
      user_principal_name: alice@example.com   # identifies the user
      display_name: Alice Example
      department: Finance
      adopt: true
  - name: finance-staff
    module: m365-entra-group
    config:
      display_name: Finance Staff              # identifies the group
      description: Finance department
      members_present: [alice@example.com]
      members_absent: [former@example.com]
```

- **Mode.** The mode is the same drift mode stewards use (`drift_mode`, overridden per module by `module_drift_modes`; unset means `apply`, an unknown value means `monitor`). In `monitor` the controller records a drift observation and never writes. In `apply` it writes the declared values and records the outcome. A workflow definition never sets the mode.
- **Managed attributes.** Only attributes the declaration names are compared and written. Users: `display_name`, `account_enabled`, `mail`, `mobile_phone`, `office_location`, `job_title`, `department`, `company_name`. Groups: `display_name`, `description`, `members_present`, `members_absent`. `groups`, licenses and passwords on a user are ignored.
- **Bind and adopt.** A declared resource is bound to the Entra object id of its user (matched by user principal name) or group (matched by exact display name). An object that exists but is not bound is left alone and reported unless the resource sets `adopt: true`; the controller then binds it. Once bound, the object is matched by id: if the user principal name or group name later resolves to a different object, the resource is refused and reported. Removing a resource from the cfg drops its binding.
- **Creation.** A declared group that does not exist is created in `apply` mode and bound. A declared user that does not exist is created in `apply` mode and bound; in `monitor` it is reported as absent.
- **One-time password.** Before creating a user the controller obtains a one-time password from its credential service, which stores it encrypted, and only then asks M365 to create the user with `force_change_password_next_signin` set, so the user must choose a new password at first sign-in. If the password cannot be stored, no user is created. The password is shown once and is never written to a log, error, audit record, outcome or configuration store, and is never part of a declaration. It is passed on create only: an update never sends a password. If M365 rejects the create outright (a 4xx and the user confirmed absent) the stored password is deleted; if the result is uncertain (timeout, 5xx, lost response) it is kept, because the user may exist with that password.
- **Enable and disable.** Declare `account_enabled: true` or `false`. Only that attribute changes. A created user is enabled unless the declaration says otherwise.
- **Group membership.** `members_present` adds the listed members (by user principal name) that are not yet in the group, and `members_absent` removes the listed members that are. Members named in neither list are never touched, and membership is never synchronised to an exact set. A user listed in both is refused.
- **Cadence.** The loop runs after each inventory pass, so its cadence is `directory.m365_inventory_interval` (60 minutes by default). A direct change made in M365 to a managed object is detected on the next pass: reported in `monitor`, reverted in `apply`. A revert can lag the change by up to one interval.
- **Reporting.** Each pass records the outcome of every declared resource (`converged`, `drift-reported`, `drift-reverted`, `created`, `absent`, `refused`, `error`) for the tenant. A failing resource is reported and skipped; the others continue. Drift is recorded as a drift-diff observation on the object's entity, carrying the cfg resource id. Inventory records of bound objects carry `managed: true`.
- **Audit.** Every write the controller makes to M365 is audited with the tenant, actor `controller`, the module as resource type, the cfg-declared resource name as resource id, the action (`update` or `create`) and the result.


## Verify coverage and recover failures

Inspect the connection with `cfg tenant m365 get`, inventory freshness/errors,
and the per-resource convergence outcome. A failing tenant must not cause another
tenant's inventory to be cleared. Recheck app consent, customer authority and
required GDAP roles on permission or relationship errors; do not fall back to
another customer's credentials.

For current code paths, workflow binary coverage and authentication mechanics,
use the [M365 implementation entry](../features/workflow/modules/m365/README.md).
For bounded live tests and credentials, use the
[M365 testing guide](../features/workflow/modules/m365/TESTING.md). The optional
[Partner Center sandbox setup](CSP_SANDBOX_SETUP_GUIDE.md) does not replace a live
Graph tenant or prove production readiness.
