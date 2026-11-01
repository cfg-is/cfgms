# Complexity Gate Calibration

Measured replay of gate [rule 3](complexity-gate.md#gate-rules) over the last 30 merged develop PRs, produced by `make complexity-replay` before the gate is enabled. Every number below is copied from that run's output.

## Method

- Window: `git log --first-parent --max-count=30` on `origin/develop`.
- For each commit C with parent P, P and C are materialised with `MaterializeRef` and analysed with `analyzer.Analyze`; the touched set is `git diff --name-only P C`. Rule 3 runs through `gate.Evaluate` with P as previous and C as current, the same path `check` uses. Rules 1 and 2 are evaluated against P as previous and listed in the run output, but are not the headline.
- The partition check is not applied (old trees predate the seven-segment manifest).
- Unmeasurable commits (analysis error) would be reported with a reason and not counted as pass.

## Result

| Item | Value |
|------|-------|
| develop SHA | `5205f1048a5964f7d67c8112615c353c80749360` |
| Window | 30 first-parent commits, `#5700` back to `#5629` |
| PRs replayed | 30 |
| PRs rule 3 would have failed | 17 |
| PRs rule 3 passes | 13 |
| Unmeasurable | 0 |
| Total rule 3 findings | 86 |
| Findings that are new functions (base CC 0) | 51 |
| Findings with unchanged CC (other metrics changed) | 9 |

Rule 3 would have failed 17 of 30 PRs (57%).

## Per-PR outcome

| Commit | PR | Files | Functions changed | Rule 3 findings | Outcome |
|--------|----|-------|-------------------|-----------------|---------|
| `5205f1048a` | #5700 | 13 | 0 | 0 | pass |
| `d7121927c6` | #5697 | 13 | 44 | 7 | fires |
| `8f45bfd039` | #5698 | 26 | 60 | 8 | fires |
| `5f9c9247f2` | #5699 | 13 | 0 | 0 | pass |
| `416b254c19` | #5696 | 6 | 30 | 3 | fires |
| `1f5032fab6` | #5693 | 11 | 38 | 8 | fires |
| `4cd8a915d6` | #5695 | 10 | 0 | 0 | pass |
| `b1e747300d` | #5694 | 14 | 52 | 8 | fires |
| `1c6abc068b` | #5692 | 12 | 43 | 11 | fires |
| `7d4109e908` | #5691 | 5 | 16 | 1 | fires |
| `ad84d761b3` | #5690 | 14 | 0 | 0 | pass |
| `6f852ab38a` | #5688 | 12 | 19 | 2 | fires |
| `cfd7737387` | #5684 | 8 | 20 | 1 | fires |
| `f296ff9b9b` | #5687 | 5 | 4 | 2 | fires |
| `b6fc1c4cb4` | #5683 | 9 | 68 | 11 | fires |
| `06fac0c634` | #5685 | 10 | 0 | 0 | pass |
| `f11d0301cf` | #5638 | 11 | 39 | 2 | fires |
| `96e37fd217` | #5648 | 16 | 6 | 2 | fires |
| `f3d0b67504` | #5599 | 32 | 75 | 16 | fires |
| `d257f2b6dd` | #5641 | 5 | 0 | 0 | pass |
| `e8c52df3ea` | #5624 | 7 | 1 | 0 | pass |
| `40e50bd209` | #5643 | 5 | 2 | 1 | fires |
| `02d71ee293` | #5645 | 2 | 1 | 0 | pass |
| `1803e49287` | #5636 | 4 | 6 | 0 | pass |
| `7a840e8ceb` | #5640 | 5 | 2 | 0 | pass |
| `c3ad2dd37f` | #5637 | 3 | 2 | 1 | fires |
| `af66c13771` | #5634 | 7 | 7 | 2 | fires |
| `38f7630a29` | #5631 | 2 | 4 | 0 | pass |
| `a32defe34d` | #5632 | 3 | 4 | 0 | pass |
| `eeffdbd283` | #5629 | 3 | 0 | 0 | pass |

## Functions that fired more than once

| Count | Identity |
|-------|----------|
| 4 | `features/controller/server/server.go::.New#0` |
| 3 | `features/controller/server/server.go::Server.Start#0` |
| 2 | `features/controller/server/server.go::Server.Stop#0` |
| 2 | `pkg/entitygraph/providers/database/entity_reads.go::DatabaseEntityGraphProvider.QueryEntities#0` |
| 2 | `pkg/entitygraph/providers/sqlite/entity_reads.go::SQLiteEntityGraphProvider.QueryEntities#0` |

The full per-finding list is reproduced below.
## All rule 3 findings

```text
  d7121927c6 features/controller/directory/m365_converge.go:274: rule 3: features/controller/directory/m365_converge.go::M365Converge.Converge#0 CC 0 -> 16
  d7121927c6 features/controller/directory/m365_converge.go:392: rule 3: features/controller/directory/m365_converge.go::converge.resource#0 CC 0 -> 15
  d7121927c6 features/controller/directory/m365_converge.go:456: rule 3: features/controller/directory/m365_converge.go::converge.lookup#0 CC 0 -> 12
  d7121927c6 features/controller/directory/m365_converge.go:727: rule 3: features/controller/directory/m365_converge.go::.newResourceSpec#0 CC 0 -> 18
  d7121927c6 features/controller/directory/m365_converge.go:852: rule 3: features/controller/directory/m365_converge.go::resourceSpec.state#0 CC 0 -> 18
  d7121927c6 features/controller/server/server.go:506: rule 3: features/controller/server/server.go::.New#0 CC 222 -> 224
  d7121927c6 features/controller/service/config_service_v2.go:440: rule 3: features/controller/service/config_service_v2.go::ConfigurationServiceV2.GetConfiguration#0 CC 11 -> 11
  8f45bfd039 features/controller/credentials/service.go:114: rule 3: features/controller/credentials/service.go::Service.Issue#0 CC 0 -> 22
  8f45bfd039 features/controller/credentials/service.go:212: rule 3: features/controller/credentials/service.go::Service.Sweep#0 CC 0 -> 16
  8f45bfd039 features/controller/credentials/store.go:266: rule 3: features/controller/credentials/store.go::store.Put#0 CC 0 -> 18
  8f45bfd039 features/controller/server/server.go:506: rule 3: features/controller/server/server.go::.New#0 CC 216 -> 222
  8f45bfd039 features/controller/server/server.go:2854: rule 3: features/controller/server/server.go::Server.Start#0 CC 65 -> 70
  8f45bfd039 features/controller/server/server.go:3317: rule 3: features/controller/server/server.go::Server.Stop#0 CC 78 -> 80
  8f45bfd039 features/controller/transport/credential_handler.go:87: rule 3: features/controller/transport/credential_handler.go::CredentialHandler.HandleGRPC#0 CC 0 -> 19
  8f45bfd039 features/steward/client/client_transport.go:851: rule 3: features/steward/client/client_transport.go::TransportClient.InitializeConfigExecutor#0 CC 12 -> 13
  416b254c19 cmd/cfg/cmd/directory.go:117: rule 3: cmd/cfg/cmd/directory.go::directoryListFlags.validate#0 CC 0 -> 11
  416b254c19 cmd/cfg/cmd/directory.go:268: rule 3: cmd/cfg/cmd/directory.go::.directoryFetch#0 CC 0 -> 16
  416b254c19 cmd/cfg/cmd/directory_group_changes.go:48: rule 3: cmd/cfg/cmd/directory_group_changes.go::.runDirectoryGroupChanges#0 CC 0 -> 12
  1f5032fab6 features/controller/api/handlers_directory.go:107: rule 3: features/controller/api/handlers_directory.go::.validDirectoryObjectID#0 CC 0 -> 13
  1f5032fab6 features/controller/api/handlers_directory.go:123: rule 3: features/controller/api/handlers_directory.go::.validDirectoryAuthority#0 CC 0 -> 13
  1f5032fab6 features/controller/api/handlers_directory.go:231: rule 3: features/controller/api/handlers_directory.go::.decodeDirectoryCursor#0 CC 0 -> 12
  1f5032fab6 features/controller/api/handlers_directory.go:363: rule 3: features/controller/api/handlers_directory.go::Server.listDirectory#0 CC 0 -> 33
  1f5032fab6 features/controller/api/handlers_directory.go:503: rule 3: features/controller/api/handlers_directory.go::Server.findDirectoryEID#0 CC 0 -> 12
  1f5032fab6 features/controller/api/handlers_directory.go:548: rule 3: features/controller/api/handlers_directory.go::Server.loadDirectoryObject#0 CC 0 -> 13
  1f5032fab6 features/controller/api/handlers_directory.go:770: rule 3: features/controller/api/handlers_directory.go::Server.handleListDirectoryMembershipChanges#0 CC 0 -> 23
  1f5032fab6 features/controller/api/validation_middleware.go:181: rule 3: features/controller/api/validation_middleware.go::Server.validateQueryParameters#0 CC 19 -> 20
  b1e747300d features/controller/directory/m365_inventory.go:159: rule 3: features/controller/directory/m365_inventory.go::.NewM365Inventory#0 CC 0 -> 18
  b1e747300d features/controller/directory/m365_inventory.go:381: rule 3: features/controller/directory/m365_inventory.go::.normalizeEntraGUID#0 CC 0 -> 12
  b1e747300d features/controller/directory/m365_inventory.go:493: rule 3: features/controller/directory/m365_inventory.go::M365Inventory.saveManifest#0 CC 0 -> 11
  b1e747300d features/controller/directory/m365_inventory.go:564: rule 3: features/controller/directory/m365_inventory.go::M365Inventory.collectTenant#0 CC 0 -> 16
  b1e747300d features/controller/directory/m365_inventory.go:667: rule 3: features/controller/directory/m365_inventory.go::inventoryRun.applyMemberships#0 CC 0 -> 14
  b1e747300d features/controller/server/server.go:498: rule 3: features/controller/server/server.go::.New#0 CC 213 -> 216
  b1e747300d features/controller/server/server.go:2820: rule 3: features/controller/server/server.go::Server.Start#0 CC 64 -> 65
  b1e747300d features/controller/server/server.go:3255: rule 3: features/controller/server/server.go::Server.Stop#0 CC 77 -> 78
  1c6abc068b features/controller/heartbeat/service.go:266: rule 3: features/controller/heartbeat/service.go::Service.handleHeartbeatFromProvider#0 CC 16 -> 18
  1c6abc068b features/controller/server/server.go:2793: rule 3: features/controller/server/server.go::Server.Start#0 CC 64 -> 64
  1c6abc068b features/controller/transport/dna_bulk_round.go:184: rule 3: features/controller/transport/dna_bulk_round.go::DNAHandler.HandleHeartbeatBulkRoot#0 CC 0 -> 15
  1c6abc068b features/controller/transport/dna_bulk_round.go:398: rule 3: features/controller/transport/dna_bulk_round.go::DNAHandler.handleBulkRoots#0 CC 0 -> 12
  1c6abc068b features/controller/transport/dna_bulk_round.go:470: rule 3: features/controller/transport/dna_bulk_round.go::DNAHandler.handleBulkManifest#0 CC 0 -> 22
  1c6abc068b features/controller/transport/dna_bulk_round.go:610: rule 3: features/controller/transport/dna_bulk_round.go::DNAHandler.handleBulkFragments#0 CC 0 -> 14
  1c6abc068b features/controller/transport/dna_bulk_round.go:660: rule 3: features/controller/transport/dna_bulk_round.go::DNAHandler.finishBulkRound#0 CC 0 -> 13
  1c6abc068b features/controller/transport/dna_bulk_round.go:726: rule 3: features/controller/transport/dna_bulk_round.go::DNAHandler.applyBulkToSink#0 CC 0 -> 17
  1c6abc068b features/controller/transport/dna_handler.go:271: rule 3: features/controller/transport/dna_handler.go::DNAHandler.HandleHeartbeatRoot#0 CC 11 -> 12
  1c6abc068b features/controller/transport/dna_handler.go:442: rule 3: features/controller/transport/dna_handler.go::DNAHandler.HandleGRPC#0 CC 25 -> 29
  1c6abc068b features/controller/transport/dna_handler.go:599: rule 3: features/controller/transport/dna_handler.go::DNAHandler.handleDeltaGRPC#0 CC 23 -> 26
  7d4109e908 cmd/cfg/cmd/report.go:462: rule 3: cmd/cfg/cmd/report.go::.runReportCustomPage#0 CC 0 -> 13
  6f852ab38a features/controller/server/server.go:464: rule 3: features/controller/server/server.go::.New#0 CC 213 -> 213
  6f852ab38a features/controller/server/server.go:2620: rule 3: features/controller/server/server.go::.reportShareScope#0 CC 0 -> 11
  cfd7737387 pkg/logging/subscribers/systemlog/subscriber.go:133: rule 3: pkg/logging/subscribers/systemlog/subscriber.go::.parseConfig#0 CC 0 -> 20
  f296ff9b9b pkg/entitygraph/providers/database/entity_reads.go:195: rule 3: pkg/entitygraph/providers/database/entity_reads.go::DatabaseEntityGraphProvider.QueryEntities#0 CC 19 -> 22
  f296ff9b9b pkg/entitygraph/providers/sqlite/entity_reads.go:114: rule 3: pkg/entitygraph/providers/sqlite/entity_reads.go::SQLiteEntityGraphProvider.QueryEntities#0 CC 15 -> 18
  b6fc1c4cb4 features/controller/directory/membership_log.go:201: rule 3: features/controller/directory/membership_log.go::Membership.ListChanges#0 CC 0 -> 13
  b6fc1c4cb4 features/controller/directory/membership_log.go:281: rule 3: features/controller/directory/membership_log.go::Membership.SweepRetention#0 CC 0 -> 16
  b6fc1c4cb4 features/controller/directory/membership_sink.go:240: rule 3: features/controller/directory/membership_sink.go::.validObjectID#0 CC 0 -> 13
  b6fc1c4cb4 features/controller/directory/membership_sink.go:516: rule 3: features/controller/directory/membership_sink.go::Membership.applyPatches#0 CC 0 -> 24
  b6fc1c4cb4 features/controller/directory/membership_sink.go:591: rule 3: features/controller/directory/membership_sink.go::.parseMemberOf#0 CC 0 -> 11
  b6fc1c4cb4 features/controller/directory/membership_sink.go:626: rule 3: features/controller/directory/membership_sink.go::.parseOtherMembers#0 CC 0 -> 14
  b6fc1c4cb4 features/controller/directory/membership_sink.go:679: rule 3: features/controller/directory/membership_sink.go::Membership.ApplyBatch#0 CC 0 -> 19
  b6fc1c4cb4 features/controller/directory/membership_sink.go:760: rule 3: features/controller/directory/membership_sink.go::Membership.applyUpserts#0 CC 0 -> 20
  b6fc1c4cb4 features/controller/directory/membership_sink.go:858: rule 3: features/controller/directory/membership_sink.go::Membership.applyRemovals#0 CC 0 -> 11
  b6fc1c4cb4 features/controller/directory/membership_sink.go:949: rule 3: features/controller/directory/membership_sink.go::Membership.ApplyGroup#0 CC 0 -> 21
  b6fc1c4cb4 features/controller/directory/membership_store.go:287: rule 3: features/controller/directory/membership_store.go::Membership.ListMembers#0 CC 0 -> 12
  f11d0301cf features/modules/extended/activedirectory/module.go:359: rule 3: features/modules/extended/activedirectory/module.go::activeDirectoryModule.Set#0 CC 12 -> 13
  f11d0301cf features/modules/extended/activedirectory/module.go:545: rule 3: features/modules/extended/activedirectory/module.go::activeDirectoryModule.getInventory#0 CC 0 -> 12
  96e37fd217 features/modules/hyperv/vm_provision.go:388: rule 3: features/modules/hyperv/vm_provision.go::hypervModule.provisionVM#0 CC 32 -> 32
  96e37fd217 features/modules/hyperv/vm_provision.go:679: rule 3: features/modules/hyperv/vm_provision.go::hypervModule.provisionCloudInit#0 CC 11 -> 11
  f3d0b67504 features/controller/api/handlers_roles.go:102: rule 3: features/controller/api/handlers_roles.go::Server.handleCreateRoleConfig#0 CC 12 -> 14
  f3d0b67504 features/controller/server/directory_authority.go:68: rule 3: features/controller/server/directory_authority.go::directoryAuthority.IsDirectoryAuthority#0 CC 0 -> 15
  f3d0b67504 features/controller/service/config_service_v2.go:851: rule 3: features/controller/service/config_service_v2.go::ConfigurationServiceV2.BatchSetConfigurations#0 CC 5 -> 11
  f3d0b67504 features/controller/service/directory_config.go:77: rule 3: features/controller/service/directory_config.go::.CheckDirectoryDeclarations#0 CC 0 -> 11
  f3d0b67504 features/controller/service/directory_registry.go:115: rule 3: features/controller/service/directory_registry.go::DirectoryDomainRegistry.Claim#0 CC 0 -> 12
  f3d0b67504 pkg/entitygraph/providers/database/entity_reads.go:195: rule 3: pkg/entitygraph/providers/database/entity_reads.go::DatabaseEntityGraphProvider.QueryEntities#0 CC 18 -> 19
  f3d0b67504 pkg/entitygraph/providers/database/observations.go:107: rule 3: pkg/entitygraph/providers/database/observations.go::DatabaseEntityGraphProvider.ReportObservations#0 CC 26 -> 31
  f3d0b67504 pkg/entitygraph/providers/sqlite/entity_reads.go:114: rule 3: pkg/entitygraph/providers/sqlite/entity_reads.go::SQLiteEntityGraphProvider.QueryEntities#0 CC 14 -> 15
  f3d0b67504 pkg/entitygraph/providers/sqlite/observations.go:105: rule 3: pkg/entitygraph/providers/sqlite/observations.go::SQLiteEntityGraphProvider.ReportObservations#0 CC 22 -> 27
  f3d0b67504 pkg/entitygraph/types/directory.go:45: rule 3: pkg/entitygraph/types/directory.go::.NormalizeDirectoryDomain#0 CC 0 -> 16
  f3d0b67504 pkg/entitygraph/writers/dnasync/directory_release.go:33: rule 3: pkg/entitygraph/writers/dnasync/directory_release.go::.RetractDirectoryDomain#0 CC 0 -> 20
  f3d0b67504 pkg/entitygraph/writers/dnasync/driftdiff.go:80: rule 3: pkg/entitygraph/writers/dnasync/driftdiff.go::Writer.WriteDriftDiffs#0 CC 11 -> 12
  f3d0b67504 pkg/entitygraph/writers/dnasync/edges.go:128: rule 3: pkg/entitygraph/writers/dnasync/edges.go::.decodeEdgeDeclarations#0 CC 18 -> 18
  f3d0b67504 pkg/entitygraph/writers/dnasync/resolve.go:199: rule 3: pkg/entitygraph/writers/dnasync/resolve.go::.ResolveSubjectEID#0 CC 11 -> 13
  f3d0b67504 pkg/entitygraph/writers/dnasync/resolve.go:277: rule 3: pkg/entitygraph/writers/dnasync/resolve.go::.resolveDirectoryEID#0 CC 0 -> 11
  f3d0b67504 pkg/entitygraph/writers/dnasync/writer.go:200: rule 3: pkg/entitygraph/writers/dnasync/writer.go::Writer.writeFragments#0 CC 25 -> 29
  40e50bd209 features/workflow/modules/m365/entra_user/module.go:79: rule 3: features/workflow/modules/m365/entra_user/module.go::EntraUserConfig.AsMap#0 CC 12 -> 12
  c3ad2dd37f features/workflow/modules/m365/entra_user/module.go:223: rule 3: features/workflow/modules/m365/entra_user/module.go::entraUserModule.Set#0 CC 29 -> 32
  af66c13771 features/modules/stdlib/script/executor.go:322: rule 3: features/modules/stdlib/script/executor.go::Executor.buildWindowsCommand#0 CC 11 -> 11
  af66c13771 features/modules/stdlib/script/executor.go:377: rule 3: features/modules/stdlib/script/executor.go::Executor.buildUnixCommand#0 CC 15 -> 15
```

## Observations

- Rule 3 fires on a function that was only touched, not made worse: for 9 of the 86 findings the CC is unchanged (for example `server.go::.New#0` `CC 213 -> 213`), because rule 3 compares all metrics and a Halstead-only change counts as "different". Rule 3 logic is out of scope for this story and was not modified; this is flagged here for the gate-enablement decision.
- 51 findings are new functions above the CC threshold; these are the cases rule 3 is designed to catch.
- A small number of large functions (`server.go::.New#0`, `Server.Start#0`, `Server.Stop#0`) fire on repeated PRs because any edit to them counts.
