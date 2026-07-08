# DNA Collection Audit

**Epic:** [#1932](https://github.com/cfgis/cfgms/issues/1932) — DNA collection audit: documented attributes vs implemented attributes

> **Status — legacy collector.** This document audits the **flat-map `Collector`** ([`features/steward/dna/dna.go`](../../features/steward/dna/dna.go)) that [ADR-016](decisions/016-steward-module-foundation.md) and [ADR-017](decisions/017-dna-composition-and-sync.md) **retire**. The target model is a **fragment set** — managed fragments from module `Get` plus observe-only `host:*` facts from an osquery allowlist — each with a typed entity id, a provenance envelope (`source`, `observed_at`, `confidence`, outside the hash), and controller-side versioned history (ADR-017 Amendment A1.3). Ephemeral values (process snapshots, live utilisation) are **telemetry, not DNA** (ADR-017 clause 4). Read this as the coverage/gap baseline the fragment migration inherits, **not** as the go-forward design.

This document cross-references every documented DNA category from `steward-operating-model.md` against the attribute keys that the collectors actually emit. It is the authoritative source for platform coverage, sensitivity classification, and gap tracking **of the legacy collector**.

## Legend

**Collection path:**
- **Fast** — returned synchronously on every `Collect()` call; safe to read immediately
- **Background** — collected asynchronously; merged into result when the background goroutine closes `bgDone`

**Platform status:**
- `GREEN` — collector emits a real, meaningful value
- `YELLOW` — partial value (count-only, best-effort, or tool-absent fallback)
- `RED` — emits `"generic_collector_limited"` stub; no real data collected
- `N/A` — attribute does not apply to this platform

**Sensitivity:**
- `public` — safe to log, display, or transmit without redaction
- `tenant-sensitive` — reveals internal network topology, RFC1918 addresses, routing, or organizational infrastructure; must not appear in logs unsanitized
- `pii` — usernames, account names, or device-identifying data that can be traced to an individual

**GAP:** `YES` when the attribute is promised by `steward-operating-model.md` or is absent from one or more platforms where it is architecturally expected.

---

## Collection Architecture

```
Collect() ─── Fast path (synchronous) ──────────────────────────────────────────────
              │  collectBasicInfo()        → basic system + Go runtime attributes
              │  collectHardwareInfo()     → CPU, memory, disk, motherboard (cached)
              │  collectNetworkInfo()      → interfaces, routing, DNS, firewall
              │  collectEnvironmentInfo()  → env vars, shell, timezone
              │
              └── Background goroutine (async, started on first Collect()) ─────────
                   concurrent:
                     collectSoftwareInfo()  → OS detail, packages, services, processes
                     collectSecurityInfo()  → users, groups, permissions, certificates
```

Hardware data is cached via `hwCacheOnce` after the first call. Background data is merged into the fast-path result only when `bgDone` is closed.

Factory routing (from `factory_*.go`):

| Platform | Hardware | Software | Network | Security |
|----------|----------|----------|---------|----------|
| Linux | `LinuxHardwareCollector` | `LinuxSoftwareCollector` | `LinuxNetworkCollector` | `LinuxSecurityCollector` |
| Windows | `WindowsHardwareCollector` | `WindowsSoftwareCollector` | `WindowsNetworkCollector` | `WindowsSecurityCollector` |
| macOS | `DarwinHardwareCollector` | `DarwinSoftwareCollector` | `DarwinNetworkCollector` | `DarwinSecurityCollector` |
| Other | `GenericHardwareCollector` | `GenericSoftwareCollector` | `GenericNetworkCollector` | `GenericSecurityCollector` |

---

## Audit Table

### 1. Basic / Environment

Collected synchronously in `collectBasicInfo()` and `collectEnvironmentInfo()`. Present on all platforms regardless of OS-specific collector availability.

| Attribute Key | Description | Collector Method | Path | Sensitivity | Linux | Windows | macOS | GAP |
|---|---|---|---|---|---|---|---|---|
| `timestamp` | UTC collection time (RFC3339) | `collectBasicInfo` | Fast | public | GREEN | GREEN | GREEN | NO |
| `runtime_version` | Go runtime version string | `collectBasicInfo` | Fast | public | GREEN | GREEN | GREEN | NO |
| `runtime_os` | GOOS value (`linux`, `windows`, `darwin`) | `collectBasicInfo` | Fast | public | GREEN | GREEN | GREEN | NO |
| `runtime_arch` | GOARCH value (`amd64`, `arm64`, etc.) | `collectBasicInfo` | Fast | public | GREEN | GREEN | GREEN | NO |
| `num_cpu` | Logical CPU count from `runtime.NumCPU()` | `collectBasicInfo` | Fast | public | GREEN | GREEN | GREEN | NO |
| `hostname` | System hostname from `os.Hostname()` | `collectBasicInfo` | Fast | tenant-sensitive | GREEN | GREEN | GREEN | NO |
| `working_directory` | Steward working directory | `collectBasicInfo` | Fast | public | GREEN | GREEN | GREEN | NO |
| `user` | `USER` environment variable | `collectEnvironmentInfo` | Fast | pii | YELLOW | YELLOW | YELLOW | NO |
| `home_directory` | `HOME` environment variable | `collectEnvironmentInfo` | Fast | pii | YELLOW | YELLOW | YELLOW | NO |
| `path_elements` | Count of entries in `PATH` (not the paths) | `collectEnvironmentInfo` | Fast | public | GREEN | GREEN | GREEN | NO |
| `shell` | `SHELL` environment variable | `collectEnvironmentInfo` | Fast | public | GREEN | N/A | GREEN | NO |
| `terminal` | `TERM` environment variable | `collectEnvironmentInfo` | Fast | public | YELLOW | YELLOW | YELLOW | NO |
| `timezone` | System timezone name | `collectEnvironmentInfo` | Fast | public | GREEN | GREEN | GREEN | NO |
| `timezone_offset` | Timezone UTC offset in seconds | `collectEnvironmentInfo` | Fast | public | GREEN | GREEN | GREEN | NO |
| `env_os_name` | `OS` env var value (set on Windows by default) | `collectSoftwareInfo` | Background | public | N/A | YELLOW | N/A | NO |

---

### 2. Hardware — CPU

Collected on the fast path via `collectHardwareInfo()`, cached after first call.

| Attribute Key | Description | Collector Method | Path | Sensitivity | Linux | Windows | macOS | GAP |
|---|---|---|---|---|---|---|---|---|
| `cpu_count` | Logical CPU count (`runtime.NumCPU()`) | `CollectCPU` | Fast | public | GREEN | GREEN | GREEN | NO |
| `cpu_arch` | CPU architecture (GOARCH) | `CollectCPU` | Fast | public | GREEN | GREEN | GREEN | NO |
| `cpu_model` | CPU model name string | `parseProcCPUInfo` / sysctl | Fast | public | GREEN | N/A | GREEN | NO |
| `cpu_name` | CPU name string (Windows wmic) | `parseWMICPUOutput` | Fast | public | N/A | GREEN | N/A | NO |
| `cpu_vendor` | CPU vendor string (`/proc/cpuinfo`) | `parseProcCPUInfo` | Fast | public | GREEN | N/A | N/A | NO |
| `cpu_manufacturer` | CPU manufacturer (Windows wmic) | `parseWMICPUOutput` | Fast | public | N/A | GREEN | N/A | NO |
| `cpu_family` | CPU family ID | `parseProcCPUInfo` / sysctl | Fast | public | GREEN | N/A | GREEN | NO |
| `cpu_model_id` | CPU model number | `parseProcCPUInfo` / sysctl | Fast | public | GREEN | N/A | GREEN | NO |
| `cpu_stepping` | CPU stepping value | `parseProcCPUInfo` / sysctl | Fast | public | GREEN | N/A | GREEN | NO |
| `cpu_frequency_mhz` | CPU frequency in MHz | `parseCPUFrequency` / sysctl | Fast | public | GREEN | N/A | GREEN | NO |
| `cpu_frequency_hz` | CPU frequency in Hz (macOS sysctl) | `CollectCPU` (darwin) | Fast | public | N/A | N/A | GREEN | NO |
| `cpu_max_clock_speed` | Max clock speed MHz (Windows wmic) | `parseWMICPUOutput` | Fast | public | N/A | GREEN | N/A | NO |
| `cpu_cache_size` | CPU cache size string | `parseProcCPUInfo` | Fast | public | GREEN | N/A | N/A | NO |
| `cpu_flags` | First 10 CPU feature flags | `parseProcCPUInfo` | Fast | public | GREEN | N/A | N/A | NO |
| `proc_cpu_count` | Logical CPU count from `/proc/cpuinfo` | `parseProcCPUInfo` | Fast | public | GREEN | N/A | N/A | NO |
| `cpu_current_frequency_mhz` | Current CPU frequency MHz | `parseCPUFrequency` | Fast | public | GREEN | N/A | N/A | NO |
| `cpu_current_frequency_ghz` | Current CPU frequency GHz | `parseCPUFrequency` | Fast | public | GREEN | N/A | N/A | NO |
| `cpu_min_frequency_khz` | Min CPU frequency kHz (sysfs) | `parseCPUFrequency` | Fast | public | YELLOW | N/A | N/A | NO |
| `cpu_max_frequency_khz` | Max CPU frequency kHz (sysfs) | `parseCPUFrequency` | Fast | public | YELLOW | N/A | N/A | NO |
| `cpu_min_frequency_mhz` | Min CPU frequency MHz (derived) | `parseCPUFrequency` | Fast | public | YELLOW | N/A | N/A | NO |
| `cpu_max_frequency_mhz` | Max CPU frequency MHz (derived) | `parseCPUFrequency` | Fast | public | YELLOW | N/A | N/A | NO |
| `cpu_architecture` | Architecture string (lscpu / wmic) | `parseLSCPUOutput` / `parseWMICPUOutput` | Fast | public | GREEN | GREEN | N/A | NO |
| `cpu_op_modes` | CPU operation modes (lscpu) | `parseLSCPUOutput` | Fast | public | GREEN | N/A | N/A | NO |
| `cpu_byte_order` | Byte order (lscpu) | `parseLSCPUOutput` | Fast | public | GREEN | N/A | N/A | NO |
| `cpu_logical_count` | Logical CPU count (lscpu) | `parseLSCPUOutput` | Fast | public | GREEN | N/A | N/A | NO |
| `cpu_online_list` | Online CPU list (lscpu) | `parseLSCPUOutput` | Fast | public | GREEN | N/A | N/A | NO |
| `cpu_threads_per_core` | Threads per core (lscpu) | `parseLSCPUOutput` | Fast | public | GREEN | N/A | N/A | NO |
| `cpu_cores_per_socket` | Cores per socket (lscpu) | `parseLSCPUOutput` | Fast | public | GREEN | N/A | N/A | NO |
| `cpu_sockets` | Socket count (lscpu) | `parseLSCPUOutput` | Fast | public | GREEN | N/A | N/A | NO |
| `cpu_numa_nodes` | NUMA node count (lscpu) | `parseLSCPUOutput` | Fast | public | GREEN | N/A | N/A | NO |
| `cpu_virtualization` | Virtualization support flag (lscpu) | `parseLSCPUOutput` | Fast | public | GREEN | N/A | N/A | NO |
| `cpu_l1d_cache` | L1 data cache size (lscpu) | `parseLSCPUOutput` | Fast | public | GREEN | N/A | N/A | NO |
| `cpu_l1i_cache` | L1 instruction cache size (lscpu) | `parseLSCPUOutput` | Fast | public | GREEN | N/A | N/A | NO |
| `cpu_l2_cache` | L2 cache size (lscpu) | `parseLSCPUOutput` | Fast | public | GREEN | N/A | N/A | NO |
| `cpu_l3_cache` | L3 cache size (lscpu) | `parseLSCPUOutput` | Fast | public | GREEN | N/A | N/A | NO |
| `cpu_bogomips` | BogoMIPS rating (lscpu) | `parseLSCPUOutput` | Fast | public | GREEN | N/A | N/A | NO |
| `cpu_vendor_lscpu` | CPU vendor from lscpu | `parseLSCPUOutput` | Fast | public | GREEN | N/A | N/A | NO |
| `cpu_family_lscpu` | CPU family from lscpu | `parseLSCPUOutput` | Fast | public | GREEN | N/A | N/A | NO |
| `cpu_model_lscpu` | CPU model from lscpu | `parseLSCPUOutput` | Fast | public | GREEN | N/A | N/A | NO |
| `cpu_model_name_lscpu` | CPU model name from lscpu | `parseLSCPUOutput` | Fast | public | GREEN | N/A | N/A | NO |
| `cpu_stepping_lscpu` | CPU stepping from lscpu | `parseLSCPUOutput` | Fast | public | GREEN | N/A | N/A | NO |
| `cpu_frequency_lscpu` | CPU frequency from lscpu | `parseLSCPUOutput` | Fast | public | GREEN | N/A | N/A | NO |
| `cpu_cores` | Physical core count (Windows wmic) | `parseWMICPUOutput` | Fast | public | N/A | GREEN | N/A | NO |
| `cpu_logical_processors` | Logical processors (Windows wmic) | `parseWMICPUOutput` | Fast | public | N/A | GREEN | N/A | NO |
| `cpu_architecture_ps` | Architecture (Windows PS fallback) | `parsePowerShellCPUOutput` | Fast | public | N/A | YELLOW | N/A | NO |
| `cpu_manufacturer_ps` | Manufacturer (Windows PS fallback) | `parsePowerShellCPUOutput` | Fast | public | N/A | YELLOW | N/A | NO |
| `cpu_max_clock_speed_ps` | Max clock speed (Windows PS fallback) | `parsePowerShellCPUOutput` | Fast | public | N/A | YELLOW | N/A | NO |
| `cpu_name_ps` | CPU name (Windows PS fallback) | `parsePowerShellCPUOutput` | Fast | public | N/A | YELLOW | N/A | NO |
| `cpu_cores_ps` | Core count (Windows PS fallback) | `parsePowerShellCPUOutput` | Fast | public | N/A | YELLOW | N/A | NO |
| `cpu_logical_processors_ps` | Logical processor count (Windows PS fallback) | `parsePowerShellCPUOutput` | Fast | public | N/A | YELLOW | N/A | NO |
| `cpu_physical_cores` | Physical cores (macOS sysctl `hw.physicalcpu`) | `CollectCPU` (darwin) | Fast | public | N/A | N/A | GREEN | NO |
| `cpu_logical_cores` | Logical cores (macOS sysctl `hw.logicalcpu`) | `CollectCPU` (darwin) | Fast | public | N/A | N/A | GREEN | NO |

---

### 3. Hardware — Memory

Collected on the fast path via `collectHardwareInfo()`, cached after first call.

| Attribute Key | Description | Collector Method | Path | Sensitivity | Linux | Windows | macOS | GAP |
|---|---|---|---|---|---|---|---|---|
| `memory_total_bytes` | Total physical RAM in bytes | `CollectMemory` | Fast | public | N/A | GREEN | GREEN | NO |
| `memory_total_gb` | Total RAM in GB | `CollectMemory` | Fast | public | GREEN | GREEN | GREEN | NO |
| `memory_total_kb` | Total RAM in kB (from `/proc/meminfo`) | `parseProcMemInfo` | Fast | public | GREEN | N/A | N/A | NO |
| `memory_total_mb` | Total RAM in MB (derived) | `parseProcMemInfo` | Fast | public | GREEN | N/A | N/A | NO |
| `memory_free_kb` | Free RAM in kB | `parseProcMemInfo` | Fast | public | GREEN | N/A | N/A | NO |
| `memory_available_kb` | Available RAM in kB | `parseProcMemInfo` | Fast | public | GREEN | N/A | N/A | NO |
| `memory_buffers_kb` | Buffered memory in kB | `parseProcMemInfo` | Fast | public | GREEN | N/A | N/A | NO |
| `memory_cached_kb` | Cached memory in kB | `parseProcMemInfo` | Fast | public | GREEN | N/A | N/A | NO |
| `swap_total_kb` | Total swap in kB | `parseProcMemInfo` | Fast | public | GREEN | N/A | N/A | NO |
| `swap_free_kb` | Free swap in kB | `parseProcMemInfo` | Fast | public | GREEN | N/A | N/A | NO |
| `memory_dirty_kb` | Dirty pages in kB | `parseProcMemInfo` | Fast | public | GREEN | N/A | N/A | NO |
| `memory_writeback_kb` | Writeback pages in kB | `parseProcMemInfo` | Fast | public | GREEN | N/A | N/A | NO |
| `memory_anon_pages_kb` | Anonymous pages in kB | `parseProcMemInfo` | Fast | public | GREEN | N/A | N/A | NO |
| `memory_mapped_kb` | Mapped memory in kB | `parseProcMemInfo` | Fast | public | GREEN | N/A | N/A | NO |
| `memory_shared_kb` | Shared memory in kB | `parseProcMemInfo` | Fast | public | GREEN | N/A | N/A | NO |
| `memory_total_human` | Total RAM (human-readable, `free -h`) | `parseMemoryUsage` | Fast | public | GREEN | N/A | N/A | NO |
| `memory_used_human` | Used RAM (human-readable) | `parseMemoryUsage` | Fast | public | GREEN | N/A | N/A | NO |
| `memory_free_human` | Free RAM (human-readable) | `parseMemoryUsage` | Fast | public | GREEN | N/A | N/A | NO |
| `memory_shared_human` | Shared RAM (human-readable) | `parseMemoryUsage` | Fast | public | GREEN | N/A | N/A | NO |
| `memory_buff_cache_human` | Buff/cache RAM (human-readable) | `parseMemoryUsage` | Fast | public | GREEN | N/A | N/A | NO |
| `memory_available_human` | Available RAM (human-readable) | `parseMemoryUsage` | Fast | public | GREEN | N/A | N/A | NO |
| `memory_dmidecode_available` | Flag: dmidecode memory info accessible | `parseDMIDecodeMemory` | Fast | public | YELLOW | N/A | N/A | NO |
| `memory_slot_count` | RAM slot count (dmidecode) | `parseDMIDecodeMemory` | Fast | public | YELLOW | N/A | N/A | NO |
| `memory_module_count` | RAM module count (Windows wmic) | `parseWMIMemoryModulesOutput` | Fast | public | N/A | GREEN | N/A | NO |
| `memory_module_capacity` | First module capacity in bytes | `parseWMIMemoryModulesOutput` | Fast | public | N/A | GREEN | N/A | NO |
| `memory_module_form_factor` | First module form factor code | `parseWMIMemoryModulesOutput` | Fast | public | N/A | GREEN | N/A | NO |
| `memory_module_type` | First module type code | `parseWMIMemoryModulesOutput` | Fast | public | N/A | GREEN | N/A | NO |
| `memory_module_speed` | First module speed MHz | `parseWMIMemoryModulesOutput` | Fast | public | N/A | GREEN | N/A | NO |
| `memory_modules_total_capacity` | Total capacity of all modules | `parseWMIMemoryModulesOutput` | Fast | public | N/A | GREEN | N/A | NO |
| `pagefile_allocated_size` | Windows pagefile allocated size MB | `parsePowerShellVirtualMemoryOutput` | Fast | public | N/A | GREEN | N/A | NO |
| `pagefile_current_usage` | Windows pagefile current usage MB | `parsePowerShellVirtualMemoryOutput` | Fast | public | N/A | GREEN | N/A | NO |
| `memory_page_size` | Memory page size in bytes (macOS) | `CollectMemory` (darwin) | Fast | public | N/A | N/A | GREEN | NO |
| `memory_pages_free` | Free memory pages (vm_stat) | `parseVMStat` | Fast | public | N/A | N/A | GREEN | NO |
| `memory_pages_active` | Active memory pages (vm_stat) | `parseVMStat` | Fast | public | N/A | N/A | GREEN | NO |
| `memory_pages_inactive` | Inactive memory pages (vm_stat) | `parseVMStat` | Fast | public | N/A | N/A | GREEN | NO |
| `memory_go_alloc` | Go heap allocated bytes (generic fallback) | `GenericHardwareCollector.CollectMemory` | Fast | public | N/A | N/A | N/A | NO |
| `memory_go_sys` | Go total system bytes (generic fallback) | `GenericHardwareCollector.CollectMemory` | Fast | public | N/A | N/A | N/A | NO |

---

### 4. Hardware — Disk

Collected on the fast path via `collectHardwareInfo()`, cached after first call. `N` is a 1-based index; `LETTER` is a Windows drive letter without colon.

| Attribute Key | Description | Collector Method | Path | Sensitivity | Linux | Windows | macOS | GAP |
|---|---|---|---|---|---|---|---|---|
| `disk_mount_count` | Count of mounted `/dev/` filesystems (df) | `parseDiskUsage` (linux) | Fast | public | GREEN | N/A | N/A | NO |
| `disk_N_device` | Device path for disk N | `parseDiskUsage` | Fast | public | GREEN | N/A | GREEN | NO |
| `disk_N_size` | Disk N total size (human) | `parseDiskUsage` | Fast | public | GREEN | N/A | GREEN | NO |
| `disk_N_used` | Disk N used space (human) | `parseDiskUsage` | Fast | public | GREEN | N/A | GREEN | NO |
| `disk_N_available` | Disk N available space (human) | `parseDiskUsage` | Fast | public | GREEN | N/A | GREEN | NO |
| `disk_N_use_percent` | Disk N use percentage | `parseDiskUsage` | Fast | public | GREEN | N/A | GREEN | NO |
| `disk_N_mount` | Disk N mount point | `parseDiskUsage` | Fast | public | GREEN | N/A | GREEN | NO |
| `disk_count` | Count of `/dev/` disks (macOS df) | `parseDiskUsage` (darwin) | Fast | public | N/A | N/A | GREEN | NO |
| `disk_info_available` | Flag: diskutil output accessible | `CollectDisk` (darwin) | Fast | public | N/A | N/A | GREEN | NO |
| `disk_collection_method` | Collection method used (macOS) | `CollectDisk` (darwin) | Fast | public | N/A | N/A | GREEN | NO |
| `block_device_count` | Count of block devices (lsblk) | `parseLSBLKOutput` | Fast | public | GREEN | N/A | N/A | NO |
| `block_device_N_name` | Block device N name | `parseLSBLKOutput` | Fast | public | GREEN | N/A | N/A | NO |
| `block_device_N_size` | Block device N size | `parseLSBLKOutput` | Fast | public | GREEN | N/A | N/A | NO |
| `block_device_N_type` | Block device N type (disk/part) | `parseLSBLKOutput` | Fast | public | GREEN | N/A | N/A | NO |
| `block_device_N_model` | Block device N model string | `parseLSBLKOutput` | Fast | public | GREEN | N/A | N/A | NO |
| `block_device_N_vendor` | Block device N vendor string | `parseLSBLKOutput` | Fast | public | GREEN | N/A | N/A | NO |
| `fdisk_disk_count` | Disk count from fdisk | `parseFdiskOutput` | Fast | public | YELLOW | N/A | N/A | NO |
| `fdisk_sample_disk` | Sample disk size line from fdisk | `parseFdiskOutput` | Fast | public | YELLOW | N/A | N/A | NO |
| `smart_sda_health` | SMART health for sda (PASSED/FAILED) | `collectSMARTInfo` | Fast | public | YELLOW | N/A | N/A | NO |
| `smart_sdb_health` | SMART health for sdb | `collectSMARTInfo` | Fast | public | YELLOW | N/A | N/A | NO |
| `smart_nvme0n1_health` | SMART health for nvme0n1 | `collectSMARTInfo` | Fast | public | YELLOW | N/A | N/A | NO |
| `smart_nvme1n1_health` | SMART health for nvme1n1 | `collectSMARTInfo` | Fast | public | YELLOW | N/A | N/A | NO |
| `physical_disk_count` | Physical disk count (Windows wmic) | `parseWMIDiskOutput` | Fast | public | N/A | GREEN | N/A | NO |
| `physical_disk_N_interface` | Physical disk N interface type | `parseWMIDiskOutput` | Fast | public | N/A | GREEN | N/A | NO |
| `physical_disk_N_media_type` | Physical disk N media type | `parseWMIDiskOutput` | Fast | public | N/A | GREEN | N/A | NO |
| `physical_disk_N_model` | Physical disk N model string | `parseWMIDiskOutput` | Fast | public | N/A | GREEN | N/A | NO |
| `physical_disk_N_size_bytes` | Physical disk N size in bytes | `parseWMIDiskOutput` | Fast | public | N/A | GREEN | N/A | NO |
| `physical_disk_N_size_gb` | Physical disk N size in GB | `parseWMIDiskOutput` | Fast | public | N/A | GREEN | N/A | NO |
| `logical_drive_count` | Logical drive count (Windows wmic) | `parseWMILogicalDiskOutput` | Fast | public | N/A | GREEN | N/A | NO |
| `logical_drive_LETTER_device` | Logical drive device ID (e.g., `C:`) | `parseWMILogicalDiskOutput` | Fast | public | N/A | GREEN | N/A | NO |
| `logical_drive_LETTER_drive_type` | Logical drive type code | `parseWMILogicalDiskOutput` | Fast | public | N/A | GREEN | N/A | NO |
| `logical_drive_LETTER_filesystem` | Logical drive filesystem | `parseWMILogicalDiskOutput` | Fast | public | N/A | GREEN | N/A | NO |
| `logical_drive_LETTER_free_space_gb` | Logical drive free space GB | `parseWMILogicalDiskOutput` | Fast | public | N/A | GREEN | N/A | NO |
| `logical_drive_LETTER_total_size_gb` | Logical drive total size GB | `parseWMILogicalDiskOutput` | Fast | public | N/A | GREEN | N/A | NO |
| `ps_drive_LETTER_filesystem` | Drive filesystem (PowerShell fallback) | `parsePowerShellDiskUsageOutput` | Fast | public | N/A | YELLOW | N/A | NO |
| `ps_drive_LETTER_free_space_gb` | Drive free space GB (PowerShell fallback) | `parsePowerShellDiskUsageOutput` | Fast | public | N/A | YELLOW | N/A | NO |
| `ps_drive_LETTER_total_size_gb` | Drive total size GB (PowerShell fallback) | `parsePowerShellDiskUsageOutput` | Fast | public | N/A | YELLOW | N/A | NO |
| `disk_info` | Stub (generic/unsupported platforms) | `GenericHardwareCollector.CollectDisk` | Fast | public | N/A | N/A | N/A | NO |

---

### 5. Hardware — System Identity

Collected on the fast path via `collectHardwareInfo()`, cached after first call.

| Attribute Key | Description | Collector Method | Path | Sensitivity | Linux | Windows | macOS | GAP |
|---|---|---|---|---|---|---|---|---|
| `system_manufacturer` | System manufacturer | `CollectMotherboard` | Fast | public | GREEN (dmidecode) | GREEN (wmic) | N/A | NO |
| `system_product_name` | System product name (Linux dmidecode) | `CollectMotherboard` (linux) | Fast | public | GREEN | N/A | N/A | NO |
| `system_model` | System model (Windows wmic) | `parseWMIComputerSystemOutput` | Fast | public | N/A | GREEN | N/A | NO |
| `system_version` | System version (Linux dmidecode) | `CollectMotherboard` (linux) | Fast | public | GREEN | N/A | N/A | NO |
| `system_serial_number` | System serial number | `CollectMotherboard` (linux) | Fast | tenant-sensitive | GREEN (dmidecode) | N/A | N/A | YES <!-- GAP: Windows stores motherboard_serial only via wmic baseboard; macOS has no serial number collector. Downstream device identity workflows that rely on serial number will fail on Windows and macOS. --> |
| `system_uuid` | System UUID | `CollectMotherboard` | Fast | tenant-sensitive | GREEN (dmidecode) | GREEN (wmic) | N/A | NO |
| `system_total_memory` | System total memory string (Windows) | `parseWMIComputerSystemOutput` | Fast | public | N/A | GREEN | N/A | NO |
| `bios_vendor` | BIOS vendor (Linux dmidecode) | `CollectMotherboard` (linux) | Fast | public | GREEN | N/A | N/A | NO |
| `bios_manufacturer` | BIOS manufacturer (Windows wmic) | `parseWMIBIOSOutput` | Fast | public | N/A | GREEN | N/A | NO |
| `bios_version` | BIOS version | `CollectMotherboard` | Fast | public | GREEN | GREEN | N/A | NO |
| `bios_release_date` | BIOS release date | `CollectMotherboard` | Fast | public | GREEN | GREEN | N/A | NO |
| `motherboard_manufacturer` | Motherboard manufacturer | `CollectMotherboard` | Fast | public | GREEN | GREEN | N/A | NO |
| `motherboard_product` | Motherboard product name | `CollectMotherboard` | Fast | public | GREEN | GREEN | N/A | NO |
| `motherboard_version` | Motherboard version | `CollectMotherboard` (linux) | Fast | public | GREEN | N/A | N/A | NO |
| `motherboard_serial` | Motherboard serial number (Windows) | `parseWMIMotherboardOutput` | Fast | tenant-sensitive | N/A | GREEN | N/A | NO |
| `system_uptime` | System uptime string | `CollectMotherboard` (linux) | Fast | public | GREEN | N/A | N/A | NO |
| `kernel_version` | Kernel version string (Linux) | `CollectMotherboard` (linux) | Fast | public | GREEN | N/A | N/A | NO |
| `kernel_info` | Full `uname -a` output (Linux) | `CollectMotherboard` (linux) | Fast | public | GREEN | N/A | N/A | NO |
| `hardware_model` | Hardware model (macOS sysctl `hw.model`) | `CollectMotherboard` (darwin) | Fast | public | N/A | N/A | GREEN | NO |
| `hardware_uuid` | Hardware UUID (macOS sysctl `kern.uuid`) | `CollectMotherboard` (darwin) | Fast | tenant-sensitive | N/A | N/A | GREEN | NO |
| `os_version` | macOS version from `sw_vers` | `CollectMotherboard` (darwin) | Fast | public | N/A | N/A | GREEN | NO |
| `os_build` | macOS build from `sw_vers` | `CollectMotherboard` (darwin) | Fast | public | N/A | N/A | GREEN | NO |
| `os_name` | macOS product name from `sw_vers` | `CollectMotherboard` (darwin) | Fast | public | N/A | N/A | GREEN | NO |
| `boot_time` | Boot time string (macOS sysctl `kern.boottime`) | `CollectMotherboard` (darwin) | Fast | public | N/A | N/A | GREEN | NO |
| `windows_caption` | Windows product name (registry) | `collectOSVersionFromRegistry` | Fast | public | N/A | GREEN | N/A | NO |
| `windows_build_number` | Windows build number (registry) | `collectOSVersionFromRegistry` | Fast | public | N/A | GREEN | N/A | NO |
| `windows_version` | Windows version string (registry) | `collectOSVersionFromRegistry` | Fast | public | N/A | GREEN | N/A | NO |
| `system_info` | Stub (generic/unsupported platforms) | `GenericHardwareCollector.CollectMotherboard` | Fast | public | N/A | N/A | N/A | NO |

---

### 6. Network — Interfaces

Collected synchronously via `collectNetworkInfo()` (fast path). Linux and Windows delegate `CollectInterfaces` entirely to `GenericNetworkCollector`; macOS augments with `ifconfig` and `networksetup`.

| Attribute Key | Description | Collector Method | Path | Sensitivity | Linux | Windows | macOS | GAP |
|---|---|---|---|---|---|---|---|---|
| `ip_addresses` | All non-loopback IPv4 addresses, comma-separated | `GenericNetworkCollector.CollectInterfaces` | Fast | tenant-sensitive | GREEN | GREEN | GREEN | NO |
| `primary_ip` | First non-loopback IPv4 address | `GenericNetworkCollector.CollectInterfaces` | Fast | tenant-sensitive | GREEN | GREEN | GREEN | NO |
| `mac_addresses` | All non-loopback MAC addresses, comma-separated | `GenericNetworkCollector.CollectInterfaces` | Fast | tenant-sensitive | GREEN | GREEN | GREEN | NO |
| `primary_mac` | First non-loopback MAC (used in system ID generation) | `GenericNetworkCollector.CollectInterfaces` | Fast | tenant-sensitive | GREEN | GREEN | GREEN | NO |
| `network_interfaces` | Interface names, comma-separated | `GenericNetworkCollector.CollectInterfaces` | Fast | tenant-sensitive | GREEN | GREEN | GREEN | NO |
| `network_interface_count` | Total interface count (including loopback) | `GenericNetworkCollector.CollectInterfaces` | Fast | public | GREEN | GREEN | GREEN | NO |
| `active_interfaces` | Interfaces with RUNNING flag (ifconfig, macOS) | `parseIfconfigOutput` (darwin) | Fast | tenant-sensitive | N/A | N/A | GREEN | NO |
| `active_interface_count` | Count of RUNNING interfaces | `parseIfconfigOutput` (darwin) | Fast | public | N/A | N/A | GREEN | NO |
| `wired_interfaces` | Wired interface names (macOS ifconfig) | `parseIfconfigOutput` (darwin) | Fast | tenant-sensitive | N/A | N/A | GREEN | NO |
| `wireless_interfaces` | Wireless interface names (macOS ifconfig) | `parseIfconfigOutput` (darwin) | Fast | tenant-sensitive | N/A | N/A | GREEN | NO |
| `interface_IFNAME_mtu` | MTU for each named interface (macOS) | `parseIfconfigOutput` (darwin) | Fast | public | N/A | N/A | GREEN | NO |
| `network_service_count` | Count of network services (networksetup) | `parseNetworkServices` (darwin) | Fast | public | N/A | N/A | GREEN | NO |
| `network_services_sample` | First 5 network service names | `parseNetworkServices` (darwin) | Fast | tenant-sensitive | N/A | N/A | GREEN | NO |
| `wifi_current_ssid` | Connected Wi-Fi SSID | `collectWiFiInfo` (darwin) | Fast | tenant-sensitive | N/A | N/A | GREEN | NO |
| `wifi_power_status` | Wi-Fi radio power state | `collectWiFiInfo` (darwin) | Fast | public | N/A | N/A | GREEN | NO |

---

### 7. Network — Routing

Collected synchronously via `collectNetworkInfo()` (fast path). All IP and gateway values are sanitized via `logging.SanitizeLogValue()` before storage.

| Attribute Key | Description | Collector Method | Path | Sensitivity | Linux | Windows | macOS | GAP |
|---|---|---|---|---|---|---|---|---|
| `default_gateway` | Default IPv4 gateway (sanitized) | `CollectRouting` | Fast | tenant-sensitive | GREEN (`/proc/net/route`) | GREEN (`route print -4`) | GREEN (`route get default`) | NO |
| `ipv4_route_count` | Total IPv4 route count, capped at 500 | `CollectRouting` | Fast | public | GREEN | GREEN | N/A | NO |
| `routing_table_ipv4_count` | IPv4 route count (macOS netstat) | `parseRoutingTable` (darwin) | Fast | public | N/A | N/A | GREEN | NO |
| `routing_table_ipv6_count` | IPv6 route count (macOS netstat) | `parseRoutingTable` (darwin) | Fast | public | N/A | N/A | GREEN | NO |
| `default_gateways_ipv4` | Default IPv4 gateway list from routing table | `parseRoutingTable` (darwin) | Fast | tenant-sensitive | N/A | N/A | GREEN | NO |
| `default_gateways_ipv6` | Default IPv6 gateway list from routing table | `parseRoutingTable` (darwin) | Fast | tenant-sensitive | N/A | N/A | GREEN | NO |
| `default_interface` | Default route interface name | `parseDefaultGateway` (darwin) | Fast | tenant-sensitive | N/A | N/A | GREEN | NO |
| `routing_info` | Stub (generic/unsupported platforms) | `GenericNetworkCollector.CollectRouting` | Fast | public | N/A | N/A | N/A | NO |

**Linux note:** `/proc/net/route` stores addresses in host byte order (little-endian on x86/x64). The collector decodes hex values to dotted-decimal before applying `SanitizeLogValue`.

---

### 8. Network — DNS

Collected synchronously via `collectNetworkInfo()` (fast path). DNS server addresses and domain names are sanitized before storage.

| Attribute Key | Description | Collector Method | Path | Sensitivity | Linux | Windows | macOS | GAP |
|---|---|---|---|---|---|---|---|---|
| `dns_servers` | DNS server IPs, comma-separated, sanitized, truncated to 256 chars | `CollectDNS` | Fast | tenant-sensitive | GREEN (`/etc/resolv.conf`) | GREEN (registry per-adapter) | N/A | NO |
| `dns_search_domains` | DNS search domains, sanitized, truncated to 256 chars | `CollectDNS` (linux) | Fast | tenant-sensitive | GREEN | N/A | N/A | NO |
| `dns_domain` | Primary DNS domain (Windows registry) | `collectDNSDomainFromRegistry` | Fast | tenant-sensitive | N/A | GREEN | N/A | NO |
| `dns_resolver_count` | DNS resolver count (macOS scutil) | `parseDNSConfig` (darwin) | Fast | public | N/A | N/A | GREEN | NO |
| `dns_nameservers` | Nameservers from scutil --dns, comma-separated (raw — sanitize at consumption) | `parseDNSConfig` (darwin) | Fast | tenant-sensitive | N/A | N/A | GREEN | NO |
| `dns_servers_wi-fi` | DNS servers for Wi-Fi service (networksetup) | `collectDNSServers` (darwin) | Fast | tenant-sensitive | N/A | N/A | GREEN | NO |
| `dns_servers_ethernet` | DNS servers for Ethernet service | `collectDNSServers` (darwin) | Fast | tenant-sensitive | N/A | N/A | GREEN | NO |
| `search_domains_wi-fi` | Search domains for Wi-Fi (networksetup) | `collectSearchDomains` (darwin) | Fast | tenant-sensitive | N/A | N/A | GREEN | NO |
| `search_domains_ethernet` | Search domains for Ethernet | `collectSearchDomains` (darwin) | Fast | tenant-sensitive | N/A | N/A | GREEN | NO |
| `hosts_file_lines` | Line count of `/etc/hosts` | `CollectDNS` (darwin) | Fast | public | N/A | N/A | GREEN | NO |
| `dns_info` | Stub (generic/unsupported platforms) | `GenericNetworkCollector.CollectDNS` | Fast | public | N/A | N/A | N/A | NO |

**Linux note:** On systemd-resolved systems the nameserver is the stub `127.0.0.53` — this is expected and stored as-is.

---

### 9. Network — Firewall

Collected synchronously via `collectNetworkInfo()` (fast path). No single unified firewall state key exists across platforms; each platform uses platform-specific attribute names.

| Attribute Key | Description | Collector Method | Path | Sensitivity | Linux | Windows | macOS | GAP |
|---|---|---|---|---|---|---|---|---|
| `ufw_firewall_state` | UFW state: `active` or `inactive` | `parseUFWStatus` (linux) | Fast | public | GREEN (if ufw present) | N/A | N/A | NO |
| `iptables_rule_count` | Non-header iptables rule count | `countIPTablesRules` (linux) | Fast | public | YELLOW (fallback when ufw absent) | N/A | N/A | NO |
| `firewall_state` | `unknown` when neither ufw nor iptables respond | `CollectFirewall` (linux) | Fast | public | YELLOW (last-resort fallback) | N/A | N/A | YES <!-- GAP: Linux lacks a reliable binary enabled/disabled firewall state. nftables and firewalld are not probed. When ufw is absent and iptables returns permission denied, the only emitted key is firewall_state=unknown. --> |
| `windows_firewall_domain_profile` | Windows domain profile: `enabled`/`disabled` | `parseNetshFirewallOutput` | Fast | public | N/A | GREEN | N/A | NO |
| `windows_firewall_private_profile` | Windows private profile: `enabled`/`disabled` | `parseNetshFirewallOutput` | Fast | public | N/A | GREEN | N/A | NO |
| `windows_firewall_public_profile` | Windows public profile: `enabled`/`disabled` | `parseNetshFirewallOutput` | Fast | public | N/A | GREEN | N/A | NO |
| `macos_firewall_state` | macOS ALF state: `disabled`/`enabled_essential`/`enabled_all` | `CollectFirewall` (darwin) | Fast | public | N/A | N/A | GREEN | NO |
| `pfctl_rule_count` | pfctl rule count (requires pfctl access) | `CollectFirewall` (darwin) | Fast | public | N/A | N/A | YELLOW | NO |
| `macos_firewall_stealth` | macOS firewall stealth mode flag | `CollectFirewall` (darwin) | Fast | public | N/A | N/A | GREEN | NO |
| `macos_firewall_logging` | macOS firewall logging enabled flag | `CollectFirewall` (darwin) | Fast | public | N/A | N/A | GREEN | NO |
| `firewall_info` | Stub (generic/unsupported platforms) | `GenericNetworkCollector.CollectFirewall` | Fast | public | N/A | N/A | N/A | NO |

**Linux degradation order:** `ufw status` → `iptables -L` → `firewall_state=unknown`.

---

### 10. Software — OS Information

Collected in the background via `collectSoftwareInfo()` → `CollectOS`.

| Attribute Key | Description | Collector Method | Path | Sensitivity | Linux | Windows | macOS | GAP |
|---|---|---|---|---|---|---|---|---|
| `os` | OS name (`runtime.GOOS`) | `CollectOS` | Background | public | GREEN | GREEN | GREEN | NO |
| `go_version` | Go runtime version | `CollectOS` | Background | public | GREEN | GREEN | GREEN | NO |
| `runtime_compiler` | Go compiler name | `CollectOS` | Background | public | GREEN | GREEN | GREEN | NO |
| `os_name` | Distro name from `/etc/os-release` `NAME=` | `parseOSRelease` (linux) | Background | public | GREEN | N/A | N/A | NO |
| `os_version` | Distro version from `/etc/os-release` | `parseOSRelease` (linux) | Background | public | GREEN | N/A | N/A | NO |
| `os_id` | Distro ID (e.g., `ubuntu`, `centos`) | `parseOSRelease` (linux) | Background | public | GREEN | N/A | N/A | NO |
| `os_id_like` | Parent distro ID | `parseOSRelease` (linux) | Background | public | GREEN | N/A | N/A | NO |
| `os_version_id` | Version ID string | `parseOSRelease` (linux) | Background | public | GREEN | N/A | N/A | NO |
| `os_version_codename` | Release codename | `parseOSRelease` (linux) | Background | public | GREEN | N/A | N/A | NO |
| `os_pretty_name` | Full OS description string | `parseOSRelease` (linux) | Background | public | GREEN | N/A | N/A | NO |
| `os_home_url` | OS home URL | `parseOSRelease` (linux) | Background | public | GREEN | N/A | N/A | NO |
| `os_support_url` | OS support URL | `parseOSRelease` (linux) | Background | public | GREEN | N/A | N/A | NO |
| `os_bug_report_url` | OS bug report URL | `parseOSRelease` (linux) | Background | public | GREEN | N/A | N/A | NO |
| `lsb_distributor_id` | Distributor ID (lsb_release) | `parseLSBRelease` (linux) | Background | public | YELLOW | N/A | N/A | NO |
| `lsb_description` | LSB description string | `parseLSBRelease` (linux) | Background | public | YELLOW | N/A | N/A | NO |
| `lsb_release` | LSB release version string | `parseLSBRelease` (linux) | Background | public | YELLOW | N/A | N/A | NO |
| `lsb_codename` | LSB release codename | `parseLSBRelease` (linux) | Background | public | YELLOW | N/A | N/A | NO |
| `kernel_info` | Full `uname -a` output | `CollectOS` (linux) | Background | public | GREEN | N/A | N/A | NO |
| `kernel_version` | `uname -r` output (same key emitted on both Linux and macOS) | `CollectOS` (linux, darwin) | Background | public | GREEN | N/A | GREEN | NO |
| `kernel_build_info` | `uname -v` output | `CollectOS` (linux) | Background | public | GREEN | N/A | N/A | NO |
| `static_hostname` | hostnamectl static hostname | `parseHostnamectl` (linux) | Background | tenant-sensitive | GREEN | N/A | N/A | NO |
| `icon_name` | hostnamectl icon name | `parseHostnamectl` (linux) | Background | public | GREEN | N/A | N/A | NO |
| `chassis` | System chassis type | `parseHostnamectl` (linux) | Background | public | GREEN | N/A | N/A | NO |
| `machine_id` | Machine ID | `parseHostnamectl` (linux) | Background | tenant-sensitive | GREEN | N/A | N/A | NO |
| `boot_id` | Boot ID | `parseHostnamectl` (linux) | Background | public | GREEN | N/A | N/A | NO |
| `hostnamectl_os` | OS string from hostnamectl | `parseHostnamectl` (linux) | Background | public | GREEN | N/A | N/A | NO |
| `hostnamectl_kernel` | Kernel string from hostnamectl | `parseHostnamectl` (linux) | Background | public | GREEN | N/A | N/A | NO |
| `hostnamectl_arch` | Architecture from hostnamectl | `parseHostnamectl` (linux) | Background | public | GREEN | N/A | N/A | NO |
| `system_uptime` | Uptime string from `uptime` | `CollectOS` (linux/darwin) | Background | public | GREEN | N/A | GREEN | NO |
| `system_boot_time` | Boot time from `who -b` (Linux) | `CollectOS` (linux) | Background | public | GREEN | N/A | N/A | NO |
| `macos_version` | macOS version (`sw_vers -productVersion`) | `CollectOS` (darwin) | Background | public | N/A | N/A | GREEN | NO |
| `macos_build` | macOS build version (`sw_vers -buildVersion`) | `CollectOS` (darwin) | Background | public | N/A | N/A | GREEN | NO |
| `macos_product_name` | macOS product name (`sw_vers -productName`) | `CollectOS` (darwin) | Background | public | N/A | N/A | GREEN | NO |
| `kernel_name` | macOS kernel name (`uname -s`) | `CollectOS` (darwin) | Background | public | N/A | N/A | GREEN | NO |
| `windows_service_pack` | Windows service pack (registry) | `collectOSVersion` (windows) | Background | public | N/A | GREEN | N/A | NO |
| `windows_install_date` | Windows install date (registry) | `collectOSVersion` (windows) | Background | public | N/A | GREEN | N/A | NO |
| `windows_os_architecture` | Windows OS architecture (registry) | `collectOSVersion` (windows) | Background | public | N/A | GREEN | N/A | NO |
| `windows_last_boot_time` | Last boot time (kernel32 `GetTickCount64`) | `collectOSVersion` (windows) | Background | public | N/A | GREEN | N/A | NO |
| `dotnet_framework_versions` | .NET Framework versions (registry) | `collectDotNetVersions` (windows) | Background | public | N/A | GREEN | N/A | NO |
| `powershell_version` | PowerShell version string | `CollectOS` (windows) | Background | public | N/A | GREEN | N/A | NO |
| `dotnet_core_runtimes` | .NET Core runtime list (`dotnet --list-runtimes`) | `CollectOS` (windows) | Background | public | N/A | YELLOW | N/A | NO |

---

### 11. Software — Packages

Collected in the background via `collectSoftwareInfo()` → `CollectPackages`. Keys are absent when the package manager is not installed. Sample keys hold only first 10–20 names.

| Attribute Key | Description | Collector Method | Path | Sensitivity | Linux | Windows | macOS | GAP |
|---|---|---|---|---|---|---|---|---|
| `apt_package_count` | APT/dpkg installed package count | `collectAPTPackages` | Background | public | YELLOW (Debian/Ubuntu) | N/A | N/A | NO |
| `apt_packages_sample` | First 20 APT package names | `collectAPTPackages` | Background | public | YELLOW | N/A | N/A | NO |
| `dpkg_installed_count` | dpkg -l installed count (fallback) | `collectAPTPackages` | Background | public | YELLOW | N/A | N/A | NO |
| `yum_package_count` | YUM installed package count | `collectYUMPackages` | Background | public | YELLOW (RHEL/CentOS) | N/A | N/A | NO |
| `yum_packages_sample` | First 20 YUM package names | `collectYUMPackages` | Background | public | YELLOW | N/A | N/A | NO |
| `rpm_package_count` | RPM package count (YUM fallback) | `collectYUMPackages` | Background | public | YELLOW | N/A | N/A | NO |
| `rpm_packages_sample` | First 20 RPM package names | `collectYUMPackages` | Background | public | YELLOW | N/A | N/A | NO |
| `dnf_package_count` | DNF installed package count | `collectDNFPackages` | Background | public | YELLOW (Fedora/RHEL 8+) | N/A | N/A | NO |
| `pacman_package_count` | Pacman installed package count | `collectPacmanPackages` | Background | public | YELLOW (Arch) | N/A | N/A | NO |
| `pacman_packages_sample` | First 20 Pacman package names | `collectPacmanPackages` | Background | public | YELLOW | N/A | N/A | NO |
| `aur_package_count` | AUR package count (yay, optional) | `collectPacmanPackages` | Background | public | YELLOW | N/A | N/A | NO |
| `zypper_package_count` | Zypper installed package count | `collectZypperPackages` | Background | public | YELLOW (openSUSE) | N/A | N/A | NO |
| `snap_package_count` | Snap package count | `collectSnapPackages` | Background | public | YELLOW | N/A | N/A | NO |
| `snap_packages_sample` | First 10 Snap package names | `collectSnapPackages` | Background | public | YELLOW | N/A | N/A | NO |
| `flatpak_package_count` | Flatpak package count | `collectFlatpakPackages` | Background | public | YELLOW | N/A | N/A | NO |
| `flatpak_packages_sample` | First 10 Flatpak package names | `collectFlatpakPackages` | Background | public | YELLOW | N/A | N/A | NO |
| `pip3_package_count` | pip3 package count | `collectPipPackages` | Background | public | YELLOW | N/A | N/A | NO |
| `pip_package_count` | pip2 package count (pip3 fallback) | `collectPipPackages` | Background | public | YELLOW | N/A | N/A | NO |
| `npm_global_package_count` | Global npm package count | `collectNPMPackages` | Background | public | YELLOW | N/A | N/A | NO |
| `installed_program_count` | Installed program count (Uninstall registry) | `collectInstalledPrograms` (windows) | Background | public | N/A | GREEN | N/A | NO |
| `installed_programs_sample` | First 20 installed programs and versions | `collectInstalledPrograms` (windows) | Background | public | N/A | GREEN | N/A | NO |
| `installed_update_count` | Installed KB count (CBS registry) | `collectInstalledUpdates` (windows) | Background | public | N/A | GREEN | N/A | NO |
| `installed_updates_sample` | Up to 10 KB numbers | `collectInstalledUpdates` (windows) | Background | public | N/A | GREEN | N/A | NO |
| `windows_features_enabled_count` | Windows optional feature count (DISM, opt-in via env var) | `collectWindowsFeatures` (windows) | Background | public | N/A | YELLOW | N/A | NO |
| `windows_features_sample` | First 10 enabled feature names (opt-in) | `collectWindowsFeatures` (windows) | Background | public | N/A | YELLOW | N/A | NO |
| `chocolatey_package_count` | Chocolatey package count | `collectChocolateyPackages` (windows) | Background | public | N/A | YELLOW | N/A | NO |
| `chocolatey_packages_sample` | First 10 Chocolatey package names | `collectChocolateyPackages` (windows) | Background | public | N/A | YELLOW | N/A | NO |
| `winget_package_count` | Winget package count | `collectWingetPackages` (windows) | Background | public | N/A | YELLOW | N/A | NO |
| `winget_packages_sample` | First 15 winget package entries | `collectWingetPackages` (windows) | Background | public | N/A | YELLOW | N/A | NO |
| `winget_version` | Winget version string | `collectWingetPackages` (windows) | Background | public | N/A | YELLOW | N/A | NO |
| `winget_source_count` | Winget source count | `collectWingetPackages` (windows) | Background | public | N/A | YELLOW | N/A | NO |
| `winget_sources` | Winget source names | `collectWingetPackages` (windows) | Background | public | N/A | YELLOW | N/A | NO |
| `windows_store_app_count` | Windows Store app count | `collectWindowsStoreApps` (windows) | Background | public | N/A | GREEN | N/A | NO |
| `windows_store_apps_sample` | First 10 Windows Store app names | `collectWindowsStoreApps` (windows) | Background | public | N/A | GREEN | N/A | NO |
| `homebrew_formula_count` | Homebrew formula count | `collectHomebrewPackages` (darwin) | Background | public | N/A | N/A | YELLOW | NO |
| `homebrew_formulas_sample` | First 10 Homebrew formula names | `collectHomebrewPackages` (darwin) | Background | public | N/A | N/A | YELLOW | NO |
| `homebrew_cask_count` | Homebrew cask count | `collectHomebrewPackages` (darwin) | Background | public | N/A | N/A | YELLOW | NO |
| `homebrew_casks_sample` | First 10 Homebrew cask names | `collectHomebrewPackages` (darwin) | Background | public | N/A | N/A | YELLOW | NO |
| `macports_package_count` | MacPorts package count | `collectMacPortsPackages` (darwin) | Background | public | N/A | N/A | YELLOW | NO |
| `applications_count` | `.app` bundle count in /Applications | `collectApplications` (darwin) | Background | public | N/A | N/A | GREEN | NO |
| `applications_sample` | First 10 application names | `collectApplications` (darwin) | Background | public | N/A | N/A | GREEN | NO |
| `system_dylib_count` | dylib count in /usr/lib | `collectSystemLibraries` (darwin) | Background | public | N/A | N/A | GREEN | NO |
| `system_framework_count` | Framework count in /System/Library/Frameworks | `collectSystemLibraries` (darwin) | Background | public | N/A | N/A | GREEN | NO |
| `package_info` | Stub (generic/unsupported platforms) | `GenericSoftwareCollector.CollectPackages` | Background | public | N/A | N/A | N/A | NO |

---

### 12. Software — Services

Collected in the background via `collectSoftwareInfo()` → `CollectServices`.

| Attribute Key | Description | Collector Method | Path | Sensitivity | Linux | Windows | macOS | GAP |
|---|---|---|---|---|---|---|---|---|
| `running_process_count` | Running process count | `CollectServices` | Background | public | GREEN | GREEN | GREEN | NO |
| `systemd_total_services` | Total systemd service unit count | `collectSystemdServices` (linux) | Background | public | GREEN | N/A | N/A | NO |
| `systemd_active_services` | Active systemd service count | `collectSystemdServices` (linux) | Background | public | GREEN | N/A | N/A | NO |
| `systemd_failed_services` | Failed systemd service count | `collectSystemdServices` (linux) | Background | public | GREEN | N/A | N/A | NO |
| `systemd_enabled_services` | Enabled systemd service count | `collectSystemdServices` (linux) | Background | public | GREEN | N/A | N/A | NO |
| `initd_service_count` | Count of `/etc/init.d/` entries | `collectInitDServices` (linux) | Background | public | YELLOW | N/A | N/A | NO |
| `total_service_count` | Total Windows service count (native SCM) | `collectServicesViaSCM` (windows) | Background | public | N/A | GREEN | N/A | NO |
| `running_service_count` | Running Windows service count | `collectServicesViaSCM` (windows) | Background | public | N/A | GREEN | N/A | NO |
| `stopped_service_count` | Stopped Windows service count | `collectServicesViaSCM` (windows) | Background | public | N/A | GREEN | N/A | NO |
| `auto_start_service_count` | Auto-start Windows service count | `collectServicesViaSCM` (windows) | Background | public | N/A | GREEN | N/A | NO |
| `manual_start_service_count` | Manual-start Windows service count | `collectServicesViaSCM` (windows) | Background | public | N/A | GREEN | N/A | NO |
| `startup_program_count` | Run/RunOnce registry entry count | `collectStartupPrograms` (windows) | Background | public | N/A | GREEN | N/A | NO |
| `startup_programs_sample` | First 10 startup program names | `collectStartupPrograms` (windows) | Background | public | N/A | GREEN | N/A | NO |
| `system_launch_daemon_count` | System LaunchDaemon plist count | `collectLaunchDaemons` (darwin) | Background | public | N/A | N/A | GREEN | NO |
| `user_launch_daemon_count` | User LaunchDaemon plist count | `collectLaunchDaemons` (darwin) | Background | public | N/A | N/A | GREEN | NO |
| `system_launch_agent_count` | System LaunchAgent plist count | `collectLaunchAgents` (darwin) | Background | public | N/A | N/A | GREEN | NO |
| `user_launch_agent_count` | User LaunchAgent plist count | `collectLaunchAgents` (darwin) | Background | public | N/A | N/A | GREEN | NO |
| `service_info` | Stub (generic/unsupported platforms) | `GenericSoftwareCollector.CollectServices` | Background | public | N/A | N/A | N/A | NO |

---

### 13. Software — Processes

Collected in the background via `collectSoftwareInfo()` → `CollectProcesses`.

| Attribute Key | Description | Collector Method | Path | Sensitivity | Linux | Windows | macOS | GAP |
|---|---|---|---|---|---|---|---|---|
| `current_pid` | Steward process PID | `CollectProcesses` | Background | public | GREEN | GREEN | GREEN | NO |
| `parent_pid` | Steward parent PID | `CollectProcesses` | Background | public | GREEN | GREEN | GREEN | NO |
| `current_uid` | Effective UID | `CollectProcesses` | Background | public | GREEN | N/A | GREEN | NO |
| `current_gid` | Effective GID | `CollectProcesses` | Background | public | GREEN | N/A | GREEN | NO |
| `current_user` | Running user name | `CollectProcesses` | Background | pii | GREEN | GREEN | GREEN | NO |
| `goroutine_count` | Steward goroutine count | `CollectProcesses` | Background | public | GREEN | GREEN | GREEN | NO |
| `total_process_count` | Total running process count | `CollectProcesses` | Background | public | GREEN | GREEN | GREEN | NO |
| `unique_process_users` | Unique user count across processes | `parseProcessStats` / `collectProcessSnapshot` | Background | public | GREEN | GREEN | GREEN | NO |
| `unique_process_commands` | Unique command count across processes | `parseProcessStats` (linux/darwin) | Background | public | GREEN | N/A | GREEN | NO |
| `unique_process_names` | Unique process name count (Windows snapshot) | `collectProcessSnapshot` (windows) | Background | public | N/A | GREEN | N/A | NO |
| `top_processes_by_cpu` | Top 10 processes by CPU usage | `parseTopProcesses` (linux) | Background | public | GREEN | N/A | N/A | NO |
| `top_processes` | Top 5 processes by instance count | `collectProcessSnapshot` (windows) | Background | public | N/A | GREEN | N/A | NO |
| `process_state_R` | Count of processes in R (running) state | `parseProcessStats` (linux) | Background | public | GREEN | N/A | N/A | NO |
| `process_state_S` | Count of processes in S (sleeping) state | `parseProcessStats` (linux) | Background | public | GREEN | N/A | N/A | NO |

Note: `process_state_*` keys are emitted dynamically for each distinct `ps` state character. Only R and S are shown; D, Z, and T are also possible.

---

### 14. Security — Users

Collected in the background via `collectSecurityInfo()` → `CollectUsers`. Linux and Windows store counts only to prevent identity exfiltration; macOS stores samples.

| Attribute Key | Description | Collector Method | Path | Sensitivity | Linux | Windows | macOS | GAP |
|---|---|---|---|---|---|---|---|---|
| `local_user_count` | Local account count | `CollectUsers` | Background | pii | GREEN (`/etc/passwd` or getent) | GREEN (wmic/PS) | N/A | NO |
| `total_user_count` | Total user count including system (macOS dscl) | `parseSystemUsers` (darwin) | Background | pii | N/A | N/A | GREEN | NO |
| `regular_user_count` | Regular user (UID≥500) count (macOS) | `parseSystemUsers` (darwin) | Background | pii | N/A | N/A | GREEN | NO |
| `system_user_count` | System user count (macOS) | `parseSystemUsers` (darwin) | Background | pii | N/A | N/A | GREEN | NO |
| `regular_users_sample` | First 10 regular user names (macOS) | `parseSystemUsers` (darwin) | Background | pii | N/A | N/A | GREEN | NO |
| `logged_in_user_count` | Count of currently logged-in users (macOS) | `collectUserDetails` (darwin) | Background | pii | N/A | N/A | GREEN | NO |
| `logged_in_users` | Currently logged-in user names (macOS) | `collectUserDetails` (darwin) | Background | pii | N/A | N/A | GREEN | NO |
| `recent_login_users` | Last 5 login user names (macOS) | `collectUserDetails` (darwin) | Background | pii | N/A | N/A | GREEN | NO |
| `available_shell_count` | Count of shells in `/etc/shells` (macOS) | `collectLoginShells` (darwin) | Background | public | N/A | N/A | GREEN | NO |
| `available_shells` | Shell paths from `/etc/shells` (macOS) | `collectLoginShells` (darwin) | Background | public | N/A | N/A | GREEN | NO |
| `root_account_locked` | Whether root account is locked | `checkRootLocked` (linux) | Background | public | GREEN | N/A | N/A | NO |
| `domain_joined` | Whether host is domain-joined | `collectDomainMembership` | Background | public | GREEN | GREEN | N/A | YES <!-- GAP: domain_joined is not collected on macOS. DarwinSecurityCollector has no domain membership detection. Hosts enrolled via Enterprise Connect, Jamf Connect, or AD binding via Directory Utility will not report domain membership. --> |
| `domain_name` | AD/LDAP domain name, sanitized | `collectDomainMembership` | Background | pii | GREEN | GREEN | N/A | YES <!-- GAP: domain_name is absent on macOS for the same reason as domain_joined. --> |
| `user_info` | Stub (generic/unsupported platforms) | `GenericSecurityCollector.CollectUsers` | Background | public | N/A | N/A | N/A | NO |

---

### 15. Security — Groups

Collected in the background via `collectSecurityInfo()` → `CollectGroups`. Group names are never stored on Linux or Windows.

| Attribute Key | Description | Collector Method | Path | Sensitivity | Linux | Windows | macOS | GAP |
|---|---|---|---|---|---|---|---|---|
| `local_group_count` | Local group count | `CollectGroups` | Background | public | GREEN (`/etc/group`) | GREEN (wmic/PS) | N/A | NO |
| `local_admins_count` | sudo/wheel (Linux) or Administrators (Windows) member count | `CollectGroups` | Background | public | GREEN | GREEN | N/A | NO |
| `total_group_count` | Total group count (macOS dscl) | `parseSystemGroups` (darwin) | Background | public | N/A | N/A | GREEN | NO |
| `regular_group_count` | Regular (GID≥500) group count (macOS) | `parseSystemGroups` (darwin) | Background | public | N/A | N/A | GREEN | NO |
| `system_group_count` | System group count (macOS) | `parseSystemGroups` (darwin) | Background | public | N/A | N/A | GREEN | NO |
| `regular_groups_sample` | First 10 regular group names (macOS) | `parseSystemGroups` (darwin) | Background | pii | N/A | N/A | GREEN | NO |
| `admin_user_count` | Admin group member count (macOS dseditgroup) | `parseAdminUsers` (darwin) | Background | public | N/A | N/A | GREEN | NO |
| `admin_users` | Admin group member names (macOS) | `parseAdminUsers` (darwin) | Background | pii | N/A | N/A | GREEN | NO |
| `group_info` | Stub (generic/unsupported platforms) | `GenericSecurityCollector.CollectGroups` | Background | public | N/A | N/A | N/A | NO |

---

### 16. Security — Permissions / Encryption / AV

Collected in the background via `collectSecurityInfo()` → `CollectPermissions`.

| Attribute Key | Description | Collector Method | Path | Sensitivity | Linux | Windows | macOS | GAP |
|---|---|---|---|---|---|---|---|---|
| `sudo_installed` | Whether sudo binary is present | `checkSudoInstalled` (linux) | Background | public | GREEN | N/A | N/A | NO |
| `suid_binary_count` | SUID binary count in standard bin dirs (10s timeout) | `collectSUIDBinaries` (linux) | Background | public | GREEN | N/A | N/A | NO |
| `luks_encrypted_devices` | Count of LUKS-encrypted block devices | `collectLUKSState` (linux) | Background | public | GREEN | N/A | N/A | NO |
| `luks_device_names` | LUKS device names, comma-separated | `collectLUKSState` (linux) | Background | public | GREEN | N/A | N/A | NO |
| `bitlocker_enabled` | Whether any BitLocker-protected volume exists | `collectBitLockerState` (windows) | Background | public | N/A | GREEN | N/A | NO |
| `bitlocker_volumes` | BitLocker-protected drive letters, comma-separated | `collectBitLockerState` (windows) | Background | public | N/A | GREEN | N/A | NO |
| `encryption_state` | Unified encryption state key | — | — | public | N/A | N/A | N/A | YES <!-- GAP: No unified encryption_state key exists across platforms. Linux uses luks_encrypted_devices (count), Windows uses bitlocker_enabled (bool). macOS has no encryption state collector at all — FileVault status is not collected by DarwinSecurityCollector. --> |
| `av_products_detected` | Detected AV product names, comma-separated | `collectAVProducts` | Background | public | GREEN (process/path match) | GREEN (WMI SecurityCenter2) | N/A | YES <!-- GAP: av_products_detected is not collected on macOS. DarwinSecurityCollector.CollectPermissions has no AV detection path. --> |
| `sip_status` | SIP (System Integrity Protection) state | `CollectPermissions` (darwin) | Background | public | N/A | N/A | GREEN | NO |
| `gatekeeper_status` | Gatekeeper state (`spctl --status`) | `CollectPermissions` (darwin) | Background | public | N/A | N/A | GREEN | NO |
| `permissions_System` | Permissions string on /System | `collectSystemPermissions` (darwin) | Background | public | N/A | N/A | GREEN | NO |
| `permissions_usr` | Permissions string on /usr | `collectSystemPermissions` (darwin) | Background | public | N/A | N/A | GREEN | NO |
| `permissions_bin` | Permissions string on /bin | `collectSystemPermissions` (darwin) | Background | public | N/A | N/A | GREEN | NO |
| `permissions_sbin` | Permissions string on /sbin | `collectSystemPermissions` (darwin) | Background | public | N/A | N/A | GREEN | NO |
| `permissions_Applications` | Permissions string on /Applications | `collectSystemPermissions` (darwin) | Background | public | N/A | N/A | GREEN | NO |
| `etc_permissions` | Permissions string on /etc | `collectKeyDirectoryPermissions` (darwin) | Background | public | N/A | N/A | GREEN | NO |
| `tmp_permissions` | Permissions string on /tmp | `collectKeyDirectoryPermissions` (darwin) | Background | public | N/A | N/A | GREEN | NO |
| `var_permissions` | Permissions string on /var | `collectKeyDirectoryPermissions` (darwin) | Background | public | N/A | N/A | GREEN | NO |
| `hyperv_role_installed` | Whether the Hyper-V role (vmms service) is installed | `collectHyperVInfo` (windows) | Fast | public | N/A | N/A | GREEN | NO |
| `hyperv_enabled` | Whether the Microsoft-Hyper-V-All feature is enabled (DISM; elevation-gated, omitted with a WARN when unavailable) | `collectHyperVInfo` (windows) | Fast | public | N/A | N/A | GREEN | NO |
| `virtualization_type` | Detected hypervisor when running as a guest, else `none` | `collectVirtualizationInfo` (linux) / `collectHyperVInfo` (windows) | Fast | public | GREEN | N/A | GREEN | NO |
| `virtualization_role` | `guest` / `host` / `baremetal` | `collectVirtualizationInfo` (linux) / `collectHyperVInfo` (windows) | Fast | public | GREEN | N/A | GREEN | NO |
| `hyperv_host` | Whether this Linux host runs the mshv hypervisor (`/dev/mshv` or mshv module) | `collectVirtualizationInfo` (linux) | Fast | public | GREEN | N/A | N/A | NO |
| `vm_inventory` | Summary of hosted virtual machines | — | — | tenant-sensitive | N/A | N/A | N/A | NO <!-- N/A — deferred to module Monitor epic #2110: VM presence/state is observed via the hyperv module Get() + Monitor capability, not a DNA snapshot. VM names are tenant-sensitive and must never enter DNA; a running-VM count is volatile telemetry that would churn the DNA hash. --> |
| `permission_info` | Stub (generic/unsupported platforms) | `GenericSecurityCollector.CollectPermissions` | Background | public | N/A | N/A | N/A | NO |

---

### 17. Security — Certificates

Collected in the background via `collectSecurityInfo()` → `CollectCertificates`.

| Attribute Key | Description | Collector Method | Path | Sensitivity | Linux | Windows | macOS | GAP |
|---|---|---|---|---|---|---|---|---|
| `certificate_info` | Stub value emitted by `LinuxSecurityCollector` | `LinuxSecurityCollector.CollectCertificates` | Background | public | RED | N/A | N/A | YES <!-- GAP: LinuxSecurityCollector.CollectCertificates delegates entirely to GenericSecurityCollector, emitting certificate_info="generic_collector_limited". No system certificate store is enumerated on Linux (e.g., /etc/ssl/certs, ca-certificates package state, or NSS database). --> |
| `cert_root_count` | Root CA cert count in system store (CryptoAPI) | `CollectCertificates` (windows) | Background | public | N/A | GREEN | N/A | NO |
| `cert_intermediate_count` | Intermediate CA cert count | `CollectCertificates` (windows) | Background | public | N/A | GREEN | N/A | NO |
| `cert_personal_count` | Personal cert count (My store) | `CollectCertificates` (windows) | Background | public | N/A | GREEN | N/A | NO |
| `certificates_System_count` | System keychain cert count (macOS) | `collectKeychainCertificates` (darwin) | Background | public | N/A | N/A | GREEN | NO |
| `certificates_System_sample` | System keychain cert label sample | `collectKeychainCertificates` (darwin) | Background | public | N/A | N/A | GREEN | NO |
| `certificates_login_count` | Login keychain cert count (macOS) | `collectKeychainCertificates` (darwin) | Background | public | N/A | N/A | GREEN | NO |
| `certificates_login_sample` | Login keychain cert label sample | `collectKeychainCertificates` (darwin) | Background | public | N/A | N/A | GREEN | NO |
| `keychain_count` | Total keychain count (`security list-keychains`) | `CollectCertificates` (darwin) | Background | public | N/A | N/A | GREEN | NO |
| `code_signing_certificates` | Code signing identity count | `collectCodeSigningCertificates` (darwin) | Background | public | N/A | N/A | GREEN | NO |
| `developer_id_certificates` | Developer ID cert count | `collectCodeSigningCertificates` (darwin) | Background | public | N/A | N/A | YELLOW | NO |

---

## GAP Summary

### Attributes documented in `steward-operating-model.md` but not fully collected

The operating model doc (lines 221–226) documents four DNA categories. This table maps each documented example to actual collection status.

| Documented Example | Status |
|---|---|
| "Firewall status" | Platform-specific keys only. No unified `firewall_state` key. Linux `firewall_state=unknown` is a degraded fallback, not a reliable status. |
| "Encryption state" | Platform-specific: `bitlocker_enabled` (Windows), `luks_encrypted_devices` (Linux). macOS has no encryption collection. No unified key. |
| "Admin accounts" | Counts only on Linux/Windows (`local_admins_count`). Names on macOS only (`admin_users`). No canonical cross-platform key. |
| Hyper-V role (epic notes) | **Not collected on any platform.** |
| VM inventory (epic notes) | **Not collected on any platform.** |

### Per-platform gap register

| Gap | Affected Platform(s) | Responsible Collector | Status |
|---|---|---|---|
| `domain_joined` / `domain_name` not collected | macOS | `DarwinSecurityCollector.CollectUsers` | Open |
| `av_products_detected` not collected | macOS | `DarwinSecurityCollector.CollectPermissions` | Open |
| `encryption_state` (FileVault) not collected | macOS | `DarwinSecurityCollector.CollectPermissions` | Open |
| Linux certificate store not enumerated (`certificate_info` = stub) | Linux | `LinuxSecurityCollector.CollectCertificates` | Open |
| `firewall_state` unreliable when ufw/iptables absent | Linux | `LinuxNetworkCollector.CollectFirewall` | Open |
| No unified `firewall_state` key (Windows uses per-profile keys only) | Windows | `WindowsNetworkCollector.CollectFirewall` | Open |
| `hyperv_role` not collected | Windows | `WindowsHardwareCollector.collectHyperVInfo` (now `hyperv_role_installed` + `hyperv_enabled`) | Resolved (#1950) |
| `vm_inventory` not collected | Windows | N/A — deferred to module Monitor epic #2110 (observed via module `Get()` + `Monitor`, not DNA) | Resolved (#1950) |
| `system_serial_number` not collected | Windows, macOS | `WindowsHardwareCollector`, `DarwinHardwareCollector` | Open |
| No unified `encryption_state` key | All | Multi-platform | Open |

### Sanitization register

The following attributes contain raw values that must be sanitized before any log output. Values marked "YES at collection" are sanitized in the collector before being stored in `dna.Attributes`; downstream callers reading `dna.Attributes` directly still receive sanitized strings. Attributes marked "NO — raw" are stored as-is and must be sanitized at the consumption point.

| Attribute | Sanitized at collection? | Code location |
|---|---|---|
| `default_gateway` | YES | `network_linux.go:65`, `network_windows.go:81` |
| `dns_servers` | YES | `network_linux.go:118`, `network_windows.go:156` |
| `dns_search_domains` | YES | `network_linux.go:121` |
| `dns_domain` | YES | `network_windows.go:177` |
| `domain_name` | YES | `security_linux.go:135` (realm), `:144` (sssd), `security_windows.go:106` |
| `av_products_detected` (Windows) | YES | `security_windows.go:190` |
| `ip_addresses`, `primary_ip` | NO — raw | Callers must sanitize before logging |
| `mac_addresses`, `primary_mac` | NO — raw | Callers must sanitize before logging |
| `hostname` | NO — raw | Callers must sanitize before logging |
| `dns_nameservers` (macOS) | NO — raw | `parseDNSConfig` stores raw; callers must sanitize before logging |
| `dns_servers_wi-fi`, `dns_servers_ethernet` (macOS) | NO — raw | `collectDNSServers` stores raw; callers must sanitize before logging |
| `search_domains_wi-fi`, `search_domains_ethernet` (macOS) | NO — raw | `collectSearchDomains` stores raw; callers must sanitize before logging |
| `regular_users_sample`, `logged_in_users`, `admin_users` | NO — raw | Never log; pii |

---

## Must-Collect Attributes

The following attributes are the minimum set that a compliant steward binary MUST emit. Story 5's integration test will assert the presence and non-empty value of each attribute on the corresponding platform. An attribute is "must-collect" if its absence prevents device identity, controller targeting, or drift detection from functioning.

### All platforms

| Attribute Key | Expected value | Rationale |
|---|---|---|
| `timestamp` | RFC3339 string | Required for cache validity and delta freshness checks |
| `runtime_os` | `linux`, `windows`, or `darwin` | Required for platform-specific config targeting |
| `runtime_arch` | `amd64` or `arm64` | Required for binary delivery targeting |
| `hostname` | non-empty string | Required for device display and log correlation |
| `num_cpu` | integer string ≥ 1 | Core identity signal; used in system ID derivation |
| `primary_mac` | MAC address string | Primary input to `generateSystemID()` — absence produces a time-varying ID |
| `ip_addresses` | non-empty string | Required for network reachability targeting |
| `network_interface_count` | integer string ≥ 1 | Required for connectivity classification |
| `default_gateway` | IP address string | Required for network topology classification |
| `os` | non-empty string | Required for OS-level config targeting |

### Linux

| Attribute Key | Expected value | Rationale |
|---|---|---|
| `os_name` OR `os_pretty_name` | non-empty string | Required for distro-specific config targeting |
| `kernel_version` | non-empty string | Required for kernel-version-based policy targeting |
| `memory_total_gb` | decimal string | Required for resource capacity targeting |
| `local_user_count` | integer string ≥ 1 | Security baseline assertion |
| `domain_joined` | `"true"` or `"false"` | Required for AD-based policy targeting |
| `av_products_detected` | non-empty string | Security compliance baseline (value `"none"` is acceptable) |
| `luks_encrypted_devices` | integer string ≥ 0 | Encryption baseline |
| `ufw_firewall_state` OR `iptables_rule_count` OR `firewall_state` | non-empty string | At least one firewall signal must be present |

### Windows

| Attribute Key | Expected value | Rationale |
|---|---|---|
| `windows_caption` OR `windows_version` | non-empty string | Required for Windows version targeting |
| `windows_build_number` | integer string | Required for patch-level targeting |
| `memory_total_gb` | decimal string | Required for resource capacity targeting |
| `local_user_count` | integer string ≥ 1 | Security baseline assertion |
| `domain_joined` | `"true"` or `"false"` | Required for AD-based policy targeting |
| `av_products_detected` | non-empty string | Security compliance baseline (value `"none"` on Server SKU is acceptable) |
| `bitlocker_enabled` | `"true"` or `"false"` | Encryption baseline |
| `windows_firewall_domain_profile` | `"enabled"` or `"disabled"` | Firewall baseline |

### macOS

| Attribute Key | Expected value | Rationale |
|---|---|---|
| `macos_version` | version string (e.g., `14.5`) | Required for macOS version targeting |
| `hardware_model` | non-empty string (e.g., `MacBookPro18,3`) | Required for hardware-specific policy targeting |
| `memory_total_gb` | decimal string | Required for resource capacity targeting |
| `total_user_count` | integer string ≥ 1 | Security baseline assertion |
| `sip_status` | `"enabled"`, `"disabled"`, or `"unknown"` | Security integrity baseline |
| `gatekeeper_status` | non-empty string | Security integrity baseline |
| `macos_firewall_state` | non-empty string | Firewall baseline |

---

## Gap Tracking

Stories that resolved gaps in this document:

| Story | Gap Resolved |
|---|---|
| #1946 | Linux and Windows routing, DNS, and firewall attributes implemented (previously RED/GAP via `GenericNetworkCollector`) |
| #1939 | Linux and Windows security collectors implemented: `domain_joined`, `domain_name`, `luks_*`, `bitlocker_*`, `av_products_detected`, `local_admins_count` (previously RED/GAP via `GenericSecurityCollector`) |
