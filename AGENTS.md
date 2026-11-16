# Разрешения Игната

21 октября 2026 Игнат явно разрешил push собственных проверенных изменений
и создание новых тегов в этом репозитории без повторного подтверждения.
Это разрешение не расширяет объём работы и не разрешает переписывать
опубликованные теги или включать чужие изменения.

# Temperature backend

`cargo run -p xtask -- lhm --release` builds the Windows service and deploys the
NativeAOT backend next to its executable. The build requires .NET SDK 10.0.115
and the Windows C++ NativeAOT toolchain. It checks out LibreHardwareMonitor
commit `2808d80564b6761e1b01f42fabfd966ed695fcbc` into `native/lhm/.source` and uses
the committed NuGet lock file. Native output lives in `target/lhm-native-aot`;
`CARGO_TARGET_DIR` selects the Rust output directory. Deploy the generated DLLs
and `lhm-licenses` directory together with the service executable.

The build validates and applies `native/lhm/skip-unused-nvml.patch`, then reverses
it in finally so the cached upstream source is pristine again. The patch adds an
opt-out switch to NvidiaML.Initialize. This bridge enables it before Computer.Open:
NVIDIA temperatures retain LHM's NVAPI path, while NVML-only PCIe, GPU power and
memory sensors are not exported by this bridge. CPU package watts are unaffected.
The patch and modification notice are deployed with the original LHM licenses.
Do not restore NVML just to populate readings the service never publishes.

The optional `uniproc-lhm.dll` exports ABI version 1: `lhm_abi_version`, `lhm_open`,
`lhm_update`, `lhm_read`, and `lhm_close`. `lhm_read` returns the required UTF-8 JSON
byte length without a terminator; it copies only when the supplied capacity fits.
It reads the cached snapshot and never polls hardware itself. The NativeAOT library
stays loaded for the process lifetime; closing it releases the LHM Computer.

`MachineMetric::Temperatures` requests CPU, GPU, DIMM, and storage temperature
readings with original LHM device and sensor identifiers. The worker polls once
per second while any subscriber requests temperatures. RPC returns its latest
snapshot; a snapshot older than five seconds becomes Error with no devices.
Worker shutdown waits at most two seconds. Missing DLLs report Unavailable;
backend and per-device errors retain diagnostic strings. Missing readings are
None; zero is a valid reading. DIMM/NVMe limits and CPU distance-to-TjMax are excluded.

While polling, the LHM bridge requests a blocking compacting aggressive full GC
at most once per fifteen seconds and after closing its Computer. This returns unused
managed heap pages without trimming the process working set. Collection runs on
the existing worker; it can delay that snapshot and has no hard pause-time bound.
The five-second stale cutoff remains unchanged. Measurements and limits are in
`diagnostics/memory/20261116/RESULTS.txt`.

Hardware coverage depends on LHM, installed drivers (including PawnIO for some
CPU/RAM access), and the machine. NativeAOT warnings from System.Management and
other dependencies are not proof of support. Run `cargo run --example temperatures`
against the deployed LocalSystem service to inspect actual availability and values.
`Remote::can_temperatures()` reports peer support; requests to Windows protocol
versions older than 2.11 omit this metric. Per-device error text uses protocol 2.12.

# VM memory

VM hosts use the ordinary Windows working-set measurement. The service does not
walk VM memory maps, read VM working-set pages or deduplicate .vmem views.
VmHost classification remains independent of memory measurement.
The former wire metric/column slots are reserved and are never collected.

# CPU name

`MachineSample.cpu_package_power_watts: Option<f64>` is projected under the existing
`MachineMetric::Temperatures` demand. It shares the LHM temperature worker's coherent
one-second snapshots and five-second stale cutoff. Missing, failed or stale readings
remain None; finite nonnegative readings, including zero, are valid watts.
The native bridge selects only CPU Power sensors named CPU Package (Intel) or Package
(AMD). On multiple CPU hardware devices the value is the sum only when every device
has exactly one valid package reading. Cores, Graphics, Memory, Platform and TDP are
not substitutes. ABI 1 is unchanged; older bridge JSON and older peers omit power.
`cargo run --example cpu_power -- --require-reading` validates ten live IPC samples.
`dotnet run --project native/lhm-tests/PowerTests.csproj -c Release` checks native selection.

`MachineSample.cpu_name: Option<SmolStr>` is static metadata included with
`MachineMetric::Cpu`, independently of counter or temperature availability.
The core reads `ProcessorNameString` from HKLM's CentralProcessor/0 key once
per process through winreg and trims surrounding whitespace. Empty values and
read failures produce None. CPU times and `MachineCpu` remain unchanged.
The additive Windows protocol 2.14 `cpuName` text defaults to unavailable for
older peers; no new metric or peer filtering is required.

# Fatal service diagnostics and recovery

Service stderr shares the live log file handle, so Rust allocation failures and
panics reach `agent.log`, rotated to `agent.previous.log` on the next start.
The service defaults its own RUST_BACKTRACE to 1 and RUST_LIB_BACKTRACE to 0
only when each was unset: panic stacks remain enabled, ordinary error reports
do not initialize the persistent DbgHelp symbol cache. Explicit diagnostic values
remain supported. This changes no machine or user environment setting.
Release diagnostics can use an
explicit linker MAP artifact without enabling PDBs or changing build profiles.

A service with no configured failure actions is initialized at startup with
restart delays of 10, 30, and 60 seconds, resetting after 24 hours without failure.
SCM repeats the final action for later failures. Existing nonempty policies are
preserved. Installation uses the same defaults. Normal requested stops remain
stops. Recovery is applied by the service to its own SCM record as LocalSystem.

The 2026-11-05 15:14:35 Moscow v0.28.0 crash matched Rust's allocation-error
handler at RVA 0x6111b1 in PE timestamp 6AEC6C20. The old stderr was not captured;
WER retained no dump, so the failed byte count and allocation stack are unknown.
This diagnostic/recovery change does not establish or fix the source of that
allocation failure. No unproven queue or buffer rewrite was included.

# CPU parity metadata

Windows protocol 2.15 (uniproc-protocol v0.24.0) adds `system_stats` and
`cpu_inventory` to `MachineSample` under the existing `MachineMetric::Cpu`.
Old peers leave both groups absent; no new requested metric or peer gate exists.
`MachineSystemStats` has atomic GetPerformanceInfo process/thread/handle totals
and GetTickCount64 boot uptime in milliseconds, including sleep. A failed counts
query leaves the whole group absent, including uptime; zeros remain valid.

`CpuInventory` is an Arc cached on its first read for the process lifetime.
Package/core/cache relationships use GetLogicalProcessorInformationEx, and
logical processor count covers all active groups. Counts describe active topology
at the cached read, not installed/offline hardware. Cache totals count each native
cache relationship once; L1 sums Data and Instruction or Unified cache records.
Failures can leave individual fields absent. The variable-length SDK records are
bounded and validated. Base MHz uses Intel CPUID leaf 0x16 EAX bits 15:0 when
available and nonzero. Otherwise Intel's CPUID brand-string frequency suffix is
used as documented by the Intel SDM. Both paths require GenuineIntel; the brand
path checks extended-leaf support and validates its frequency suffix. Missing or
unsupported values remain unavailable. Current, maximum and boost frequency are
never substituted for base frequency, and the UI receives the resolved number.

Virtualization hardware support means the visible Intel VMX/AMD SVM CPUID feature,
not a claim about features hidden by another layer. A detected hypervisor leaves
hardware and firmware fields unknown. Absent/unknown capability also leaves
firmware unknown; otherwise firmware availability uses the Windows processor flag.
Inventory numeric absence uses MAX defaults on the wire; three optional booleans
use Toggle unknown/off/on. Valid zero and false are preserved.

`cargo run --example cpu_inventory` checks a service after its separately
approved update; `-- --allow-missing` also accepts older peers' absent groups.
Read-only core tests can validate current-machine topology without starting or
restarting the service, ETW sessions, or the UI.

# Full diagnostic dump

CPU inventory additionally carries optional `details` in Windows protocol 2.16
(uniproc-protocol v0.25.0). Vendor and decoded family/model/stepping come from
raw-cpuid and share the cached diagnostic identity. Microcode revision remains
unavailable without a verified source. Zero is distinct from unavailable.
Instruction sets use the standard Rust OS-usable detector, not raw advertised
CPUID flags. The scope is `selected_x86_features`, a sorted selection rather than
an exhaustive ISA inventory. `None`, a known empty list and a populated list stay
distinct. Older peers omit Details; no new metric request or peer filter exists.

`uniproc-windows-agent dump --format json --output report.json` asks the running
service's authenticated loopback diagnostics endpoint to collect every metric.
The access record is administrator-only. `--format summary` is the default;
`--format text` prints all field observations. `--input report.json` renders a
saved report without collecting again or requiring elevation. See DIAGNOSTICS.md.
Both the service endpoint and offline CLI output pseudonymize identities, process
labels, paths, arguments and free-form errors by default. Original text needs
explicit `--include-sensitive`. Aliases are per-report, consistent across duplicate
values and service keys, and no reverse mapping is exported. Numeric raw values
remain unchanged. Hardware, versions and timing can still fingerprint a machine;
do not describe this as guaranteed anonymity. Historical private reports are not
silently rewritten.

All sampling and CIM inventory run inside the service. The command never starts
another monitor. The core derives JSON Schema and generates column metadata from
the sampling declaration. New raw fields are serialized automatically; numeric
fields with unknown diagnostic units are explicitly unclassified. Unknown causes
of null values and sentinels are not inferred. Current ETW health is distinct from
unreported startup history and unavailable per-field error details.

Raw samples, coherent process/service lists, process instances, retained process
events, source context, field availability, validations and counter intervals are
preserved. No new power-plan or battery source is collected. Existing monitoring
model fields remain present. Only one bounded diagnostic collection runs at once;
limits fail explicitly instead of returning an apparently complete truncated dump.

# Memory ownership

Persistent signature verdicts use Store point reads/writes at the existing
signatures/verdicts/path key. Do not construct a resident ReactiveMap for the
entire historical catalog. The image worker already caches validated current
verdicts. Stamp/resolver checks, old disk entries, five-second debounce and
shutdown save_now remain part of the cache behavior.

The native build additionally pins DiskInfoToolkit 2.2.2 source commit
073a31312b9f5147340488e551e06df5f3ab9715 in native/lhm/.diskinfo-source.
It applies diskinfo-project.patch to LHM and stream-pci-ids.patch to that
project, then reverses all applied patches in finally. PCI names are resolved
from the original embedded catalog for the requested IDs without retaining
its entire object graph. PciLookupTests compares names and missing results
with the original NuGet assembly on a distributed set of IDs. The build runs
this test and ships both projects' source links, patches and licenses.
Private resident pages and logical live allocation sizes are different
measurements. Physical totals must be taken from one VMMap/page snapshot;
do not add live allocation categories to working-set categories.

Signature verdicts expire 24 hours from saved_at_ms, without renewal on reads.
The existing image worker removes expired direct entries at startup and hourly;
lookup expiry also deletes immediately through the existing buffered writer.
Old records without timestamps expire; future timestamps miss but are not
mass-deleted as old. Hot verdicts retain the disk write timestamp. Cleanup
holds only a temporary keys list, not a resident projection of all values.
