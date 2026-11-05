# Разрешения Игната

21 октября 2026 Игнат явно разрешил push собственных проверенных изменений
и создание новых тегов в этом репозитории без повторного подтверждения.
Это разрешение не расширяет объём работы и не разрешает переписывать
опубликованные теги или включать чужие изменения.

# Temperature backend

`cargo run -p xtask -- lhm --release` builds the Windows service and deploys the
NativeAOT backend next to its executable. The build requires .NET SDK 10.0.114
and the Windows C++ NativeAOT toolchain. It checks out pristine LibreHardwareMonitor
commit `2808d80564b6761e1b01f42fabfd966ed695fcbc` into `target/lhm-source` and uses
the committed NuGet lock file. Native output lives in `target/lhm-native-aot`;
`CARGO_TARGET_DIR` selects the Rust output directory. Deploy the generated DLLs
and `lhm-licenses` directory together with the service executable.

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

Hardware coverage depends on LHM, installed drivers (including PawnIO for some
CPU/RAM access), and the machine. NativeAOT warnings from System.Management and
other dependencies are not proof of support. Run `cargo run --example temperatures`
against the deployed LocalSystem service to inspect actual availability and values.
`Remote::can_temperatures()` reports peer support; requests to Windows protocol
versions older than 2.11 omit this metric. Per-device error text uses protocol 2.12.
