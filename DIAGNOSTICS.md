# Service diagnostic dump

Run on the monitored Windows computer from an administrator terminal:

```powershell
uniproc-windows-agent.exe dump
uniproc-windows-agent.exe dump --format json --output diagnostic.json
uniproc-windows-agent.exe dump --format text --output diagnostic.txt
uniproc-windows-agent.exe dump --input diagnostic.json --format text --output diagnostic-rendered.txt
uniproc-windows-agent.exe dump --duration-ms 5000 --interval-ms 1000 --format json --output diagnostic-5s.json
uniproc-windows-agent.exe dump --include-sensitive --format json --output diagnostic-private.json
```

The command reads the running service's protected loopback access record. The
service collects the report; the command does not start a second monitor, ETW
session, or UI. The installed service must include the diagnostic endpoint.
Existing output files are preserved. JSON is the complete exchange format;
summary and full text render that same report. `--input` renders an existing JSON
report without contacting the service or requiring elevation. Raw counters remain exact JSON
integers. Formatted values use diagnostic IEC units and are independent of UI
localization. CPU percentages use all active logical processors, without Task
Manager's frequency adjustment.

The default requests all process and machine metrics for four observations at a
one-second interval. Process passports, states, service lists, process event
history, sparse GPU-engine counters and health accompany the samples. Frames
preserve their original list tags, PIDs and sequence numbers. Current SCM statuses are queried
separately after sampling, retaining exit codes, checkpoints, wait hints and exact
Win32 query errors. The snapshot lists and changes remain intact. Rate joins use
process instances and adapter/engine identities. Rates preserve both integers,
the actual sample interval and the integer delta. Decreasing counters produce a
reset status unless their catalog explicitly declares wrapping.

The core JSON Schema describes every nested model field. Process column metadata
is generated from the same declaration that samples the columns, including units,
counter semantics and sentinel rules. Coverage lists every requested column and
machine group, including unavailable groups. Unavailable scalar children of an
object remain represented even when its entire source group is null. Empty
device arrays mean no returned entities; they are not invented device records.
New serialized fields enter the dump automatically; unknown numeric units are
reported as unclassified rather than assigned an invented unit.

Availability, validation, source errors, legitimate zeros, unknown values and
no-data sentinels remain distinct. A null or sentinel alone cannot establish
whether Windows denied access or a driver lacks support. Such reasons remain
unknown. Existing ETW session states and loss counters are reported; historical
startup failures and RPC client reconnection history are not retained by the
current monitoring API and are explicitly described as unreported.

The service adds Windows edition/build/UBR, architecture, CPU identity and processor
groups, hypervisor and VBS/HVCI information, GPU/disk/network inventory and driver
versions through Windows CIM. Each query carries its own status and error.
Context inventory has its own collection duration; it is not an atomic sample of
the machine. Hardware identity is what Windows exposes, not proof of the physical
host behind a hypervisor. Temperature backend file versions and hashes complement
the actual sensor statuses and error messages in machine samples.

No power-plan or battery inventory is collected. Existing process throttling and
GPU power fields remain in the monitoring models. Computer/user names, serial
numbers and MAC addresses are not requested for system inventory.

Output is pseudonymized by default, both inside the service and when the CLI reads
an older JSON report. User and service identities, process labels, arguments,
paths, device identifiers and free-form errors are replaced with per-report
aliases. Corresponding values and service keys in raw frames, events, field paths,
formatted strings and issues share aliases. The reverse mapping is not exported.
Numeric raw counters remain exact. Replaced field observations have `redacted:true`;
the report's `privacy` section records this policy. This is pseudonymization, not
a guarantee of anonymity: timestamps, hardware models, OS/driver versions and
numeric measurements are retained and can fingerprint a computer.

Original text requires explicit `--include-sensitive`. With `--input`, that flag
preserves whatever the input contains; it cannot recover already removed text.
Old reports are not overwritten or automatically sanitized in place. In particular,
the first local verification capture predates this default and remains private.

One collection runs at a time. Requests are limited to 30 seconds, 16 observations,
64 MiB of raw data and 500000 field observations. Exceeding a limit returns an
explicit error rather than a silently truncated report. The Windows inventory
query has a 45-second deadline. A sample that does not arrive within 15 seconds
fails collection. The CLI bounds the complete request and response size too.
