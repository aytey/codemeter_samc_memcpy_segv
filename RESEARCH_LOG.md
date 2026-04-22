# CodeMeter crash research log

This repository is a working history of the CodeMeter crash research effort.
It contains vendor-reportable findings, failed or saturated fuzzing
directions, reduction notes, and the tooling that was built along the way.

## Current state

As of 2026-04-22, the client-facing SAMC work has one confirmed crash class:

```text
memcpy_8f431d_prefixed_hello
libc memcpy/memmove
CodeMeterLin+0x8f431d
CodeMeterLin+0x8f41b5
CodeMeterLin+0x8f5491
CodeMeterLin+0x8f3c36
CodeMeterLin+0x87647e
CodeMeterLin+0x86271c
CodeMeterLin+0x805ab5
```

The crash is reached by routing a parser-visible SAMC plaintext into opcode
`0x5e`. The vulnerable parser then accepts the u32 at payload offset `+0xc`
as a copy length without a sufficient bound, eventually reaching the memcpy at
`CodeMeterLin+0x8f431d`.

There are two practical reproduction routes into the same crash:

| route | shape | repro |
|---|---|---|
| Fresh HELLO | `5e00000000 || canonical HELLO` | `fuzzer/repro_prefixed_hello.py` |
| Post-HELLO ACK | normal HELLO, extract SID, then `5e0000000000000000000000000000 || 0b000000 || SID` | `fuzzer/repro_prefixed_ack_standalone.py` |

The older captured HELLO prefix `5e355ed6f2` is still historically important:
it was the first reduced deterministic trigger. It is no longer believed to be
special. Zero-tail prefixes reach the same parser layout and are simpler.

## Chronology

### Initial SAMC fuzzing

The original stateful SAMC fuzzer exercised valid encrypted sessions against a
live `CodeMeterLin` on `127.0.0.1:22350`. It mutated HELLO, ACK, and the
post-handshake `0x64` request and found repeated crashes in libc
`memcpy`/`memmove` with return address `CodeMeterLin+0x8f431d`.

The first crash artifacts were noisy because every worker noticed the daemon
death and saved whatever it was sending at the time. This is why early
`crash_*.bin` files should be treated as crash-adjacent until confirmed by the
supervisor ring buffers.

### Core and disassembly triage

The full-memory core analysis established that the immediate crash is a source
over-read, not a destination overflow. The destination allocation succeeds; the
source pointer walks beyond the readable mapping while `memcpy` is copying an
attacker-influenced length.

Useful analysis documents:

- `TRIAGE.md` reconstructs the register state and class layout from the core.
- `ROOT_CAUSE.md` explains the tag-4 to tag-5 dispatch-helper path.
- `TIER_B.md` identifies opcode `0x5e`, the dispatch map, and the input u32 at
  `*(rbx+0xc)`.
- `BUG_CLASS_AUDIT.md` checks sibling unbounded-copy helper sites and concludes
  that the confirmed site is the only one reached by the SAMC opcode map.

### Attribution supervisor and first deterministic HELLO

`fuzzer/samc_light_supervisor.py` was added to centralize crash detection and
preserve per-worker ring buffers. It isolated a deterministic HELLO trigger
from:

```text
/home/avj/clones/ax_fuzz/output/light_supervisor_mixed2_20260421_103043
```

The attributed historical mutation inserted these five bytes at the beginning
of the canonical HELLO:

```text
5e 35 5e d6 f2
```

That shifted the HELLO so the parser-visible u32 at offset `0x0c` became
`0x28000010`, which is stored at `this+0x68` and reaches the memcpy length.

### One-hour namespace farm

`fuzzer/fuzz_farm_launcher.py` and `fuzzer/fuzz_farm_namespace_init.sh` were
added to run multiple isolated `CodeMeterLin` daemons on the same host using
Linux namespaces.

The first 8-farm run on 2026-04-21 produced:

```text
8 farms x 10 workers
1 hour wall clock
23.2M attempts
67 crashes
0 new signatures
all classified as memcpy_8f431d_prefixed_hello
```

This run established that ACK-only fuzzing can reach the same crash without
mutating the HELLO frame, while `0x64` request fuzzing did not reach the crash
under the byte-level mutator. Details are in `MULTI_INSTANCE_FUZZING.md`.

### ECDH and non-loopback reproduction

The repros were extended to support the ECDH-selected application channel used
against non-loopback targets. The standalone HELLO reproducer was created so
the crash can be demonstrated without importing project-local session data.

Relevant scripts:

- `fuzzer/repro_prefixed_hello.py`
- `fuzzer/repro_prefixed_hello_standalone.py`

### Six-hour ECDH prefix campaign

`fuzzer/samc_ecdh_prefix_supervisor.py` and
`fuzzer/samc_veth_farm_launcher.py` were used for a purpose-built prefix
campaign over the ECDH-selected channel:

```text
output root: /home/avj/clones/ax_fuzz/output/veth_farms/20260422_013945
log:         /home/avj/clones/ax_fuzz/output/veth_prefix_6h_logs/run_20260422_013945.log
farms:       8
workers:     8 per farm
modes:       ecdh_prefix_hello, ecdh_prefix_ack
attempts:    1,398,462
classified:  360 crashes
new sigs:    0
```

All classified cores landed in the same `memcpy_8f431d_prefixed_hello`
signature. The campaign did not discover a new bug class, but it simplified
the repro inputs:

- HELLO: `5e00000000 || canonical HELLO`
- ACK: `5e` plus zero padding before canonical ACK, especially the 15-byte
  prefix form

The apparent `opcode=0x22,prefix_len=2` no-response events are not currently
treated as a confirmed distinct crash. They occur near crashes, but the core
evidence and repeated reproductions still point at the opcode-`0x5e` route.

### ACK repro consolidation

The ACK route is now captured by:

- `fuzzer/repro_ack_0x5e.py`, which uses project-local helpers and supports
  older captured sample prefixes.
- `fuzzer/repro_prefixed_ack_standalone.py`, which builds HELLO and ACK
  internally, extracts the live SID, and sends the simplified zero-tail ACK
  prefix over PSK or ECDH.

## Open directions

- Treat the opcode-`0x22` observations as a separate parser/no-response
  candidate only if a single-worker confirmation produces a new core or a
  different signature.
- Continue daemon-to-server protocol fuzzing separately from the SAMC
  client-facing crash class. The DS tooling exists, but it should not be
  conflated with the opcode-`0x5e` SAMC crash until it produces its own
  signature.
- For finding additional SAMC bugs, avoid immediately rediscovering opcode
  `0x5e` by filtering known prefix shapes or running narrowed campaigns such
  as structurally aware `0x64` request fuzzing.
