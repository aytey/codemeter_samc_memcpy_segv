# CodeMeter `CodeMeterLin` SIGSEGV in samc request handler

**Severity**: Denial of Service (remote, unauthenticated — local-TCP scope)
**Reporter**: Vector Informatik GmbH
**Target**: `CodeMeter-8.40.7154-505.x86_64` (CodeMeterLin build 8.40e of 2026-Mar-06 / Build 7154)
**Binary sha256**: `6bf82aa09b7f9696b4bf7535a7cb9a2fee62be5220952f2c237b6c73cbe09917`
**Host OS**: openSUSE Tumbleweed (Kernel 6.19.3-1-default), x86_64
**Status**: Reliably reproduced under concurrent-session fuzzing; single-session
           deterministic repro not yet isolated (see "Reproducibility" below).

## Summary

The CodeMeter daemon (`/usr/sbin/CodeMeterLin`) crashes with `SIGSEGV` inside
`__memcpy_evex_unaligned_erms` (libc) when processing samc-protocol requests
from concurrent clients. All observed crashes share the same return address
`CodeMeterLin + 0x8f431d`, indicating a single bug site.

Disassembly around the crash point shows a memcpy whose length (`%rbx`) is
validated only against a signed-negative case; the caller does not bound the
length against any reasonable maximum, and does not verify it against the
source buffer size.

```
 8f42f6:  test %rbx, %rbx
 8f42f9:  js   8f4b1f               ; only rejects signed-negative lengths
 8f42ff:  mov  %rbx, %rdi           ; use %rbx as allocation size
 8f4302:  call 8f3b70               ; allocator → dst ptr in %rax
 8f4307:  mov  %rax, %r14
 8f430a:  cmp  %r12, %rbp
 8f430d:  je   8f431d
 8f430f:  mov  %r14, %rdi           ; memcpy dst
 8f4312:  mov  %r12, %rsi           ; memcpy src
 8f4315:  mov  %rbx, %rdx           ; memcpy len (no upper bound)
 8f4318:  call 3acd00 <memcpy@plt>  ; <<< SEGV in libc memcpy
 8f431d:  …                         ; return address observed in all cores
```

Full disassembly: [`disasm/crash_site_0x8f431d.txt`](disasm/crash_site_0x8f431d.txt)

## Crashing stack (representative)

```
#0  __memcpy_evex_unaligned_erms          libc.so.6 + 0x1872a0
#1  CodeMeterLin + 0x8f431d               <- PC after the bad memcpy
#2  CodeMeterLin + 0x8f41b5
#3  CodeMeterLin + 0x8f5491
#4  CodeMeterLin + 0x8f3c36
#5  CodeMeterLin + 0x87647e               <- probable dispatcher
#6  CodeMeterLin + 0x86271c
#7  CodeMeterLin + 0x805ab5
#8  CodeMeterLin + 0x803884
#9  CodeMeterLin + 0x7fd921
#10 CodeMeterLin + 0x7fa52f
#11 CodeMeterLin + 0x7f90c6
#12 CodeMeterLin + 0x7fceab
#13 CodeMeterLin + 0x7f90a1
#14 CodeMeterLin + 0x7fe24e
#15 CodeMeterLin + 0x7f907a
#16 CodeMeterLin + 0xb8c303               <- connection worker
#17 CodeMeterLin + 0xb8de8f
#18 CodeMeterLin + 0xb8e4d6
#19 CodeMeterLin + 0xb8d6cc
#20 CodeMeterLin + 0xbf0d87
#21 CodeMeterLin + 0x12c1229
#22 start_thread                          libc.so.6 + 0x9bdf1
#23 __clone3                              libc.so.6 + 0x120c8c
```

All 10 observed cores have identical top two frames
(`__memcpy_evex_unaligned_erms` ← `CodeMeterLin + 0x8f431d`).

Individual core-dump stack traces are in [`triage/stack_traces/`](triage/stack_traces/).

## Reproducibility

Observed over a ~6-hour fuzzing campaign with 16 concurrent client sessions:

| metric | value |
|---|---|
| Daemon SIGSEGV core dumps | **10** |
| Total fuzz iterations | ~4.9 million |
| Crashes per iteration | ~1 per 500 K |
| Distinct crash instruction sites | **1** (`+0x8f431d`) |

Random replay of 10 saved "crash inputs" reproduced the bug **0 / 10** times.
The saved inputs are mostly bystanders: with 16 concurrent workers, one
daemon SIGSEGV is detected by all 16 workers nearly simultaneously, each of
which saves whatever input it happened to be sending at the moment of
detection. Only a small fraction of these are the actual trigger, and even
the guilty worker may have been several iterations past the trigger by the
time it noticed.

The non-deterministic single-input replay strongly suggests this is a
**race / state-dependent bug** rather than a single-message vulnerability.
Plausible mechanisms include:

- a shared buffer / allocator state corrupted by concurrent sessions,
- heap layout-sensitive out-of-bounds read inside the memcpy source buffer,
- accumulated state in the dispatcher at `+0x87647e`.

## Fuzzing methodology

See [`fuzzer/README.md`](fuzzer/README.md) for the harness design.

- Python stateful fuzzer: replays a real captured testbench session
  (HELLO → cookie-ACK → 0x64 request), extracts the session ID from the
  daemon's response at runtime, substitutes it into subsequent frames,
  mutates one plaintext frame per iteration.
- 16 concurrent client sessions against a live `CodeMeterLin` on
  `127.0.0.1:22350`.
- Crypto uses the published time-derived session-key derivation
  (SHA-1(magic_div_1009(`time(NULL)`))[:16] for the AES-128 key,
  digest[4:20] for the IV), AES-128-CBC-CTS, and the CRC-32 tail MAC.

The fuzzer itself is at [`fuzzer/samc_fuzz.py`](fuzzer/samc_fuzz.py).

## Impact

At minimum, this is a **remote-over-loopback DoS**: any process able to
open a TCP connection to `127.0.0.1:22350` (the daemon's NetworkPort) can
repeatedly crash the daemon under concurrent request load. If the daemon
is configured for network-facing use
(`/etc/wibu/CodeMeter/Server.ini` → `IsNetworkServer=1` or
`BindAddress=0.0.0.0`), the impact extends to any host on the network
with TCP access to the port.

Given the bug is a memcpy with an apparently attacker-influenced length,
further analysis should consider whether a crafted concurrent session can
turn this into an out-of-bounds write (code execution) rather than just an
out-of-bounds read (DoS).

## Files in this package

```
README.md                   this file
disasm/
  crash_site_0x8f431d.txt   objdump around the crash instruction
triage/
  stack_traces/             coredumpctl info output, all 10 cores
  fuzz_logs/                fuzzer event logs (grep '[CRASH]' entries)
seeds/
  samc_session_data.py      canonical cleartext plaintexts of a real session
  crash_inputs_sample/      24 representative crash-adjacent inputs
fuzzer/
  samc_fuzz.py              stateful fuzzer main
  samc_session_data.py      session plaintexts (shared copy)
  samc_replay.py            single-input replay harness
  run_samc_fuzz_parallel.sh 16-worker launcher
  README.md                 tool overview
```

## What's **not** included (on purpose)

- `/usr/sbin/CodeMeterLin` — Wibu's copyrighted binary; you have the source.
- Core dump `.zst` files — contain internal process memory; available
  on request.
- Cracked crypto keys / derivation artefacts from the Vector research
  (`ax_decrypt` repository) — not needed for triage; the fuzzer uses only
  the public time-derived KDF.
