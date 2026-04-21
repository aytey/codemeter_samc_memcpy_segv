# CodeMeter `CodeMeterLin` SIGSEGV in SAMC HELLO parser

**Severity**: Denial of Service (remote, unauthenticated, local-TCP scope).
Possible out-of-bounds read / information disclosure should be assessed by
the vendor from source.
**Reporter**: Vector Informatik GmbH
**Target**: `CodeMeter-8.40.7154-505.x86_64` (CodeMeterLin build 8.40e of 2026-Mar-06 / Build 7154)
**Binary sha256**: `6bf82aa09b7f9696b4bf7535a7cb9a2fee62be5220952f2c237b6c73cbe09917`
**Host OS**: openSUSE Tumbleweed (Kernel 6.19.3-1-default), x86_64
**Status**: Deterministic single-packet reproducer isolated on 2026-04-21.

## Summary

`CodeMeterLin` crashes with `SIGSEGV` inside libc `memcpy`/`memmove` when it
processes a crafted SAMC HELLO plaintext. The crashing return address is
stable across all analyzed cores:

```text
libc __memmove_evex_unaligned_erms
CodeMeterLin + 0x8f431d
```

The deterministic trigger is a valid encrypted SAMC frame whose cleartext is
the canonical HELLO with five bytes inserted at the front:

```text
5e 35 5e d6 f2 || canonical HELLO with fresh 4-byte client token
```

That shifted HELLO starts:

```text
5e 35 5e d6 f2 0a 00 00 00 00 00 00 10 00 00 28
```

The parser later sees those bytes as the 32-bit words:

```text
0xd65e355e  0x00000af2  0x00000000  0x28000010
```

The fourth word, `0x28000010` (671,088,656), is stored into the parser object
at `this + 0x68` and reaches the `memcpy` length at `CodeMeterLin+0x8f431d`.
The destination allocation succeeds; the crash is a source over-read when
`memcpy` walks beyond the readable source mapping.

## Deterministic Reproducer

The one-packet reproducer is [`fuzzer/repro_prefixed_hello.py`](fuzzer/repro_prefixed_hello.py).

Run it only on a disposable reproduction host because it intentionally crashes
the daemon:

```bash
python3 fuzzer/repro_prefixed_hello.py
```

Expected result:

```text
plaintext_head=5e355ed6f20a00000000000010000028
response_wire_len=None
after_pid=None
crashed=True
```

After the manual validation run, the host produced:

```text
/var/tmp/cm_cores/core.CodeMeterLin.580674.1776764065
```

GDB confirmed the same crash signature:

```text
#0 __memmove_evex_unaligned_erms
#1 CodeMeterLin + 0x8f431d
rbx = 0x28000010
```

At parser frame 3 in that core:

```text
parsed buffer +0x00: 0xd65e355e
parsed buffer +0x04: 0x00000af2
parsed buffer +0x08: 0x00000000
parsed buffer +0x0c: 0x28000010
object +0x68:       0x28000010
```

## How We Reduced It

The original 16-worker fuzzer reproduced the crash reliably, but the saved
`crash_*.bin` files were crash-adjacent bystanders: when one daemon process
died, every worker noticed and saved whatever it was currently sending.

The reduction used the lightweight supervisor
[`fuzzer/samc_light_supervisor.py`](fuzzer/samc_light_supervisor.py).

It preserves the high-throughput 16-worker fuzzing shape while adding:

- strict `CodeMeterLin` PID detection with `pgrep -x`
- raw-core detection in `/var/tmp/cm_cores` and systemd-coredump
- a single supervisor that stops all workers on crash
- per-worker in-memory rings of the last real sent sessions
- plaintext and metadata dumps only after stop/crash

The key reduction run was:

```text
output:   /home/avj/clones/ax_fuzz/output/light_supervisor_mixed2_20260421_103043
attempts: 49,944 before detection
core:     /var/tmp/cm_cores/core.CodeMeterLin.576861.1776763974
```

The attributed triggering attempt was:

```text
worker:       09
iteration:    4667
target frame: 0 (HELLO)
mutation:     insert_rand
insert pos:   0
insert bytes: 5e 35 5e d6 f2
status:       ok / no response from daemon
```

The saved plaintext is under:

```text
/home/avj/clones/ax_fuzz/output/light_supervisor_mixed2_20260421_103043/worker_09/ring/iter_00004667/frame_0_plaintext.bin
```

## Crash Site

The crashing copy helper computes the copy length from parser state and then
performs an unchecked copy:

```text
8f42ff: mov  %rbx, %rdi
8f4302: call 8f3b70                  ; allocate rbx bytes
8f4307: mov  %rax, %r14
8f430f: mov  %r14, %rdi              ; dst
8f4312: mov  %r12, %rsi              ; src
8f4315: mov  %rbx, %rdx              ; len
8f4318: call memcpy@plt
8f431d: ...                          ; observed caller/return address
```

Observed deterministic core values:

```text
rbx = 0x28000010                     ; memcpy length
r12 = source pointer
r14 = allocated destination
fault = source over-read beyond readable mapping
```

Earlier full-memory cores with different random mutations produced the same
crash site with other large values, including `0x612b09cb` and `0x000b7542`.
The deterministic HELLO prefix now provides a simple root-cause reproducer.

## Impact

At minimum this is an unauthenticated denial of service for any process that
can connect to `127.0.0.1:22350`. If CodeMeter is configured as a network
server (`IsNetworkServer=1` or a non-loopback bind address), the same issue
extends to hosts with TCP access to the CodeMeter port.

The observed primitive is an out-of-bounds source read into an allocated
destination buffer. It is not a direct out-of-bounds write. Vendor source
review should determine whether any non-crashing variant can copy adjacent
process memory into a response buffer and leak it.

## Reachability

The bug is reachable from at least two distinct SAMC session states:

1. **Fresh HELLO.** A newly-connected client sends a crafted first frame
   whose plaintext opcode byte (offset 0) is `0x5e`. This is the
   deterministic reproducer in `fuzzer/repro_prefixed_hello.py`.
2. **Post-HELLO during ACK.** After a valid HELLO/SID exchange, a mutated
   or truncated ACK-stage frame can land a plaintext whose opcode byte is
   `0x5e`. The SID returned in the HELLO response often contains the byte
   `0x5e` naturally (e.g. `sid_hex: 4e035e36` in one captured session),
   so even small mutations to the ACK payload can cause the daemon to
   re-dispatch into the `0x5e` handler.

Both paths terminate in the same call site
(`CodeMeterLin + 0x8f431d`) with the same signature. The point-fix at
`+0x8f5460..+0x8f548c` (bounding `*(u32)(rbx+0xc)`) closes both paths
because the vulnerability sits in the shared tag-`0x5e` parser rather
than in any session-state-specific handler.

For the static attribution of opcode `0x5e` (the `std::map<byte,
Handler*>` at `+0x5e36e0` and the 65-entry dispatch table), see
[`TIER_B.md`](TIER_B.md) §B-4 and
[`disasm/opcode_dispatch_map.txt`](disasm/opcode_dispatch_map.txt).
For the bug-class analysis across the rest of the binary (two other
unbounded-memcpy sites exist but are *not* reachable from the SAMC
surface), see [`BUG_CLASS_AUDIT.md`](BUG_CLASS_AUDIT.md).

## Fuzz-Campaign Attestation

A final fleet campaign was run to confirm that no other distinct bug
reaches the same surface. Configuration
(`output/farms/20260421_120217/launcher_config.json`):

```
farms:             8
workers per farm:  10  (80 concurrent workers total)
wall clock:        3600 s  (1 hour)
modes:             mixed, hello, ack, big, rotate, mixed  (farm_00..farm_07)
known signature:   CodeMeterLin+0x8f431d -> memcpy_8f431d_prefixed_hello
```

Result (`output/farms/20260421_120217/final_report.json`):

```
total crashes:     67
new signatures:    0
```

Per-mode breakdown:

| farm | mode   | runs | crashes | rate  |
|-----:|--------|-----:|--------:|------:|
| 00   | mixed  |   15 |      14 |  93%  |
| 01   | hello  |    9 |       6 |  67%  |
| 02   | ack    |   23 |      22 |  96%  |
| 03   | big    |    5 |       0 |   0%  |
| 04   | rotate |    7 |       2 |  29%  |
| 05   | mixed  |   13 |      11 |  85%  |
| 06   | mixed  |   12 |      10 |  83%  |
| 07   | hello  |    7 |       2 |  29%  |
| **Σ**| —      |  *91*|   **67**| *74%* |

Two useful readings:

- **BIG-mode immunity.** Post-session BIG-frame mutations (5 runs) produced
  zero crashes. The vulnerability sits in HELLO-phase parsing, not in the
  bulk-data path that follows a completed handshake.
- **One bucket, no escapes.** 67 crashes across 5 distinct mutation
  strategies all fell into the one known signature. No other exploitable
  parser defect appeared on this attack surface within an hour of
  80-worker fleet time, supporting the claim that the point-fix plus the
  recommended helper-level systemic fix is sufficient for the SAMC
  protocol surface.

## Suggested Fix

At source level, reject malformed HELLO fields before they populate the parser
object. In particular, the field that lands at `this + 0x68` must be bounded
before it can reach the copy helper. A reasonable defense-in-depth check is:

```c
if (len > MaxMessageLen || len > remaining_input_bytes) {
    reject_frame();
}
```

Also add an upper bound at the shared copy helper before allocation and
`memcpy`, so other malformed parser paths cannot reach the same unchecked
copy with a large length.

## Files

```text
README.md                              this summary
REPRODUCING.md                         deterministic reproduction recipe
ROOT_CAUSE.md                          parser-state-level root cause
NEXT_STEPS_PROCESS.md                  reduction process and completed result
MULTI_INSTANCE_FUZZING.md              namespace-isolated multi-daemon fuzz-farm notes
TRIAGE.md                              earlier core/disassembly triage notes
TIER_B.md                              static analysis: %rdx origin, class, opcode 0x5e
BUG_CLASS_AUDIT.md                     audit for sibling unbounded-memcpy sites
FIX_GUIDANCE.md                        suggested source-level fix
fuzzer/
  repro_prefixed_hello.py              deterministic one-packet crash reproducer
  samc_light_supervisor.py             high-throughput attribution harness
  samc_fuzz.py                         original stateful fuzzer
  samc_replay.py                       replay harness for saved plaintexts
  run_samc_fuzz_parallel.sh            original 16-worker launcher
disasm/
  opcode_dispatch_map.txt              all 65 SAMC opcode -> handler entries
  cross_core_register_comparison.txt   Tier C-7: rbx variance across 12 cores
  (plus per-frame annotated disassembly)
triage/                                historical stack traces and fuzz logs
seeds/                                 captured canonical SAMC session plaintexts
```

Full raw cores are not included in the repository because they contain process
memory and are large. The most useful local cores from this reduction are:

```text
/var/tmp/cm_cores/core.CodeMeterLin.576861.1776763974
/var/tmp/cm_cores/core.CodeMeterLin.580674.1776764065
```
