# CodeMeter `CodeMeterLin` SIGSEGV in samc request handler

**Severity**: Denial of Service (remote, unauthenticated — local-TCP scope)
**Reporter**: Vector Informatik GmbH
**Target**: `CodeMeter-8.40.7154-505.x86_64` (CodeMeterLin build 8.40e of 2026-Mar-06 / Build 7154)
**Binary sha256**: `6bf82aa09b7f9696b4bf7535a7cb9a2fee62be5220952f2c237b6c73cbe09917`
**Host OS**: openSUSE Tumbleweed (Kernel 6.19.3-1-default), x86_64
**Status**: Reliably reproduced under concurrent-session fuzzing
           (~1 daemon SIGSEGV per 4–5 min of 16-client fuzz; 0/10 random
           single-input replays — strongly consistent with a state-dependent
           or range-inconsistency bug rather than a one-packet trigger).

> **Updated 2026-04-21** after full-memory core analysis. See
> [`TRIAGE.md`](TRIAGE.md) for the revised root cause; the original
> "memcpy length is an attacker-supplied field" framing below has been
> corrected. TL;DR: the memcpy length is the difference of two pointers,
> `%rbp - %r12`, one of which is valid and one of which points into a
> no-access reservation. It's a *bad source-end pointer*, not a bad
> length field.

## Summary

The CodeMeter daemon (`/usr/sbin/CodeMeterLin`) crashes with `SIGSEGV` inside
`__memcpy_evex_unaligned_erms` (libc, reached via `memcpy@plt`) when
processing samc-protocol requests from concurrent clients. All observed
crashes share the same return address `CodeMeterLin + 0x8f431d`, indicating
a single bug site.

The memcpy length in `%rbx` is computed by
`CodeMeterLin+0x8f41c6..0x8f41c9` as a pointer difference:

```
 8f41c6:  mov   %rbp, %rbx           ; rbx = source_end
 8f41c9:  sub   %r12, %rbx           ; rbx = source_end - source_begin   <<< length
 …
 8f42f6:  test  %rbx, %rbx
 8f42f9:  js    8f4b1f               ; ONLY guard before use: signed-negative
 8f42ff:  mov   %rbx, %rdi           ; alloc(length)
 8f4302:  call  8f3b70
 8f4307:  mov   %rax, %r14
 8f430a:  cmp   %r12, %rbp
 8f430d:  je    8f431d               ; skip if empty range
 8f430f:  mov   %r14, %rdi           ; memcpy(dst = alloc result,
 8f4312:  mov   %r12, %rsi           ;        src = source_begin,
 8f4315:  mov   %rbx, %rdx           ;        len = rbp - r12)
 8f4318:  call  3acd00 <memcpy@plt>  ; <<< SEGV inside libc
 8f431d:  …                          ; return address observed in every core
```

In the captured core, `%r12 = 0x7ff0ac00db74` points inside a valid
heap mapping `[0x7ff0ac000000, 0x7ff0aca48000)`, but `%rbp =
0x7ff10d2be53f` is in a non-access reservation region — i.e. `%rbp`
isn't a real pointer. The subtraction yields
`0x612b09cb = 1,630,210,507 bytes`, which the allocator happily
satisfies, and memcpy then walks off the end of the source mapping at
`0x7ff0aca48000 + 0xba4 = 0x7ff0aca48ba4` — the fault address.

**The bug is therefore not "trust the length field from the packet"
but "compute a length from two pointers without validating that both
pointers describe a consistent range."** The fix direction changes
accordingly: not a bounds-check on a size field, but a range-validity
check on the `%rbp` pointer before the subtraction at `+0x8f41c9`.

Full annotated call site: [`disasm/memcpy_call_site_annotated.txt`](disasm/memcpy_call_site_annotated.txt)
Full objdump excerpt: [`disasm/crash_site_0x8f431d.txt`](disasm/crash_site_0x8f431d.txt)

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

The non-deterministic single-input replay is consistent with this being
a **state-dependent / range-inconsistency bug** rather than a single-
message vulnerability. Combined with the core-dump finding that `%rbp`
holds a non-mapped pointer, the most likely mechanisms are:

- a concurrently-modified source container: `%r12` and `%rbp` are loaded
  from an object's `_M_start`/`_M_finish` (or equivalent span fields) in
  non-atomic fashion, and another thread has since mutated or freed the
  container.
- a pair of offsets / pointers into a packet buffer where the end-offset
  is computed without bound-checking against the allocation, allowing
  the parser to believe the range is much larger than it actually is.
- an upstream "advance the end pointer by N" operation whose N came
  from an attacker-influenced field and was not bounded.

[`TRIAGE.md`](TRIAGE.md) elaborates. The advisor document
[`NEXT_STEPS_PROCESS.md`](NEXT_STEPS_PROCESS.md) gives a staged reduction
plan for narrowing it further.

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

Because the memcpy walks off the end of the *source* mapping (not the
destination), the immediate impact is a crash / DoS — there is no
attacker-controlled write here. However:

- The memcpy copies arbitrary adjacent memory into a newly-allocated
  heap buffer up until the point of fault, which in principle leaks
  post-`%rsi` bytes to whichever code consumes the destination. Whether
  the destination buffer is later serialised back to the attacker over
  the samc channel is a question only the source can answer.
- If the upstream computation that produces `%rbp` is itself
  attacker-steerable to in-range-but-wrong values, a smaller bogus
  length could avoid the SEGV and produce an OOB read leak with no
  crash.

## Files in this package

```
README.md                              this file
TRIAGE.md                              revised root cause from full-memory core
NEXT_STEPS_PROCESS.md                  reduction methodology (concurrent-bug
                                       triage playbook)
disasm/
  crash_site_0x8f431d.txt              objdump around the crash instruction
  memcpy_call_site_annotated.txt       annotated call-site (NEW; shows
                                       rbx = rbp - r12)
  vtable_at_0x88a4c0.txt               raw bytes of the parsing object's
                                       vtable
  vtable_slot0_destructor_at_0x8f3c40.txt
                                       the class destructor — identifies
                                       four std::vector members + base
                                       class inheritance
triage/
  stack_traces/                        coredumpctl info output, all 10 cores
  fuzz_logs/                           fuzzer event logs (grep '[CRASH]' entries)
seeds/
  samc_session_data.py                 canonical cleartext plaintexts of a
                                       real session
  crash_inputs_sample/                 24 representative crash-adjacent inputs
fuzzer/
  samc_fuzz.py                         stateful fuzzer main
  samc_session_data.py                 session plaintexts (shared copy)
  samc_replay.py                       single-input replay harness
  run_samc_fuzz_parallel.sh            16-worker launcher
  README.md                            tool overview
```

## What's **not** included (on purpose)

- `/usr/sbin/CodeMeterLin` — Wibu's copyrighted binary; you have the source.
- Full-memory core dumps (~1.9 GB each). Available on request; they
  contain internal process memory including any recently-decrypted
  plaintext from all 16 concurrent sessions, so out-of-band transfer
  is preferred.
- Cracked crypto keys / derivation artefacts from the Vector research
  (`ax_decrypt` repository) — not needed for triage; the fuzzer uses only
  the public time-derived KDF.
