# CodeMeter crash and fuzzing research workspace

This repository is the working history for the CodeMeter crash research effort.
It contains the current reproductions, the binary/root-cause analysis, fuzzing
infrastructure, campaign notes, and historical reduction process. It is no
longer only a vendor-report bundle, although the confirmed crash class is still
written up in a form that can be extracted for vendor triage.

## Target

- Package: `CodeMeter-8.40.7154-505.x86_64`
- CodeMeterLin build: 8.40e of 2026-Mar-06 / Build 7154
- Binary sha256:
  `6bf82aa09b7f9696b4bf7535a7cb9a2fee62be5220952f2c237b6c73cbe09917`
- Host OS used for most analysis: openSUSE Tumbleweed, x86_64

## Current State

As of 2026-04-25, the client-facing SAMC work still has one confirmed
network-reachable crash class:

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

The important parser-visible property is a SAMC plaintext whose first byte is
opcode `0x5e`. The opcode dispatcher routes it into the same tag-`0x5e`
parser class from both the fresh-HELLO and post-HELLO ACK states. That parser
accepts a u32 at payload offset `+0xc` as a copy length without a sufficient
bound; the value reaches a shared copy helper and crashes at
`CodeMeterLin+0x8f431d`.

At minimum this is an unauthenticated denial of service for any process that
can connect to the CodeMeter SAMC listener. If CodeMeter is configured as a
network server or bound to a non-loopback address, the same issue extends to
hosts with TCP access to the CodeMeter port.

## Confirmed Routes

There are two practical reproduction routes into the same crash.

| route | cleartext shape | script |
|---|---|---|
| Fresh HELLO | `5e00000000 || canonical HELLO` | `fuzzer/repro_prefixed_hello.py` |
| Post-HELLO ACK | normal HELLO, extract SID, then `5e0000000000000000000000000000 || 0b000000 || SID` | `fuzzer/repro_prefixed_ack_standalone.py` |

The older captured HELLO prefix `5e355ed6f2` is retained as provenance. It was
the first deterministic reduced trigger, but the later prefix campaign showed
that the random-looking tail is not special. The current default HELLO
reproducer uses the simpler zero-tail prefix `5e00000000`.

Since the original vendor-style writeup, three additional results matter:

- the in-process AFL++/QEMU harness for the `0x5e` parser path is now working,
  but its first saved crashes minimized back to the same known `0x8f431d`
  crash family; and
- broader QEMU tracing of native-valid public SDK commands identified a
  different set of hot native handlers than the earlier `0x9f...` candidates;
  the later direct-call native triplet (`bef830`, `7f9060`, `54ace0`) was
  useful for hot-path discovery, but the current packet-translatable direction
  is the newer network-faithful `net_*` AFL/QEMU harness family plus the
  namespaced weekend launchers in `fuzzer/run_cm_afl_netns_weekend.sh` and
  `fuzzer/run_cm_afl_netns_weekend6.sh`; and
- the packet-faithful `net_*` family now also includes second-stage stateful
  modes built from captured `access/access2 -> op -> release` conversations:
  `public-key`, `calc-sig`, `crypt2`, `validate-signedtime`,
  `validate-signedlist`, `validate-deletefi`, `lt-create-context`,
  `lt-import-update`, and `lt-cleanup`. Those modes reuse the existing
  token+SID patch model and are exercised through the new namespaced wrappers
  in `fuzzer/run_cm_afl_netns_smoke18_stateful.sh`,
  `fuzzer/run_cm_afl_netns_weekend12_stateful.sh`,
  `fuzzer/run_cm_afl_netns_weekend9_stateful_access.sh`, and
  `fuzzer/run_cm_afl_netns_weekend9_stateful_access2.sh`.

Those newer findings are documented in `AFL_QEMU_NATIVE_FUZZING.md`.

Run repros only on a disposable target because they intentionally crash the
daemon:

```bash
python3 fuzzer/repro_prefixed_hello.py
python3 fuzzer/repro_prefixed_ack_standalone.py
```

For a non-loopback target, the current repros can use the ECDH-selected
application channel:

```bash
python3 fuzzer/repro_prefixed_hello.py --host TARGET
python3 fuzzer/repro_prefixed_ack_standalone.py --host TARGET
```

Full reproduction details are in `REPRODUCING.md`.

## Crash Mechanism

The reduced HELLO route starts:

```text
5e 00 00 00 00 0a 00 00 00 00 00 00 10 00 00 28
```

When parsed as little-endian words by the vulnerable path:

```text
0x0000005e
0x00000a00
0x00000000
0x28000010
```

The fourth word, `0x28000010`, is stored into the parser object at
`this+0x68` and reaches the memcpy length at `CodeMeterLin+0x8f431d`.

The crashing helper allocates the requested destination and then performs an
unchecked source copy:

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

Observed deterministic cores show a source over-read: destination allocation
succeeds, but `memcpy` walks beyond the readable source mapping. The core and
disassembly evidence is in `TRIAGE.md`, `ROOT_CAUSE.md`, and `TIER_B.md`.

The 2026-04-22 full-core rerun also corrected an earlier working hypothesis:
the confirmed bug is not an argument-order swap at the helper call. The
opcode-`0x5e` parser passes `begin = payload+0x14` and
`size = *(uint32_t *)(payload+0x0c)` consistently; the missing check is that
`size` must fit within the remaining decrypted payload bytes.

## Campaign Findings

The research history is documented in `RESEARCH_LOG.md`. Key campaign results:

| campaign | result |
|---|---|
| Supervisor reduction, 2026-04-21 | isolated historical HELLO prefix `5e355ed6f2` from `/home/avj/clones/ax_fuzz/output/light_supervisor_mixed2_20260421_103043` |
| 8-farm namespace run, 2026-04-21 | 23.2M attempts, 67 crashes, 0 new signatures; ACK-only fuzzing also reached the same crash |
| 8-farm ECDH prefix run, 2026-04-22 | 1,398,462 attempts, 360 classified crashes, 0 new signatures; simplified HELLO and ACK zero-tail prefixes |
| 192-farm SDK crash matrix, 2026-04-24 | broadened the same crash family to additional native bodies such as `0x11`, `0x6d`, `0x6f`, and `0x72`, but did not produce a second crash bucket |
| In-process AFL++/QEMU `0x5e` harness, 2026-04-24 | working preload/QEMU fuzz target; initial crashes minimized to the same network-reachable `0x8f431d` bug |
| Native-valid QEMU block coverage, 2026-04-24 | identified `FUN_00bef130`, `FUN_007fd840`, `FUN_007feb90`, `FUN_00552530`, and `FUN_0071ab20` as the real hot native handler families |

The 6-hour ECDH prefix run did not find a second crash class. It did make the
two repro routes cleaner and increased confidence that the opcode-`0x5e`
parser path is the dominant issue on this surface. The apparent
`opcode=0x22,prefix_len=2` no-response events are not currently treated as a
distinct crash because the cores still classify into the `0x5e` bucket.

## Documentation Map

| file | role |
|---|---|
| `README.md` | current status and repo map |
| `RESEARCH_LOG.md` | chronological working history and campaign summary |
| `REPRODUCING.md` | current HELLO and ACK reproduction procedures |
| `ROOT_CAUSE.md` | end-to-end parser/helper narrative |
| `TRIAGE.md` | core-register and class-layout triage |
| `TIER_B.md` | static analysis: opcode `0x5e`, `%rdx` origin, dispatch map |
| `BUG_CLASS_AUDIT.md` | audit for sibling unbounded-copy helper sites |
| `FIX_GUIDANCE.md` | source-level fix guidance and defense in depth |
| `MULTI_INSTANCE_FUZZING.md` | namespace farm design and first 1-hour findings |
| `NEXT_STEPS_PROCESS.md` | historical reduction process that led to the first deterministic repro |
| `GHIDRA_AUTOMATION.md` | no-click Ghidra GUI startup and MCP automation path |
| `SDK_SEED_CAPTURE.md` | official SDK probe, MITM capture, and baseline valid seeds |
| `AFL_QEMU_NATIVE_FUZZING.md` | `0x5e` in-process AFL++/QEMU harness, native-valid coverage, direct-call native triplet, and network-faithful `net_*`/namespace runners |
| `fuzzer/README.md` | fuzzer and repro tool guide |
| `disasm/README.md` | index of annotated disassembly windows |
| `memory_snapshots/README.md` | index of extracted core-memory snapshots |

## No-Click Ghidra GUI Startup

To let Codex bring up the correct Ghidra GUI project and binary without Andrew
clicking through FrontEnd or CodeBrowser, use:

```bash
python3 ghidra_scripts/start_codex_ghidra_gui.py
```

By default this launcher uses `DISPLAY=:100` and validates that the matching X
socket exists before launch. You can override the display or project with
`--display` and `--project`. It patches FrontEnd to auto-load
`GhidraMCPPlugin`, pins the startup project to `CodeMeterLin_import_only`,
waits for the FrontEnd MCP socket, and opens `/CodeMeterLin` over the UDS
transport. Full details are in `GHIDRA_AUTOMATION.md`.

## Suggested Fix Direction

At the confirmed SAMC call site, reject malformed opcode-`0x5e` payloads
before the input-derived u32 at `*(rbx+0xc)` can populate the parser object or
reach the copy helper:

```c
if (len > MaxMessageLen || len > remaining_input_bytes) {
    reject_frame();
}
```

Also add an upper bound at the shared copy helper before allocation and
`memcpy`, so future malformed parser paths cannot reach the same unchecked
copy with a large positive length. `FIX_GUIDANCE.md` has the layered version
of this recommendation.

## Important Artifacts

Full raw cores are not stored in this repository because they are large and
contain process memory. Useful local artifacts referenced by the docs include:

```text
/var/tmp/cm_cores/core.CodeMeterLin.576861.1776763974
/var/tmp/cm_cores/core.CodeMeterLin.580674.1776764065
/home/avj/clones/ax_fuzz/output/light_supervisor_mixed2_20260421_103043
/home/avj/clones/ax_fuzz/output/farms/20260421_120217
/home/avj/clones/ax_fuzz/output/veth_farms/20260422_013945
/var/tmp/cm_full_core_capture_20260422_090148/cores
```
