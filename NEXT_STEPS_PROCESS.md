# Next Steps: Reducing the `CodeMeterLin + 0x8f431d` Crash

## Completed Result

This process produced the first deterministic single-packet reproducer and led
to the current opcode-`0x5e` crash model. The current preferred HELLO trigger
is the simplified zero-tail prefix:

```text
5e 00 00 00 00 || canonical HELLO with fresh client token
```

The prefixed HELLO starts:

```text
5e 00 00 00 00 0a 00 00 00 00 00 00 10 00 00 28
```

The vulnerable parser later reads those bytes as:

```text
0x0000005e  0x00000a00  0x00000000  0x28000010
```

`0x28000010` is stored at `this + 0x68` and reaches the `memcpy` length at
`CodeMeterLin + 0x8f431d`.

The original reduction found the historical prefix:

```text
5e 35 5e d6 f2 || canonical HELLO with fresh client token
```

That prefix remains important provenance, but later ECDH prefix fuzzing showed
that the random-looking tail is not special. A post-HELLO ACK route also
reaches the same crash via a zero-tail opcode-`0x5e` prefix.

Artifacts from the successful attribution run:

```text
supervisor output:
  /home/avj/clones/ax_fuzz/output/light_supervisor_mixed2_20260421_103043

triggering attempt:
  worker_09/ring/iter_00004667/

attribution core:
  /var/tmp/cm_cores/core.CodeMeterLin.576861.1776763974

single-packet validation core:
  /var/tmp/cm_cores/core.CodeMeterLin.580674.1776764065
```

New scripts:

```text
fuzzer/samc_light_supervisor.py     high-throughput attribution supervisor
fuzzer/repro_prefixed_hello.py      deterministic one-packet reproducer
fuzzer/repro_prefixed_ack_standalone.py
                                    standalone two-frame ACK reproducer
```

The remainder of this file is retained as the historical reduction process
that led to the result.

This document describes a practical process for reducing the current
concurrent SAMC fuzzing crash into a more reproducible triage case.

The goal is not necessarily to find a one-packet reproducer. Based on the
available core state, the crash looks state-dependent: a valid source pointer
is paired with a bogus end pointer, producing a huge copy length and an
out-of-bounds source read in `memcpy`.

## Current Crash Signature

Use this as the reduction oracle. A candidate is interesting only if it
reproduces the same failure class:

```text
top frame:    libc memcpy/memmove implementation
caller:       CodeMeterLin + 0x8f431d
copy length:  unusually large, derived from rbp - r12
failure mode: source pointer walks past readable mapping
```

Representative core state from `core.CodeMeterLin.477656.1776755891`:

```text
r12 = 0x7ff0ac00db74      source start, valid heap mapping
rbp = 0x7ff10d2be53f      supposed source end, not a valid mapped pointer
rbx = 0x612b09cb          copy length = rbp - r12 = 1,630,210,507 bytes
r14 = 0x7ff01ed4f010      allocated destination

source mapping:        0x7ff0ac000000 - 0x7ff0aca48000  RW
fault address:         0x7ff0aca48ba4
following reservation: 0x7ff0aca48000 - 0x7ff0b0000000  no access
```

This strongly suggests an inconsistent range or stale container state rather
than a straightforward destination overflow.

## Phase 1: Fix Crash Attribution

The current 16-worker fuzzing setup can detect crashes, but it cannot reliably
identify the triggering request. Multiple workers notice one daemon death and
save whatever they happened to send near that time.

Before reducing inputs, tighten attribution.

Log these fields for every iteration:

```text
daemon PID / generation
worker ID
iteration number
monotonic timestamp before and after each send
target frame
mutation strategy
RNG seed or serialized RNG state
client token
session ID
plaintext length
plaintext hash
saved plaintext path
response status
```

During reduction, check daemon liveness after every iteration, not every 10
iterations.

Replace per-worker daemon restart logic with a single supervisor:

```text
1. Start CodeMeterLin.
2. Record daemon PID and current newest core.
3. Launch workers.
4. Watch for PID change, daemon exit, connection refusal, or a new core.
5. Stop all workers immediately on crash.
6. Preserve each worker's last N events.
7. Restart the daemon once.
8. Repeat.
```

This creates a bounded crash window and avoids every worker racing to restart
the service.

## Phase 2: Save Rolling Session Traces

For each worker, keep a ring buffer of the last 100 complete session attempts.
For each attempt, preserve:

```text
HELLO plaintext after token substitution
ACK plaintext after SID patching
BIG plaintext after token substitution
mutated frame index
mutation metadata
wire send timestamps
daemon responses, if any
status returned by the harness
```

When the daemon crashes, write the ring buffer for every worker to disk. For a
race or state-dependent bug, the actual trigger may be a short sequence across
multiple clients, not the last packet sent by the worker that noticed the
crash.

## Phase 3: Reduce Concurrency

Once attribution is improved, reduce the number of workers while keeping seeds
and target-frame mix fixed:

```text
16 workers -> 8 -> 4 -> 2 -> 1
```

If the crash disappears at 1 worker but still appears at 2, the reduction
target becomes much more manageable: a two-client schedule.

If the crash only appears at higher concurrency, split workers by role:

```text
pressure workers: send only valid HELLO -> ACK -> BIG sessions
mutator worker:   sends one controlled mutation family
```

Then test:

```text
valid pressure only
HELLO mutations + valid pressure
ACK mutations + valid pressure
BIG mutations + valid pressure
```

This separates "many sessions are needed" from "many malformed sessions are
needed".

## Phase 4: Use A Barrier Harness

Random concurrency is hard to reduce. Build a small two-client barrier harness
that can force overlap at specific protocol points:

```text
client A: connect, send HELLO, wait
client B: connect, send HELLO, wait
client A: send ACK, wait
client B: send ACK, wait
client A: send BIG or mutated frame
client B: send BIG or mutated frame
```

Exercise fixed schedules first:

```text
A frame 2, then B frame 2
B frame 2, then A frame 2
A and B send frame 2 at the same barrier release
A sends partial wire frame, pauses, B sends full frame, A resumes
A closes immediately after send
B closes while A response is pending
```

Partial-frame scheduling is useful because it can force overlapping parser or
session state without requiring 16 workers.

## Phase 5: Reduce Mutation Families

Disable mixed mutations during reduction. Run one strategy at a time:

```text
bitflip only
byteflip only
insert only
delete only
truncate only
extend_zero only
dict_splice only
sentinel_byte only
```

Prioritize strategies that affect lengths, offsets, or structural fields:

```text
delete / truncate
insert / extend_zero
dictionary boundary values:
  0x00000000
  0x00000001
  0x7fffffff
  0x80000000
  0xffffffff
```

Rank each strategy by how often it reproduces the same `+0x8f431d` crash
signature, not by generic connection resets or unrelated daemon failures.

## Phase 6: Delta-Debug Candidate Plaintexts

Only start plaintext minimization once there is a candidate sequence that
reproduces the target crash with measurable probability.

Use protocol-aware minimization:

```text
1. Keep SAMC framing valid.
2. Keep encryption and CRC generation valid.
3. Keep SID patching valid.
4. Keep per-session token substitution valid.
5. Minimize the cleartext difference from the captured canonical frame.
```

Because the crash is nondeterministic, use a frequency threshold rather than a
single pass/fail result. Example:

```text
candidate is interesting if it triggers the target crash >= 2 times in 50 runs
```

As the reproducer improves, tighten the threshold:

```text
>= 5 / 50
>= 10 / 50
>= 1 / 5
```

Reject candidates that only produce unrelated crashes or connection failures.

## Phase 7: Core-Based Validation

For every reduced crash, collect the same minimal GDB facts:

```gdb
info threads
bt
info registers rip rsp rbp rbx r12 r14 rdi rsi rdx rcx rax r13 r15 eflags
p $_siginfo
x/24i $pc-64
frame 1
info registers rip rsp rbp rbx r12 r14 rdi rsi rdx rcx rax r13 r15 eflags
info proc mappings
```

Record:

```text
fault address
copy length
source start and computed source end
destination start and computed destination end
source mapping bounds
destination mapping bounds
whether destination allocation succeeded
```

The current working hypothesis should be revised if a future core shows:

```text
destination allocation smaller than rbx
r14 == NULL or invalid
destination write fault
controlled source pointer
controlled rbp/end pointer
copied data returned to client before crash
```

## Success Criteria

A useful reduced reproducer does not need to be one packet. A strong result
would be:

```text
two unauthenticated TCP clients
fixed valid HELLO / ACK setup
one malformed frame or one small malformed sequence
one overlapping valid or malformed frame
same +0x8f431d crash in fewer than 100 attempts
```

That is enough for vendor triage and a solid vulnerability report.

## Suggested Immediate Work Items

1. Add per-iteration crash checks and richer event logging to the fuzzer.
2. Add per-worker rolling session trace buffers.
3. Move daemon restart and crash detection into a single supervisor.
4. Re-run the 16-worker campaign until one crash is captured with tight traces.
5. Try replaying the last few sessions from the crash window under a two-client
   barrier harness.
6. Reduce worker count and mutation family based on measured crash frequency.
7. Delta-debug the cleartext mutation only after a repeatable schedule exists.
