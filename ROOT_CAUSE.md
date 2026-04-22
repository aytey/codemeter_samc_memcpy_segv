# ROOT_CAUSE - opcode 0x5e unchecked length

This is the current end-to-end explanation for the confirmed
`CodeMeterLin+0x8f431d` SAMC crash. It supersedes the earlier
"argument swap" interpretation: the fresh full-core runs show a simpler bug.
The helper is being called with a consistent `(begin, size)` pair, but the
`size` comes directly from attacker-controlled decrypted payload bytes and is
not checked against the number of bytes actually present.

## One-sentence version

The SAMC opcode `0x5e` parser copies a u32 from decrypted payload offset
`+0x0c`, treats it as the length of a variable byte range beginning at
payload offset `+0x14`, then reaches a shared helper that allocates that many
bytes and calls `memcpy(dst, payload + 0x14, length)` without first verifying
that the decrypted payload contains `0x14 + length` bytes.

## Confirmed routes into the same bug

Both practical repro families route into opcode `0x5e` and the same
`memcpy` call site. They only differ in which canonical protocol body gets
shifted under the `0x5e` parser's fixed fields.

| route | parser-visible plaintext shape | bad length at `+0x0c` |
|---|---|---|
| Prefixed HELLO | `5e00000000 || canonical HELLO` | `0x28000010` |
| Prefixed ACK | `5e0000000000000000000000000000 || canonical ACK` | `0x0b000000` |

The older HELLO prefix `5e355ed6f2` was the first deterministic reduced
trigger. It is provenance, not a special value. The zero-tail prefixes reach
the same class and the same crash.

## Layer 1 - wire and decrypt

A client sends a valid SAMC application frame to TCP port `22350`. The frame
is encrypted and authenticated correctly for the selected channel, either the
local PSK channel or the ECDH-selected channel used for non-loopback targets.

After decryption, the parser-visible application plaintext starts with byte
`0x5e`. This is the important routing property. The crash is not a HELLO-only
or ACK-only bug; HELLO and ACK are two convenient bodies whose bytes can be
placed under the opcode-`0x5e` parser.

## Layer 2 - opcode dispatch

Static analysis in [`TIER_B.md`](TIER_B.md) identifies the opcode dispatcher
as the map lookup at `CodeMeterLin+0x5e36e0`. The entry for opcode `0x5e`
routes to handler thunk `CodeMeterLin+0x862700`, which leads to construction
and parsing of the tag-`0x5e` request object.

The relevant backtrace is stable across the HELLO and ACK repros:

```text
libc memcpy/memmove
CodeMeterLin+0x8f431d
CodeMeterLin+0x8f41b5
CodeMeterLin+0x8f5491
CodeMeterLin+0x8f3c36
CodeMeterLin+0x87647e
CodeMeterLin+0x86271c
CodeMeterLin+0x805ab5
```

## Layer 3 - opcode 0x5e body parse

The parser for this object treats the decrypted opcode-`0x5e` payload as a
fixed header followed by a variable byte range. The critical call site is the
only external tag-4 caller of the shared helper:

```text
8f5452:  mov  0x4(%rbx), %eax         ; payload + 0x04
8f5455:  mov  %eax, 0x60(%r15)
8f5459:  mov  0x8(%rbx), %eax         ; payload + 0x08
8f545c:  mov  %eax, 0x64(%r15)
8f5460:  mov  0xc(%rbx), %edx         ; payload + 0x0c = byte-range length
8f5463:  mov  %edx, 0x68(%r15)
8f5467:  mov  0x10(%rbx), %eax        ; payload + 0x10
8f546e:  mov  %eax, 0x6c(%r15)
8f5472:  lea  0x88(%r15), %rcx        ; destination vector/member
8f5479:  lea  0x14(%rbx), %rsi        ; source begin = payload + 0x14
8f547d:  movabs $0x7fffffffffffffff, %r8
8f5487:  mov  $0x2ff3ff34, %edi       ; tag 4
8f548c:  call 0x8f3d60
```

Between the load at `+0x8f5460` and the call at `+0x8f548c`, `%rdx` is not
overwritten. Therefore the helper's size argument is exactly:

```c
uint32_t length = *(uint32_t *)(payload + 0x0c);
uint8_t *begin = payload + 0x14;
```

The missing check is:

```c
if (decrypted_payload_len < 0x14 ||
    length > decrypted_payload_len - 0x14) {
    reject_frame();
}
```

## Layer 4 - shared helper behavior

The shared helper at `CodeMeterLin+0x8f3d60` is a small tag-dispatched
copy/parse helper. The opcode-`0x5e` parser enters it through tag 4, which
recurses into tag 5.

With:

```text
arg2 = begin = payload + 0x14
arg3 = size  = *(uint32_t *)(payload + 0x0c)
```

the tag-4 body computes:

```text
end = begin + size
```

and then recurses into the tag-5 raw-range copy path. At the tag-5 crash site:

```text
rbx = end - begin = size
r12 = begin
```

The GROW path has only a signed-negative check before allocation and copy:

```text
8f42f6:  test %rbx, %rbx
8f42f9:  js   8f4b1f                  ; only rejects negative lengths
8f42ff:  mov  %rbx, %rdi
8f4302:  call 8f3b70                  ; allocate length bytes
8f4307:  mov  %rax, %r14
8f430f:  mov  %r14, %rdi              ; dst
8f4312:  mov  %r12, %rsi              ; src = payload + 0x14
8f4315:  mov  %rbx, %rdx              ; len
8f4318:  call memcpy@plt              ; SIGSEGV inside libc
8f431d:  ...                          ; observed return address
```

So the immediate primitive is:

```c
dst = alloc(length);
memcpy(dst, payload + 0x14, length);
```

where `length` is an unchecked u32 from `payload + 0x0c`.

## Fresh full-core evidence

Fresh cores were captured on 2026-04-22 with:

```text
kernel.core_pattern = core.%e.%p
LimitCORE = infinity
coredump_filter = 0xff
```

The raw cores are sparse files under:

```text
/var/tmp/cm_full_core_capture_20260422_090148/cores
```

| repro | apparent size | disk blocks | `rbx` length at crash |
|---|---:|---:|---:|
| `repro_prefixed_hello.py` | 831M | 62M | `0x28000010` |
| `repro_prefixed_hello_standalone.py` | 831M | 62M | `0x28000010` |
| `repro_ack_0x5e.py` | 368M | 62M | `0x0b000000` |
| `repro_prefixed_ack_standalone.py` | 368M | 62M | `0x0b000000` |

The HELLO parser buffer in the core begins:

```text
payload+0x00: 0x0000005e
payload+0x04: 0x00000a00
payload+0x08: 0x00000000
payload+0x0c: 0x28000010   ; copied to object +0x68, then used as length
```

The ACK parser buffer begins:

```text
payload+0x00: 0x0000005e
payload+0x04: 0x00000000
payload+0x08: 0x00000000
payload+0x0c: 0x0b000000   ; copied to object +0x68, then used as length
payload+0x10: 0x10000000
```

For both families, GDB shows the same fault shape:

```text
#0 libc __memmove_evex_unaligned_erms
#1 CodeMeterLin+0x8f431d
```

The destination allocation succeeds. The crash occurs while reading from the
source side of the copy. In the fresh HELLO and ACK cores, `memcpy` copied
about `0x1c030` bytes from adjacent readable heap before the source pointer
entered an unmapped/no-access region and faulted. That makes the demonstrated
impact a remote daemon crash/DoS. It is an out-of-bounds read into an internal
destination buffer; no information disclosure has been demonstrated.

## What the two variants mean

The HELLO and ACK variants are not separate root causes. They are two routes
through different session states into the same opcode-`0x5e` parser:

- HELLO route: one application frame; the shifted canonical HELLO contributes
  `10 00 00 28` at offset `+0x0c`, interpreted as little-endian
  `0x28000010`.
- ACK route: normal HELLO first, live SID extracted, then a prefixed ACK; the
  shifted canonical ACK contributes `00 00 00 0b` at offset `+0x0c`,
  interpreted as little-endian `0x0b000000`.

The different bad lengths explain the different apparent core sizes. The
stack and vulnerable copy path are the same.

## What is not proven

The six-hour ECDH prefix campaign produced apparent `opcode=0x22,
prefix_len=2` no-response events near crashes, but those have not produced a
confirmed distinct core/signature. The confirmed evidence still points to the
opcode-`0x5e` parser and `CodeMeterLin+0x8f431d`.

## Confidence

| claim | confidence | evidence |
|---|---|---|
| SIGSEGV is inside libc memcpy/memmove with return at `+0x8f431d` | certain | all reproduced HELLO and ACK cores |
| Opcode byte `0x5e` selects the vulnerable parser | high | opcode map in `TIER_B.md`, repro plaintexts |
| `payload+0x0c` is loaded into `%edx` and cached at object `+0x68` | certain | disassembly at `+0x8f5460..+0x8f5463`, fresh cores |
| The helper copies from `payload+0x14` for that unchecked length | certain | disassembly at `+0x8f5479`, tag-4/tag-5 helper, fresh registers |
| The fault is a source out-of-bounds read after successful allocation | high | destination allocation returned; faulting `rsi` walks past readable source mapping |
| HELLO and ACK are two variants of the same crash class | high | same stack, same helper, same field flow, different controlled lengths |
| Opcode `0x22` is a separate crash | unproven | no confirmed isolated core/signature |

## See also

- [`REPRODUCING.md`](REPRODUCING.md) for the current repro procedures.
- [`TRIAGE.md`](TRIAGE.md) for core-register details and historical triage.
- [`TIER_B.md`](TIER_B.md) for static opcode-dispatch and field-origin
  analysis.
- [`FIX_GUIDANCE.md`](FIX_GUIDANCE.md) for source-level remediation.
- [`RESEARCH_LOG.md`](RESEARCH_LOG.md) for campaign chronology.
