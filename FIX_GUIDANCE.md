# FIX_GUIDANCE — where to fix, defence in depth

Recommended remediation, in order of specificity. Apply layers 1 and 2
minimum; layers 3 and 4 are defensive.

## Layer 1 — fix the caller at `CodeMeterLin + 0x8f548c`

This is the root cause. At this call site, the opcode-`0x5e` parser reads
four u32 fields from the decrypted payload, caches them in the parser object,
then passes a variable byte range to the shared helper:

```text
8f5460:  mov  0xc(%rbx), %edx         ; length = *(u32 *)(payload + 0x0c)
8f5463:  mov  %edx, 0x68(%r15)        ; cache at object +0x68
8f5479:  lea  0x14(%rbx), %rsi        ; begin = payload + 0x14
8f548c:  call 0x8f3d60                ; helper copies begin,length
```

The fresh cores show this is not an argument-order bug. The helper convention
is effectively `(begin, size)`, and the call uses it that way. The bug is that
`size` is copied directly from `payload+0x0c` and is not checked against the
remaining decrypted payload bytes before the helper reaches:

```c
memcpy(alloc(size), payload + 0x14, size);
```

**From source**, locate the parser reached by the SAMC opcode-`0x5e` handler
and add bounds before the call:

```c
uint32_t size = load_le32(payload + 0x0c);
size_t data_off = 0x14;

if (payload_len < data_off || size > payload_len - data_off) {
    reject_frame();
}
```

Also enforce a protocol-level maximum such as `MaxMessageLen` or a tighter
per-field limit. `Server.ini`'s `MaxMessageLen` default is `67_108_864`
(64 MB); the confirmed HELLO length `0x28000010` and ACK length `0x0b000000`
are both far beyond any valid body present in these frames.

## Layer 2 — bound `%rbx` in the dispatch helper's tag-5 GROW path

At `+0x8f42f6..+0x8f4318` the helper allocates `rbx` bytes and memcpys
`rbx` bytes with only a `js <negative>` guard. Even if the caller in
Layer 1 is fixed, any other caller that reaches this path with a bogus
length will behave the same way.

```
 8f42f6:  test %rbx, %rbx
 8f42f9:  js   8f4b1f                  ; currently the ONLY guard
 8f42ff:  mov  %rbx, %rdi
 8f4302:  call 8f3b70                   ; allocator
 …
 8f4315:  mov  %rbx, %rdx
 8f4318:  call 3acd00 <memcpy@plt>
```

Add a positive upper bound in this path. A reasonable ceiling is
`MaxMessageLen` (64 MB by default), enforced before the allocator call.
Anything larger indicates a parser bug upstream and should immediately
return an error to the session, not allocate.

Pseudocode:

```c
if (rbx < 0 || rbx > server.ini.MaxMessageLen) {
    // reject this frame, drop session, maybe log
    return ERR_BAD_RANGE;
}
```

## Layer 3 — validate the `rbp += rsi` in the tag-4 body

At `+0x8f419f` the tag-4 branch does `rbp += rsi` unconditionally after
only checking that each is individually non-zero. In the confirmed crash,
those values are `begin` and `size`, so the add forms `end = begin + size`.
A bogus-but-positive size produces an end pointer far beyond the decoded input
buffer, which is exactly the range tag 5 then copies.

Possible hardening:

- Check that the result fits inside the arg-5 (`%r13`) limit before
  doing the add. The code already does a `cmp %r13, %rbp` just before,
  but only against the pre-add value — re-check after the add.
- Better: validate that `rbp + rsi` stays inside the source object's
  mapped range. That needs a "source extent" parameter the helper
  doesn't currently carry.

## Layer 4 — surface the source-buffer extent into the helper

More invasive, but closes the whole pattern: add a parameter (e.g.
via `%r9`) that conveys the known end of the source buffer the caller
is reading from. The helper can then reject any arithmetic that exceeds
it. This would require touching every call site, but many of them
likely already have the extent available as a local.

## Side note — the global boolean at `0x17d7a55(%rip)`

The tag-5 body currently does:

```
 8f41cc:  cmpb $0x0, 0x17d7a55(%rip)
 8f41d3:  jne  8f42f6                   ; true → GROW path (crash)
                                        ; false → cheap in-place path
```

Whatever this flag controls, leaving it on makes the crash path the
default. Triaging whether it's a testing/debug hook that shouldn't be
enabled in production may already mitigate the exploitable surface
even without the source-level fix.

## Testing a candidate fix

Use the fuzzer in this package to regression-test:

```bash
# direct current repros should no longer crash
python3 fuzzer/repro_prefixed_hello.py
python3 fuzzer/repro_prefixed_ack_standalone.py

# then run the purpose-built prefix campaign long enough to catch regressions
sudo ./fuzzer/run_ecdh_prefix_6h.sh
```

Criterion: zero SEGV cores with `CodeMeterLin + 0x8f431d` as caller
from the direct repros and from a long ECDH prefix campaign. The unfixed
binary produced 360 classified `memcpy_8f431d_prefixed_hello` crashes in the
2026-04-22 6-hour campaign, so even a shorter prefix regression run should
give a clear signal.
