# FIX_GUIDANCE — where to fix, defence in depth

Recommended remediation, in order of specificity. Apply layers 1 and 2
minimum; layers 3 and 4 are defensive.

## Layer 1 — fix the caller at `CodeMeterLin + 0x8f548c`

This is the root cause. At this call site the 3rd arg (`%rdx`, which
the helper puts into `%rbp`) carries a ~1.6 GB value in the observed
crash — almost certainly an attacker-controlled length field read from
the incoming samc message. The 2nd arg (`%rsi`) is
`&rbx[0x14]` — a pointer into the input buffer.

In the helper's tag-4 body those two are consumed as
`(begin = arg3, size = arg2)` and then recursed with `(size, begin)`
swapped for the tag-5 consumer, which ends up doing
`memcpy(alloc(arg3), arg2, arg3)`.

**From source**, the compiled code at `+0x8f548c` is likely in the
function that parses one of the structured fields of the samc `0x64`
(big) request. Review that function's call and:

1. Confirm whether `arg3` is supposed to be a pointer or a size. The
   helper's body expects `arg3` = begin, but the caller is passing a
   size value there.
2. Fix the argument order, or read from the correct field of the input
   structure, so the (begin, size) pair reaches the helper matching
   its convention.
3. Add a `size <= MaxMessageLen` (or a tighter per-field bound) check
   before the call. `Server.ini`'s `MaxMessageLen` default is
   `67_108_864` (64 MB); nothing that can be meaningfully parsed out of
   a single samc frame should exceed that.

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
only checking that each is individually non-zero. A caller that passes
a well-formed pointer for `rbp` and a bogus-but-positive size in `rsi`
(or vice-versa) produces an `rbp` that no longer points anywhere real,
which is exactly the input the tag-5 recursion then copies from.

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
# with the fix in place, run the same 16-worker campaign that produced
# the crash on the unfixed binary
WORKERS=16 ITERATIONS=10000000 ./fuzzer/run_samc_fuzz_parallel.sh
```

Criterion: zero SEGV cores with `CodeMeterLin + 0x8f431d` as caller
over a 24-hour run at 16 workers. (The unfixed binary averages one core
every 4-5 minutes under that load, so 24 h is comfortably past the
noise floor.)
