# TRIAGE — what the core dump reveals about the bug

This document supersedes the "bug characterisation" section of
[`README.md`](README.md) with analysis performed on a full-memory core
(`coredump_filter=0xff`, 1.9 GB). Summary of what changed:

- The value passed to `memcpy` is computed as `source_end - source_begin` at
  `CodeMeterLin+0x8f41c6..0x8f41c9`. Later static analysis in `TIER_B.md`
  showed why this still becomes input-driven: the tag-4 recursion makes that
  difference equal to the u32 loaded from the opcode-`0x5e` payload at
  `*(rbx+0xc)`.
- `source_begin` (`%r12`) is a valid heap pointer; `source_end` (`%rbp`)
  is **not in any mapped region** at crash time. The bug is that a pair
  of pointers describing a range is inconsistent — one valid, one stale
  or corrupt.
- The only guard on the subtraction result before allocation + memcpy is
  `js <negative_path>`. Any positive value, however large, proceeds.
- The code at `CodeMeterLin+0x8f3c40` — the vtable-slot-0 function of
  the object the parser was building — is a libstdc++ `std::vector`
  destructor pattern: four vector members at `this+0x30`, `+0x48`,
  `+0x88`, `+0xa0`, plus a base-class vtable installed mid-function.
  Confirms the surrounding code is C++ with vector-based request objects,
  and gives Wibu a strong class-identification hint.

See [`disasm/memcpy_call_site_annotated.txt`](disasm/memcpy_call_site_annotated.txt)
for the annotated disassembly of the call site, and
[`disasm/vtable_slot0_destructor_at_0x8f3c40.txt`](disasm/vtable_slot0_destructor_at_0x8f3c40.txt)
for the class destructor.

## Crash core state

From `core.CodeMeterLin.477656.1776755891`. Registers at SIGSEGV:

```
rip = __memmove_evex_unaligned_erms + 1594      (libc memcpy fast path)
rbx = 0x612b09cb                                 copy length (bytes) ~= 1.63 GB
rdx = 0x99b                                      bytes remaining in memmove loop
                                                 (≈ 1.63 GB already copied)
rdi = 0x7ff01f787040                             memcpy dst (current position)
rsi = 0x7ff0aca45ba4                             memcpy src (current position)
r12 = 0x7ff0ac00db74                             SOURCE BEGIN (valid, mapped)
rbp = 0x7ff10d2be53f                             SOURCE END   (NOT MAPPED)
r14 = 0x7ff01ed4f010                             destination base (fresh alloc)
r15 = 0x7ff0980038c0                             this-pointer of the building object
r13 = 0x7ff098003948                             element pointer inside r15 (r15+0x88)
rsp = 0x7ff0a57f4828
```

Mappings at crash time (relevant excerpt):

```
0x7ff0ac000000 - 0x7ff0aca48000   RW    (source buffer — r12 and initial rsi inside)
0x7ff0aca48000 - 0x7ff0b0000000   ---   (no-access reservation immediately after)
                                        fault addr 0x7ff0aca48ba4 is inside this gap
```

Verification of the key identity `%rbx == %rbp - %r12`:

```python
>>> hex(0x7ff10d2be53f - 0x7ff0ac00db74)
'0x612b09cb'
```

i.e. `rbx` is the pointer subtraction at the crash site. `TIER_B.md` later
traces why this pointer subtraction reduces to the input-derived u32 from
`*(rbx+0xc)` at the external tag-4 caller.

## Call-site disassembly (compact)

```
 8f41c6:  mov   %rbp, %rbx
 8f41c9:  sub   %r12, %rbx              ; rbx = rbp - r12  (length)
 8f41cc:  cmpb  $0, 0x17d7a55(%rip)     ; global boolean
 8f41d3:  jne   8f42f6                  ; take grow path on flag
 …   (cheap copy-in-place path, not taken in this crash)

 8f42f6:  test  %rbx, %rbx
 8f42f9:  js    8f4b1f                  ; ONLY guard: signed-negative
 8f42ff:  mov   %rbx, %rdi
 8f4302:  call  8f3b70                  ; allocator — succeeds for 1.6 GB
 8f4307:  mov   %rax, %r14
 8f430a:  cmp   %r12, %rbp
 8f430d:  je    8f431d                  ; skip if empty range
 8f430f:  mov   %r14, %rdi              ; memcpy(dst, src, len)
 8f4312:  mov   %r12, %rsi
 8f4315:  mov   %rbx, %rdx
 8f4318:  call  3acd00 <memcpy@plt>     ; <<< SIGSEGV
 8f431d:  …                             ; return address in all cores
```

Full annotated version: [`disasm/memcpy_call_site_annotated.txt`](disasm/memcpy_call_site_annotated.txt).

## The class being parsed (`%r15`)

The object at `r15 = 0x7ff0980038c0` has its vtable pointer at
`CodeMeterLin+0x88a4c0`. The first vtable slot is the destructor at
`+0x8f3c40`, which is textbook libstdc++ std::vector dtor pattern:

```
mov  0xN (this), %rdi         ; v._M_start
test %rdi, %rdi ; je NEXT     ; skip if NULL
mov  0xN+0x10 (this), %rsi    ; v._M_end_of_storage
sub  %rdi, %rsi               ; size = end - begin
call operator delete(void*, size_t)
```

repeated four times, with a **second vtable `0x1e8d230` installed
between the second and third pair** — this is the C++ derived→base dtor
chain. So this class has single inheritance from some base class, with
two vector members in each class.

Class layout deduced:

```
+0x00   vtable pointer                    (= 0x88a4c0 at crash)
+0x08   scalar (low32 = -1 sentinel, from core)
+0x10   scalar (0)
+0x18   scalar (high32 = -1 sentinel)
+0x20   scalar (0)
+0x28   scalar (0x5e00 = 24064 — looks like a capacity/limit)
+0x30   std::vector #1  _M_start  /  +0x38 _M_finish  /  +0x40 _M_end_of_storage   (base class)
+0x48   std::vector #2  _M_start  /  +0x50 _M_finish  /  +0x58 _M_end_of_storage   (base class)
+0x60   scalar (0x7f33b89f927c4608 — high-entropy; hash / nonce?)
+0x68   scalar (0x0000000b612b09cb)  ← same low32 bytes as rbx — likely cached length
+0x70   scalar (0)
+0x78   scalar (0)
+0x80   scalar (0)
+0x88   std::vector #3  _M_start  /  +0x90 _M_finish  /  +0x98 _M_end_of_storage   (derived)
+0xa0   std::vector #4  _M_start  /  +0xa8 _M_finish  /  +0xb0 _M_end_of_storage   (derived)
+0xb8   end
```

All four vectors are empty (begin = finish = end_of_storage = NULL) at crash
time. The parser was building this object from the wire and had populated
several scalar fields — including `+0x68` — but had not yet filled any
vector. The memcpy at `+0x8f4318` is the point at which it was about to
populate one of them.

## Where do `%r12` and `%rbp` come from?

Traced by disassembling from the function prologue forward. The
containing function is **at `CodeMeterLin+0x8f3d60`** — a type-dispatched
copy/serialize helper whose first 4-bit tag (`arg1 & 0xf`) selects which
branch runs:

```
 8f3d60:  push … ; sub $0x118, %rsp       ; prologue
 8f3d74:  mov  %rcx, %r12                  ; r12 = arg4
 8f3d77:  mov  %rdx, %rbp                  ; rbp = arg3
 …                                          ; arg2 = %rsi (preserved)
 8f3d8f:  mov  %edi, %eax
 8f3d91:  and  $0xf, %eax
 8f3daa:  je   8f4182                      ; tag == 4 → composite path
 8f3db3:  jne  8f41ba                      ; tag == 5 → raw-range path (CRASH)
```

So **`%rbp` and `%r12` are the 3rd and 4th function arguments**, provided
by the caller. The tag-5 path computes `rbx = rbp - r12` — the
"serialize the bytes between these two pointers" operation. The tag-4
path does `rbp += rsi` and **recursively calls 0x8f3d60 with tag=5**,
passing the new rbp (= old_rbp + rsi) as arg3 and the old rsi as arg4.

That recursion is the crash path in our core. The backtrace's "frame #2"
at `+0x8f41b5` is the return site of the recursive self-call, not a
separate function (no frame pointers → GDB mistakes the recursion for a
distinct frame).

### What that recursion implies for the register state at crash

Let `P` = outer caller's arg3 and `S` = outer caller's arg2. Then:

```
outer body:       rbp := P, r12 := <outer arg4>, rsi := S
                  rbp += rsi              =>  rbp' = P + S
                  recurse(tag=5, rdx=rbp'=P+S, rcx=S, r8=<outer r12>)

recursion body:   r12 := S,        rbp := P + S
                  rbx := rbp - r12 = P                     ← length
                  memcpy(alloc(P), src=r12=S, len=P)       ← SEGV
```

So the memcpy is effectively:

```
memcpy(alloc(P), src = (caller's arg2 value), len = P)
```

where `P` is caller's *arg3* treated as a length, and `arg2` is treated
as a source pointer.

### The concrete values in the core

```
rbx (length, memcpy) = P = 0x612b09cb        ; ~1.6 GB
r12 (src,    memcpy) = S = 0x7ff0ac00db74    ; inside a real heap mapping
rbp (src end impl.) = P+S = 0x7ff10d2be53f   ; in a non-accessed gap
```

Matching these back to the outer caller: the **caller passed arg2 =
0x7ff0ac00db74 and arg3 = 0x612b09cb**. The first is clearly a pointer
value (user-space heap range); the second is clearly a size value (~1.6
GB). **They're in swapped positions** — the caller passed `(size,
pointer)` to a helper that expects `(pointer, size)`, or equivalently
pulled them from a structure whose layout the caller has wrong.

## Most likely buggy caller

Static callers of `0x8f3d60` and the low-4-bits of the tag they pass:

| call site | tag | notes |
|---|---|---|
| 0x8f3459 | 1 | primitive path |
| 0x8f3bf9 | 9 | — |
| 0x8f3f52 | 0 | — |
| 0x8f408b | 0 | — |
| 0x8f411a | 3 | — |
| 0x8f4161 | 2 | — |
| **0x8f41b0** | **5** | *recursive self-call, triggered by tag-4* |
| 0x8f44c8 | 6 | — |
| 0x8f4892 | 6 | — |
| 0x8f48f9 | 7 | — |
| **0x8f548c** | **4** | **the only external tag-4 caller** — likely the one |

The call site at **`0x8f548c`** is the one plausible external entry into
tag-4, which is the only route to the crashing tag-5 recursion. Its
argument setup immediately before the call is:

```
 8f5467:  mov  0x10(%rbx), %eax        ; eax = *(rbx + 0x10) — a u32 from input
 8f546a:  lea  0x6c(%r15), %r12
 8f546e:  mov  %eax, 0x6c(%r15)        ; store u32 at r15+0x6c
 8f5472:  lea  0x88(%r15), %rcx        ; arg4 = &r15[0x88]
 8f5479:  lea  0x14(%rbx), %rsi        ; arg2 = &rbx[0x14]
 8f547d:  movabs $0x7fffffffffffffff, %r8   ; arg5 = LLONG_MAX (no-limit sentinel)
 8f5487:  mov  $0x2ff3ff34, %edi       ; arg1, low 4 bits = 4
 8f548c:  call 0x8f3d60
```

Here `%rbx` is clearly an input-buffer pointer (caller does `*(rbx+0x10)`
etc.), and `%r15` is the target object. The 3rd arg (`%rdx`) is not set
in this snippet — it's whatever the caller left in `%rdx` from earlier,
or was loaded a few instructions before. That's where the bad value
originates.

## Recommended focus for Wibu

From source, the fix is straightforward once the `+0x8f548c` caller is
identified:

1. Locate the function whose compiled entry point ends up near
   `+0x8f5400` and whose body performs `lea 0x14(%rbx), %rsi; call
   0x8f3d60` at tag=4.
2. Identify where `%rdx` / `%rsi` come from just before that call — most
   likely a pair of fields in the `*rbx`-pointed input structure.
3. Add a bound: either enforce `size < MaxMessageLen` at that source
   structure's parse site, or validate the (begin, size) pair before
   passing to `0x8f3d60`.

The existing flag tested at `+0x8f41cc` (the global bool that currently
only controls a fast/slow selector for the in-place-vs-grow path) is
also a good place to add a hard cap on `%rbx` before the
`call 0x8f3b70` allocator.

See [`disasm/dispatch_function_at_0x8f3d60.txt`](disasm/dispatch_function_at_0x8f3d60.txt)
for the full annotated disassembly of the dispatch function.

## Reproducibility

This section is historical core triage. Reproducibility has improved since the
initial report: the crash now has deterministic direct repros for both
`5e00000000 || HELLO` and a zero-tail prefixed ACK after a normal HELLO/SID
exchange. See [`REPRODUCING.md`](REPRODUCING.md).

The older statistical observation is still useful context: before the
deterministic prefix shape was reduced, the crash appeared under high-worker
random mutation campaigns and was hard to attribute because many workers saved
post-crash bystanders.

**Update to the original report's bug characterisation**: the earlier
phrasing of "length field with only a signed-negative guard" was incomplete
at this layer. The immediate guard is applied to a pointer difference, but the
tag-4 to tag-5 recursion makes that difference equal to an input-derived u32
loaded by the external caller. The fix should therefore validate both the
source-buffer extent and the u32 length field before the helper call, with a
final upper-bound check inside the helper.

## What Wibu can do without the fuzzer

1. Build a debug or symbol-equipped `CodeMeterLin` and load the core,
   the function at `+0x8f3c40`/`+0x87647e`/`+0x8f41b5` will be named
   straight away.
2. Audit the caller (frame #2) of the pointer-subtraction at
   `+0x8f41c6`: what produces `%rbp` and `%r12`? That's the field-level
   root cause.
3. Add an invariant that `source_end >= source_begin` and
   `source_end ≤ <some known upper bound of the backing allocation>`
   before the subtraction. Ideally at the place where `%rbp` is loaded;
   alternatively a hard `rbx ≤ MaxMessageLen` gate at `+0x8f42f6`.
