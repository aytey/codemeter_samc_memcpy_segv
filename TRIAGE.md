# TRIAGE — what the core dump reveals about the bug

This document supersedes the "bug characterisation" section of
[`README.md`](README.md) with analysis performed on a full-memory core
(`coredump_filter=0xff`, 1.9 GB). Summary of what changed:

- The length passed to memcpy is **not an attacker-supplied length
  field** read from the packet. It is `source_end - source_begin`,
  computed from a pair of pointers at `CodeMeterLin+0x8f41c6..0x8f41c9`.
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

i.e. `rbx` is the pointer subtraction, not an input field.

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

Both are caller-saved registers that were set in the **caller's frame**
before the `call` that lands at `+0x8f42f6`'s region. The backtrace gives
us the call chain:

```
#1  0x8f431d   <-- return addr (after memcpy)
#2  0x8f41b5   <-- frame that holds rbp/r12 as locals
#3  0x8f5491
#4  0x8f3c36   <-- close to vtable-slot-0 at +0x8f3c40; probable virtual call
#5  0x87647e   <-- likely the dispatcher that constructed r15's class
#6  0x86271c
#7  0x805ab5
#8  0x803884
#9  0x7fd921
```

Frame `#2` (at `+0x8f41b5`) is the one that loaded `%rbp` and `%r12`
from somewhere before the path reached `+0x8f41c6`. Finding that load
site is the next analysis step for Wibu; from source they should be able
to identify it immediately.

Plausible sources for `%rbp` and `%r12`, in decreasing likelihood given
the class-contains-vectors shape:

1. **Iterators of a std::vector from elsewhere** that was concurrently
   modified or freed: one pointer caches the old begin, the other an
   old end that has since been orphaned.
2. **Packet-derived pointers**: a pair of offsets into a received-frame
   buffer, parsed as (begin, end) without checking both land inside the
   buffer.
3. **A span/range temporary** whose end pointer was taken from a
   sibling structure whose lifetime had ended.

The advisor document [`NEXT_STEPS_PROCESS.md`](NEXT_STEPS_PROCESS.md)
describes how to narrow this further via reduced-concurrency experiments.

## Reproducibility

Unchanged from initial report: statistically reproducible at 16 concurrent
clients (~1 core per 500 K iterations, empirically ~1 per 4–5 min on a
fresh daemon). 8 concurrent clients did not reproduce within a 30 min
window in limited testing. See [`README.md`](README.md) and
[`NEXT_STEPS_PROCESS.md`](NEXT_STEPS_PROCESS.md) §Phase 3.

**Update to the original report's bug characterisation**: the earlier
phrasing of "length field with only a signed-negative guard" was
incomplete. The guard *is* only signed-negative, but the value being
guarded is a pointer difference, not a raw input field. That distinction
matters for fix direction — the remediation is not "add a MaxMessageLen
bound on a length field" but "validate that `source_end` is in-range of
the owning buffer before taking the difference."

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
