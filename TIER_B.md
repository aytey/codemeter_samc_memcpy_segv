# Tier B — Deeper static analysis

Findings from walking backward from the call site at `+0x8f548c` and
upward through the backtrace, purely from the on-disk binary.

> **Superseded in several places.** The single-packet reproducer,
> runtime-observed RTTI walk, and attributed reduction are in
> [`README.md`](README.md),
> [`REPRODUCING.md`](REPRODUCING.md),
> [`NEXT_STEPS_PROCESS.md`](NEXT_STEPS_PROCESS.md), and
> [`disasm/rtti_class_hierarchy.txt`](disasm/rtti_class_hierarchy.txt).
> This doc is kept as the *static-only* analysis of how `%rdx` ends
> up holding the bug value, which complements the runtime repro.

## B-5 (DONE): origin of `%rdx` in the tag-4 caller

Critical: we can now point at the **exact input byte range** that drives
the unbounded memcpy length.

Disassembly immediately before `call 0x8f3d60`:

```
 8f5452:  mov  0x4(%rbx), %eax         ; eax = *(u32*)(rbx + 0x4)
 8f5455:  mov  %eax, 0x60(%r15)        ; store at r15+0x60
 8f5459:  mov  0x8(%rbx), %eax         ; eax = *(u32*)(rbx + 0x8)
 8f545c:  mov  %eax, 0x64(%r15)        ; store at r15+0x64
 8f5460:  mov  0xc(%rbx), %edx         ; ★ %edx = *(u32*)(rbx + 0xc)
 8f5463:  mov  %edx, 0x68(%r15)        ;   also cache it at r15+0x68
 8f5467:  mov  0x10(%rbx), %eax        ; eax = *(u32*)(rbx + 0x10)
 8f546a:  lea  0x6c(%r15), %r12
 8f546e:  mov  %eax, 0x6c(%r15)        ; store at r15+0x6c
 8f5472:  lea  0x88(%r15), %rcx        ; arg4 = &r15[0x88] (vector begin slot)
 8f5479:  lea  0x14(%rbx), %rsi        ; arg2 = &rbx[0x14] (data start)
 8f547d:  movabs $0x7fffffffffffffff, %r8   ; arg5 = LLONG_MAX (no real cap)
 8f5487:  mov  $0x2ff3ff34, %edi       ; tag = 4
 8f548c:  call 0x8f3d60                ; → memcpy with len = %rdx
```

Between `0x8f5460` and `0x8f548c`, **nothing writes `%rdx`**. So at call
time, `%rdx` (= dispatch function's `%rbp` = arg3) is exactly the 4-byte
integer at `*rbx+0xc`, zero-extended.

In our core, that value was `0x612b09cb`. The dispatch function's
tag-4 → tag-5 recursion turns it into the memcpy length — so that 4-byte
field of the input buffer is **the bug trigger**.

### The input-buffer structure (`*rbx` layout)

Based on what the caller reads and stores:

```
offset  size  field                                     stored to
  +0x0   4 B  (unread by this caller)                   —
  +0x4   4 B  u32 field A                               r15 + 0x60
  +0x8   4 B  u32 field B                               r15 + 0x64
  +0xc   4 B  u32 field C — ★ becomes memcpy length ★   r15 + 0x68
 +0x10   4 B  u32 field D                               r15 + 0x6c
 +0x14   N B  payload — passed as arg2 (source ptr)     → vector begin
```

The same `*(u32*)(rbx+0xc)` value ends up in TWO places after this
function runs:

1. Cached in the parser-state object at `this+0x68` (matches the
   `0x0000000b612b09cb` u64 we saw in the core at r15+0x68 — its low
   32 bits are field C, and the top 32 bits are field D stored
   contiguously at r15+0x6c).
2. Passed as the `arg3` / length-forming value into the dispatch
   function.

### Remediation direction (concrete)

The obvious fix at the caller:

```
// Somewhere around 0x8f5452, once you have *rbx:
uint32_t payload_len = *(uint32_t*)(rbx + 0xc);
if (payload_len > MAX_REASONABLE_PAYLOAD) {
    // reject
}
if (payload_len > available_bytes_at(rbx + 0x14)) {
    // reject — more than the input buffer actually carries
}
```

or equivalently hard-cap `%rdx` / `%rbx` in the dispatch function
itself at `+0x8f42f6` (before the `call 0x8f3b70` allocator).

## B-6 (DONE): class identification

RTTI is **stripped**: the 16 bytes immediately before the vtable at
`0x88a4c0` are code bytes (end of a previous function), not
`offset_to_top | typeinfo_ptr` as the Itanium C++ ABI would require.
So `dynamic_cast` / `typeid` would not work on this class, and we
cannot extract a human-readable class name from the binary.

What we DO know about the class:

- Constructed at `+0x876449`: vtable installed at `this+0x0`, fixed
  byte `0x5e` written at `this+0x29` (probably a subclass / tag
  discriminator), several scalar fields initialised to `-1` sentinels,
  four `std::vector<T>` members zeroed.
- 12-entry vtable at `+0x88a4c0`, slot 0 = destructor at `+0x8f3c40`,
  slot 4 = some virtual method called immediately after construction
  at `+0x876478` (probably the "parse" entry point — see B-4 below).
- Single inheritance: the destructor installs a second vtable at
  `+0x1e8d230` before destroying the base-class half.

So we describe the class as "the samc request-parser object with
tag byte `0x5e`, vtable `+0x88a4c0`, four `std::vector` members." Wibu
can name it from source in seconds.

## B-4 (partial): upper call chain

Backtrace above the parser:

```
#4  0x8f3c36   (≈ vtable-slot-0 dtor — destructor being walked because
                of stack unwind? or reached from inside another vcall?)
#5  0x87647e   → CONSTRUCTION SITE OF THE CLASS
#6  0x86271c   → switch/jump-table dispatch:
                  rax = base_table + *(u32-case + const)
                  jmp  *rax
                This is the shape of a C++ `switch` or a hand-rolled
                vector-of-handlers. Almost certainly the samc-opcode
                dispatcher — which command byte in the cleartext
                plaintext picks this class to instantiate.
#7  0x805ab5   → vcall via `call *0x10(%rax)` on a global object at
                `fs:0x18c60e6(%rip)` — looks like a per-thread message
                context or allocator lookup.
#8  0x803884   — per-connection worker scaffolding
#9  0x7fd921   — per-connection read / decrypt loop
```

Frame #5's key instruction (`87647e`) is right after `call *0x1614062(%rip)`
which equals `*(0x1e8a4e0)` = `vtable_at_0x88a4c0[4]` (slot 4). So the
pattern at frame #5 is "construct a parser object, then invoke its
vtable[4]" — that's the "parse me" virtual method.

Frame #6 (the jump-table dispatcher) is the code that selects *which*
class to construct for each samc opcode. We didn't fully decode its
jump table because the jump-target lookup uses two runtime u32 globals
(`0x1f33a40`, `0x1f33a50`); from source, identifying the handler for
tag-byte `0x5e` is trivial. From static analysis alone, we can confirm
this function is a switch-dispatcher but we can't enumerate its cases
without dynamic state.

## Summary for Wibu

1. **Specific vulnerable code**: `+0x8f548c` reads `*(uint32_t*)(rbx + 0xc)`
   from a parse-state input buffer and forwards it (untyped, unbounded)
   as a length into the dispatch helper at `+0x8f3d60`.
2. **Triggering input**: a samc cleartext payload whose sub-structure at
   offset 0xc carries a u32 length field > ~64 MB (or whatever the real
   daemon-wide limit should be). The payload eventually routes into the
   class constructed at `+0x876449` (vtable `+0x88a4c0`, tag byte `0x5e`)
   via the switch-dispatcher at `+0x86271c`.
3. **Fix**: bound `*(u32*)(rbx + 0xc)` against either the remaining
   payload size or `Server.ini`'s `MaxMessageLen` at the call site
   `+0x8f5460..+0x8f548c`. An extra safety net at the allocator
   `+0x8f3b70` (reject `> N MB`) would also catch any missed caller.
4. **Reproducibility**: this is a **single-session, single-packet bug**
   once the upstream command opcode is identified. Our 16-worker
   stochastic setup finds it only because random mutation has to land a
   huge value in the specific 4-byte window; you can replace the
   campaign with a one-shot repro as soon as you know which samc opcode
   dispatches to this class.
