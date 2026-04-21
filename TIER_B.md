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

## B-4 (DONE): upper call chain and opcode attribution

Re-analysed from the archived core
(`core.CodeMeterLin.477656.1776755891`). The earlier read of frame #6
conflated two adjacent functions; the true dispatcher is one frame
higher.

Corrected call chain (static VMAs, PIE-relative):

```
#4  0x8f3c36   vtable[4] parser entry of the tag-0x5e class
#5  0x87647e   return addr inside 0x874890 — the class-construction
                and "invoke vtable[4]" site. At 0x876478:
                  call *0x1614062(%rip)      = *(0x1e8a4e0) = vtable[4]
                Vtable of this class is at static 0x1e8a4c0; tag byte
                0x5e is written at `this+0x29` during construction.
#6  0x86271c   return addr inside an argument-shuffling thunk at
                0x862700. The thunk's body is:
                  sub  $0x28, %rsp
                  mov  %rdi, 0x8(%rsp)
                  movl $0x86687a5d, 0x18(%rsp)   ; dispatch tag
                  mov  %rdx, %rdi
                  mov  %rsi, %r9
                  call 0x874890
                  add  $0x28, %rsp
                  ret
                0x862700 has zero direct callers — it is only reached
                by tail-jmp from the opcode-dispatcher below.
#7  0x87005ab5 return addr after `call *0x10(%rax)` where
                rax = (per-connection singleton at *(0x20cbb88))->vtable.
                The vcall target is 0x5e36e0 — the opcode dispatcher
                (see below). Tail-jmp semantics make it "invisible"
                in the backtrace.
#8  0x87003884 thunk with dispatch tag 0x8119da18 calling 0x87004940.
#9  0x86ffd921 per-connection read/decrypt loop.
```

### The opcode dispatcher at 0x5e36e0

Frame #7's vcall goes into `0x5e36e0`, which is a classical RB-tree
`find` implementation with the following in-core structure:

```
per-connection singleton (static 0x20cbb88 → heap object)
  +0x00  vtable_0  (primary base)
  +0x08  vtable_1  (secondary base — multiple inheritance)
  +0x20  pointer to tree-root node  ────────┐
  +0x38  size_t node_count (= 65)           │
                                            │
Each tree node:                             │
  +0x10  left child          ◄──────────────┘
  +0x18  right child
  +0x20  pointer to { HandlerStruct* obj; byte key; ... }
                      ^---+0x00---^    ^---+0x08---^

Inner find loop (0x5e3710..0x5e372b):
   r9  = *(node + 0x20)      ; value ptr
   cmp al, *(r9 + 0x8)       ; input_byte vs node_key
   setb r10b
   node = *(node + 0x10 + r10*8)   ; recurse left (0) or right (8)

Tail-jmp on found node (0x5e3747..0x5e374e):
   rdi = *(rcx + 0x20)        ; value ptr of found node
   rax = *rdi                 ; handler struct
   rax = *(rax + 0x10)        ; handler fn ptr
   jmp *rax
```

The map is populated with **65 entries** — see
[`disasm/opcode_dispatch_map.txt`](disasm/opcode_dispatch_map.txt) for the
full dump. The entry for the vulnerable opcode:

```
opcode 0x5e  →  handler struct 0x01e88868
              →  fn ptr 0x00862700   ← the arg-shuffling thunk above
```

### Answer to "which SAMC opcode triggers this?"

**Opcode byte `0x5e`.** The same byte is used as both:

1. The *first byte of the SAMC plaintext*, read as `*rsi` by the map
   `find` at `0x5e36e0`, selecting handler `0x862700`.
2. The *class-instance tag* written at `this+0x29` during construction
   inside `0x874890`.

This matches the on-wire reproducer in
[`fuzzer/repro_prefixed_hello.py`](fuzzer/repro_prefixed_hello.py):
the five-byte plaintext prefix `5e 35 5e d6 f2` is what makes the
daemon route into the 0x5e handler — the appended "canonical HELLO"
bytes become the payload that supplies the malicious u32 at offset
`+0xc`. There is no dedicated "HELLO mutation"; it is a crafted SAMC
frame with opcode `0x5e`.

### Earlier (incorrect) hypothesis — why it was off

The previous draft of this doc identified the short function at
`0x862680` (the `jmp *%rax` one with `*0x1f33a50 + *0x1f33a40 + eax`)
as "the switch-dispatcher." That function *is* a computed-jump
trampoline, but reading the globals from the archived core shows:

```
*(0x1f33a50) = 0x562aa4c8d334     (heap-anchor pointer)
*(0x1f33a40) = 0x5b9e4c08         (u32 offset constant)
```

and its helper at `0x862eb0` is a single `jmp 0x85f6d0`, which is a
**lazy config reader** that returns `*(0x20f2544)` — a cached u32
sourced from a vcall on a config-holder object (key index 1). It is
config-selected at daemon startup, not opcode-selected per request.
So `0x862680` is unrelated to opcode dispatch; the real dispatch is
the std::map described above.

## Summary for Wibu

1. **Specific vulnerable code**: `+0x8f548c` reads `*(uint32_t*)(rbx + 0xc)`
   from a parse-state input buffer and forwards it (untyped, unbounded)
   as a length into the dispatch helper at `+0x8f3d60`.
2. **Triggering input**: a samc cleartext frame whose **opcode byte
   (plaintext offset 0) is `0x5e`** and whose u32 at offset `+0xc` is
   large enough that the source pointer walks past the readable mapping
   (≥ ~2 MB past the per-request heap allocation suffices on stock
   builds). The opcode dispatcher is the `std::map<byte, Handler*>::find`
   at `+0x5e36e0`, invoked from `+0x87005aa2` as
   `*((*(0x20cbb88))->vtable[2])`.
3. **Fix**: bound `*(u32*)(rbx + 0xc)` against either the remaining
   payload size or `Server.ini`'s `MaxMessageLen` at the call site
   `+0x8f5460..+0x8f548c`. An extra safety net at the allocator
   `+0x8f3b70` (reject `> N MB`) would also catch any missed caller.
4. **Reproducibility**: **single-session, single-packet bug.** The
   deterministic reproducer is
   [`fuzzer/repro_prefixed_hello.py`](fuzzer/repro_prefixed_hello.py).
