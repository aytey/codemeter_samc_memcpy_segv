# Bug-class audit — tagged-memcpy helpers without length caps

## Motivation

The confirmed `CodeMeterLin + 0x8f431d` memcpy SIGSEGV is caused by an
external caller passing `%r8 = LLONG_MAX` to a tagged-memcpy dispatch
helper (`+0x8f3d60`), which means the helper's upper-bound check is
disabled and an input-derived u32 is used verbatim as the copy length
(see `TIER_B.md` §B-5 and `ROOT_CAUSE.md`).

This doc audits whether the same pattern exists elsewhere in the
daemon, i.e. whether the bug is 1-of-N or a **bug class**.

## Method

Binary-only static audit, no dynamic traces:

1. Enumerate every `movabs $0x7fffffffffffffff, %r8` instruction in
   `/usr/sbin/CodeMeterLin` — that immediate constant only appears in
   code that explicitly wants to disable a length cap, so it is a good
   marker for the pattern.
2. For each site, locate the containing function (DWARF
   `.eh_frame` FDE ranges).
3. Discard sites that live *inside* a tagged-memcpy helper itself
   (those are recursive internal calls where the helper forwards an
   already-unbounded cap downwards — they are not new external
   call sites; they just carry the attacker's `LLONG_MAX` forward).
4. For each surviving external site, look at:
   a. which helper it calls;
   b. whether that helper actually reaches `memcpy`/`memmove`;
   c. whether the "length" argument it forwards is input-derived;
   d. where the containing function sits in the broader callgraph.

## Results

### Sites with `%r8 = LLONG_MAX`

```
0x8bea35  in fn 0x8be8f0..0x8bee99 (0x5a9 B)  -> helper 0x8beea0
0x8e47fd  in fn 0x8e4230..0x8e6123 (0x1ef3 B) -> helper 0x8e4230   (recursive!)
0x8f547d  in fn 0x8f4e60..0x8f5622 (0x7c2 B)  -> helper 0x8f3d60   (KNOWN BUG at 0x8f548c)
0x91d804  in fn 0x91c770..0x91dcef (0x157f B) -> helper 0x918e30
```

### The helper family

All four helpers share a canonical template — DWARF-confirmed distinct
functions with the same prologue fingerprint:

```
    sub  $STACK, %rsp
    mov  %rdx, %rbp               ; save length arg
    mov  %fs:0x28, %rax           ; stack canary
    mov  %rax, STACK-8(%rsp)
    mov  %edi|%esi|%ecx, STACK_OFFSET(%rsp)
    mov  %edi|..., %eax
    and  $0xf | $0x1f, %eax       ; tag mask
    cmp  $SMALL_CONST, %eax       ; tag dispatch
    <jcc>
```

All four reach real `memcpy`/`memmove` calls internally:

| helper     | memcpy/memmove sites inside |
|------------|-----------------------------|
| `0x8beea0` | 0x8bf17b, 0x8bf558, 0x8bf72d (memcpy/memmove ×3) |
| `0x8e4230` | 0x8e43eb, 0x8e4881, 0x8e4c1e, 0x8e4f43, 0x8e50db (×5) |
| `0x8f3d60` | 0x8f4213, 0x8f422e, 0x8f4318, 0x8f446f, 0x8f4723 (×5)  |
| `0x918e30` | 0x91a683, 0x91a82c, 0x91b002 (×3) |

### The external caller family

The three surviving external call sites (after removing the
`0x8e47fd` recursive false-positive) live in functions whose prologues
match the *same* parser-caller template (`push {rbp, r15..rbx}; sub
$N, %rsp; and $MASK, %eax; cmp $SMALL, %eax; ...`). These parser
callers have large fan-in:

| parser-caller fn | size     | direct callers | internal `LLONG_MAX` site | known |
|------------------|----------|----------------|----------------------------|-------|
| `0x8be8f0`       | 0x5a9 B  | 28             | `0x8bea35`                 | candidate |
| `0x8f4e60`       | 0x7c2 B  | 22             | `0x8f548c`                 | **confirmed (opcode 0x5e)** |
| `0x91c770`       | 0x157f B | 112            | `0x91d804`                 | candidate |

None of these parser-caller functions appears as a vtable slot in
`.data`/`.rodata` (searched for little-endian image-relative and
absolute addresses — zero hits). They are invoked by regular `call`
instructions, not virtual dispatch. So reachability is a
standard static callgraph problem, not a vtable walk.

### Per-site triage

**Site 0x8bea35** (in fn `0x8be8f0`, calls helper `0x8beea0`)

```
8bea26: lea 0x80(%r13), %rdx           ; arg3 = &r13+0x80     (pointer, not length)
8bea31: mov 0x34(%r13), %esi            ; arg2 = *(u32)(r13+0x34)  ← input-derived
8bea35: movabs $0x7fffffffffffffff, %r8 ; arg5 = no cap
8bea3f: mov %rcx, %rdi                  ; arg1
8bea42: mov $0x76062a96, %ecx           ; arg4 = dispatch tag
8bea47: call 0x8beea0
8bea4c: mov %rax, 0x38(%r13)            ; store return in r13+0x38
```

The length-shaped arg here is the u32 in `%rsi` (`*(r13+0x34)`). If
`0x8beea0` forwards `%rsi` as a memcpy length under any tag path,
and `r13` can be driven by an attacker-controlled SAMC frame, this
is a sibling of the confirmed bug.

**Site 0x91d804** (in fn `0x91c770`, calls helper `0x918e30`)

```
91d7f9: lea 0x58(%rbx), %rcx            ; arg4 = &rbx+0x58   (vector-begin style)
91d7fd: add $0xc, %r13                   ; r13 += 0xc          (input ptr advance)
91d801: mov 0x30(%rbx), %esi             ; arg2 = *(u32)(rbx+0x30) ← input-derived
91d804: movabs $0x7fffffffffffffff, %r8  ; arg5 = no cap
91d80e: mov $0x28f3ea, %edi              ; arg1 = dispatch tag
91d813: mov %r13, %r9                    ; arg6 = input ptr + 0xc
91d816: call 0x918e30
91d81b: mov %rax, 0x34(%rbx)             ; store return in rbx+0x34
```

The length-shaped arg is again in `%rsi` (`*(rbx+0x30)`).
The `+0xc` advance of `%r13` and the `&rbx+0x58` vector-begin
destination both echo the same shapes we see in the confirmed site
(where the `lea 0x14(%rbx), %rsi` copy source sits 0x14 bytes past
the header). If `rbx` maps to an attacker-controlled SAMC frame,
this too is a sibling.

### Notes

- Both candidate sites do pass an **input-derived u32 as the
  length-shaped argument** and both use the `LLONG_MAX` marker.
- We did not trace to a specific SAMC opcode; that would require
  walking the parser-class hierarchy for each of the 64 other
  opcodes and checking whose `vtable[k]` chains into either
  `0x8be8f0` or `0x91c770`.
- Helper-internal `memcpy` calls show the same element-type fanout
  (u8/u16/u32/u64 tag paths) as `0x8f3d60`, so the overflow behaviour
  is expected to be the same: source over-read when the final
  byte-length walks off the allocated mapping.

## Recommendations for Wibu

1. **Treat the confirmed bug as representative of a class.** The
   immediate fix at `+0x8f5460..+0x8f548c` (bound the `*(u32)(rbx+0xc)`
   length field) closes exactly one caller. It does not close
   `0x8bea35` or `0x91d804`, both of which invoke structurally
   identical helpers without any upper-bound cap.
2. **Systemic fix at the helpers.** Each of `0x8f3d60`, `0x8beea0`,
   `0x8e4230`, `0x918e30` should reject a copy length greater than
   either the remaining input-buffer size OR `MaxMessageLen` from
   `Server.ini`, regardless of the caller-supplied `%r8`. That way,
   any external caller that forgets to pass a real cap is caught at
   the last line of defence.
3. **Grep the source for callers that pass `std::numeric_limits<int64_t>::max()`
   or `LLONG_MAX` or `0x7fffffffffffffff` as the size-limit parameter
   to the template(s) that got instantiated as these helpers.** Each
   such caller is a potential hole.

## SAMC reachability of the candidate sites

A static-callgraph analysis (direct `call imm` edges only, bridged once
through vtable slots found in .rodata) answers the reachability
question for each of the 65 SAMC opcodes dumped in
[`disasm/opcode_dispatch_map.txt`](disasm/opcode_dispatch_map.txt):

| target parser-caller | vtables | constructor fn(s) | SAMC opcodes that reach the constructor |
|----------------------|---------|-------------------|-----------------------------------------|
| `0x8f4e60` (known)   | `0x1e8a4c0` | `0x874890` (+ dtor installs `0x8f3c40`, `0x8f3cc0`) | **61 of 65** (opcode `0x5e` is one of them) |
| `0x8be8f0` (candidate) | `0x1e896e0` | `0x8be780`, `0x8be800` | **0 of 65** |
| `0x91c770` (candidate) | `0x1e8aaf0` | `0x9168c0` | **0 of 65** |

The 4 of 65 opcodes that don't reach `0x874890` (`0x7e`, `0x80`,
`0x89`, `0x8a`) are lazy-init config-reader thunks in the `0x85e000`
range, not parser dispatches.

### What this means

- The confirmed bug at `0x8f548c` is the **only** member of this bug
  class reachable from the client-facing SAMC dispatcher. A point-fix
  bounding `*(u32)(rbx+0xc)` at `0x8f5460..0x8f548c` is sufficient to
  close the SAMC attack surface.
- The candidate sites at `0x8bea35` and `0x91d804` still *exist* as
  unbounded `memcpy` patterns, but they live on functions that no
  SAMC opcode reaches. They may be reachable from a different
  surface (daemon↔server responses, license-file parsing, admin
  channels, or internal-only state); we did not trace those.
- The systemic helper-level fix suggested above remains the cleaner
  remediation if Wibu wants defence-in-depth against future callers
  that might reintroduce the pattern.

### Method note

The bridging step is a one-level walk: for each direct caller of
a target parser-caller, if the caller's function body is < 0x80 B
(looks like a vtable-slot thunk), the caller's entry-point address
is searched byte-for-byte in the binary data to find it used as a
code pointer in `.rodata`. The 8-byte-aligned hits are vtables;
walking backward over code-pointer-shaped words identifies the
vtable base. That base's VMA is then searched as a `lea` target in
text to find the constructor. If a deeper chain of vtable hops
existed (e.g., the constructor itself is installed by *another*
vtable), this would miss it; we manually inspected the few
reference sites involved and they were all leaf constructors.
