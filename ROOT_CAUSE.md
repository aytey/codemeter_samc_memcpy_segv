# ROOT_CAUSE — end-to-end narrative of the bug

A single walkthrough from "attacker sends a samc packet" to "daemon
SIGSEGV inside libc memcpy," consolidating what [`TRIAGE.md`](TRIAGE.md)
and the annotated disassembly show. Intended as the quickest way in for
anyone reading this repo cold.

## One-sentence version

A helper at `CodeMeterLin + 0x8f3d60`, invoked during samc-request
parsing, accepts a `(begin, size)` pair and internally reduces it to a
`memcpy` of `size` bytes from `begin` — but one of its callers supplies
those two fields in **swapped positions**, so the memcpy tries to copy
`≈ 1.6 GB` starting from an address that only has `≈ 10 MB` of mapped
memory after it, and SEGVs.

## The five layers

### Layer 1 — the wire

A samc frame arrives on TCP `127.0.0.1:22350`. It decrypts successfully
(correct key-derivation from `time(NULL)`, valid CRC tail MAC), meaning
its ciphertext and integrity are well-formed.

The mutation that exposes the bug sits inside the **cleartext** payload,
which is what the parser consumes after decryption. We don't yet know
exactly which cleartext bytes map to the two swapped fields — that's
the one remaining question — but we know they come from the cleartext
because the bad values are observable in registers during parsing after
decrypt has completed.

### Layer 2 — the parser state object

The daemon constructs an instance of a **C++ class** to hold the
parsed request. We identified this class from:

- its vtable at `CodeMeterLin + 0x88a4c0` (12 slots)
- slot 0 = destructor at `+0x8f3c40`, whose libstdc++-idiomatic body
  destroys four `std::vector` members at offsets `+0x30`, `+0x48`,
  `+0x88`, `+0x a0`.
- two vtables installed mid-destructor (`0x88a4c0` then `0x1e8d230`)
  reveal a single-inheritance `Derived : Base` layout: the `+0x30` and
  `+0x48` vectors are `Base` members; the `+0x88` and `+0xa0` vectors
  are `Derived` members.

Class layout (reconstructed from the dtor + the live core):

```
+0x00   vtable pointer  (= CodeMeterLin + 0x88a4c0 at crash)
+0x08   scalar, low32 == -1 sentinel
+0x10   scalar  (zero at crash)
+0x18   scalar, high32 == -1 sentinel
+0x20   scalar  (zero at crash)
+0x28   scalar  (0x5e00 = 24064 at crash)
+0x30   std::vector  (Base member)  {begin, finish, end_of_storage}
+0x48   std::vector  (Base member)
+0x60   scalar  (0x7f33b89f927c4608 at crash — hash/nonce-looking)
+0x68   scalar  (0x0000000b612b09cb at crash — the cached bad length)
+0x70   scalar  (zero)
+0x78   scalar  (zero)
+0x80   scalar  (zero)
+0x88   std::vector  (Derived member)
+0xa0   std::vector  (Derived member)
+0xb8   end of class
```

At crash time all four vectors are **empty** (begin = finish = end =
NULL). Several scalars, including the bad length at `+0x68`, have
already been populated. The parser is mid-way through filling the
object when the crash happens.

### Layer 3 — the dispatch helper at `0x8f3d60`

This function is called many times during parsing. Low 4 bits of the
1st argument select a branch:

| tag | branch | purpose (inferred) |
|---|---|---|
| 0 – 3 | `+0x8f3e12` | primitive-ish |
| 4 | `+0x8f4182` | composite: `rbp += rsi`, then recurse tag=5 |
| 5 | `+0x8f41ba` | raw byte range: `rbx = rbp - r12; alloc+memcpy` |
| 6 | fall-through | — |
| 7 + | `+0x8f3ef7` | alternate |

The tag-5 body is the crash site.

```
 8f41c6:  mov  %rbp, %rbx
 8f41c9:  sub  %r12, %rbx              ; length = rbp - r12
 8f41cc:  cmpb $0, 0x17d7a55(%rip)     ; global fast/slow selector
 8f41d3:  jne  8f42f6                   ; take GROW path
 …
 8f42f6:  test %rbx, %rbx
 8f42f9:  js   8f4b1f                   ; ONLY sanity check on length
 8f42ff:  mov  %rbx, %rdi
 8f4302:  call 8f3b70                   ; alloc(length)
 8f4307:  mov  %rax, %r14
 …
 8f430f:  mov  %r14, %rdi
 8f4312:  mov  %r12, %rsi
 8f4315:  mov  %rbx, %rdx
 8f4318:  call 3acd00 <memcpy@plt>      ; ★ SIGSEGV
```

That `js` is the sole guard between "arbitrary pointer subtraction" and
"allocate + memcpy that many bytes from that source pointer". Anything
non-negative passes.

### Layer 4 — the tag-4 → tag-5 recursion

The tag-4 branch does this:

```
 8f4182:  cmp  %r13, %rbp                ; rbp ≤ limit (arg5)
 8f4185:  ja   8f4a8d
 8f418b:  test %rbp, %rbp; sete %al       ; rbp != 0
 8f4191:  test %rsi, %rsi; sete %cl       ; rsi != 0
 8f4199:  jne  8f433c                     ; either zero → bail
 8f419f:  add  %rsi, %rbp                 ; rbp = rbp + rsi
 8f41a2:  mov  $0xd7b4dd5, %edi           ; tag & 0xf = 5
 8f41a7:  mov  %rbp, %rdx                 ; recursive arg3 = new end
 8f41aa:  mov  %rsi, %rcx                 ; recursive arg4 = old rsi
 8f41ad:  mov  %r12, %r8                  ; recursive arg5 = old r12
 8f41b0:  call 8f3d60                     ; recurse
 8f41b5:  jmp  8f4dfc
```

If we name the outer call's interesting args `P = outer_arg3` and
`S = outer_arg2`, the recursion's registers when it reaches the tag-5
body become:

```
recursion.rbp  =  outer_arg3 + outer_arg2  =  P + S
recursion.r12  =                outer_arg2 =  S
recursion.rbx  =  rbp - r12                =  (P + S) - S  =  P
```

So **the memcpy runs with `len = outer_arg3` and `src = outer_arg2`**.

That's by design if the outer caller passes `(size, begin)` —
`arg2 = S = size`, `arg3 = P = begin` — and means
`memcpy(alloc(size), begin, size)`. Clean.

### Layer 5 — the outer caller at `0x8f548c` and the swap

Exactly one external call site passes tag = 4:

```
 8f5467:  mov  0x10(%rbx), %eax        ; read u32 field from *(rbx + 0x10)
 8f546a:  lea  0x6c(%r15), %r12        ; r12 = &r15[0x6c]
 8f546e:  mov  %eax, 0x6c(%r15)        ; r15[0x6c] := u32 (caching?)
 8f5472:  lea  0x88(%r15), %rcx        ; arg4 = &r15[0x88]
 8f5479:  lea  0x14(%rbx), %rsi        ; arg2 = &rbx[0x14]
 8f547d:  movabs $0x7fffffffffffffff, %r8   ; arg5 = LLONG_MAX
 8f5487:  mov  $0x2ff3ff34, %edi       ; tag & 0xf = 4
 8f548c:  call 0x8f3d60
                                       ; arg3 = (rdx) — set earlier in caller
```

In our core: at the moment of the crash, `outer_arg2 = S = 0x7ff0ac00db74`
(a valid user-space heap pointer, exactly the shape of `&rbx[0x14]`), and
`outer_arg3 = P = 0x612b09cb` (~1.63 GB — a size value).

The code above is consistent with **the caller treating `arg2` as a
source pointer (`&rbx[0x14]`) and `arg3` as a size**. But the helper's
tag-4 body does `rbp += rsi` and then a tag-5 memcpy with
`len = rbp - r12 = rbp_outer = outer_arg3`. So to work correctly it
needs **`arg2` to be the size and `arg3` to be the begin pointer** —
the reverse.

Either the caller is passing them in the wrong slots, or the helper's
convention for tag-4 differs from the other tags and this caller
happens to get the opposite variant. From source Wibu can tell
instantly which it is.

## What mutation produces the crash

Any fuzz mutation of the cleartext payload that causes the parse to
reach `+0x8f548c` with `arg3` carrying a bogus ~1.6 GB value is
sufficient. Because that value is read from an input-derived field (we
can see `*(rbx + 0x10)` read into `eax` just before the call, and
similar loads likely set `arg3`), the bug is reachable from a single
crafted request. The reason 16 concurrent workers find it ~4× faster
than 8 is mutation throughput on the 712-byte `0x64` frame — not
concurrent-access mechanics.

## Confidence and remaining unknowns

| claim | confidence | evidence |
|---|---|---|
| SIGSEGV site is reached via `memcpy@plt` from `+0x8f4318` | certain | 10/10 cores, matching disasm |
| `rbx = rbp - r12` is the length formula | certain | disassembly at `+0x8f41c6`, verified by `rbp-r12==rbx` in core |
| `rbp` is not in any mapped region at crash | certain | proc-mappings check in core |
| Containing function is `+0x8f3d60` with tag-based dispatch | certain | prologue at `+0x8f3d60`, branch structure |
| Crash path is tag-4 → tag-5 recursion | high | arithmetic reduction matches the core values exactly |
| Outer caller is `+0x8f548c` | high | it is the only external tag-4 caller in the binary |
| Arg-swap at `+0x8f548c` | **medium** | consistent with the value semantics but not proven from source |
| Bug is single-session reachable | medium–high | no cross-session machinery appears in the call chain; concurrency scaling is O(mutation-rate), not O(pairs-of-sessions) |
| Exact input byte → bad arg3 mapping | unknown | needs either source or longer reduction (see
[`NEXT_STEPS_PROCESS.md`](NEXT_STEPS_PROCESS.md)) |

## See also

- [`TRIAGE.md`](TRIAGE.md) for the mechanical register/stack analysis
- [`disasm/dispatch_function_at_0x8f3d60.txt`](disasm/dispatch_function_at_0x8f3d60.txt)
  for the full annotated disassembly of the dispatch helper
- [`disasm/memcpy_call_site_annotated.txt`](disasm/memcpy_call_site_annotated.txt)
  for the crash-site disassembly annotated with the register meanings
- [`FIX_GUIDANCE.md`](FIX_GUIDANCE.md) for recommended remediation layers
