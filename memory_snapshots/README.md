# Memory snapshots extracted from the crash core

All extracted from
`/var/tmp/cm_cores/core.CodeMeterLin.477656.1776755891` (1.9 GB raw
core, `coredump_filter=0xff`, daemon pid 477656).

CodeMeterLin loaded at base `0x562a86800000` in the crashing process.

| file | address | size | meaning |
|------|---------|------|---------|
| `src_begin_at_r12.bin` | `0x7ff0ac00db74` | 4 KB | First 4 KB of the memcpy source. Starts at the byte where `memcpy(dst, src=%r12, len=%rbx)` began reading. Content is opaque 32-bit words — looks like either ciphertext or packed struct data. |
| `src_at_memcpy_crash_rsi.bin` | `0x7ff0aca44ba4` | 4 KB | 4 KB window ending at the fault address (`0x7ff0aca48ba4`). Spans from 0x1000 before the end of the mapped source region to the mapping boundary. |
| `dst_fresh_alloc_at_r14.bin` | `0x7ff01ed4f000` | 4 KB | First page of the freshly-allocated destination buffer (`%r14 = 0x7ff01ed4f010`). Shows what bytes from the source got copied in before the SEGV — the first u32 is `0x700c05ad` followed by zeros. |
| `parser_state_at_r15.bin` | `0x7ff098003800` | 512 B | The C++ parser-state object (`%r15 = 0x7ff0980038c0`) with 0xc0 bytes of preceding context. Shows the class layout: vtable pointer at `+0x0`, scalars at `+0x8..+0x28`, four `std::vector` members at `+0x30,+0x48,+0x88,+0xa0`, and the offending length value `0x0000000b612b09cb` at `+0x68`. All four vectors are empty at crash time. |
| `subobject_at_r13.bin` | `0x7ff098003900` | 256 B | Region around `%r13 = 0x7ff098003948` (= `%r15 + 0x88`) — the third vector's `_M_start` slot. Non-zero values after offset 0x78 suggest a nested object whose state may be relevant. |
| `stack_at_rsp.bin` | `0x7ff0a57f4800` | 512 B | Top of the crashing thread's stack; includes the return address to `+0x8f431d` at offset +0x28 and further addresses up the call chain. |

## How to read these

```bash
xxd memory_snapshots/parser_state_at_r15.bin | less
# …or, with symbols if you have them:
gdb /usr/sbin/CodeMeterLin -ex "restore memory_snapshots/parser_state_at_r15.bin binary 0x7ff098003800"
```

(Addresses are the crashing process's layout; ASLR means the same class
in a fresh process will be at a different base — but all internal
offsets are preserved.)
