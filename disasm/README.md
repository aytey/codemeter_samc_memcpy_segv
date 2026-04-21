# Disassembly windows — backtrace-aligned

Each `frameNN_*.txt` is an `objdump -d` window of `/usr/sbin/CodeMeterLin`
around the instruction at the given backtrace return address. Window
is ± a few dozen bytes so reviewers can see the call that invoked the
inner frame and a few instructions on either side, without needing the
whole binary.

| file | covers | role |
|------|--------|------|
| `frame01_memcpy_site.txt`                | +0x8f4280..+0x8f4380 | The `call memcpy@plt` and its return site at +0x8f431d (backtrace frame #1). |
| `frame02_inside_dispatch.txt`            | +0x8f4100..+0x8f41d0 | The tag-4 body of the dispatch function, including `add %rsi, %rbp` and the recursive call that produces "frame #2" at +0x8f41b5. |
| `frame03_composite_to_tag5.txt`          | +0x8f5440..+0x8f54c0 | The **external tag-4 caller** at +0x8f548c — the known plausible root of the crash path. |
| `frame04_virtual_call_nearby.txt`        | +0x8f3b90..+0x8f3c40 | The allocator helper `+0x8f3b70` and the vtable-slot-0 entry `+0x8f3c40` (class destructor). |
| `frame05_probable_request_dispatcher.txt`| +0x876400..+0x8764a0 | Backtrace frame #5 at +0x87647e — a layer above the parser class. Likely the dispatcher that picked which class to construct for this samc command. |
| `frame06_upper_handler.txt`              | +0x862700..+0x862760 | Backtrace frame #6 at +0x86271c. |
| `frame07_samc_msg_dispatcher.txt`        | +0x805a80..+0x805b00 | Backtrace frame #7 at +0x805ab5 — plausibly the samc-opcode dispatcher. |
| `frame08_connection_worker.txt`          | +0x803860..+0x803900 | Backtrace frame #8 at +0x803884. |
| `frame09_read_loop.txt`                  | +0x7fd8e0..+0x7fd960 | Backtrace frame #9 at +0x7fd921 — probable per-connection message-read loop. |

## Other files here

| file | role |
|------|------|
| `crash_site_0x8f431d.txt`                     | Wider objdump around the crashing instruction and the ±0x80-byte neighbourhood. |
| `memcpy_call_site_annotated.txt`              | Hand-annotated version of the call site showing `rbx = rbp - r12` and the only guard. |
| `dispatch_function_at_0x8f3d60.txt`           | Full annotated disassembly of the type-dispatched helper whose tag-5 branch is the crash path. |
| `vtable_at_0x88a4c0.txt`                      | Raw bytes of the parser-state class's vtable. |
| `vtable_slot0_destructor_at_0x8f3c40.txt`     | Disasm of the destructor; identifies four `std::vector` members + base class. |

## Binary used

`/usr/sbin/CodeMeterLin` from package `CodeMeter-8.40.7154-505.x86_64`
(sha256 `6bf82aa09b7f9696b4bf7535a7cb9a2fee62be5220952f2c237b6c73cbe09917`).
