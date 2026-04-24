# AFL++/QEMU and Native Handler Coverage

This document captures the post-`0x5e` research state as of 2026-04-24:

- the in-process AFL++/QEMU harness for the known `0x5e` parser family;
- what that harness did and did not find;
- which native public SDK commands are actually healthy enough to use for
  coverage discovery;
- which native `CodeMeterLin` handlers are hot under those commands; and
- which functions are the best second-stage in-process fuzzing targets.

It is complementary to:

- `ROOT_CAUSE.md` for the confirmed `0x5e -> 0x8f431d` crash;
- `SDK_SEED_CAPTURE.md` for the SDK probe and MITM seed capture path; and
- `RESEARCH_LOG.md` for chronology.

## Executive Summary

1. The first in-process AFL++/QEMU harness for the `0x5e` parser family is
   working.
2. Its first saved crashes all minimized to the same network-reachable
   20-byte trigger:

   ```text
   5e30303030303030303030303030303030303030
   ```

3. That trigger is not a new bug class. It replays back into the already known
   `CodeMeterLin+0x8f431d` crash family.
4. Native public SDK traffic does **not** naturally hit the obvious `0x5e`
   neighborhood candidates such as:
   - `FUN_009f2ca0`
   - `FUN_008f08f0`
   - `FUN_009f4e60`
5. Broader QEMU block coverage on native-valid commands identifies better
   second-stage native targets:
   - `FUN_00bef130`
   - `FUN_007fd840`
   - `FUN_007feb90`
   - `FUN_00552530`
   - `FUN_0071ab20`
6. The later direct-call native triplet (`bef830`, `7f9060`, `54ace0`) was
   useful for hot-path discovery, but it fuzzes post-parse heap state and does
   not translate cleanly back into network requests.
7. The current weekend-scale recommendation is the newer network-faithful
   `net_*` harness family, where the AFL input is again the decrypted native
   C->D request body.

## Current Reproducer Surface

All currently maintained local crash variants were revalidated serially with a
daemon restart between runs. The current repro surface is:

- dedicated reproducers:
  - `fuzzer/repro_prefixed_hello.py`
  - `fuzzer/repro_prefixed_ack_standalone.py`
- preset SDK crash wrapper:
  - `fuzzer/repro_sdk_crash.py`

The validated SDK-seeded variants cover the following native families:

- `access2_body`
- `access_info_system`, `access2_info_system`
- `access_public_key`, `access2_public_key`
- `access_calc_sig`, `access2_calc_sig`
- `access_crypt2`, `access2_crypt2`
- `access_cryptsim`, `access2_cryptsim`
- `access_validate_signedtime`, `access2_validate_signedtime`
- `access_lt_create_context`, `access2_lt_create_context`
- `access_lt_import_update`, `access2_lt_import_update`
- `access_lt_cleanup`, `access2_lt_cleanup`

These are all currently understood as different ways to reach the same
`0x5e -> 0x8f431d` bug class, not independent crash signatures.

## In-Process AFL++/QEMU Harness for `0x5e`

### Files

- preload harness:
  - `preload/cm_afl_harness.c`
- helper scripts:
  - `scripts/build_cm_afl_harness.sh`
  - `scripts/build_cm_afl_corpus.py`
  - `scripts/run_cm_afl_harness_probe.sh`
  - `scripts/run_cm_afl_showmap.sh`
  - `scripts/run_cm_afl_qemu_smoke.sh`
  - `scripts/start_cm_afl_qemu.sh`
- crash triage and replay:
  - `scripts/triage_cm_afl_crashes.py`
  - `fuzzer/replay_afl_5e_input.py`

### Harness shape

The harness does **not** try to relink `CodeMeterLin` as a library. Instead it
uses `LD_PRELOAD`/`AFL_PRELOAD` to hook `__libc_start_main`, resolve the PIE
base at runtime, and call the real `CodeMeterLin` parser wrapper in-process.

The current working mode is:

- `CM_AFL_HARNESS_MODE=call_stub`

The recovered working contract for the `0x5e` case-`0x0e` wrapper is:

- wrapper entry: `0x8f3c20`
- parser entry: `0x8f4e60`
- object size: `0xb8`
- wrapper ABI:
  - `RDI = obj`
  - `RSI = input_buf`
  - `EDX = input_len`
  - `R8  = ctx`
  - `R9  = 0xb8`

The harness synthesizes:

- the `0xb8` object;
- the required vtable/state fields; and
- the minimal live context/back-pointer pattern observed at the natural
  callsite.

### AFL configuration

The stable working setup is:

```bash
AFL_PRELOAD=/path/to/preload/cm_afl_harness.so \
CM_AFL_HARNESS_MODE=call_stub \
AFL_NO_FORKSRV=1 \
AFL_QEMU_INST_RANGES=0x8f3c20-0x8f4f20 \
afl-fuzz -Q ...
```

Notes:

- normal AFL forkserver mode was not stable for this target;
- restricting QEMU instrumentation to the parser/wrapper range materially
  reduced startup noise; and
- the fuzz input is the parser-visible cleartext body, not a full encrypted
  SAMC packet.

## What the `0x5e` AFL Harness Found

The first live AFL run produced 3 saved crashes and 2 hangs. Those crashes
were then minimized and replayed.

Result:

- all 3 saved crashes minimized to the same 20-byte input:

  ```text
  5e30303030303030303030303030303030303030
  ```

- that minimized input:
  - crashes the in-process harness;
  - crashes on direct network replay; and
  - crashes via seeded MITM replay through a valid SDK session.

This means the current `0x5e` harness found a new **minimal trigger** for the
known bug class, not a new independent vulnerability.

### Replay path

`fuzzer/replay_afl_5e_input.py` converts the AFL artifact back into the
parser-visible request body and then replays it either:

- directly as a network request; or
- injected into a valid SDK-generated session.

That script is the bridge from harness findings back to real network
reachability.

## Native Public Command Quality

The public/native SDK commands currently fall into three practical buckets.

### Strong/native-valid

These complete cleanly and are the best current sources for native-path
coverage discovery:

- `version-null`
- `get-servers`
- `access`
- `access2`
- `access-version`
- `access2-version`
- `access-info-system`
- `access2-info-system`
- `access-info-version`
- `access2-info-version`

### Semi-valid but precondition-gated

These get through the initial access path but fail with structured daemon/API
errors (`105` or `115`). They are useful as seed families, but were not the
best place to start for native-path discovery.

Representative families:

- `public-key`
- `calc-sig`
- `crypt2`
- `cryptsim`
- `validate-*`
- `lt-*`
- `cloud-delete`
- `cloud-verify`

### Weak defaults

- `cloud-raw`

These are currently the weakest defaults without extra structured parameters.

## Negative Result: The Obvious `0x5e` Neighbors Are Cold Natively

The following targets were traced under native public SDK traffic and stayed
cold:

- `FUN_009f2ca0`
- `FUN_008f08f0`
- `FUN_009f4e60`

This matters because it means:

- the working `0x5e` harness is fuzzing a path that becomes reachable only
  when traffic is reinterpreted as `0x5e`;
- those functions are not good second-stage native harness targets; and
- the next in-process harness should be chosen from the actual native hot path,
  not from the `0x5e` neighborhood by proximity.

Relevant helper scripts:

- `scripts/trace_9f4e60_entry.py`
- `scripts/trace_9f2ca0_entry.py`
- `scripts/trace_8f08f0_entry.py`
- `scripts/run_cm_native_wrapper_qemu_trace.sh`
- `qemu_plugins/cm_native_wrapper_trace.c`

## Native-Valid QEMU Block Coverage

To find the real native hot path, a broader QEMU plugin was used:

- plugin:
  - `qemu_plugins/cm_block_cov_trace.c`
- runner:
  - `scripts/run_cm_block_cov_trace.sh`

Method:

1. run a startup-only baseline;
2. run one native-valid command per daemon instance;
3. diff the executed basic-block set against startup-only; and
4. map the hot offsets back to Ghidra functions.

### Incremental block counts over startup

Observed useful deltas:

- `access`: `3985` new blocks
- `access2`: `4017`
- `access-info-system`: `4291`
- `access-info-version`: `4230`
- `get-servers`: `5568`

### Common hot native families

The most important hot offsets mapped back to these functions:

#### `FUN_00bef130`

Hot for:

- `access`
- `access2`
- `access-info-system`
- `access-info-version`

Representative offsets:

- `0xbef830`
- `0xbef8b2`
- `0xbf0a0b`

Static characteristics:

- large stateful builder/dispatcher;
- repeatedly hit under multiple native-valid commands;
- calls `memcpy`, `memmove`, `memset`.

#### `FUN_007fd840`

Hot for the same `access` / `info-*` family.

Representative offsets:

- `0x7fdeb0`
- `0x7fdf03`
- `0x7f9dc0`
- `0x7fcd13`

Static characteristics:

- large stateful container/string-style manipulator;
- calls `memcpy`, `memmove`.

#### `FUN_007feb90`

Also hot in the same family.

Representative offsets:

- `0x7ff22a`
- `0x7ff20e`

Static characteristics:

- adjacent container/helper logic;
- calls `memmove`.

#### `FUN_00552530`

Especially important for `get-servers`.

Representative offset:

- `0x552aaa`

Static characteristics:

- large buffer/container builder;
- calls `memcpy`, `memmove`, `strlen`;
- good candidate for a distinct second harness.

#### `FUN_0071ab20`

Also `get-servers`-specific.

Representative offset:

- `0x71ae60`

Static characteristics:

- message/status/string builder;
- calls `memcpy`, `memset`, `snprintf`, `strlen`.

#### `FUN_00548010`

Representative offset:

- `0x548030`

Static characteristics:

- smaller helper;
- calls `memcpy`;
- lower priority than the larger stateful targets above.

## Recommended Next Native Harness Targets

The current ranking is:

1. `FUN_00bef130`
2. `FUN_00552530`
3. `FUN_007fd840`

Reasoning:

- they are hot under real native-valid traffic;
- they are not merely tiny helper leaves;
- and they have enough internal copy/move behavior to justify direct-call
  in-process fuzzing.

Targets that currently look lower-value:

- `FUN_007feb90`
  - likely too close to `FUN_007fd840` to be the next one;
- `FUN_00548010`
  - smaller helper, lower leverage as a first native harness;
- `FUN_0071ab20`
  - plausible later, but still behind `FUN_00552530`.

## Recommended Process From Here

1. Recover the ABI for `FUN_00bef130`.
2. Add a second `CM_AFL_HARNESS_MODE=...` to `preload/cm_afl_harness.c`.
3. Seed it only with native-valid parser-visible bodies, not `0x5e`
   reinterpretations.
4. Smoke-test with `afl-showmap`.
5. Only then scale it out with AFL `-M` / `-S` workers.

This keeps the next harness attached to the actual native hot path instead of
repeating the already-understood `0x5e` reinterpretation bug.

## Native Direct-Call Triplet

That next step is now in place. The repo has a second-stage native harness
setup for three hot native paths:

- `bef830` for the `FUN_00bef130` family
- `7f9060` for the `FUN_007fd840` family
- `54ace0` for the `FUN_00552530` family

These are intentionally the traced hot offsets / wrapper entries, not the
larger enclosing Ghidra function starts. The direct-call targets were chosen
because they are:

- reached by native-valid public SDK traffic;
- narrow enough to snapshot and relocate in-process; and
- materially more stable than the earlier cold `0x9f...` candidates.

### Files

- entry tracer:
  - `gdb_scripts/trace_function_entry.py`
  - `scripts/trace_function_entry.py`
- asset generator:
  - `scripts/build_cm_afl_native_assets.py`
  - generated header: `preload/cm_afl_native_assets.h`
- preload harness:
  - `preload/cm_afl_harness.c`
- corpus builder:
  - `scripts/build_cm_afl_native_corpus.py`
- runners:
  - `scripts/run_cm_afl_native_showmap.sh`
  - `scripts/start_cm_afl_native_qemu.sh`
  - `scripts/start_cm_afl_native_triplet.sh`

### How the call contracts were recovered

The process was:

1. trace native-valid commands with QEMU block coverage to find hot offsets;
2. attach hidden GDB to live `CodeMeterLin` and hardware-break on those hot
   offsets;
3. dump entry registers, pointer-like arguments, and a short backtrace;
4. inspect the immediate callers in raw disassembly; and
5. choose the smallest wrapper / hot callee that preserved a stable live ABI.

The generic entry tracer is `scripts/trace_function_entry.py`, which drives
the hidden-GDB script at `gdb_scripts/trace_function_entry.py`.

The traces used for the current asset header were:

- `bef830` under `access_info_system`
- `7f9060` under `access_info_system`
- `54ace0` under `get_servers`

### Snapshot / relocation model

`scripts/build_cm_afl_native_assets.py` turns the captured traces into
`preload/cm_afl_native_assets.h`. For each mode it records:

- original PIE base;
- direct-call function offset;
- preserved scalar register values;
- the readable argument blobs captured at entry; and
- mutation metadata describing which blob region should receive AFL input.

At runtime the preload harness:

- clones those blobs into fresh heap memory;
- relocates qwords that originally pointed into the executable mapping to the
  current PIE base;
- relocates qwords that originally pointed inside a captured blob to the new
  live clone address; and
- then calls the real native target in-process.

This keeps the harness in-process while preserving enough live pointer
topology for the native handlers to run.

### Current mode details

#### `bef830`

- target offset: `0xbef830`
- family: `FUN_00bef130`
- current mutation strategy:
  - mutate a region in the captured `rdi` blob at offset `0x200`
- current seed set:
  - `large.bin`

This mode is working, but still shows slight instrumentation variability
(`var_byte_count` / `corpus_variable` nonzero). It is usable, but it is the
least clean of the three current mains.

#### `7f9060`

- target offset: `0x7f9060`
- family: `FUN_007fd840`
- current mutation strategy:
  - mutate a region in the captured `rsi` blob at offset `0x100`
  - set `rdx = input_len`
  - mirror the same length into the captured blob fields at `+0x10` and
    `+0x18`
- current seed set:
  - `small.bin`

This is currently the cleanest of the three native mains.

#### `54ace0`

- target offset: `0x54ace0`
- family: `FUN_00552530`
- current mutation strategy:
  - mutate a region in the captured `rsi` blob at offset `0x20`
- current seed set:
  - `host-ish.bin`
  - `medium.bin`

This is the most distinct additional native surface because it comes from the
`get-servers` path rather than the `access/info` family.

### Seed corpus policy

The native corpora are deliberately minimal.

Early broader corpora were a mistake:

- `7f9060` had seeds that AFL immediately binned as crashing during dry run;
- `54ace0` had duplicate low-value seeds; and
- those made the mains look worse than they were.

`scripts/build_cm_afl_native_corpus.py` now deletes stale `.bin` files and
rebuilds only the curated seeds per mode.

### Showmap proof

Each mode is proven with `afl-showmap` before being launched as a main:

```bash
bash scripts/run_cm_afl_native_showmap.sh bef830
bash scripts/run_cm_afl_native_showmap.sh 7f9060
bash scripts/run_cm_afl_native_showmap.sh 54ace0
```

The mode-specific instrumentation ranges are:

- `bef830`: `0xbeeac0-0xbf0000`
- `7f9060`: `0x7f9000-0x7fe800`
- `54ace0`: `0x54ace0-0x553300`

### Launching the three mains

The three working mains can be launched together with:

```bash
bash scripts/start_cm_afl_native_triplet.sh
```

Or individually:

```bash
bash scripts/start_cm_afl_native_qemu.sh bef830
bash scripts/start_cm_afl_native_qemu.sh 7f9060
bash scripts/start_cm_afl_native_qemu.sh 54ace0
```

All native runners currently use:

- `AFL_PRELOAD=preload/cm_afl_harness.so`
- `AFL_NO_FORKSRV=1`
- mode-specific `AFL_QEMU_INST_RANGES`
- `afl-fuzz -Q`

### Adding secondaries

Once the mains are running and producing sane `fuzzer_stats`, add secondaries
per mode rather than launching a larger mixed farm:

```bash
bash scripts/start_cm_afl_native_qemu.sh bef830  /path/to/out/bef830  S bef830_s1
bash scripts/start_cm_afl_native_qemu.sh 7f9060 /path/to/out/7f9060 S 7f9060_s1
bash scripts/start_cm_afl_native_qemu.sh 54ace0 /path/to/out/54ace0 S 54ace0_s1
```

The current recommended order remains:

1. `7f9060`
2. `54ace0`
3. `bef830`

That ranking reflects runner cleanliness, not just hotness.

## Network-Faithful Native Request Harnesses

The direct-call triplet above was a useful exploratory step, but it breaks the
most important property the original `0x5e` harness had: the AFL artifact is
not itself a request body. The next pivot was therefore back to a
network-faithful model where the fuzz input again maps directly to bytes sent
over the wire.

### Files

- preload harness:
  - `preload/cm_afl_harness.c`
  - generated assets: `preload/cm_afl_net_assets.h`
- asset / corpus builders:
  - `scripts/build_cm_afl_net_assets.py`
  - `scripts/build_cm_afl_net_corpus.py`
  - `scripts/rebuild_cm_afl_net_assets.sh`
  - `scripts/build_cm_afl_harness.sh`
- single-run proofs:
  - `scripts/run_cm_afl_net_showmap.sh`
  - `scripts/start_cm_afl_net_qemu.sh`
- namespaced scale-out:
  - `fuzzer/cm_afl_netns_init.sh`
  - `fuzzer/cm_afl_netns_launcher.py`
  - `fuzzer/run_cm_afl_netns_weekend.sh`

### Harness shape

These `net_*` modes do not call a mid-pipeline helper directly. Instead, the
preload harness:

1. starts the real `CodeMeterLin` daemon main on the main thread;
2. launches a helper thread;
3. replays captured native-valid C->D frame sequences for one request family;
4. patches per-session token and SID fields before each send; and
5. mutates the decrypted target request body with AFL input before wrapping it
   back into the loopback PSK `0xa0` AES-CBC-CTS transport.

That means the AFL testcase is once again a network-meaningful request body,
not a synthetic heap blob.

### Current modes

Validated network-faithful modes:

- `net_get_servers`
- `net_access`
- `net_access2`
- `net_version`
- `net_info_system`
- `net_info_version`

These modes are built from captured native-valid sequences under
`/tmp/cm_sdk_api_sweep/frames`.

### `afl-showmap` proof

The current input-sensitive coverage proofs are:

- `net_get_servers`
  - base: `44962` tuples, hash `2a326f50979f227e`
  - zero-seed: `44656` tuples, hash `e34058b8594ff0e7`
- `net_info_system`
  - base: `32222` tuples, hash `e8633b9db70197dc`
  - zero-seed: `32222` tuples, hash `b46e915c3cecaa3a`
- `net_info_version`
  - base: `45074` tuples, hash `417f722d52dff583`
- `net_access`
  - base: `32222` tuples, hash `e8633b9db70197dc`
- `net_access2`
  - base: `32222` tuples, hash `e8633b9db70197dc`
- `net_version`
  - base: `45090` tuples, hash `7d3c2615a127b08f`
  - zero-seed: `32222` tuples, hash `b46e915c3cecaa3a`

The key conclusion is that these are not all equally distinct yet.

### Recommended weekend groups

For a weekend namespaced run, the best current three groups are:

- `net_get_servers`
- `net_info_version`
- `net_version`

Do not spend first-class workers on `net_access` or `net_access2` yet. On the
current validated seeds they collapse to the same coverage fingerprint as
`net_info_system`.

### Namespaced launcher

The weekend-scale launcher runs one worker per Linux namespace so that each
instance gets:

- private loopback namespace with its own `:22350`;
- private `/etc/wibu/CodeMeter`;
- private `/var/lib/CodeMeter`;
- private `/var/log/CodeMeter`;
- private `/run/lock`;
- private `/tmp`;
- private `/dev/shm`; and
- private `/var/tmp/cm_cores`.

Because the workers live in isolated namespaces, the host `codemeter` service
can stay up while the fuzz campaign runs.

The current recommended weekend wrapper is:

```bash
bash fuzzer/run_cm_afl_netns_weekend.sh
```

That launches:

- modes:
  - `net_get_servers`
  - `net_info_version`
  - `net_version`
- `6` workers per mode
- total `18` workers

### Timeout note

The first 18-worker launch failed during AFL dry-run calibration because the
older timeout was too small for the namespaced network-faithful path. The
working default is now:

- `--timeout-ms 30000+`

The one-worker smoke with that timeout completed calibration, wrote
`fuzzer_stats`, and stayed on the real namespaced daemon path.
