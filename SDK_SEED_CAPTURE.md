# SDK Seed Capture

This note covers the SDK-linked seed harness built from the official
CodeMeter SDK and the static archive at:

```text
/home/avj/CodeMeter-static/usr/lib/x86_64-linux-gnu/libwibucm.a
```

The goal is to call the public API surface directly, capture the daemon-facing
plaintext requests through the existing app-to-daemon MITM, and save them as
structured baseline seeds before mutation.

## Scripts

- `scripts/cm_sdk_probe.c`
  SDK-linked probe for the public APIs that looked interesting from static RE.
- `scripts/build_cm_sdk_probe.sh`
  Builds the probe against the static `libwibucm.a`.
- `scripts/run_cm_sdk_probe.sh`
  Rebuilds on demand and sets the required `LD_LIBRARY_PATH`.
- `scripts/capture_cm_sdk_seeds.sh`
  Runs the API sweep one case at a time through
  `ax_decrypt/004/research_scripts/mitm_app_daemon.py`.
- `scripts/extract_cm_sdk_seed_frames.py`
  Converts per-case MITM logs into per-command JSON frame files.
- `scripts/capture_cm_cloud_5e.sh`
  Targeted `CmCloudContainerControl` matrix for the SDK-generated `0x5e` family.

## Current Capture Flow

```bash
./scripts/capture_cm_sdk_seeds.sh /tmp/cm_sdk_api_sweep
./scripts/extract_cm_sdk_seed_frames.py /tmp/cm_sdk_api_sweep
```

Artifacts:

- command manifest:
  `/tmp/cm_sdk_api_sweep/commands.jsonl`
- per-case MITM logs:
  `/tmp/cm_sdk_api_sweep/*.mitm.log`
- per-command frame files:
  `/tmp/cm_sdk_api_sweep/frames/*.json`

## Sweep Coverage

The current harness exercises:

- `CmGetVersion(NULL)`
- `CmGetServers`
- `CmAccess --subsystem --local`
- `CmAccess2 --subsystem --local`
- handle-based follow-ons on both handle types:
  - `CmGetVersion`
  - `CmGetInfo(CM_GEI_SYSTEM)`
  - `CmGetInfo(CM_GEI_VERSION)`
  - `CmGetPublicKey`
  - `CmCalculateSignature`
  - `CmCrypt2`
  - `CmCryptSim`
  - `CmValidateEntry` with:
    - `CM_VAL_SIGNEDTIME`
    - `CM_VAL_SIGNEDLIST`
    - `CM_VAL_DELETE_FI`
  - `CmLtCreateContext`
  - `CmLtDoTransfer`
  - `CmLtImportUpdate`
  - `CmLtCreateReceipt`
  - `CmLtConfirmTransfer`
  - `CmLtCleanup`
  - `CmLtLiveTransfer`

## First Validated Plaintext Sequences

The important result is that both access families are now confirmed from the
public SDK path:

- `CmAccess` emits `0x0a`
- `CmAccess2` emits `0x64`

### `CmGetVersion(NULL)`

- no daemon traffic observed
- local library query only

### `CmGetServers`

Captured request:

```text
220000001000000000100000
```

This is a short `0x22` request. The response body begins:

```text
000000001a00000001000000...
```

and includes the server name `vadcpctlic2.vi.vector.int`.

### `CmAccess --subsystem --local`

Captured client sequence:

1. `0x0a` request, 184 bytes
2. handle reply, 8 bytes
3. `0x0b` release request, 8 bytes
4. release ack, 8 bytes

This matches the earlier static `Access1 -> 0x0a00` finding.

### `CmAccess2 --subsystem --local`

Captured client sequence:

1. `0x64` request, 712 bytes
2. handle reply, 8 bytes
3. `0x0b` release request, 8 bytes
4. release ack, 8 bytes

This confirms the internal split:

- `CmAccess` / `CMACCESS` -> `0x0a`
- `CmAccess2` / `CMACCESS2` -> `0x64`

### `CmGetVersion(handle)`

Captured client sequence:

1. access request (`0x0a` or `0x64`)
2. handle reply
3. `0x23` version request
4. version reply
5. `0x0b` release request
6. release ack

The `0x23` request captured here is:

```text
23000000<handle_le32>
```

### `CmGetInfo(CM_GEI_SYSTEM)` and `CmGetInfo(CM_GEI_VERSION)`

Both handle families produce:

- access request (`0x0a` or `0x64`)
- handle reply
- `0x21` info request
- reply
- `0x0b` release request
- release ack

Examples:

```text
21000000<handle_le32>0a00000018010000
21000000<handle_le32>0b00000010000000
```

## Broad Sweep Results

The first broad SDK sweep produced the following client opcodes on the daemon
channel:

- `0x0a` via `CmAccess`
- `0x0b` via `CmRelease`
- `0x21` via `CmGetInfo`
- `0x22` via `CmGetServers`
- `0x23` via `CmGetVersion(handle)`
- `0x5a` via `CmCalculateSignature`
- `0x5b` via `CmGetPublicKey`
- `0x64` via `CmAccess2`
- `0x69` via `CmCrypt2`
- `0x6d` via `CmLtCreateContext`
- `0x6f` via `CmLtImportUpdate`
- `0x72` via `CmLtCleanup`

It also surfaced two mismatches relative to the earlier static label guesses:

- `CmCryptSim` emitted `0x11`, not the expected `0x6a`
- `CmValidateEntry(...)` emitted `0x36`, not the expected `0x65`

And several APIs did not reach a distinct follow-on wire opcode with the
minimal dummy arguments used here:

- `CmLtDoTransfer`
- `CmLtCreateReceipt`
- `CmLtConfirmTransfer`
- `CmLtLiveTransfer`

Those still opened and released handles, but the follow-on call failed locally
before any distinct request beyond access/release was visible.

## Why This Matters For Fuzzing

This gives us a much broader baseline-seed set generated from documented public
API calls rather than from hand-crafted plaintexts. That improves exploratory
fuzzing in three ways:

1. the starting requests are valid for the daemon state machine
2. the seeds are tagged by originating API and command shape
3. follow-on mutation can target known-good request families:
   `0x0a`, `0x0b`, `0x21`, `0x22`, `0x23`, `0x5a`, `0x5b`, `0x64`, `0x69`,
   `0x6d`, `0x6f`, `0x72`, plus the observed `0x11` and `0x36` divergences

## Immediate Next Step

Use the extracted frame files in `/tmp/cm_sdk_api_sweep/frames/*.json` as the
starting corpus for structured mutation. The next useful refinements are:

- try richer argument values for the handle-type-sensitive APIs that currently
  return error `115`
- try less-trivial LT buffers for the calls that currently fail locally with
  error `105`
- decide whether `0x75` and the missing `0x6e` / `0x70` / `0x71` paths need a
  higher-level `libwibucm` wrapper rather than the public C SDK alone

## Targeted `0x5e` Cloud Sweep

The SDK also exposes a public `0x5e` path:

- `CmCloudContainerControl(hcmse, flCtrl, pvData, cbData, pvReturn, cbReturn)`

The static `libwibucm.a` lead was correct: this generates a `0x5e` request
family via `CmdCloudContainerControl`.

Current targeted sweep:

```bash
./scripts/capture_cm_cloud_5e.sh /tmp/cm_cloud_5e_sweep
./scripts/extract_cm_sdk_seed_frames.py /tmp/cm_cloud_5e_sweep
```

Key results:

- `CM_GF_CLOUD_DELETE_CREDENTIALS` emits `0x5e` with:
  - flag `0x00000001`
  - `in_len=0`
  - `out_len=0`
  - 8-byte reply `7300000000000000`
  - probe-side error `115` (`CMERROR_WRONG_HANDLE_TYPE`)

- `CM_GF_CLOUD_VERIFY_CONNECTION` emits `0x5e` with:
  - flag `0x00000002`
  - caller-controlled `in_len`
  - caller-controlled `out_len`

For `verify` with `in_len=0`, the daemon reply shape is:

- reply length `8 + out_len`
- first dword `0x69` (probe-side error `105`, invalid parameter)
- body all zeroes in the cases tested up to `out_len=4096`

For `verify` with `out_len=64` and nonzero input, behavior depends on input
length:

- `in_len=1`
  - `CmAccess` path: zero-filled body, returned length `103`
  - `CmAccess2` path: ASCII curl error string for HTTP `502`
- `in_len=16`
  - `CmAccess` and `CmAccess2`: ASCII curl error string
    `Curl errorcode 52 : Empty reply from server`
- `in_len=256` and `1024`
  - zero-filled body, returned length `68`

So `CmCloudContainerControl` is now a confirmed SDK-generated `0x5e` seed
family. The immediate replies seen so far are either zero-filled buffers or
server-generated ASCII curl diagnostics, not obvious leaked heap bytes.
