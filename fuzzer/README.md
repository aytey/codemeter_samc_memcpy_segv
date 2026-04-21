# Fuzzer used to find this bug

Stateful samc-protocol fuzzer in Python. Talks to a **live** CodeMeterLin on
`127.0.0.1:22350`; does not instrument or wrap the daemon in any way.

## Files

| file | purpose |
|---|---|
| `samc_fuzz.py` | main fuzzer loop; stateful session replay with per-iteration mutation |
| `samc_session_data.py` | canonical cleartext plaintexts captured from a real testbench session |
| `samc_replay.py` | single-input replay harness (for crash triage) |
| `run_samc_fuzz_parallel.sh` | launches N concurrent workers (default 16) |

## Prerequisites

- `python3` ≥ 3.10 (uses `list[bytes]` type hints)
- `python3-cryptography` (for AES-128-CBC)
- A running CodeMeterLin on `127.0.0.1:22350` (just `systemctl start codemeter`)
- Run as the `daemon` user OR any user with `NOPASSWD` sudo for `systemctl
  restart codemeter` + `rm /var/lock/cm_lock` (auto-restart on crash).

## Run

Single instance:

```bash
python3 samc_fuzz.py --iterations 1000 --seed 42 --out-dir /tmp/fuzz_out
```

16-worker parallel, writing to `$REPO/output/samc_fuzz_par/`:

```bash
WORKERS=16 ITERATIONS=10000000 ./run_samc_fuzz_parallel.sh
```

## What it does per iteration

1. Connect to `127.0.0.1:22350`.
2. Encrypt + send the canonical HELLO plaintext (replacing the 4-byte
   client token at offset 28 with a fresh random value so the daemon
   doesn't reject it as a replay).
3. Receive daemon's 8-byte cookie response, decrypt, extract the last
   4 bytes as the session ID (SID).
4. Encrypt + send the canonical `0x0b` ACK plaintext with the SID patched
   in at offset 4.
5. Encrypt + send the canonical 712-byte `0x64` request plaintext.
6. In whichever of the above frames is the *fuzz target* for this
   iteration (rotates across HELLO/ACK/`0x64` by default), apply a random
   mutation (bit-flip, byte-flip, random insert/delete, length extend,
   truncate, dictionary splice, boundary-value substitution) before
   encrypting.
7. Close the connection.
8. Every 10 iterations, check whether the daemon PID changed or a new
   coredump appeared; if so, save the last-sent plaintext as a crash
   artefact under `<out>/crashes/`, and restart the daemon via
   `sudo systemctl restart codemeter` (serialized with `flock`).

## Crypto used

- Session key derivation: `SHA-1(<little-endian u32 of magic_div_1009(time(NULL))>)`
  → first 16 bytes = AES-128 key, bytes [4:20] = IV.
- AES-128-CBC + CTS (swap last two ciphertext blocks).
- MAC tail: `8 zero bytes || length_u32_le || crc32_u32_le` appended to the
  plaintext before encryption; length fits the aligned 16-byte block size.

All derived from publicly observable behaviour of testbench clients and
the matching daemon decode paths; no private crypto material used.
