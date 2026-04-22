#!/usr/bin/env python3
"""Daemon-to-server protocol fuzzer for CodeMeterLin veth farm targets.

Covers all five daemon→server message kinds that the PSK-channel and
ECDH-prefix supervisors never send:

  0x0021  auth record    — 32 B CTS-encrypted
  0x0511  init record    — 1296 B CTS-encrypted, template-based
  0x0031  query record   — 48 B custom-MAC format
  0x00f1  sub=0x5a       — 240 B CTS-encrypted, prerequisite SEED query
  0x00f1  sub=0x69       — 240 B CTS-encrypted, SEED exchange

Modes: auth0021 | init0511 | query0031 | cmd00f1_5a | cmd00f1_69 | mixed

Run as a subprocess by samc_veth_farm_launcher.py; follows the same
exit-code contract as samc_ecdh_prefix_supervisor.py:
  exit 0  — timeout or workers_exited (clean)
  exit 2  — crash_or_restart detected
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import importlib.util
import json
import multiprocessing as mp
import os
from pathlib import Path
import random
import socket
import struct
import sys
import time
import traceback
import zlib
from typing import Any


HERE = Path(__file__).resolve().parent
DEFAULT_HELPER_DIR = Path("/home/avj/clones/ax_decrypt/009/research_scripts")

INTERESTING_TYPES = [
    0x00, 0x0A, 0x0B, 0x20, 0x21, 0x23, 0x31, 0x5A,
    0x5E, 0x64, 0x69, 0x76, 0xA1, 0xA2, 0xDD, 0xFF,
]
INTERESTING_QTYPES = [
    0x00, 0x01, 0x03, 0x0B, 0x20, 0x21, 0x23, 0x31,
    0x33, 0x37, 0x5A, 0x5E, 0x64, 0x69, 0x76, 0xFF,
    0x0100, 0x1000, 0xFFFF, 0xFFFFFFFF,
]
INTERESTING_SIZES = [
    0x00, 0x01, 0x08, 0x0F, 0x10, 0x11, 0x20, 0x30,
    0x40, 0x80, 0x90, 0xA0, 0x100, 0x220, 0x400, 0x1000,
    0x7FFFFFFF, 0x80000000, 0xFFFFFFFF,
]
INTERESTING_LENGTHS = [
    0x00, 0x01, 0x08, 0x0F, 0x10, 0x11, 0x20, 0x30,
    0x90, 0x220, 0xFFFF, 0xFFFFFFFF,
]

MODES = frozenset({"auth0021", "init0511", "query0031", "cmd00f1_5a", "cmd00f1_69", "mixed"})
_MIXED_MODES = ["auth0021", "init0511", "query0031", "cmd00f1_5a", "cmd00f1_69"]
_MIXED_WEIGHTS = [25, 25, 25, 15, 10]


def json_write(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_v7(helper_dir: Path):
    helper = helper_dir / "cm_direct_client_v7.py"
    if not helper.exists():
        raise FileNotFoundError(f"missing helper: {helper}")
    if str(helper_dir) not in sys.path:
        sys.path.insert(0, str(helper_dir))
    spec = importlib.util.spec_from_file_location("cm_direct_client_v7_ds_fuzz", helper)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot import helper: {helper}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Protocol helpers
# ---------------------------------------------------------------------------

def _do_ecdh(v7, sock: socket.socket) -> tuple[bytes, bytes]:
    privkey = v7.ec.generate_private_key(v7.ec.SECP224R1(), v7.default_backend())
    pub = privkey.public_key().public_numbers()
    our_point = b"\x04" + pub.x.to_bytes(28, "big") + pub.y.to_bytes(28, "big")
    v7.send_samc(sock, 0x3B)
    sock.sendall(b"\xA2\x05" + our_point)
    _, resp, _ = v7.recv_samc(sock)
    if len(resp) < 65:
        raise ConnectionError(f"short ECDH response: {len(resp)} bytes")
    sx = int.from_bytes(resp[9:37], "big")
    sy = int.from_bytes(resp[37:65], "big")
    server_pub = v7.ec.EllipticCurvePublicNumbers(
        sx, sy, v7.ec.SECP224R1()
    ).public_key(v7.default_backend())
    shared = privkey.exchange(v7.ec.ECDH(), server_pub)
    return v7.derive_key_iv(shared)


def _send_cts(v7, sock: socket.socket, key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """CTS-encrypt plaintext and send with SAMC framing. Returns wire bytes."""
    wire = v7.cts_encrypt(key, iv, plaintext)
    v7.send_samc(sock, 1 + len(wire))
    sock.sendall(b"\xA1" + wire)
    return wire


def _recv_one(v7, sock: socket.socket) -> tuple[int | None, bytes]:
    """Receive one SAMC frame; returns (None, b"") on timeout, raises on close."""
    try:
        n, data, _ = v7.recv_samc(sock)
        return n, data
    except socket.timeout:
        return None, b""


def _fixed_auth(v7, sock: socket.socket, key: bytes, iv: bytes,
                token: bytes | None = None) -> None:
    record = bytearray(v7.CMD_0021_AUTH_RECORD)
    if token is not None:
        record[4:8] = token
        record[28:32] = struct.pack("<I", zlib.crc32(bytes(record[:28])) & 0xFFFFFFFF)
    _send_cts(v7, sock, key, iv, bytes(record))
    _recv_one(v7, sock)


def _fixed_init(v7, sock: socket.socket, key: bytes, iv: bytes,
                rng: random.Random) -> bytes:
    """Send fixed init record with random UIDs. Returns session token (4B)."""
    cm_uid = rng.getrandbits(32).to_bytes(4, "little")
    prev_uid = rng.getrandbits(32).to_bytes(4, "little")
    wire = v7.build_cmd_0511(key, iv, cm_uid, prev_uid)
    v7.send_samc(sock, 1 + len(wire))
    sock.sendall(b"\xA1" + wire)
    _, ack = _recv_one(v7, sock)
    if not ack or len(ack) < 32 or len(ack) % 16 != 0:
        return b"\x00" * 4
    unswapped = ack[:-32] + ack[-16:] + ack[-32:-16]
    pt = v7.aes_cbc_dec(key, iv, unswapped)
    return pt[4:8] if len(pt) >= 8 else b"\x00" * 4


def _fixed_query(v7, sock: socket.socket, key: bytes, iv: bytes,
                 token: bytes, qtype: int, size: int) -> None:
    wire = v7.build_cmd_0031(key, iv, token, qtype, size)
    v7.send_samc(sock, 1 + len(wire))
    sock.sendall(b"\xA1" + wire)
    _recv_one(v7, sock)


def _fixed_00f1_5a(v7, sock: socket.socket, key: bytes, iv: bytes,
                   token: bytes) -> None:
    pt = bytearray(240)
    pt[0x00] = 0x5A
    pt[0x04:0x08] = token
    pt[0x08] = 0x05
    pt[0xB0:0xD0] = os.urandom(32)
    pt[0xD0] = 0x40
    pt[0xE8:0xEC] = struct.pack("<I", 0xD4)
    pt[0xEC:0xF0] = struct.pack("<I", zlib.crc32(bytes(pt[:0xEC])) & 0xFFFFFFFF)
    _send_cts(v7, sock, key, iv, bytes(pt))
    _recv_one(v7, sock)


def _recv_response_meta(v7, sock: socket.socket) -> dict[str, Any]:
    n, data = _recv_one(v7, sock)
    if n is None:
        return {"status": "timeout", "wire_len": 0}
    return {
        "status": "response",
        "samc_len": n,
        "wire_len": len(data),
        "head_hex": data[:32].hex(),
    }


# ---------------------------------------------------------------------------
# Mutation functions
# ---------------------------------------------------------------------------

def _pick(rng: random.Random, values: list[int], *, bits: int = 32) -> int:
    if rng.randrange(5) == 0:
        return rng.getrandbits(bits)
    return rng.choice(values)


def _rb(rng: random.Random, n: int) -> bytes:
    return bytes(rng.randrange(256) for _ in range(n))


def choose_auth_mutation(v7, rng: random.Random) -> tuple[bytes, dict[str, Any]]:
    record = bytearray(v7.CMD_0021_AUTH_RECORD)
    roll = rng.randrange(100)
    strategy = "auth_type_dictionary"
    recompute_crc = True

    if roll < 30:
        record[0:4] = struct.pack("<I", 0x5E)
        record[4:8] = struct.pack("<I", _pick(rng, INTERESTING_TYPES, bits=8))
        strategy = "auth_type_5e"
    elif roll < 48:
        record[0:4] = struct.pack("<I", _pick(rng, INTERESTING_TYPES, bits=8))
        strategy = "auth_type_dictionary"
    elif roll < 63:
        record[4:8] = struct.pack("<I", _pick(rng, INTERESTING_QTYPES))
        strategy = "auth_field1"
    elif roll < 78:
        record[8:24] = _rb(rng, 16)
        strategy = "auth_middle_noise"
    elif roll < 90:
        record[24:28] = struct.pack("<I", _pick(rng, INTERESTING_SIZES))
        strategy = "auth_size_field"
    else:
        record[0:28] = _rb(rng, 28)
        strategy = "auth_random_prefix"

    if rng.randrange(12) == 0:
        recompute_crc = False
    if recompute_crc:
        record[28:32] = struct.pack("<I", zlib.crc32(bytes(record[:28])) & 0xFFFFFFFF)
    else:
        old = struct.unpack("<I", bytes(record[28:32]))[0]
        record[28:32] = struct.pack("<I", old ^ (1 << rng.randrange(32)))

    return bytes(record), {
        "strategy": strategy,
        "recompute_crc": recompute_crc,
        "msg_type": struct.unpack("<I", bytes(record[0:4]))[0],
        "field1": struct.unpack("<I", bytes(record[4:8]))[0],
    }


def choose_0511_mutation(v7, rng: random.Random) -> tuple[bytes, dict[str, Any]]:
    with open(v7.TEMPLATE_0511, "rb") as f:
        pt = bytearray(f.read())
    assert len(pt) == 1296, f"unexpected template length: {len(pt)}"

    cm_uid = rng.getrandbits(32).to_bytes(4, "little")
    prev_uid = rng.getrandbits(32).to_bytes(4, "little")
    pt[684:688] = cm_uid
    pt[688:692] = prev_uid

    roll = rng.randrange(100)
    strategy = "init_uid_rand"
    recompute_crc = True

    if roll < 15:
        strategy = "init_uid_rand"
    elif roll < 30:
        pt[12:16] = struct.pack("<I", _pick(rng, INTERESTING_SIZES) & 0xFFFFFFFF)
        strategy = "init_firm_fuzz"
    elif roll < 45:
        pt[16:20] = struct.pack("<I", _pick(rng, INTERESTING_SIZES) & 0xFFFFFFFF)
        strategy = "init_product_fuzz"
    elif roll < 58:
        off = rng.randrange(0, 28)
        count = rng.randrange(1, 6)
        for i in range(count):
            if off + i < len(pt):
                pt[off + i] = rng.randrange(256)
        strategy = "init_header_fuzz"
    elif roll < 70:
        block_idx = rng.randrange(1296 // 16)
        off = block_idx * 16
        pt[off:off + 16] = _rb(rng, 16)
        strategy = "init_block_fuzz"
    elif roll < 80:
        pt[1288:1292] = struct.pack("<I", _pick(rng, INTERESTING_LENGTHS) & 0xFFFFFFFF)
        strategy = "init_length_fuzz"
    elif roll < 88:
        pt[1292:1296] = struct.pack("<I", rng.getrandbits(32))
        recompute_crc = False
        strategy = "init_crc_flip"
    elif roll < 94:
        n_blocks = rng.randrange(2, 81)  # 32 B to 1280 B; CTS requires ≥32
        pt = pt[:n_blocks * 16]
        recompute_crc = False
        strategy = "init_truncated"
    else:
        pt = bytearray(_rb(rng, 1296))
        recompute_crc = False
        strategy = "init_full_random"

    if recompute_crc and len(pt) >= 1296:
        pt[1292:1296] = struct.pack("<I", zlib.crc32(bytes(pt[:1292])) & 0xFFFFFFFF)

    return bytes(pt), {
        "strategy": strategy,
        "plaintext_len": len(pt),
        "header_hex": bytes(pt[:16]).hex(),
    }


def _build_query0031_plaintext(
    token: bytes,
    *,
    msg_type: int,
    qtype: int,
    size: int,
    struct_len: int,
    pad16: bytes,
    struct_pad8: bytes,
    corrupt_crc: bool,
) -> bytes:
    header = struct.pack("<I", msg_type & 0xFFFFFFFF) + token
    header += struct.pack("<II", qtype & 0xFFFFFFFF, size & 0xFFFFFFFF)
    prefix = header + pad16 + struct_pad8 + struct.pack("<I", struct_len & 0xFFFFFFFF)
    crc = zlib.crc32(prefix) & 0xFFFFFFFF
    if corrupt_crc:
        crc ^= 1 << ((qtype ^ size ^ msg_type) & 31)
    struct_blk = struct_pad8 + struct.pack("<I", struct_len & 0xFFFFFFFF)
    struct_blk += struct.pack("<I", crc)
    plaintext = header + pad16 + struct_blk
    assert len(plaintext) == 48
    return plaintext


def _encrypt_query0031(v7, key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    first_two = v7.aes_cbc_enc(key, iv, plaintext[:32])
    c0, c1 = first_two[:16], first_two[16:32]
    struct_blk = plaintext[32:48]
    mac_in = bytes(a ^ b for a, b in zip(c1, struct_blk))
    mac = v7.aes_ecb_enc(key, mac_in)
    return c0 + mac + c1


def choose_query_mutation(rng: random.Random, token: bytes) -> tuple[bytes, dict[str, Any]]:
    roll = rng.randrange(100)
    msg_type = 0x21
    qtype = _pick(rng, INTERESTING_QTYPES)
    size = _pick(rng, INTERESTING_SIZES)
    struct_len = 0x10
    pad16 = b"\x00" * 16
    struct_pad8 = b"\x00" * 8
    corrupt_crc = False
    strategy = "query_fields"

    if roll < 22:
        msg_type = 0x5E
        qtype = _pick(rng, INTERESTING_QTYPES)
        size = _pick(rng, INTERESTING_SIZES)
        strategy = "query_msg_type_5e"
    elif roll < 38:
        msg_type = _pick(rng, INTERESTING_TYPES, bits=8) & 0xFF
        strategy = "query_msg_type_dictionary"
    elif roll < 55:
        struct_len = _pick(rng, INTERESTING_LENGTHS)
        strategy = "query_struct_len"
    elif roll < 70:
        pad16 = _rb(rng, 16)
        strategy = "query_padding_noise"
    elif roll < 82:
        struct_pad8 = _rb(rng, 8)
        strategy = "query_struct_padding_noise"
    elif roll < 92:
        corrupt_crc = True
        strategy = "query_bad_crc"
    else:
        msg_type = rng.getrandbits(32)
        qtype = rng.getrandbits(32)
        size = rng.getrandbits(32)
        struct_len = rng.getrandbits(32)
        corrupt_crc = bool(rng.randrange(2))
        strategy = "query_random_header"

    plaintext = _build_query0031_plaintext(
        token,
        msg_type=msg_type, qtype=qtype, size=size, struct_len=struct_len,
        pad16=pad16, struct_pad8=struct_pad8, corrupt_crc=corrupt_crc,
    )
    return plaintext, {
        "strategy": strategy,
        "msg_type": msg_type & 0xFFFFFFFF,
        "qtype": qtype & 0xFFFFFFFF,
        "size": size & 0xFFFFFFFF,
        "struct_len": struct_len & 0xFFFFFFFF,
        "corrupt_crc": corrupt_crc,
    }


def choose_00f1_5a_mutation(rng: random.Random, token: bytes) -> tuple[bytes, dict[str, Any]]:
    """Mutate the 240B 0x00f1 sub=0x5a plaintext."""
    pt = bytearray(240)
    pt[0x00] = 0x5A
    pt[0x04:0x08] = token
    pt[0x08] = 0x05
    pt[0xB0:0xD0] = _rb(rng, 32)
    pt[0xD0] = 0x40
    pt[0xE8:0xEC] = struct.pack("<I", 0xD4)
    strategy = "cmd5a_canonical"
    recompute_crc = True

    roll = rng.randrange(100)
    if roll < 12:
        alt = [b for b in INTERESTING_TYPES if b != 0x5A]
        pt[0x00] = rng.choice(alt) if alt else 0x5B
        strategy = "cmd5a_subcmd_fuzz"
    elif roll < 24:
        pt[0x04:0x08] = _rb(rng, 4)
        strategy = "cmd5a_token_fuzz"
    elif roll < 36:
        pt[0x08] = rng.randrange(256)
        strategy = "cmd5a_flag_fuzz"
    elif roll < 50:
        pt[0:16] = _rb(rng, 16)
        recompute_crc = False
        strategy = "cmd5a_header_fuzz"
    elif roll < 64:
        off = rng.randrange(15) * 16
        pt[off:off + 16] = _rb(rng, 16)
        recompute_crc = False
        strategy = "cmd5a_block_fuzz"
    elif roll < 76:
        pt[0xE8:0xEC] = struct.pack("<I", _pick(rng, INTERESTING_LENGTHS) & 0xFFFFFFFF)
        strategy = "cmd5a_length_fuzz"
    elif roll < 86:
        pt[0xEC:0xF0] = struct.pack("<I", rng.getrandbits(32))
        recompute_crc = False
        strategy = "cmd5a_crc_flip"
    elif roll < 94:
        pt[0xB0:0xD0] = _rb(rng, 32)
        strategy = "cmd5a_nonce_rand"
    else:
        for i in range(240):
            pt[i] = rng.randrange(256)
        recompute_crc = False
        strategy = "cmd5a_full_random"

    if recompute_crc:
        pt[0xEC:0xF0] = struct.pack("<I", zlib.crc32(bytes(pt[:0xEC])) & 0xFFFFFFFF)

    return bytes(pt), {
        "strategy": strategy,
        "subcmd": pt[0x00],
        "token_hex": bytes(pt[0x04:0x08]).hex(),
        "length_field": struct.unpack("<I", bytes(pt[0xE8:0xEC]))[0],
    }


def choose_00f1_69_mutation(rng: random.Random, token: bytes) -> tuple[bytes, dict[str, Any]]:
    """Mutate the 240B 0x00f1 sub=0x69 plaintext."""
    pt = bytearray(240)
    pt[0x00] = 0x69
    pt[0x04:0x08] = token
    pt[0x0C:0x10] = b"\x00\x00\x00\x06"
    pt[0x14:0x18] = b"\x37\x13\x00\x00"
    pt[0x18:0x1A] = _rb(rng, 2)
    pt[0x1A] = 0x04
    pt[0x1B] = rng.randrange(256)
    pt[0x1C:0x20] = _rb(rng, 4)
    pt[0x9C:0xA0] = struct.pack("<I", 0x28)
    pt[0xA0:0xA8] = _rb(rng, 8)
    pt[0xA8:0xC8] = _rb(rng, 32)
    pt[0xE8:0xEC] = struct.pack("<I", 0xCC)
    strategy = "cmd69_canonical"
    recompute_crc = True

    roll = rng.randrange(100)
    if roll < 12:
        alt = [b for b in INTERESTING_TYPES if b != 0x69]
        pt[0x00] = rng.choice(alt) if alt else 0x6A
        strategy = "cmd69_subcmd_fuzz"
    elif roll < 24:
        pt[0x04:0x08] = _rb(rng, 4)
        strategy = "cmd69_token_fuzz"
    elif roll < 38:
        pt[0x18:0x20] = _rb(rng, 8)
        recompute_crc = False
        strategy = "cmd69_correlation_fuzz"
    elif roll < 52:
        pt[0xA8:0xC8] = _rb(rng, 32)
        strategy = "cmd69_inner_ct_fuzz"
    elif roll < 64:
        pt[0xA0:0xA8] = _rb(rng, 8)
        strategy = "cmd69_noise_fuzz"
    elif roll < 74:
        pt[0xE8:0xEC] = struct.pack("<I", _pick(rng, INTERESTING_LENGTHS) & 0xFFFFFFFF)
        strategy = "cmd69_length_fuzz"
    elif roll < 82:
        pt[0xEC:0xF0] = struct.pack("<I", rng.getrandbits(32))
        recompute_crc = False
        strategy = "cmd69_crc_flip"
    elif roll < 90:
        pt[0:32] = _rb(rng, 32)
        recompute_crc = False
        strategy = "cmd69_header_fuzz"
    elif roll < 96:
        off = rng.randrange(15) * 16
        pt[off:off + 16] = _rb(rng, 16)
        recompute_crc = False
        strategy = "cmd69_block_fuzz"
    else:
        for i in range(240):
            pt[i] = rng.randrange(256)
        recompute_crc = False
        strategy = "cmd69_full_random"

    if recompute_crc:
        pt[0xEC:0xF0] = struct.pack("<I", zlib.crc32(bytes(pt[:0xEC])) & 0xFFFFFFFF)

    return bytes(pt), {
        "strategy": strategy,
        "subcmd": pt[0x00],
        "token_hex": bytes(pt[0x04:0x08]).hex(),
    }


# ---------------------------------------------------------------------------
# Per-iteration attempt
# ---------------------------------------------------------------------------

def run_one_attempt(
    v7,
    *,
    worker_id: int,
    iteration: int,
    host: str,
    port: int,
    connect_timeout: float,
    socket_timeout: float,
    mode: str,
    rng: random.Random,
) -> tuple[dict[str, Any], list[tuple[str, bytes]]]:
    start = time.time()
    attempt: dict[str, Any] = {
        "worker_id": worker_id,
        "iteration": iteration,
        "mode": mode,
        "wall_start": start,
        "sent_target": False,
    }
    files: list[tuple[str, bytes]] = []

    chosen_mode = mode
    if mode == "mixed":
        chosen_mode = rng.choices(_MIXED_MODES, weights=_MIXED_WEIGHTS, k=1)[0]
    attempt["chosen_mode"] = chosen_mode

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(connect_timeout)
        sock.connect((host, port))
        sock.settimeout(socket_timeout)

        key, iv = _do_ecdh(v7, sock)
        attempt["ecdh"] = "ok"

        # auth0021: fuzz the auth record directly (no prior setup needed)
        if chosen_mode == "auth0021":
            plaintext, mutation = choose_auth_mutation(v7, rng)
            wire = _send_cts(v7, sock, key, iv, plaintext)
            response = _recv_response_meta(v7, sock)
            files += [
                ("target_auth0021_plaintext.bin", plaintext),
                ("target_auth0021_wire.bin", wire),
            ]
            attempt.update({"target": "auth0021", "mutation": mutation, "response": response})
            attempt["sent_target"] = True
            return attempt, files

        # All remaining modes need a valid auth first.
        _fixed_auth(v7, sock, key, iv)

        # init0511: fuzz the init record (auth already sent above)
        if chosen_mode == "init0511":
            plaintext, mutation = choose_0511_mutation(v7, rng)
            wire = v7.cts_encrypt(key, iv, plaintext)
            v7.send_samc(sock, 1 + len(wire))
            sock.sendall(b"\xA1" + wire)
            response = _recv_response_meta(v7, sock)
            files += [
                ("target_init0511_plaintext.bin", plaintext),
                ("target_init0511_wire.bin", wire),
            ]
            attempt.update({"target": "init0511", "mutation": mutation, "response": response})
            attempt["sent_target"] = True
            return attempt, files

        # All deeper modes need a valid init too.
        token = _fixed_init(v7, sock, key, iv, rng)
        attempt["session_token_hex"] = token.hex()

        # query0031: fuzz a query record
        if chosen_mode == "query0031":
            plaintext, mutation = choose_query_mutation(rng, token)
            wire = _encrypt_query0031(v7, key, iv, plaintext)
            v7.send_samc(sock, 1 + len(wire))
            sock.sendall(b"\xA1" + wire)
            response = _recv_response_meta(v7, sock)
            files += [
                ("target_query0031_plaintext.bin", plaintext),
                ("target_query0031_wire.bin", wire),
            ]
            attempt.update({"target": "query0031", "mutation": mutation, "response": response})
            attempt["sent_target"] = True
            return attempt, files

        # cmd00f1_5a and cmd00f1_69 need the pre-5a query sequence from v9.
        _fixed_query(v7, sock, key, iv, token, 0x01, 0x90)
        _fixed_query(v7, sock, key, iv, token, 0x37, 0x0220)
        _fixed_auth(v7, sock, key, iv, token)
        _fixed_query(v7, sock, key, iv, token, 0x01, 0x90)

        # cmd00f1_5a: fuzz the 0x5a prerequisite SEED query
        if chosen_mode == "cmd00f1_5a":
            plaintext, mutation = choose_00f1_5a_mutation(rng, token)
            wire = _send_cts(v7, sock, key, iv, plaintext)
            response = _recv_response_meta(v7, sock)
            files += [
                ("target_00f1_5a_plaintext.bin", plaintext),
                ("target_00f1_5a_wire.bin", wire),
            ]
            attempt.update({"target": "cmd00f1_5a", "mutation": mutation, "response": response})
            attempt["sent_target"] = True
            return attempt, files

        # cmd00f1_69: send canonical 5a, then re-auth + 2 queries, then fuzz 0x69.
        _fixed_00f1_5a(v7, sock, key, iv, token)
        _fixed_auth(v7, sock, key, iv, token)
        _fixed_query(v7, sock, key, iv, token, 0x03, 0x30)
        _fixed_query(v7, sock, key, iv, token, 0x33, 0x0400)

        plaintext, mutation = choose_00f1_69_mutation(rng, token)
        wire = _send_cts(v7, sock, key, iv, plaintext)
        response = _recv_response_meta(v7, sock)
        files += [
            ("target_00f1_69_plaintext.bin", plaintext),
            ("target_00f1_69_wire.bin", wire),
        ]
        attempt.update({"target": "cmd00f1_69", "mutation": mutation, "response": response})
        attempt["sent_target"] = True
        return attempt, files

    except (ConnectionError, BrokenPipeError, ConnectionResetError) as exc:
        attempt["status"] = "connection_error"
        attempt["error"] = {"type": type(exc).__name__, "detail": str(exc)}
        return attempt, files
    except socket.timeout as exc:
        attempt["status"] = "timeout"
        attempt["error"] = {"type": "timeout", "detail": str(exc)}
        return attempt, files
    except Exception as exc:
        attempt["status"] = "exception"
        attempt["error"] = {
            "type": type(exc).__name__,
            "detail": str(exc),
            "traceback": traceback.format_exc(limit=8),
        }
        return attempt, files
    finally:
        attempt["wall_end"] = time.time()
        attempt["duration_s"] = attempt["wall_end"] - start
        try:
            sock.close()
        except OSError:
            pass


def _status_for(attempt: dict[str, Any]) -> str:
    if "status" in attempt:
        return str(attempt["status"])
    resp = attempt.get("response") or {}
    return str(resp.get("status", "unknown"))


# ---------------------------------------------------------------------------
# Ring dump (matches samc_ecdh_prefix_supervisor.py format)
# ---------------------------------------------------------------------------

def _dump_ring(worker_dir: Path, ring: collections.deque,
               stats: dict[str, Any], reason: str) -> None:
    worker_dir.mkdir(parents=True, exist_ok=True)
    manifest = worker_dir / "ring_manifest.jsonl"
    with manifest.open("w", encoding="utf-8") as mf:
        for idx, item in enumerate(ring):
            attempt = dict(item["attempt"])
            iter_dir = (
                worker_dir / "ring"
                / f"idx_{idx:04d}_iter_{attempt['iteration']:08d}"
            )
            iter_dir.mkdir(parents=True, exist_ok=True)
            file_meta = []
            for name, data in item["files"]:
                p = iter_dir / name
                p.write_bytes(data)
                file_meta.append({
                    "name": name,
                    "path": str(p),
                    "len": len(data),
                    "sha256": sha256_hex(data),
                    "head_hex": data[:64].hex(),
                })
            attempt["files"] = file_meta
            json_write(iter_dir / "attempt.json", attempt)
            mf.write(json.dumps({
                "idx": idx,
                "iteration": attempt["iteration"],
                "target": attempt.get("target"),
                "chosen_mode": attempt.get("chosen_mode"),
                "status": _status_for(attempt),
                "attempt_json": str(iter_dir / "attempt.json"),
            }, sort_keys=True) + "\n")
    json_write(worker_dir / "worker_summary.json", {
        "reason": reason,
        "stats": stats,
        "ring_count": len(ring),
        "dumped_at": time.time(),
    })


# ---------------------------------------------------------------------------
# Worker
# ---------------------------------------------------------------------------

def worker_main(worker_id: int, args_dict: dict[str, Any],
                stop_event, counter) -> None:
    out_dir = Path(args_dict["out_dir"])
    worker_dir = out_dir / f"worker_{worker_id:02d}"
    rng = random.Random(int(args_dict["seed_base"]) + worker_id * 0x1000003)
    ring: collections.deque = collections.deque(maxlen=int(args_dict["ring_size"]))
    stats: dict[str, Any] = {
        "worker_id": worker_id,
        "attempts": 0,
        "sent_targets": 0,
        "statuses": {},
        "started_at": time.time(),
    }
    reason = "completed"

    try:
        v7 = load_v7(Path(args_dict["helper_dir"]))
        for iteration in range(int(args_dict["iterations"])):
            if stop_event.is_set():
                reason = "stop_event"
                break
            attempt, files = run_one_attempt(
                v7,
                worker_id=worker_id,
                iteration=iteration,
                host=args_dict["host"],
                port=int(args_dict["port"]),
                connect_timeout=float(args_dict["connect_timeout"]),
                socket_timeout=float(args_dict["socket_timeout"]),
                mode=args_dict["mode"],
                rng=rng,
            )
            stats["attempts"] += 1
            counter.value = stats["attempts"]
            st = _status_for(attempt)
            stats["statuses"][st] = stats["statuses"].get(st, 0) + 1
            if attempt.get("sent_target"):
                stats["sent_targets"] += 1
                ring.append({"attempt": attempt, "files": files})
    except Exception as exc:
        reason = "worker_error"
        stats["fatal_error"] = {
            "type": type(exc).__name__,
            "detail": str(exc),
            "traceback": traceback.format_exc(),
        }
    finally:
        stats["finished_at"] = time.time()
        stats["duration_s"] = stats["finished_at"] - stats["started_at"]
        _dump_ring(worker_dir, ring, stats, reason)


# ---------------------------------------------------------------------------
# Crash oracle (identical to samc_ecdh_prefix_supervisor.py)
# ---------------------------------------------------------------------------

def listener_ready(host: str, port: int, timeout: float = 0.4) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def newest_core(core_dirs: list[Path]) -> dict[str, Any] | None:
    newest: tuple[int, Path] | None = None
    for root in core_dirs:
        if not root.exists():
            continue
        for path in root.glob("*CodeMeterLin*"):
            try:
                st = path.stat()
            except OSError:
                continue
            item = (st.st_mtime_ns, path)
            if newest is None or item > newest:
                newest = item
    if newest is None:
        return None
    st = newest[1].stat()
    return {"path": str(newest[1]), "mtime_ns": st.st_mtime_ns, "size": st.st_size}


def core_changed_since(
    baseline: dict[str, Any] | None,
    current: dict[str, Any] | None,
    start_wall: float,
) -> bool:
    return (
        current is not None and
        (baseline is None or
         current["path"] != baseline["path"] or
         current["mtime_ns"] != baseline["mtime_ns"]) and
        current["mtime_ns"] >= int(start_wall * 1_000_000_000)
    )


def _write_crash_attribution(out_dir: Path) -> dict[str, Any]:
    events: list[dict[str, Any]] = []
    for worker_dir in sorted(out_dir.glob("worker_*")):
        manifest = worker_dir / "ring_manifest.jsonl"
        if not manifest.exists():
            continue
        for line in manifest.read_text(encoding="utf-8").splitlines():
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if entry.get("status") in {"timeout", "connection_error", "exception"}:
                events.append(entry)
    events.sort(key=lambda e: e.get("idx", 0))
    report = {"count": len(events), "events": events[:50]}
    json_write(out_dir / "crash_attribution.json", report)
    return report


# ---------------------------------------------------------------------------
# Supervisor main loop
# ---------------------------------------------------------------------------

def run_supervisor(args: argparse.Namespace) -> int:
    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    core_dirs = [Path(p) for p in args.core_dir]
    baseline_core = newest_core(core_dirs)
    start_wall = time.time()
    start_mono = time.monotonic()

    config: dict[str, Any] = {
        "host": args.host,
        "port": args.port,
        "out_dir": str(out_dir),
        "mode": args.mode,
        "workers": args.workers,
        "iterations": args.iterations,
        "ring_size": args.ring_size,
        "seed_base": args.seed_base,
        "connect_timeout": args.connect_timeout,
        "socket_timeout": args.socket_timeout,
        "helper_dir": str(Path(args.helper_dir).resolve()),
        "core_dirs": [str(p) for p in core_dirs],
        "baseline_core": baseline_core,
        "start_wall": start_wall,
    }
    json_write(out_dir / "run_config.json", config)

    ctx = mp.get_context("fork")
    stop_event = ctx.Event()
    counters = [ctx.Value("Q", 0, lock=False) for _ in range(args.workers)]
    procs = []
    for worker_id in range(args.workers):
        proc = ctx.Process(
            target=worker_main,
            args=(worker_id, config, stop_event, counters[worker_id]),
            name=f"samc-ds-worker-{worker_id:02d}",
        )
        proc.start()
        procs.append(proc)

    print(f"out={out_dir}", flush=True)
    print(f"target={args.host}:{args.port} mode={args.mode}", flush=True)
    print(f"baseline_core={baseline_core}", flush=True)

    result: dict[str, Any] = {"reason": "unknown"}
    last_progress = 0.0
    last_listener_check = 0.0
    listener_is_ready = True

    try:
        while True:
            now = time.monotonic()
            elapsed = now - start_mono
            if elapsed >= args.timeout:
                result = {"reason": "timeout", "elapsed": elapsed}
                break
            cur_core = newest_core(core_dirs)
            changed_core = core_changed_since(baseline_core, cur_core, start_wall)
            if now - last_listener_check >= args.listener_check_interval:
                listener_is_ready = listener_ready(args.host, args.port)
                last_listener_check = now
            if changed_core or not listener_is_ready:
                result = {
                    "reason": "crash_or_restart",
                    "elapsed": elapsed,
                    "baseline_core": baseline_core,
                    "core": cur_core,
                    "core_changed": changed_core,
                    "listener_down": not listener_is_ready,
                }
                break
            if all(not p.is_alive() for p in procs):
                result = {"reason": "workers_exited", "elapsed": elapsed}
                break
            if now - last_progress >= args.progress_interval:
                counts = [c.value for c in counters]
                print(
                    f"progress elapsed={elapsed:.1f}s attempts={sum(counts)} "
                    f"per_worker={counts} listener={listener_is_ready}",
                    flush=True,
                )
                last_progress = now
            time.sleep(args.poll_interval)
    except KeyboardInterrupt:
        result = {"reason": "interrupted", "elapsed": time.monotonic() - start_mono}
    finally:
        stop_event.set()
        for proc in procs:
            proc.join(timeout=args.worker_join_timeout)
        for proc in procs:
            if proc.is_alive():
                proc.terminate()
        for proc in procs:
            proc.join(timeout=2.0)
        for proc in procs:
            if proc.is_alive():
                proc.kill()

    counts = [c.value for c in counters]
    attribution = _write_crash_attribution(out_dir)
    summary = {
        "result": result,
        "attempts": sum(counts),
        "per_worker_attempts": counts,
        "worker_pids": [p.pid for p in procs],
        "worker_exitcodes": [p.exitcode for p in procs],
        "baseline_core": baseline_core,
        "end_core": newest_core(core_dirs),
        "listener_ready_end": listener_ready(args.host, args.port),
        "crash_attribution_count": attribution["count"],
    }
    json_write(out_dir / "summary.json", summary)
    print("summary=" + json.dumps(summary, sort_keys=True), flush=True)
    return 2 if result.get("reason") == "crash_or_restart" else 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="Daemon-to-server protocol fuzzer for CodeMeterLin veth farm targets.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=22350)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--mode", choices=sorted(MODES), default="mixed")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--iterations", type=int, default=100000)
    ap.add_argument("--ring-size", type=int, default=100)
    ap.add_argument("--seed-base", type=lambda s: int(s, 0), default=0xD5000000)
    ap.add_argument("--timeout", type=float, default=900.0)
    ap.add_argument("--connect-timeout", type=float, default=3.0)
    ap.add_argument("--socket-timeout", type=float, default=3.0,
                    help="per-socket timeout; cmd00f1_69 mode has ~12 round trips")
    ap.add_argument("--poll-interval", type=float, default=0.25)
    ap.add_argument("--listener-check-interval", type=float, default=0.5)
    ap.add_argument("--progress-interval", type=float, default=30.0)
    ap.add_argument("--worker-join-timeout", type=float, default=8.0)
    ap.add_argument("--helper-dir", type=Path, default=DEFAULT_HELPER_DIR,
                    help="directory containing cm_direct_client_v7.py and "
                         "200_sessions/cmd_0511_template.bin")
    ap.add_argument("--core-dir", action="append", default=[],
                    help="core directory to watch; repeatable")
    return ap


def main() -> int:
    args = build_arg_parser().parse_args()
    if args.workers < 1:
        raise SystemExit("--workers must be >= 1")
    if args.iterations < 1:
        raise SystemExit("--iterations must be >= 1")
    if args.ring_size < 1:
        raise SystemExit("--ring-size must be >= 1")
    if not args.core_dir:
        args.core_dir = ["/var/tmp/cm_cores", "/var/lib/systemd/coredump"]
    for p in (
        args.helper_dir / "cm_direct_client_v7.py",
        args.helper_dir / "200_sessions" / "cmd_0511_template.bin",
    ):
        if not p.exists():
            raise SystemExit(f"missing required helper file: {p}")
    return run_supervisor(args)


if __name__ == "__main__":
    raise SystemExit(main())
