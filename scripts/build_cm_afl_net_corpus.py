#!/usr/bin/env python3
from __future__ import annotations

import argparse
import functools
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FRAME_ROOT = Path("/tmp/cm_sdk_api_sweep/frames")


MODE_SPECS = {
    "net_get_servers": {"frame_file": "get_servers.json", "mutate_index": 0},
    "net_access": {"frame_file": "access_local_subsystem.json", "mutate_index": 0},
    "net_access2": {"frame_file": "access2_local_subsystem.json", "mutate_index": 0},
    "net_version": {"frame_file": "access_version_local_subsystem.json", "mutate_index": 1},
    "net_info_system": {"frame_file": "access_info_system_local_subsystem.json", "mutate_index": 1},
    "net_info_version": {"frame_file": "access_info_version_local_subsystem.json", "mutate_index": 1},
    "net_access_public_key": {"frame_file": "access_public_key_local_subsystem.json", "mutate_index": 1},
    "net_access_calc_sig": {"frame_file": "access_calc_sig_local_subsystem.json", "mutate_index": 1},
    "net_access_crypt2": {"frame_file": "access_crypt2_local_subsystem.json", "mutate_index": 1},
    "net_access_validate_signedtime": {"frame_file": "access_validate_signedtime_local_subsystem.json", "mutate_index": 1},
    "net_access_validate_signedlist": {"frame_file": "access_validate_signedlist_local_subsystem.json", "mutate_index": 1},
    "net_access_validate_deletefi": {"frame_file": "access_validate_deletefi_local_subsystem.json", "mutate_index": 1},
    "net_access_lt_create_context": {"frame_file": "access_lt_create_context_local_subsystem.json", "mutate_index": 1},
    "net_access_lt_import_update": {"frame_file": "access_lt_import_update_local_subsystem.json", "mutate_index": 1},
    "net_access_lt_cleanup": {"frame_file": "access_lt_cleanup_local_subsystem.json", "mutate_index": 1},
    "net_access_authops_public_key": {
        "frame_parts": [
            ("access_public_key_local_subsystem.json", 0),
            ("access_public_key_local_subsystem.json", 1),
            ("access_calc_sig_local_subsystem.json", 1),
            ("access_crypt2_local_subsystem.json", 1),
            ("access_public_key_local_subsystem.json", 2),
        ],
        "mutate_index": 1,
    },
    "net_access_authops_calc_sig": {
        "frame_parts": [
            ("access_public_key_local_subsystem.json", 0),
            ("access_public_key_local_subsystem.json", 1),
            ("access_calc_sig_local_subsystem.json", 1),
            ("access_crypt2_local_subsystem.json", 1),
            ("access_public_key_local_subsystem.json", 2),
        ],
        "mutate_index": 2,
    },
    "net_access_authops_crypt2": {
        "frame_parts": [
            ("access_public_key_local_subsystem.json", 0),
            ("access_public_key_local_subsystem.json", 1),
            ("access_calc_sig_local_subsystem.json", 1),
            ("access_crypt2_local_subsystem.json", 1),
            ("access_public_key_local_subsystem.json", 2),
        ],
        "mutate_index": 3,
    },
    "net_access_validate_chain_signedtime": {
        "frame_parts": [
            ("access_validate_signedtime_local_subsystem.json", 0),
            ("access_validate_signedtime_local_subsystem.json", 1),
            ("access_validate_signedlist_local_subsystem.json", 1),
            ("access_validate_deletefi_local_subsystem.json", 1),
            ("access_validate_signedtime_local_subsystem.json", 2),
        ],
        "mutate_index": 1,
    },
    "net_access_validate_chain_signedlist": {
        "frame_parts": [
            ("access_validate_signedtime_local_subsystem.json", 0),
            ("access_validate_signedtime_local_subsystem.json", 1),
            ("access_validate_signedlist_local_subsystem.json", 1),
            ("access_validate_deletefi_local_subsystem.json", 1),
            ("access_validate_signedtime_local_subsystem.json", 2),
        ],
        "mutate_index": 2,
    },
    "net_access_validate_chain_deletefi": {
        "frame_parts": [
            ("access_validate_signedtime_local_subsystem.json", 0),
            ("access_validate_signedtime_local_subsystem.json", 1),
            ("access_validate_signedlist_local_subsystem.json", 1),
            ("access_validate_deletefi_local_subsystem.json", 1),
            ("access_validate_signedtime_local_subsystem.json", 2),
        ],
        "mutate_index": 3,
    },
    "net_access2_public_key": {"frame_file": "access2_public_key_local_subsystem.json", "mutate_index": 1},
    "net_access2_calc_sig": {"frame_file": "access2_calc_sig_local_subsystem.json", "mutate_index": 1},
    "net_access2_crypt2": {"frame_file": "access2_crypt2_local_subsystem.json", "mutate_index": 1},
    "net_access2_validate_signedtime": {"frame_file": "access2_validate_signedtime_local_subsystem.json", "mutate_index": 1},
    "net_access2_validate_signedlist": {"frame_file": "access2_validate_signedlist_local_subsystem.json", "mutate_index": 1},
    "net_access2_validate_deletefi": {"frame_file": "access2_validate_deletefi_local_subsystem.json", "mutate_index": 1},
    "net_access2_lt_create_context": {"frame_file": "access2_lt_create_context_local_subsystem.json", "mutate_index": 1},
    "net_access2_lt_import_update": {"frame_file": "access2_lt_import_update_local_subsystem.json", "mutate_index": 1},
    "net_access2_lt_cleanup": {"frame_file": "access2_lt_cleanup_local_subsystem.json", "mutate_index": 1},
    "net_access2_authops_public_key": {
        "frame_parts": [
            ("access2_public_key_local_subsystem.json", 0),
            ("access2_public_key_local_subsystem.json", 1),
            ("access2_calc_sig_local_subsystem.json", 1),
            ("access2_crypt2_local_subsystem.json", 1),
            ("access2_public_key_local_subsystem.json", 2),
        ],
        "mutate_index": 1,
    },
    "net_access2_authops_calc_sig": {
        "frame_parts": [
            ("access2_public_key_local_subsystem.json", 0),
            ("access2_public_key_local_subsystem.json", 1),
            ("access2_calc_sig_local_subsystem.json", 1),
            ("access2_crypt2_local_subsystem.json", 1),
            ("access2_public_key_local_subsystem.json", 2),
        ],
        "mutate_index": 2,
    },
    "net_access2_authops_crypt2": {
        "frame_parts": [
            ("access2_public_key_local_subsystem.json", 0),
            ("access2_public_key_local_subsystem.json", 1),
            ("access2_calc_sig_local_subsystem.json", 1),
            ("access2_crypt2_local_subsystem.json", 1),
            ("access2_public_key_local_subsystem.json", 2),
        ],
        "mutate_index": 3,
    },
    "net_access2_validate_chain_signedtime": {
        "frame_parts": [
            ("access2_validate_signedtime_local_subsystem.json", 0),
            ("access2_validate_signedtime_local_subsystem.json", 1),
            ("access2_validate_signedlist_local_subsystem.json", 1),
            ("access2_validate_deletefi_local_subsystem.json", 1),
            ("access2_validate_signedtime_local_subsystem.json", 2),
        ],
        "mutate_index": 1,
    },
    "net_access2_validate_chain_signedlist": {
        "frame_parts": [
            ("access2_validate_signedtime_local_subsystem.json", 0),
            ("access2_validate_signedtime_local_subsystem.json", 1),
            ("access2_validate_signedlist_local_subsystem.json", 1),
            ("access2_validate_deletefi_local_subsystem.json", 1),
            ("access2_validate_signedtime_local_subsystem.json", 2),
        ],
        "mutate_index": 2,
    },
    "net_access2_validate_chain_deletefi": {
        "frame_parts": [
            ("access2_validate_signedtime_local_subsystem.json", 0),
            ("access2_validate_signedtime_local_subsystem.json", 1),
            ("access2_validate_signedlist_local_subsystem.json", 1),
            ("access2_validate_deletefi_local_subsystem.json", 1),
            ("access2_validate_signedtime_local_subsystem.json", 2),
        ],
        "mutate_index": 3,
    },
}

@functools.lru_cache(maxsize=None)
def load_c2d_frames(frame_file: str) -> list[bytes]:
    doc = json.loads((FRAME_ROOT / frame_file).read_text(encoding="utf-8"))
    return [bytes.fromhex(fr["data_hex"]) for fr in doc["frames"] if fr["direction"] == "C→D"]


def load_target_frame(mode: str) -> bytes:
    spec = MODE_SPECS[mode]
    if "frame_parts" in spec:
        frames = []
        for frame_file, c2d_index in spec["frame_parts"]:
            frames.append(load_c2d_frames(frame_file)[c2d_index])
    else:
        frames = load_c2d_frames(spec["frame_file"])
    return frames[spec["mutate_index"]]


def write_seed(path: Path, data: bytes) -> None:
    path.write_bytes(data)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=sorted(MODE_SPECS))
    ap.add_argument("out_dir", nargs="?", default=None)
    args = ap.parse_args()

    out_dir = Path(args.out_dir) if args.out_dir else ROOT / "seeds" / f"cm_afl_{args.mode}"
    out_dir.mkdir(parents=True, exist_ok=True)

    target = load_target_frame(args.mode)
    seeds = {
        "base.bin": target,
        "zero.bin": b"\x00" * len(target),
        "tailff.bin": target[:-4] + (b"\xff" * min(4, len(target))) if target else target,
    }
    for name, blob in seeds.items():
        write_seed(out_dir / name, blob)
    print(out_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
