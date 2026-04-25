#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FRAME_ROOT = Path("/tmp/cm_sdk_api_sweep/frames")


MODE_TO_FILE = {
    "net_get_servers": "get_servers.json",
    "net_access": "access_local_subsystem.json",
    "net_access2": "access2_local_subsystem.json",
    "net_version": "access_version_local_subsystem.json",
    "net_info_system": "access_info_system_local_subsystem.json",
    "net_info_version": "access_info_version_local_subsystem.json",
    "net_access_public_key": "access_public_key_local_subsystem.json",
    "net_access_calc_sig": "access_calc_sig_local_subsystem.json",
    "net_access_crypt2": "access_crypt2_local_subsystem.json",
    "net_access_validate_signedtime": "access_validate_signedtime_local_subsystem.json",
    "net_access_validate_signedlist": "access_validate_signedlist_local_subsystem.json",
    "net_access_validate_deletefi": "access_validate_deletefi_local_subsystem.json",
    "net_access_lt_create_context": "access_lt_create_context_local_subsystem.json",
    "net_access_lt_import_update": "access_lt_import_update_local_subsystem.json",
    "net_access_lt_cleanup": "access_lt_cleanup_local_subsystem.json",
    "net_access2_public_key": "access2_public_key_local_subsystem.json",
    "net_access2_calc_sig": "access2_calc_sig_local_subsystem.json",
    "net_access2_crypt2": "access2_crypt2_local_subsystem.json",
    "net_access2_validate_signedtime": "access2_validate_signedtime_local_subsystem.json",
    "net_access2_validate_signedlist": "access2_validate_signedlist_local_subsystem.json",
    "net_access2_validate_deletefi": "access2_validate_deletefi_local_subsystem.json",
    "net_access2_lt_create_context": "access2_lt_create_context_local_subsystem.json",
    "net_access2_lt_import_update": "access2_lt_import_update_local_subsystem.json",
    "net_access2_lt_cleanup": "access2_lt_cleanup_local_subsystem.json",
}

MODE_MUTATE_INDEX = {
    "net_get_servers": 0,
    "net_access": 0,
    "net_access2": 0,
    "net_version": 1,
    "net_info_system": 1,
    "net_info_version": 1,
    "net_access_public_key": 1,
    "net_access_calc_sig": 1,
    "net_access_crypt2": 1,
    "net_access_validate_signedtime": 1,
    "net_access_validate_signedlist": 1,
    "net_access_validate_deletefi": 1,
    "net_access_lt_create_context": 1,
    "net_access_lt_import_update": 1,
    "net_access_lt_cleanup": 1,
    "net_access2_public_key": 1,
    "net_access2_calc_sig": 1,
    "net_access2_crypt2": 1,
    "net_access2_validate_signedtime": 1,
    "net_access2_validate_signedlist": 1,
    "net_access2_validate_deletefi": 1,
    "net_access2_lt_create_context": 1,
    "net_access2_lt_import_update": 1,
    "net_access2_lt_cleanup": 1,
}


def load_target_frame(mode: str) -> bytes:
    doc = json.loads((FRAME_ROOT / MODE_TO_FILE[mode]).read_text(encoding="utf-8"))
    c2d = [bytes.fromhex(fr["data_hex"]) for fr in doc["frames"] if fr["direction"] == "C→D"]
    return c2d[MODE_MUTATE_INDEX[mode]]


def write_seed(path: Path, data: bytes) -> None:
    path.write_bytes(data)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=sorted(MODE_TO_FILE))
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
