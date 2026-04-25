#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import textwrap


ROOT = Path(__file__).resolve().parents[1]
FRAME_ROOT = Path("/tmp/cm_sdk_api_sweep/frames")


MODE_SPECS = {
    "net_get_servers": {
        "frame_file": "get_servers.json",
        "mutate_index": 0,
        "token_frame": -1,
        "token_offset": 0,
        "token_len": 0,
        "sid_patches": [],
    },
    "net_access": {
        "frame_file": "access_local_subsystem.json",
        "mutate_index": 0,
        "token_frame": 0,
        "token_offset": 0x1C,
        "token_len": 4,
        "sid_patches": [(1, 0, 4)],
    },
    "net_access2": {
        "frame_file": "access2_local_subsystem.json",
        "mutate_index": 0,
        "token_frame": 0,
        "token_offset": 472,
        "token_len": 4,
        "sid_patches": [(1, 0, 4)],
    },
    "net_version": {
        "frame_file": "access_version_local_subsystem.json",
        "mutate_index": 1,
        "token_frame": 0,
        "token_offset": 0x1C,
        "token_len": 4,
        "sid_patches": [(1, 0, 4), (2, 0, 4)],
    },
    "net_info_system": {
        "frame_file": "access_info_system_local_subsystem.json",
        "mutate_index": 1,
        "token_frame": 0,
        "token_offset": 0x1C,
        "token_len": 4,
        "sid_patches": [(1, 0, 4), (2, 0, 4)],
    },
    "net_info_version": {
        "frame_file": "access_info_version_local_subsystem.json",
        "mutate_index": 1,
        "token_frame": 0,
        "token_offset": 0x1C,
        "token_len": 4,
        "sid_patches": [(1, 0, 4), (2, 0, 4)],
    },
    "net_access_public_key": {
        "frame_file": "access_public_key_local_subsystem.json",
        "mutate_index": 1,
        "token_frame": 0,
        "token_offset": 0x1C,
        "token_len": 4,
        "sid_patches": [(1, 0, 4), (2, 0, 4)],
    },
    "net_access_calc_sig": {
        "frame_file": "access_calc_sig_local_subsystem.json",
        "mutate_index": 1,
        "token_frame": 0,
        "token_offset": 0x1C,
        "token_len": 4,
        "sid_patches": [(1, 0, 4), (2, 0, 4)],
    },
    "net_access_crypt2": {
        "frame_file": "access_crypt2_local_subsystem.json",
        "mutate_index": 1,
        "token_frame": 0,
        "token_offset": 0x1C,
        "token_len": 4,
        "sid_patches": [(1, 0, 4), (2, 0, 4)],
    },
    "net_access_validate_signedtime": {
        "frame_file": "access_validate_signedtime_local_subsystem.json",
        "mutate_index": 1,
        "token_frame": 0,
        "token_offset": 0x1C,
        "token_len": 4,
        "sid_patches": [(1, 0, 4), (2, 0, 4)],
    },
    "net_access_validate_signedlist": {
        "frame_file": "access_validate_signedlist_local_subsystem.json",
        "mutate_index": 1,
        "token_frame": 0,
        "token_offset": 0x1C,
        "token_len": 4,
        "sid_patches": [(1, 0, 4), (2, 0, 4)],
    },
    "net_access_validate_deletefi": {
        "frame_file": "access_validate_deletefi_local_subsystem.json",
        "mutate_index": 1,
        "token_frame": 0,
        "token_offset": 0x1C,
        "token_len": 4,
        "sid_patches": [(1, 0, 4), (2, 0, 4)],
    },
    "net_access_lt_create_context": {
        "frame_file": "access_lt_create_context_local_subsystem.json",
        "mutate_index": 1,
        "token_frame": 0,
        "token_offset": 0x1C,
        "token_len": 4,
        "sid_patches": [(1, 0, 4), (2, 0, 4)],
    },
    "net_access_lt_import_update": {
        "frame_file": "access_lt_import_update_local_subsystem.json",
        "mutate_index": 1,
        "token_frame": 0,
        "token_offset": 0x1C,
        "token_len": 4,
        "sid_patches": [(1, 0, 4), (2, 0, 4)],
    },
    "net_access_lt_cleanup": {
        "frame_file": "access_lt_cleanup_local_subsystem.json",
        "mutate_index": 1,
        "token_frame": 0,
        "token_offset": 0x1C,
        "token_len": 4,
        "sid_patches": [(1, 0, 4), (2, 0, 4)],
    },
    "net_access2_public_key": {
        "frame_file": "access2_public_key_local_subsystem.json",
        "mutate_index": 1,
        "token_frame": 0,
        "token_offset": 472,
        "token_len": 4,
        "sid_patches": [(1, 0, 4), (2, 0, 4)],
    },
    "net_access2_calc_sig": {
        "frame_file": "access2_calc_sig_local_subsystem.json",
        "mutate_index": 1,
        "token_frame": 0,
        "token_offset": 472,
        "token_len": 4,
        "sid_patches": [(1, 0, 4), (2, 0, 4)],
    },
    "net_access2_crypt2": {
        "frame_file": "access2_crypt2_local_subsystem.json",
        "mutate_index": 1,
        "token_frame": 0,
        "token_offset": 472,
        "token_len": 4,
        "sid_patches": [(1, 0, 4), (2, 0, 4)],
    },
    "net_access2_validate_signedtime": {
        "frame_file": "access2_validate_signedtime_local_subsystem.json",
        "mutate_index": 1,
        "token_frame": 0,
        "token_offset": 472,
        "token_len": 4,
        "sid_patches": [(1, 0, 4), (2, 0, 4)],
    },
    "net_access2_validate_signedlist": {
        "frame_file": "access2_validate_signedlist_local_subsystem.json",
        "mutate_index": 1,
        "token_frame": 0,
        "token_offset": 472,
        "token_len": 4,
        "sid_patches": [(1, 0, 4), (2, 0, 4)],
    },
    "net_access2_validate_deletefi": {
        "frame_file": "access2_validate_deletefi_local_subsystem.json",
        "mutate_index": 1,
        "token_frame": 0,
        "token_offset": 472,
        "token_len": 4,
        "sid_patches": [(1, 0, 4), (2, 0, 4)],
    },
    "net_access2_lt_create_context": {
        "frame_file": "access2_lt_create_context_local_subsystem.json",
        "mutate_index": 1,
        "token_frame": 0,
        "token_offset": 472,
        "token_len": 4,
        "sid_patches": [(1, 0, 4), (2, 0, 4)],
    },
    "net_access2_lt_import_update": {
        "frame_file": "access2_lt_import_update_local_subsystem.json",
        "mutate_index": 1,
        "token_frame": 0,
        "token_offset": 472,
        "token_len": 4,
        "sid_patches": [(1, 0, 4), (2, 0, 4)],
    },
    "net_access2_lt_cleanup": {
        "frame_file": "access2_lt_cleanup_local_subsystem.json",
        "mutate_index": 1,
        "token_frame": 0,
        "token_offset": 472,
        "token_len": 4,
        "sid_patches": [(1, 0, 4), (2, 0, 4)],
    },
}


def c_bytes(blob: bytes) -> str:
    items = ", ".join(f"0x{b:02x}" for b in blob)
    return textwrap.fill(items, width=100, subsequent_indent="    ")


def load_c2d_frames(frame_path: Path) -> list[bytes]:
    doc = json.loads(frame_path.read_text(encoding="utf-8"))
    frames = []
    for fr in doc["frames"]:
        if fr["direction"] != "C→D":
            continue
        frames.append(bytes.fromhex(fr["data_hex"]))
    return frames


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--frame-root",
        default=str(FRAME_ROOT),
        help="directory containing captured frame jsons",
    )
    ap.add_argument(
        "--out",
        default=str(ROOT / "preload" / "cm_afl_net_assets.h"),
    )
    args = ap.parse_args()

    frame_root = Path(args.frame_root)
    out = Path(args.out)

    lines: list[str] = []
    lines.append("/* generated by scripts/build_cm_afl_net_assets.py */")
    lines.append("#ifndef CM_AFL_NET_ASSETS_H")
    lines.append("#define CM_AFL_NET_ASSETS_H")
    lines.append("")
    lines.append("#include <stddef.h>")
    lines.append("#include <stdint.h>")
    lines.append("")
    lines.append("struct cm_net_frame_asset {")
    lines.append("    size_t len;")
    lines.append("    const unsigned char *data;")
    lines.append("};")
    lines.append("")
    lines.append("struct cm_net_sid_patch {")
    lines.append("    size_t frame_index;")
    lines.append("    size_t reply_index;")
    lines.append("    size_t offset;")
    lines.append("};")
    lines.append("")
    lines.append("struct cm_net_mode_asset {")
    lines.append("    const char *mode;")
    lines.append("    size_t frame_count;")
    lines.append("    const struct cm_net_frame_asset *frames;")
    lines.append("    size_t mutate_index;")
    lines.append("    int token_frame;")
    lines.append("    size_t token_offset;")
    lines.append("    size_t token_len;")
    lines.append("    size_t sid_patch_count;")
    lines.append("    const struct cm_net_sid_patch *sid_patches;")
    lines.append("};")
    lines.append("")

    mode_names: list[str] = []
    for mode_name, spec in MODE_SPECS.items():
        mode_names.append(mode_name)
        frames = load_c2d_frames(frame_root / spec["frame_file"])
        frame_refs = []
        for idx, frame in enumerate(frames):
            arr_name = f"cm_net_{mode_name}_frame_{idx}_bytes"
            frame_name = f"cm_net_{mode_name}_frame_{idx}"
            lines.append(f"static const unsigned char {arr_name}[] = {{")
            lines.append(f"    {c_bytes(frame)}")
            lines.append("};")
            lines.append("")
            lines.append(f"static const struct cm_net_frame_asset {frame_name} = {{")
            lines.append(f"    .len = {len(frame)},")
            lines.append(f"    .data = {arr_name},")
            lines.append("};")
            lines.append("")
            frame_refs.append(frame_name)

        lines.append(f"static const struct cm_net_frame_asset cm_net_{mode_name}_frames[] = {{")
        for frame_name in frame_refs:
            lines.append(f"    {frame_name},")
        lines.append("};")
        lines.append("")

        patch_name = f"cm_net_{mode_name}_sid_patches"
        lines.append(f"static const struct cm_net_sid_patch {patch_name}[] = {{")
        for frame_index, reply_index, offset in spec["sid_patches"]:
            lines.append(
                "    { .frame_index = %d, .reply_index = %d, .offset = %d },"
                % (frame_index, reply_index, offset)
            )
        lines.append("};")
        lines.append("")

        lines.append(f"static const struct cm_net_mode_asset cm_net_{mode_name} = {{")
        lines.append(f'    .mode = "{mode_name}",')
        lines.append(f"    .frame_count = {len(frames)},")
        lines.append(f"    .frames = cm_net_{mode_name}_frames,")
        lines.append(f"    .mutate_index = {spec['mutate_index']},")
        lines.append(f"    .token_frame = {spec['token_frame']},")
        lines.append(f"    .token_offset = {spec['token_offset']},")
        lines.append(f"    .token_len = {spec['token_len']},")
        lines.append(f"    .sid_patch_count = {len(spec['sid_patches'])},")
        lines.append(f"    .sid_patches = {patch_name},")
        lines.append("};")
        lines.append("")

    lines.append("static const struct cm_net_mode_asset *cm_net_all_modes[] = {")
    for mode_name in mode_names:
        lines.append(f"    &cm_net_{mode_name},")
    lines.append("};")
    lines.append("")
    lines.append("#define CM_NET_MODE_COUNT (sizeof(cm_net_all_modes) / sizeof(cm_net_all_modes[0]))")
    lines.append("")
    lines.append("#endif")
    lines.append("")

    out.write_text("\n".join(lines), encoding="ascii")
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
