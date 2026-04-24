#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


SEEDS = {
    "bef830": [
        ("large.bin", bytes((0x41 + (i % 23)) for i in range(160))),
    ],
    "7f9060": [
        ("small.bin", b"hellohellohello"),
    ],
    "54ace0": [
        ("host-ish.bin", b"localhost"),
        ("medium.bin", b"alpha-beta-gamma-delta"),
    ],
}


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=sorted(SEEDS))
    ap.add_argument("out_dir", nargs="?", default=None)
    return ap.parse_args()


def main() -> int:
    args = parse_args()
    out_dir = Path(args.out_dir) if args.out_dir else ROOT / "seeds" / f"cm_afl_native_{args.mode}"
    out_dir.mkdir(parents=True, exist_ok=True)
    for stale in out_dir.glob("*.bin"):
        stale.unlink()
    for name, blob in SEEDS[args.mode]:
        path = out_dir / name
        path.write_bytes(blob)
        print(f"{path} len={len(blob)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
