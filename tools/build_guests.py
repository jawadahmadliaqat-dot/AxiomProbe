"""Compile guests/*.wat -> guests/*.wasm using wasmtime's wat2wasm.

Run:  .venv/bin/python tools/build_guests.py
"""
from pathlib import Path

from wasmtime import wat2wasm

ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    for wat in sorted((ROOT / "guests").glob("*.wat")):
        out = wat.with_suffix(".wasm")
        out.write_bytes(wat2wasm(wat.read_text(encoding="utf-8")))
        print(f"built {out.relative_to(ROOT)} ({out.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
