"""CLI: run a Wasm guest under a manifest + policy.

Usage:
  .venv/bin/python -m software_trust_layer run \
      --manifest examples/firmware_manifest.json \
      --policy   examples/policy_decision.json \
      --guest    guests/good_app.wasm
Exit codes: 0 = completed, 2 = trapped, 3 = denied, 1 = usage/io error.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from wasmtime import wat2wasm

from .engine import CapabilityEngine, load_manifest, load_policy
from .runtime import Sandbox


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="software_trust_layer")
    sub = ap.add_subparsers(dest="cmd", required=True)
    run = sub.add_parser("run")
    run.add_argument("--manifest", required=True)
    run.add_argument("--policy", required=True,
                     help="policy_decision.json (canonical) or policy_token.json (legacy), or a directory containing one")
    run.add_argument("--guest", required=True, help=".wasm binary or .wat source")
    args = ap.parse_args(argv)

    guest_path = Path(args.guest)
    raw = guest_path.read_bytes()
    wasm = wat2wasm(raw.decode("utf-8")) if guest_path.suffix == ".wat" else raw

    engine = CapabilityEngine(load_manifest(args.manifest), load_policy(args.policy))
    result = Sandbox(engine).run(wasm)
    for line in result.accesses:
        print(f"  {line}")
    if result.status == "completed":
        print(f"RESULT: COMPLETED guest={guest_path.name}")
        return 0
    if result.status == "trapped":
        print(f"RESULT: TRAPPED guest={guest_path.name} :: {result.trap}")
        return 2
    print(f"RESULT: DENIED guest={guest_path.name} :: {result.detail}")
    return 3


if __name__ == "__main__":
    sys.exit(main())
