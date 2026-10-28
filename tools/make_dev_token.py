"""Generate a fresh, correctly-signed dev policy_decision.json.

The token uses the exact field set and signing scheme of Layer 2
(context-fabric):

  fields: decision, decision_id, user_role, action, resource,
          allowed_capabilities, ambient_state, matched_permit_ids,
          issued_at, expires_at, ttl_seconds, signature
  signature: HMAC-SHA256 over the canonical body (token without
          "signature", json.dumps sort_keys=True, separators (",", ":"))

In this layer's mock usage, `allowed_capabilities` carries *peripheral*
names (GPIOB_LED, UART1). Mapping Layer 2's semantic capabilities to
peripheral names is the orchestrator's (Layer 1) job at integration time;
documented in README.md / INTERFACE.md.

The default key is the documented dev sample key shared with
context-fabric. Dev only — never a production secret.

Run:
  .venv/bin/python tools/make_dev_token.py --out /tmp/policy_decision.json
  CONTEXT_FABRIC_SIGNING_KEY=context-fabric-dev-sample-key \
    .venv/bin/python -m software_trust_layer run \
      --manifest examples/firmware_manifest.json \
      --policy /tmp/policy_decision.json --guest guests/good_app.wasm
"""
from __future__ import annotations

import argparse
import json
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from software_trust_layer.engine import sign_token_body  # noqa: E402

DEV_KEY = "context-fabric-dev-sample-key"  # documented dev key (context-fabric sample)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_token(key: str = DEV_KEY, ttl_seconds: int = 300,
               capabilities=("GPIOB_LED", "UART1")) -> dict:
    now = datetime.now(timezone.utc)
    token = {
        "decision": "ALLOW",
        "decision_id": str(uuid.uuid4()),
        "user_role": "OWNER",
        "action": "RunGuestApp",
        "resource": "wasm_guest",
        "allowed_capabilities": list(capabilities),
        "ambient_state": "HOME",
        "matched_permit_ids": [],
        "issued_at": _iso(now),
        "expires_at": _iso(now + timedelta(seconds=ttl_seconds)),
        "ttl_seconds": ttl_seconds,
    }
    token["signature"] = sign_token_body(token, key)
    return token


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="-", help="output path, or - for stdout")
    ap.add_argument("--key", default=DEV_KEY)
    ap.add_argument("--ttl", type=int, default=300)
    args = ap.parse_args()
    text = json.dumps(make_token(args.key, args.ttl), indent=2, sort_keys=True)
    if args.out == "-":
        print(text)
    else:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
        print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
