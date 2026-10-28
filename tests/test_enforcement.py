"""Enforcement test suite for software-trust-layer (stdlib unittest).

Run:  .venv/bin/python -m unittest discover -s tests -v

Guests are real Wasm, compiled in-test from WAT with wasmtime's wat2wasm.
Policies are generated fresh in each test so TTL behaviour is real, not
frozen into a stale fixture. The manifest is the mock in examples/.
"""
import copy
import hashlib
import json
import os
import sys
import tempfile
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from wasmtime import wat2wasm  # noqa: E402

from software_trust_layer import (CapabilityEngine, Sandbox,  # noqa: E402
                                  load_manifest, load_policy, sign_token_body)
from software_trust_layer.engine import Manifest, Policy  # noqa: E402

MANIFEST = load_manifest(ROOT / "examples" / "firmware_manifest.json")
NOW = datetime.now(timezone.utc)

# Documented dev signing key shared with context-fabric (sample/dev only).
DEV_KEY = "context-fabric-dev-sample-key"


def _z(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_signed_policy_dict(**overrides) -> dict:
    """A token in the exact context-fabric format (same fields, same
    canonical-JSON HMAC-SHA256 scheme), freshly signed with DEV_KEY."""
    d = {
        "decision": "ALLOW",
        "decision_id": str(uuid.uuid4()),
        "user_role": "OWNER",
        "action": "RunGuestApp",
        "resource": "wasm_guest",
        "allowed_capabilities": ["GPIOB_LED", "UART1"],
        "ambient_state": "HOME",
        "matched_permit_ids": [],
        "issued_at": _z(NOW - timedelta(seconds=5)),
        "expires_at": _z(NOW + timedelta(minutes=5)),
        "ttl_seconds": 305,
    }
    d.update(overrides)
    d["signature"] = sign_token_body(d, DEV_KEY)
    return d


def run_signed(wasm: bytes, token_dict: dict) -> object:
    """Run with signature enforcement ON (env key set for the whole run)."""
    engine = CapabilityEngine(MANIFEST, Policy.from_dict(token_dict), now=NOW)
    with mock.patch.dict(os.environ, {"CONTEXT_FABRIC_SIGNING_KEY": DEV_KEY}):
        return Sandbox(engine).run(wasm)


def make_policy(**overrides) -> Policy:
    d = {
        "decision": "ALLOW",
        "user_role": "OWNER",
        "allowed_capabilities": ["GPIOB_LED", "UART1"],
        "issued_at": NOW.isoformat(),
        "expires_at": (NOW + timedelta(minutes=5)).isoformat(),
        "signature": "TEST_SIGNATURE_PLACEHOLDER",
    }
    d.update(overrides)
    return Policy.from_dict(d)


def guest_wat(addr_hex: str, value: int = 0x1) -> bytes:
    wat = f"""
    (module
      (import "env" "sys_mmio_write" (func $write (param i32 i32)))
      (import "env" "sys_mmio_read"  (func $read  (param i32) (result i32)))
      (func (export "_start")
        (call $write (i32.const {addr_hex}) (i32.const {value}))))
    """
    return wat2wasm(wat)


def run(wasm: bytes, policy: Policy | None = None,
        manifest: Manifest = MANIFEST) -> object:
    engine = CapabilityEngine(manifest, policy or make_policy(), now=NOW)
    return Sandbox(engine).run(wasm)


def bundled_guest(name: str) -> bytes:
    return wat2wasm((ROOT / "guests" / name).read_text(encoding="utf-8"))


class TestEnforcement(unittest.TestCase):
    def test_good_app_succeeds(self):
        r = run(bundled_guest("good_app.wat"))
        self.assertEqual(r.status, "completed", r.trap or r.detail)
        self.assertEqual(len(r.accesses), 3)  # LED write, UART write, LED read

    def test_rogue_app_traps_on_forbidden_region(self):
        r = run(bundled_guest("rogue_app.wat"))
        self.assertEqual(r.status, "trapped")
        self.assertIn("0x40022000", r.trap)
        self.assertIn("FLASH_CONTROLLER", r.trap)
        self.assertIn("FORBIDDEN_REGION", r.trap)
        # Only the first (legitimate) access was logged; the trap terminated
        # the instance before the third write.
        self.assertEqual(len(r.accesses), 1)

    def test_expired_token_denied(self):
        expired = make_policy(
            issued_at=(NOW - timedelta(minutes=10)).isoformat(),
            expires_at=(NOW - timedelta(minutes=5)).isoformat())
        r = run(bundled_guest("good_app.wat"), policy=expired)
        self.assertEqual(r.status, "denied")
        self.assertIn("expired", r.detail)
        self.assertEqual(r.accesses, [])  # guest never started

    def test_policy_deny_denied(self):
        r = run(bundled_guest("good_app.wat"),
                policy=make_policy(decision="DENY"))
        self.assertEqual(r.status, "denied")
        self.assertEqual(r.accesses, [])

    def test_forbidden_region_traps_even_when_policy_allows_it(self):
        greedy = make_policy(allowed_capabilities=[
            "GPIOB_LED", "UART1", "FLASH_CONTROLLER", "CRYPTO_ENGINE"])
        r = run(guest_wat("0x40022000"), policy=greedy)
        self.assertEqual(r.status, "trapped")
        self.assertIn("FORBIDDEN_REGION", r.trap)

    def test_allowed_address_but_peripheral_not_in_policy_traps(self):
        # RCC (0x40021000) IS verified in the manifest, but the default
        # policy grants only GPIOB_LED + UART1.
        r = run(guest_wat("0x40021000"))
        self.assertEqual(r.status, "trapped")
        self.assertIn("RCC", r.trap)
        self.assertIn("PERIPHERAL_NOT_IN_POLICY", r.trap)

    def test_unverified_address_traps(self):
        r = run(guest_wat("0x12345000"))  # in no verified range at all
        self.assertEqual(r.status, "trapped")
        self.assertIn("NOT_IN_VERIFIED_MMIO_RANGES", r.trap)

    def test_legacy_policy_token_filename_accepted(self):
        d = {
            "decision": "ALLOW", "user_role": "OWNER",
            "allowed_capabilities": ["GPIOB_LED", "UART1"],
            "issued_at": NOW.isoformat(),
            "expires_at": (NOW + timedelta(minutes=5)).isoformat(),
            "signature": "TEST_SIGNATURE_PLACEHOLDER",
        }
        import json
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "policy_token.json"  # legacy name only
            p.write_text(json.dumps(d), encoding="utf-8")
            policy = load_policy(td)  # directory load must find it
            self.assertEqual(policy.source_name, "policy_token.json")
            r = run(bundled_guest("good_app.wat"), policy=policy)
            self.assertEqual(r.status, "completed")

    def test_manifest_sha256_matches_sample_binary(self):
        # The mock manifest's sha256_hash must be the REAL hash of the
        # committed sample binary — recomputed from the file here.
        sample = ROOT / "examples" / "sample_firmware.bin"
        self.assertTrue(sample.exists(), "examples/sample_firmware.bin missing")
        digest = hashlib.sha256(sample.read_bytes()).hexdigest()
        self.assertEqual(digest, MANIFEST.sha256_hash)
        self.assertNotEqual(digest, "0" * 64)  # not the old placeholder


class TestSignedPolicies(unittest.TestCase):
    """Signature gap, closed: with CONTEXT_FABRIC_SIGNING_KEY set, the
    engine verifies the context-fabric HMAC-SHA256 scheme in pre-flight."""

    def test_correctly_signed_token_good_app_passes(self):
        r = run_signed(bundled_guest("good_app.wat"), make_signed_policy_dict())
        self.assertEqual(r.status, "completed", r.trap or r.detail)
        self.assertEqual(len(r.accesses), 3)

    def test_tampered_signed_token_denied(self):
        d = make_signed_policy_dict()
        d["user_role"] = "GUEST"  # tamper a signed field, keep old signature
        r = run_signed(bundled_guest("good_app.wat"), d)
        self.assertEqual(r.status, "denied")
        self.assertIn("signature", (r.detail or "").lower())
        self.assertEqual(r.accesses, [])  # guest never started

    def test_expired_signed_token_denied(self):
        d = make_signed_policy_dict(
            issued_at=_z(NOW - timedelta(minutes=10)),
            expires_at=_z(NOW - timedelta(minutes=5)),
            ttl_seconds=300)
        r = run_signed(bundled_guest("good_app.wat"), d)
        self.assertEqual(r.status, "denied")
        self.assertIn("expired", (r.detail or "").lower())
        self.assertEqual(r.accesses, [])

    def test_mock_example_policy_shape_loads(self):
        # The shipped mock must at least parse against the engine's schema
        # (its TTL is deliberately short, so no run is attempted with it).
        policy = load_policy(ROOT / "examples" / "policy_decision.json")
        self.assertEqual(policy.decision, "ALLOW")
        self.assertIn("GPIOB_LED", policy.allowed_capabilities)
        self.assertIsNotNone(copy.deepcopy(policy).expires_at)


if __name__ == "__main__":
    unittest.main()
