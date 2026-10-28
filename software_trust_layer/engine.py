"""Capability Enforcement Engine for AmbientOS Layer 3 (software-trust-layer).

Inputs (JSON only — this layer builds no firmware analysis and no policy logic):
  * firmware_manifest.json  (Layer 4 / Bedrock)  — verified hardware facts
  * policy_decision.json    (Layer 2 / Context)  — signed, short-TTL decision
    (legacy filename ``policy_token.json`` is also accepted on load)

Enforcement order (fixed, do not reorder):
  0. signature invalid           -> DENY  (guest never starts; only when a
       signing key is configured — see below; an unauthenticated token's
       fields cannot be trusted, so this runs before expiry/decision)
  1. token expired               -> DENY  (guest never starts)
  2. decision != "ALLOW"         -> DENY  (guest never starts)
  3. address in forbidden region -> TRAP  (manifest is bedrock; overrides policy)
  4. address not in a verified MMIO range -> TRAP
  5. peripheral not in policy allowed_capabilities -> TRAP

Signature scheme (agreed with Layer 2 / context-fabric): HMAC-SHA256 over
the canonical token body — the token JSON without its ``signature`` field,
serialised with ``json.dumps(sort_keys=True, separators=(",", ":"))``.
When the env var ``CONTEXT_FABRIC_SIGNING_KEY`` is set, the engine verifies
the policy's signature against that key in pre-flight and DENIES on any
mismatch (or a missing signature). When the env var is not set, the engine
keeps the legacy behaviour of only recording that a ``signature`` field is
present — verification is opt-in by configuration, never silently claimed.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

SIGNING_KEY_ENV = "CONTEXT_FABRIC_SIGNING_KEY"


def canonical_token_body(raw: dict) -> bytes:
    """Canonical bytes that Layer 2 signs: token without ``signature``,
    JSON with sorted keys and compact separators, UTF-8."""
    body = {k: v for k, v in raw.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_token_body(raw: dict, key) -> str:
    """HMAC-SHA256 hex signature over the canonical body of `raw`
    (any ``signature`` key in `raw` is ignored). Used by token generators
    and tests; mirrors context-fabric's signing exactly."""
    if isinstance(key, str):
        key = key.encode("utf-8")
    return hmac.new(key, canonical_token_body(raw), hashlib.sha256).hexdigest()


def verify_policy_signature(policy: "Policy", key) -> bool:
    signature = policy.raw.get("signature")
    if not isinstance(signature, str) or not signature:
        return False
    return hmac.compare_digest(sign_token_body(policy.raw, key), signature)


def _parse_int(value) -> int:
    if isinstance(value, int):
        return value
    return int(str(value), 0)  # handles "0x40010C00" and decimal strings


def _parse_time(value: str) -> datetime:
    dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


@dataclass
class MmioRange:
    start: int
    end: int
    peripheral: str
    access_type: str = "read_write"

    def contains(self, addr: int) -> bool:
        return self.start <= addr <= self.end


def _coerce_range(entry) -> MmioRange:
    if isinstance(entry, dict):
        return MmioRange(
            _parse_int(entry.get("start", entry.get("start_addr"))),
            _parse_int(entry.get("end", entry.get("end_addr"))),
            entry.get("peripheral_name", entry.get("peripheral", "UNKNOWN")),
            entry.get("access_type", "read_write"),
        )
    seq = list(entry)  # [start, end, peripheral_name, access_type?]
    return MmioRange(_parse_int(seq[0]), _parse_int(seq[1]), str(seq[2]),
                     str(seq[3]) if len(seq) > 3 else "read_write")


@dataclass
class Manifest:
    target_architecture: str
    verified_mmio_ranges: list[MmioRange]
    forbidden_regions: list[MmioRange] = field(default_factory=list)
    forbidden_names: set[str] = field(default_factory=set)
    formal_proof_status: str = "UNKNOWN"
    sha256_hash: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "Manifest":
        forbidden_ranges, forbidden_names = [], set()
        for entry in d.get("forbidden_regions", []) or []:
            if isinstance(entry, str):
                forbidden_names.add(entry)  # name-only form, no address range
            else:
                r = _coerce_range(entry)
                forbidden_ranges.append(r)
                forbidden_names.add(r.peripheral)
        return cls(
            target_architecture=d.get("target_architecture", "UNKNOWN"),
            verified_mmio_ranges=[_coerce_range(e)
                                  for e in d.get("verified_mmio_ranges", [])],
            forbidden_regions=forbidden_ranges,
            forbidden_names=forbidden_names,
            formal_proof_status=d.get("formal_proof_status", "UNKNOWN"),
            sha256_hash=d.get("sha256_hash", ""),
        )


@dataclass
class Policy:
    decision: str
    user_role: str
    allowed_capabilities: list[str]
    issued_at: datetime | None
    expires_at: datetime | None
    signature: str = ""
    allowed_mmio_ranges: list[MmioRange] = field(default_factory=list)
    source_name: str = "policy_decision.json"
    raw: dict = field(default_factory=dict)  # original token, for signature checks

    @classmethod
    def from_dict(cls, d: dict, source_name: str = "policy_decision.json") -> "Policy":
        return cls(
            decision=str(d.get("decision", "DENY")),
            user_role=str(d.get("user_role", "UNKNOWN")),
            allowed_capabilities=[str(c) for c in d.get("allowed_capabilities", [])],
            issued_at=_parse_time(d["issued_at"]) if d.get("issued_at") else None,
            expires_at=_parse_time(d["expires_at"]) if d.get("expires_at") else None,
            signature=str(d.get("signature", "")),
            allowed_mmio_ranges=[_coerce_range(e)
                                 for e in d.get("allowed_mmio_ranges", []) or []],
            source_name=source_name,
            raw=copy.deepcopy(d),
        )


class PolicyDenied(Exception):
    """Pre-flight denial: the guest is never started."""


class CapabilityTrap(Exception):
    """Per-access violation: the running Wasm instance must be terminated."""

    def __init__(self, addr: int, peripheral: str | None, reason: str):
        self.addr, self.peripheral, self.reason = addr, peripheral, reason
        super().__init__(
            f"TRAP addr=0x{addr:08X} peripheral={peripheral or 'UNKNOWN'} "
            f"reason={reason}")


def load_json(path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def load_manifest(path) -> Manifest:
    return Manifest.from_dict(load_json(path))


def load_policy(path) -> Policy:
    """Load a policy file. Accepts policy_decision.json (canonical) and
    policy_token.json (legacy). If `path` is a directory, the canonical
    name is tried first, then the legacy name."""
    p = Path(path)
    if p.is_dir():
        for name in ("policy_decision.json", "policy_token.json"):
            if (p / name).exists():
                p = p / name
                break
        else:
            raise FileNotFoundError(
                f"neither policy_decision.json nor policy_token.json in {path}")
    return Policy.from_dict(load_json(p), source_name=p.name)


class CapabilityEngine:
    def __init__(self, manifest: Manifest, policy: Policy, now: datetime | None = None):
        self.manifest, self.policy = manifest, policy
        self.now = now or datetime.now(timezone.utc)
        self.trap_log: list[str] = []

    # -- pre-flight (steps 0-2) -------------------------------------------
    def check_preflight(self) -> None:
        # Step 0: signature — only when a signing key is configured.
        key = os.environ.get(SIGNING_KEY_ENV)
        if key and not verify_policy_signature(self.policy, key):
            raise PolicyDenied(
                f"policy signature verification FAILED (env {SIGNING_KEY_ENV} "
                f"is set and the token's HMAC-SHA256 signature is missing or "
                f"does not match its canonical body)")
        if self.policy.expires_at is not None and self.now >= self.policy.expires_at:
            raise PolicyDenied(
                f"policy expired at {self.policy.expires_at.isoformat()} "
                f"(now {self.now.isoformat()})")
        if self.policy.decision != "ALLOW":
            raise PolicyDenied(f"policy decision is {self.policy.decision!r}, not 'ALLOW'")

    # -- per-access (steps 3-5) -------------------------------------------
    def check_access(self, addr: int) -> str:
        """Return the peripheral name for an allowed access, else raise
        CapabilityTrap with the step-specific reason."""
        addr &= 0xFFFFFFFF
        # Step 3a: forbidden address range (bedrock overrides policy).
        for r in self.manifest.forbidden_regions:
            if r.contains(addr):
                return self._trap(addr, r.peripheral, "FORBIDDEN_REGION")
        verified = next((r for r in self.manifest.verified_mmio_ranges
                         if r.contains(addr)), None)
        # Step 3b: forbidden by peripheral name, even if also listed verified.
        if verified is not None and verified.peripheral in self.manifest.forbidden_names:
            return self._trap(addr, verified.peripheral, "FORBIDDEN_REGION")
        # Step 4: not verified at all.
        if verified is None:
            return self._trap(addr, None, "NOT_IN_VERIFIED_MMIO_RANGES")
        # Step 5: verified hardware, but policy does not grant this peripheral.
        caps = self.policy.allowed_capabilities
        if verified.peripheral not in caps and "*" not in caps:
            return self._trap(addr, verified.peripheral,
                              "PERIPHERAL_NOT_IN_POLICY_ALLOWED_CAPABILITIES")
        # Optional narrowing: if the policy carries its own MMIO ranges,
        # the address must also fall inside one of them.
        if self.policy.allowed_mmio_ranges and not any(
                r.contains(addr) for r in self.policy.allowed_mmio_ranges):
            return self._trap(addr, verified.peripheral,
                              "NOT_IN_POLICY_ALLOWED_MMIO_RANGES")
        return verified.peripheral

    def _trap(self, addr, peripheral, reason):
        exc = CapabilityTrap(addr, peripheral, reason)
        self.trap_log.append(str(exc))
        raise exc
