# INTERFACE — software-trust-layer (Layer 3) contract consumption

This layer is a pure consumer of the Phase-1 contract. It produces no
manifests and no policies; it executes or traps.

## Input 1 — `firmware_manifest.json` (from Layer 4, Agent 1)

```json
{
  "target_architecture": "ARM_CORTEX_M3",
  "verified_mmio_ranges": [["0x40010C00", "0x40010FFF", "GPIOB_LED", "read_write"]],
  "forbidden_regions": [["0x40022000", "0x400223FF", "FLASH_CONTROLLER"]],
  "formal_proof_status": "VERIFIED_LEAN4",
  "sha256_hash": "<hex>"
}
```

In the shipped MOCK manifest, `sha256_hash` is the real SHA-256 of the
committed `examples/sample_firmware.bin` (a test recomputes it from the
file); the binary and all other example values (including
`formal_proof_status`) are simulated.

Parsing tolerance (so Agent 1's exact emitter shape doesn't break the
handshake): range entries may be arrays `[start, end, name, access_type?]`
or objects `{start|start_addr, end|end_addr, peripheral_name|peripheral,
access_type?}`; addresses may be hex strings (`"0x…"`) or integers;
`forbidden_regions` entries may also be bare name strings (name-only bans).

## Input 2 — `policy_decision.json` (from Layer 2, Agent 3)

Canonical name: **`policy_decision.json`**. The legacy name
**`policy_token.json`** is also accepted — both as an explicit path and when
loading a directory (canonical is tried first).

```json
{
  "decision": "ALLOW",
  "user_role": "OWNER",
  "allowed_capabilities": ["GPIOB_LED", "UART1"],
  "allowed_mmio_ranges": [],
  "issued_at": "2026-10-28T17:00:00Z",
  "expires_at": "2026-10-28T17:05:00Z",
  "signature": "<HMAC-SHA256 hex; verified when CONTEXT_FABRIC_SIGNING_KEY is set>"
}
```

Full token field set (as emitted by context-fabric): `decision`,
`decision_id`, `user_role`, `action`, `resource`, `allowed_capabilities`,
`ambient_state`, `matched_permit_ids`, `issued_at`, `expires_at`,
`ttl_seconds`, `signature`. Extra fields are ignored by the parser but are
covered by the signature (it signs the whole body).

**Signature scheme (agreed with Layer 2):** HMAC-SHA256 over the canonical
body — the token without `signature`, `json.dumps(sort_keys=True,
separators=(",", ":"))`, UTF-8. Enforcement: when the env var
`CONTEXT_FABRIC_SIGNING_KEY` is set, pre-flight step 0 verifies the
signature and DENIES on mismatch or a missing signature, before expiry /
decision checks and before any guest code runs. When the env var is not
set, the engine only records that a signature field is present (legacy
behaviour — verification is opt-in by configuration). Layer 2's dev sample
key is `context-fabric-dev-sample-key` (documented dev key, not a secret;
production must move to asymmetric signing).

- `allowed_capabilities` entries are peripheral names (as named in the
  manifest); `"*"` grants all verified, non-forbidden peripherals.
- `allowed_mmio_ranges` is optional; when present and non-empty it narrows
  access further (same range-entry shapes as the manifest).
- Expiry is evaluated against the runtime clock at load/run time; an expired
  token denies before any guest code executes.

## Guest interface (host imports, module `env`)

| Import | Signature | Semantics |
|---|---|---|
| `sys_mmio_write` | `(addr: i32, value: i32)` | Checked write to the host-side MMIO register file |
| `sys_mmio_read` | `(addr: i32) -> i32` | Checked read; unwritten registers read as 0 |

Guests must export `_start`. Addresses are treated as unsigned 32-bit.

## Outcomes

| Outcome | When | CLI exit code |
|---|---|---|
| `completed` | Guest's `_start` returns; every access passed all checks | 0 |
| `trapped` | Any per-access check (steps 3–5) failed; instance terminated mid-run, later guest code never executes | 2 |
| `denied` | Pre-flight failed (invalid signature when a key is configured, expired token, or `decision != "ALLOW"`); guest never started | 3 |

Trap log format: `TRAP addr=0x%08X peripheral=<name|UNKNOWN> reason=<CODE>`
with `CODE` ∈ `FORBIDDEN_REGION`, `NOT_IN_VERIFIED_MMIO_RANGES`,
`PERIPHERAL_NOT_IN_POLICY_ALLOWED_CAPABILITIES`,
`NOT_IN_POLICY_ALLOWED_MMIO_RANGES`.

## Handshake checklist (Phase 1)

- [ ] Replace `examples/firmware_manifest.json` (MOCK) with Agent 1's real
      manifest emitted against `firmware_manifest.schema.json`.
- [ ] Replace `examples/policy_decision.json` (MOCK, placeholder signature)
      with Agent 3's real signed token. (The signed-token path itself is
      already exercised end-to-end with context-fabric-format dev tokens —
      see `tools/make_dev_token.py` and the signed-policy tests.)
- [x] Signature verification scheme agreed with Layer 2 (HMAC-SHA256 over
      canonical JSON) and implemented: enforced when
      `CONTEXT_FABRIC_SIGNING_KEY` is set. Still open for production:
      replace the shared dev key with asymmetric signing + key management.
- [ ] Re-run `tests/` against the real inputs; only then is the core pipeline
      considered live.
