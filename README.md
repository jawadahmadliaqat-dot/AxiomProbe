# software-trust-layer — AmbientOS Layer 3 (Sandbox / Software Trust)

Runs user applications in a real **WebAssembly (Wasmtime) sandbox** and ensures
a guest can **never** touch hardware (MMIO) unless *both* of these allow it:

- `firmware_manifest.json` — Layer 4 (firmware-liberation-engine): what hardware
  exists and is formally verified.
- `policy_decision.json` — Layer 2 (context-fabric): what the current
  user/context is allowed to do (signed, short TTL; legacy filename
  `policy_token.json` is also accepted on input).

Output: safe execution, a pre-flight **DENY**, or an immediate **TRAP** that
terminates the Wasm instance. This layer builds no firmware analysis, no
policy/context logic, and no UI. See `INTERFACE.md` for the full contract.

Note on capability names: in this layer's mock usage, the policy's
`allowed_capabilities` carries **peripheral names** (`GPIOB_LED`, `UART1`),
matching the manifest. Layer 2 (context-fabric) issues **semantic**
capabilities (e.g. `livingroom.lights.toggle`); mapping semantic →
peripheral names is the orchestrator's (Layer 1) job at integration time,
not this layer's.

## What is real vs scaffold

| Piece | Status |
|---|---|
| Python reference runtime (`software_trust_layer/`) on the real `wasmtime` pip package (v50.0.1, venv in `.venv/`) | **REAL — built, guests compiled, test suite run: 13/13 pass** |
| Guest apps `guests/good_app.wat` / `rogue_app.wat` (+ compiled `.wasm`) | **REAL — compiled with wasmtime `wat2wasm`, executed in tests and via CLI** |
| `examples/*.json` + `examples/sample_firmware.bin` | **MOCK / SIMULATED** — hand-written stand-ins, labelled `_mock: true`, until the Phase-1 handshake delivers Agent 1's manifest and Agent 3's policy. All example data is simulated — including `formal_proof_status` (no Lean proof exists for the mock). One part is genuinely real: the manifest's `sha256_hash` **is** the true SHA-256 of the committed `examples/sample_firmware.bin`, and a test recomputes it from the file and asserts equality |
| Policy `signature` | **VERIFIED when configured** — when env `CONTEXT_FABRIC_SIGNING_KEY` is set, pre-flight verifies the context-fabric scheme (HMAC-SHA256 over the canonical body: token without `signature`, JSON sorted keys, compact separators) and **DENIES** on mismatch/missing signature before the guest starts. Without the env var, legacy presence-only behaviour. Verified end-to-end by tests + CLI with the documented dev key `context-fabric-dev-sample-key` (dev key only — production needs asymmetric signing, e.g. Ed25519) |
| MMIO itself | **Simulated** — host-side register dict; no real hardware is touched |
| `rust-scaffold/` (Cargo.toml + `src/main.rs`) | **SCAFFOLD ONLY — never compiled or tested.** This box has `python3 + git` only, no `cargo`/`rustc`. It mirrors the Python logic for the production build |

## Enforcement order (fixed)

Pre-flight, before the guest starts:

0. Signature invalid → **DENY** (only when `CONTEXT_FABRIC_SIGNING_KEY` is
   set; an unauthenticated token's fields cannot be trusted, so this is
   checked first)
1. Token expired → **DENY**
2. `decision != "ALLOW"` → **DENY**

Per MMIO access, inside the host syscalls:

3. Address inside a forbidden region → **TRAP** (the manifest is bedrock and
   overrides policy — a policy that "allows" `FLASH_CONTROLLER` still traps)
4. Address not inside `verified_mmio_ranges` → **TRAP**
5. Peripheral not in policy `allowed_capabilities` → **TRAP**
   (plus: if the policy carries optional `allowed_mmio_ranges`, the address
   must also fall inside one)

## Host syscalls (module `env`)

- `sys_mmio_write(addr: i32, value: i32)`
- `sys_mmio_read(addr: i32) -> i32`

A violating access raises a Wasmtime trap from inside the host import, logging
e.g. `TRAP addr=0x40022000 peripheral=FLASH_CONTROLLER reason=FORBIDDEN_REGION`.

## Run it

```bash
python3 -m venv .venv && .venv/bin/pip install wasmtime
.venv/bin/python tools/build_guests.py          # .wat -> .wasm
.venv/bin/python -m unittest discover -s tests -v   # 13 tests

# CLI demo with a fresh, correctly-signed dev token (context-fabric format)
# and signature enforcement ON:
.venv/bin/python tools/make_dev_token.py --out /tmp/policy_decision.json
CONTEXT_FABRIC_SIGNING_KEY=context-fabric-dev-sample-key \
.venv/bin/python -m software_trust_layer run \
  --manifest examples/firmware_manifest.json \
  --policy   /tmp/policy_decision.json \
  --guest    guests/good_app.wasm     # exit 0 = completed, 2 = trapped, 3 = denied
```

Observed CLI output (2026-10-28, mock manifest + fresh signed dev token,
`CONTEXT_FABRIC_SIGNING_KEY` set):

```
=== GOOD ===
  WRITE addr=0x40010C00 peripheral=GPIOB_LED value=0x00000001 -> OK
  WRITE addr=0x40013800 peripheral=UART1 value=0x00000041 -> OK
  READ  addr=0x40010C00 peripheral=GPIOB_LED value=0x00000001 -> OK
RESULT: COMPLETED guest=good_app.wasm        (exit 0)

=== ROGUE ===
  WRITE addr=0x40010C00 peripheral=GPIOB_LED value=0x00000001 -> OK
RESULT: TRAPPED guest=rogue_app.wasm :: TRAP addr=0x40022000 peripheral=FLASH_CONTROLLER reason=FORBIDDEN_REGION   (exit 2)

=== TAMPERED (user_role flipped after signing) ===
RESULT: DENIED guest=good_app.wasm :: policy signature verification FAILED ...   (exit 3)
```

## Layout

```
software_trust_layer/   Python reference runtime (engine.py + runtime.py + CLI)
guests/                 good_app / rogue_app (.wat source + compiled .wasm)
examples/               MOCK firmware_manifest.json + policy_decision.json
                        + sample_firmware.bin (the manifest's sha256 target)
tests/                  unittest suite (13 tests, all passing)
tools/                  build_guests.py (wat -> wasm), make_dev_token.py
                        (fresh signed dev policy_decision.json)
rust-scaffold/          Rust/Wasmtime scaffold — NOT compiled (no toolchain here)
```
