//! software-trust-layer — Rust scaffold (NOT YET COMPILED).
//!
//! This mirrors the working Python reference runtime in
//! `../software_trust_layer/` (engine.rs-equivalent logic + Wasmtime host
//! imports). It exists so the production Rust implementation has a faithful
//! starting point. It has NOT been built or tested: the development box has
//! no cargo/rustc. Do not claim otherwise.
//!
//! Enforcement order (identical to the Python reference):
//!   1. token expired            -> deny (guest never starts)
//!   2. decision != "ALLOW"      -> deny (guest never starts)
//!   3. addr in forbidden region -> trap (manifest overrides policy)
//!   4. addr not in verified MMIO ranges -> trap
//!   5. peripheral not in policy allowed_capabilities -> trap

use anyhow::{bail, Result};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Manifest {
    target_architecture: String,
    /// Each entry: [start_hex, end_hex, peripheral_name, access_type]
    verified_mmio_ranges: Vec<(String, String, String, String)>,
    /// Each entry: [start_hex, end_hex, peripheral_name] (or a bare name)
    forbidden_regions: serde_json::Value,
    formal_proof_status: String,
    sha256_hash: String,
}

#[derive(Debug, Deserialize)]
struct Policy {
    decision: String, // "ALLOW" | "DENY"
    user_role: String,
    allowed_capabilities: Vec<String>,
    issued_at: String,  // RFC 3339; parse + compare against expires_at in prod
    expires_at: String, // RFC 3339, short TTL
    signature: String,  // TODO: verification scheme is not in the Phase-1 contract
}

fn parse_hex(s: &str) -> Result<u32> {
    Ok(u32::from_str_radix(s.trim_start_matches("0x"), 16)?)
}

/// Steps 3–5 of the enforcement order. Returns the peripheral name on allow.
fn check_access(manifest: &Manifest, policy: &Policy, addr: u32) -> Result<String> {
    // Step 3: forbidden regions are bedrock — checked before everything else
    // per-access, and they override any policy grant.
    if let Some(regions) = manifest.forbidden_regions.as_array() {
        for r in regions {
            if let Some(range) = r.as_array() {
                if range.len() >= 3 {
                    let start = parse_hex(range[0].as_str().unwrap_or("0"))?;
                    let end = parse_hex(range[1].as_str().unwrap_or("0"))?;
                    if (start..=end).contains(&addr) {
                        bail!("TRAP addr=0x{addr:08X} peripheral={} reason=FORBIDDEN_REGION",
                              range[2].as_str().unwrap_or("UNKNOWN"));
                    }
                }
            }
        }
    }
    // Step 4: must fall inside a verified MMIO range.
    let verified = manifest.verified_mmio_ranges.iter().find(|(s, e, _, _)| {
        let (s, e) = (parse_hex(s).unwrap_or(1), parse_hex(e).unwrap_or(0));
        (s..=e).contains(&addr)
    });
    let peripheral = match verified {
        Some((_, _, name, _)) => name.clone(),
        None => bail!("TRAP addr=0x{addr:08X} peripheral=UNKNOWN reason=NOT_IN_VERIFIED_MMIO_RANGES"),
    };
    // Step 5: policy must grant this peripheral.
    if !policy.allowed_capabilities.contains(&peripheral) {
        bail!("TRAP addr=0x{addr:08X} peripheral={peripheral} reason=PERIPHERAL_NOT_IN_POLICY_ALLOWED_CAPABILITIES");
    }
    Ok(peripheral)
}

fn main() -> Result<()> {
    // TODO (production): steps 1–2 pre-flight (expiry, decision), Wasmtime
    // Linker with host imports `sys_mmio_write` / `sys_mmio_read` in module
    // "env" that call check_access() and raise a Trap on Err, mirroring
    // ../software_trust_layer/runtime.py.
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        bail!("usage: software-trust-layer <firmware_manifest.json> <policy_decision.json> <guest.wasm>");
    }
    let manifest: Manifest = serde_json::from_str(&std::fs::read_to_string(&args[1])?)?;
    let _policy: Policy = serde_json::from_str(&std::fs::read_to_string(&args[2])?)?;
    println!("scaffold: parsed manifest for {}", manifest.target_architecture);
    println!("scaffold: guest {} NOT executed — Rust build is unverified", args[3]);
    Ok(())
}
