# Rust scaffold — NOT compiled, NOT tested

This directory is a **scaffold only**. The development box has `python3 + git`
and **no cargo/rustc**, so this code has never been built or run.

It mirrors the working Python reference runtime (`../software_trust_layer/`):
same JSON contract, same enforcement order, same host-import names, using the
`wasmtime` crate. Treat it as the starting point for the production build on a
machine with a Rust toolchain — expect to fix compile errors on first build.
