"""Wasmtime sandbox runtime for Layer 3.

Executes a real Wasm guest with two host-imported syscalls in module ``env``:

    sys_mmio_write(addr: i32, value: i32)
    sys_mmio_read(addr: i32) -> i32

Every access is checked by CapabilityEngine. A violation raises a Wasmtime
Trap from inside the host import, which terminates the Wasm instance.
MMIO state is a host-side dict (no real hardware is touched).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from wasmtime import Func, FuncType, Instance, Linker, Module, Store, Trap, ValType

from .engine import CapabilityEngine, CapabilityTrap, PolicyDenied


@dataclass
class RunResult:
    status: str  # "completed" | "trapped" | "denied"
    accesses: list[str] = field(default_factory=list)
    trap: str | None = None
    detail: str | None = None


class Sandbox:
    def __init__(self, engine: CapabilityEngine):
        self.engine = engine
        self.registers: dict[int, int] = {}

    def run(self, wasm: bytes) -> RunResult:
        # Pre-flight first: an expired / DENY policy never starts the guest.
        try:
            self.engine.check_preflight()
        except PolicyDenied as e:
            return RunResult(status="denied", detail=str(e))

        accesses: list[str] = []
        pending_trap: list[CapabilityTrap] = []

        store = Store()
        linker = Linker(store.engine)
        i32 = ValType.i32()

        def _addr(a: int) -> int:
            return a & 0xFFFFFFFF

        def sys_mmio_write(addr: int, value: int) -> None:
            addr = _addr(addr)
            try:
                peripheral = self.engine.check_access(addr)
            except CapabilityTrap as e:
                pending_trap.append(e)
                raise Trap(str(e)) from e
            self.registers[addr] = value & 0xFFFFFFFF
            accesses.append(f"WRITE addr=0x{addr:08X} peripheral={peripheral} "
                            f"value=0x{value & 0xFFFFFFFF:08X} -> OK")

        def sys_mmio_read(addr: int) -> int:
            addr = _addr(addr)
            try:
                peripheral = self.engine.check_access(addr)
            except CapabilityTrap as e:
                pending_trap.append(e)
                raise Trap(str(e)) from e
            value = self.registers.get(addr, 0)
            accesses.append(f"READ  addr=0x{addr:08X} peripheral={peripheral} "
                            f"value=0x{value:08X} -> OK")
            return value

        linker.define(store, "env", "sys_mmio_write",
                      Func(store, FuncType([i32, i32], []), sys_mmio_write))
        linker.define(store, "env", "sys_mmio_read",
                      Func(store, FuncType([i32], [i32]), sys_mmio_read))

        module = Module(store.engine, wasm)
        instance = linker.instantiate(store, module)
        start = instance.exports(store).get("_start")
        if start is None:
            return RunResult(status="denied", accesses=accesses,
                             detail="guest exports no _start function")
        try:
            start(store)
        except Trap as e:
            trap_msg = str(pending_trap[0]) if pending_trap else str(e)
            return RunResult(status="trapped", accesses=accesses, trap=trap_msg)
        return RunResult(status="completed", accesses=accesses)
