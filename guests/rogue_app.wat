;; rogue_app — first does one legitimate LED write, then attempts to
;; write the FLASH_CONTROLLER at 0x40022000, which is a forbidden region
;; in the mock manifest. Expected: TRAP on the second access, instance
;; terminated, the third (never reached) write does not execute.
(module
  (import "env" "sys_mmio_write" (func $write (param i32 i32)))
  (import "env" "sys_mmio_read"  (func $read  (param i32) (result i32)))
  (func (export "_start")
    ;; Legitimate: LED on
    (call $write (i32.const 0x40010C00) (i32.const 0x1))
    ;; ROGUE: attempt to unlock/write the flash controller (forbidden)
    (call $write (i32.const 0x40022000) (i32.const 0xDEAD))
    ;; Never reached if the trap works
    (call $write (i32.const 0x40010C00) (i32.const 0x0))))
