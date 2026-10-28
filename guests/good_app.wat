;; good_app — touches ONLY allowed peripherals (GPIOB_LED + UART1),
;; both verified in the mock manifest AND granted by the mock policy.
;; Expected: completes.
(module
  (import "env" "sys_mmio_write" (func $write (param i32 i32)))
  (import "env" "sys_mmio_read"  (func $read  (param i32) (result i32)))
  (func (export "_start")
    ;; LED on: write 0x1 to GPIOB_LED register at 0x40010C00
    (call $write (i32.const 0x40010C00) (i32.const 0x1))
    ;; UART1: write byte 'A' (0x41) to data register at 0x40013800
    (call $write (i32.const 0x40013800) (i32.const 0x41))
    ;; Read the LED register back (allowed read)
    (drop (call $read (i32.const 0x40010C00)))))
