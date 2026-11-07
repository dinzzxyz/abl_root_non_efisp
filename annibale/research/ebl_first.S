// Disassembly listing for review; use plan_ebl_first.py to generate authoritative bytes.
// New hook program only; placement is QcomBds RVA 0x1C900.
// Calls are to existing helper RVA 0x7D2C. This is not a complete EFI image.
// 0x1c900 fd7bbea9
  stp x29, x30, [sp, #-0x20]!
// 0x1c904 f35301a9
  stp x19, x20, [sp, #0x10]
// 0x1c908 f30300aa
  mov x19, x0
// 0x1c90c f40301aa
  mov x20, x1
// 0x1c910 000000b0
  adrp x0, #0x1d000
// 0x1c914 00e00391
  add x0, x0, #0xf8
// 0x1c918 41010010
  adr x1, #0x1c940
// 0x1c91c e2031faa
  mov x2, xzr
// 0x1c920 03adff97
  bl #0x7d2c
// 0x1c924 e00313aa
  mov x0, x19
// 0x1c928 e10314aa
  mov x1, x20
// 0x1c92c e2031faa
  mov x2, xzr
// 0x1c930 ffacff97
  bl #0x7d2c
// 0x1c934 f35341a9
  ldp x19, x20, [sp, #0x10]
// 0x1c938 fd7bc2a8
  ldp x29, x30, [sp], #0x20
// 0x1c93c c0035fd6
  ret
// RVA 0x1C940: UTF-16LE "Ebl\0"
.byte 0x45,0,0x62,0,0x6c,0,0,0
