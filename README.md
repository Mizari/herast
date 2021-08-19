# herast

## TODO
  - [ ] generating of patterns via selection pseudocode
  - [ ] dynamic reloading of user-scripts
  - [ ] simple form mb for reloader
  - [ ] deepexpr
  - [ ] support of all operations

| Operation | Description | Done |
|-----------|-------------|------|
| cot_comma | `x, y` | |
| cot_asg | `x = y` | |
| cot_asgbor | `x \|= y` | |
| cot_asgxor | `x ^= y` | |
| cot_asgband | `x &= y` | |
| cot_asgadd | `x += y` | |
| cot_asgsub | `x -= y` | |
| cot_asgmul | `x *= y` | |
| cot_asgsshr | `x >>= y signed` | |
| cot_asgushr | `x >>= y unsigned` | |
| cot_asgshl | `x <<= y` | |
| cot_asgsdiv | `x /= y signed` | |
| cot_asgudiv | `x /= y unsigned` | |
| cot_asgsmod | `x %= y signed` | |
| cot_asgumod | `x %= y unsigned` | |
| cot_tern | `x ? y : z` | |
| cot_lor | `x \|\| y` | |
| cot_land | `x && y` | |
| cot_bor | `x \| y` | |
| cot_xor | `x ^ y` | |
| cot_band | `x & y` | |
| cot_eq | `x == y int or fpu (see EXFL_FPOP)` | |
| cot_ne | `x != y int or fpu (see EXFL_FPOP)` | |
| cot_sge | `x >= y signed or fpu (see EXFL_FPOP)` | |
| cot_uge | `x >= y unsigned` | |
| cot_sle | `x <= y signed or fpu (see EXFL_FPOP)` | |
| cot_ule | `x <= y unsigned` | |
| cot_sgt | `x > y signed or fpu (see EXFL_FPOP)` | |
| cot_ugt | `x > y unsigned` | |
| cot_slt | `x < y signed or fpu (see EXFL_FPOP)` | |
| cot_ult | `x < y unsigned` | |
| cot_sshr | `x >> y signed` | |
| cot_ushr | `x >> y unsigned` | |
| cot_shl | `x << y` | |
| cot_add | `x + y` | |
| cot_sub | `x - y` | |
| cot_mul | `x * y` | |
| cot_sdiv | `x / y signed` | |
| cot_udiv | `x / y unsigned` | |
| cot_smod | `x % y signed` | |
| cot_umod | `x % y unsigned` | |
| cot_fadd | `x + y fp` | |
| cot_fsub | `x - y fp` | |
| cot_fmul | `x * y fp` | |
| cot_fdiv | `x / y fp` | |
| cot_fneg | `-x fp` | |
| cot_neg | `-x` | |
| cot_cast | `(type)x` | |
| cot_lnot | `!x` | |
| cot_bnot | `~x` | |
| cot_ptr | `*x, access size in 'ptrsize'` | |
| cot_ref | `&x` | |
| cot_postinc | `x++` | |
| cot_postdec | `x–` | |
| cot_preinc | `++x` | |
| cot_predec | `–x` | |
| cot_call | `x(...)` | |
| cot_idx | `x[y]` | |
| cot_memref | `x.m` | |
| cot_memptr | `x->m, access size in 'ptrsize'` | |
| cot_num | `n` | |
| cot_fnum | `fpc` | |
| cot_str | `string constant` | |
| cot_obj | `obj_ea` | |
| cot_var | `v` | |
| cot_insn | `instruction in expression, internal representation only` | |
| cot_sizeof | `sizeof(x)` | |
| cot_helper | `arbitrary name` | |
| cot_type | `arbitrary type` | |
| cit_empty | `instruction types start here` | Done|
| cit_block | `block-statement: { ... }` |Done |
| cit_expr | `expression-statement: expr;` |Done |
| cit_if | `if-statement` | Done|
| cit_for | `for-statement` | Done|
| cit_while | `while-statement` |Done |
| cit_do | `do-statement` |Done |
| cit_switch | `switch-statement` | Done|
| cit_break | `break-statement` | Done|
| cit_continue | `continue-statement` | Done |
| cit_return | `return-statement` | Done|
| cit_goto | `goto-statement` | Done|
| cit_asm | `asm-statement` | Done |
