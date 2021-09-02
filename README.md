# herast

Rewritten version of [@groke](https://github.com/grokeus)'s [HRAST](https://github.com/sibears/hrast)


## TODO
  - [ ] generating of patterns via selection pseudocode
  - [ ] dynamic reloading of user-scripts
  - [ ] simple form mb for reloader
  - [x] deepexpr
  - [ ] var binding
  - [ ] ctx as custom object (save vars, expressions)
  - [ ] support of all operations

| Operation | Description | Progress |
|-----------|-------------|------|
| cot_comma | `x, y` |Done |
| cot_asg | `x = y` |Done |
| cot_asgbor | `x \|= y` | Done|
| cot_asgxor | `x ^= y` | Done|
| cot_asgband | `x &= y` |Done |
| cot_asgadd | `x += y` |Done|
| cot_asgsub | `x -= y` | Done|
| cot_asgmul | `x *= y` | Done|
| cot_asgsshr | `x >>= y signed` |Done |
| cot_asgushr | `x >>= y unsigned` | Done|
| cot_asgshl | `x <<= y` | Done|
| cot_asgsdiv | `x /= y signed` |Done |
| cot_asgudiv | `x /= y unsigned` | Done|
| cot_asgsmod | `x %= y signed` | Done|
| cot_asgumod | `x %= y unsigned` | Done|
| cot_tern | `x ? y : z` | |
| cot_lor | `x \|\| y` | Done|
| cot_land | `x && y` | Done|
| cot_bor | `x \| y` | Done|
| cot_xor | `x ^ y` | Done|
| cot_band | `x & y` | Done|
| cot_eq | `x == y int or fpu (see EXFL_FPOP)` | Done|
| cot_ne | `x != y int or fpu (see EXFL_FPOP)` | Done|
| cot_sge | `x >= y signed or fpu (see EXFL_FPOP)` | Done|
| cot_uge | `x >= y unsigned` | Done|
| cot_sle | `x <= y signed or fpu (see EXFL_FPOP)` |Done |
| cot_ule | `x <= y unsigned` | Done|
| cot_sgt | `x > y signed or fpu (see EXFL_FPOP)` | Done|
| cot_ugt | `x > y unsigned` | Done|
| cot_slt | `x < y signed or fpu (see EXFL_FPOP)` | Done|
| cot_ult | `x < y unsigned` | Done|
| cot_sshr | `x >> y signed` | Done|
| cot_ushr | `x >> y unsigned` | Done|
| cot_shl | `x << y` | Done|
| cot_add | `x + y` | Done|
| cot_sub | `x - y` | Done|
| cot_mul | `x * y` | Done|
| cot_sdiv | `x / y signed` | Done|
| cot_udiv | `x / y unsigned` | Done|
| cot_smod | `x % y signed` | Done|
| cot_umod | `x % y unsigned` | Done|
| cot_fadd | `x + y fp` | Done|
| cot_fsub | `x - y fp` | Done|
| cot_fmul | `x * y fp` | Done|
| cot_fdiv | `x / y fp` | Done|
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
| cot_call | `x(...)` | Done|
| cot_idx | `x[y]` | Done|
| cot_memref | `x.m` | |
| cot_memptr | `x->m, access size in 'ptrsize'` | |
| cot_num | `n` | |
| cot_fnum | `fpc` | |
| cot_str | `string constant` | |
| cot_obj | `obj_ea` | Done|
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
