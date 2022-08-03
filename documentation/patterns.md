# Writing patterns
Patterns describe parts of ASTs. To get a better view what AST looks like we recommend using [HRDevHelper](https://github.com/patois/HRDevHelper/).
Herast's patterns are divided into following groups:
- [expressions](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py)
- [instructions](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/instructions.py)
- [abstracts](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/abstracts.py)
- [helpers](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/helpers.py)

There is also a base pattern for all of them: [BasePat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/base_pattern.py). It has useful options like skip_casts for ignoring type castings and debug for troubleshooting patterns.


# If example
<p align='center'>
<img src='https://github.com/mostobriv/herast/blob/main/pictures/if_example.png'>
<img src='https://github.com/mostobriv/herast/blob/main/pictures/if_ast_example.png'>
</p>  
  
Pattern for this AST code will look like this:
```
IfPat(
	ObjPat("debug_on"),
	CallInsnPat(
		ObjPat("printf"),
		AnyPat(),
		StrPat(),
		AnyPat(),
	)
)
```
Notice how there is no need for BlockPat around CallPat, since it is only 1 instruction. Also notice CallInsnPat instead of ExprInsPat(CallPat(...)).

# Struct field access example
<p align='center'>
<img src='https://github.com/mostobriv/herast/blob/main/pictures/struct_field_access_example.png'>
<img src='https://github.com/mostobriv/herast/blob/main/pictures/struct_field_access_ast_example.png'>
</p>  
  
Pattern for this AST code will look like this:
```
AsgPat(
	StructFieldAccessPat("struct_1", 0x60),
	CallPat("calloc", AnyPat(), AnyPat()),
)
```
Notice lack of type casting, since skip_casts is turned on by default in base pattern. Also no ObjPat inside CallPat.

# Patterns table
Most of the patterns developed according to HexRays [ctype_t](https://hex-rays.com/products/decompiler/manual/sdk/hexrays_8hpp.shtml#a8fff5d4d0a6974af5b5aa3feeebab2a0)

| Pattern class                                                                                        | ctree item code | pseudocode                                                                                      |
|------------------------------------------------------------------------------------------------------|-----------------|-------------------------------------------------------------------------------------------------|
| [AsgPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L265)     | cot_asg         | `x = y`                                                                                         |
| [AsgborPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L243)  | cot_asgbor      | `x \|= y`                                                                                       |
| [AsgxorPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L243)  | cot_asgxor      | `x ^= y`                                                                                        |
| [AsgbandPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L243) | cot_asgband     | `x &= y`                                                                                        |
| [AsgaddPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L243)  | cot_asgadd      | `x += y`                                                                                        |
| [AsgsubPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L243)  | cot_asgsub      | `x -= y`                                                                                        |
| [AsgmulPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L243)  | cot_asgmul      | `x *= y`                                                                                        |
| [AsgsshrPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L243) | cot_asgsshr     | `x >>= y signed`                                                                                |
| [AsgushrPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L243) | cot_asgushr     | `x >>= y unsigned`                                                                              |
| [AsgshlPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L243)  | cot_asgshl      | `x <<= y`                                                                                       |
| [AsgsdivPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L243) | cot_asgsdiv     | `x /= y signed`                                                                                 |
| [AsgudivPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L243) | cot_asgudiv     | `x /= y unsigned`                                                                               |
| [AsgsmodPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L243) | cot_asgsmod     | `x %= y signed`                                                                                 |
| [AsgumodPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L243) | cot_asgumod     | `x %= y unsigned`                                                                               |
| [TernPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L199)    | cot_tern        | `x ? y : z`                                                                                     |
| [LorPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L243)     | cot_lor         | `x \|\| y`                                                                                      |
| [LandPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L243)    | cot_land        | `x && y`                                                                                        |
| [BorPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L243)     | cot_bor         | `x \| y`                                                                                        |
| [XorPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L243)     | cot_xor         | `x ^ y`                                                                                         |
| [BandPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L243)    | cot_band        | `x & y `                                                                                        |
| [EqPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L243)      | cot_eq          | `x == y int or fpu (see EXFL_FPOP)`                                                             |
| [NePat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L243)      | cot_ne          | `x != y int or fpu (see EXFL_FPOP)`                                                             |
| [SgePat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L243)     | cot_sge         | `x >= y signed or fpu (see EXFL_FPOP)`                                                          |
| [UgePat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L243)     | cot_uge         | `x >= y unsigned`                                                                               |
| [SlePat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L243)     | cot_sle         | `x <= y signed or fpu (see EXFL_FPOP)`                                                          |
| [UlePat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L243)     | cot_ule         | `x <= y unsigned`                                                                               |
| [SgtPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L243)     | cot_sgt         | `x > y signed or fpu (see EXFL_FPOP)`                                                           |
| [UgtPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L243)     | cot_ugt         | `x > y unsigned`                                                                                |
| [SltPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L243)     | cot_slt         | `x < y signed or fpu (see EXFL_FPOP)`                                                           |
| [UltPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L243)     | cot_ult         | `x < y unsigned`                                                                                |
| [SshrPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L243)    | cot_sshr        | `x >> y signed`                                                                                 |
| [UshrPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L243)    | cot_ushr        | `x >> y unsigned`                                                                               |
| [ShlPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L243)     | cot_shl         | `x << y`                                                                                        |
| [AddPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L243)     | cot_add         | `x + y`                                                                                         |
| [SubPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L243)     | cot_sub         | `x - y`                                                                                         |
| [MulPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L243)     | cot_mul         | `x * y`                                                                                         |
| [SdivPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L243)    | cot_sdiv        | `x / y signed`                                                                                  |
| [UdivPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L243)    | cot_udiv        | `x / y unsigned`                                                                                |
| [SmodPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L243)    | cot_smod        | `x % y signed`                                                                                  |
| [UmodPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L243)    | cot_umod        | `x % y unsigned`                                                                                |
| [FaddPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L243)    | cot_fadd        | `x + y fp`                                                                                      |
| [FsubPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L243)    | cot_fsub        | `x - y fp`                                                                                      |
| [FmulPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L243)    | cot_fmul        | `x * y fp` |
| [FdivPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L243)    | cot_fdiv        | `x / y fp`                                                                                      |
| [FnegPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L228)    | cot_fneg        | `-x fp`                                                                                         |
| [NegPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L228)     | cot_neg         | `-x`                                                                                            |
| [CastPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L228)    | cot_cast        | `(type)x`                                                                                       |
| [LnotPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L228)    | cot_lnot        | `!x`                                                                                            |
| [BnotPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L228)    | cot_bnot        | `~x`                                                                                            |
| [PtrPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L228)     | cot_ptr         | `*x, access size in 'ptrsize'`                                                                   |
| [RefPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L228)     | cot_ref         | `&x`                                                                                            |
| [PostincPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L228) | cot_postinc     | `x++`                                                                                           |
| [PostdecPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L228) | cot_postdec     | `x–`                                                                                            |
| [PreincPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L228)  | cot_preinc      | `++x`                                                                                           |
| [PredecPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L228)  | cot_predec      | `–x `                                                                                           |
| [CallPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L22)     | cot_call        | `x(...)`                                                                                        |
| [IdxPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L243)     | cot_idx         | `x[y]`                                                                                          |
| [MemrefPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L169)  | cot_memref      | `x.m`                                                                                           |
| [MemptrPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L184)  | cot_memptr      | `x->m, access size in 'ptrsize'`                                                                 |
| [NumPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L85)      | cot_num         | `n`                                                                                             |
| TODO: FnumPat                                                                                        | cot_fnum        | `fpc`                                                                                           |
| TODO: StrPat                                                                                         | cot_str         | `string constant`                                                                               |
| [ObjPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L101)     | cot_obj         | `obj_ea`                                                                                        |
| [VarPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L216)     | cot_var         | `v`                                                                                             |
| [SizeofPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L228)  | cot_sizeof      | `sizeof(x)`                                                                                     |
| [HelperPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py#L68)   | cot_helper      | `arbitrary name`                                                                                |
| TODO: TypePat                                                                                        | cot_type        | `arbitrary type `                                                                               |
| [BlockPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/instructions.py#L14)   | cit_block       | `{ .. block .. }`               |
| [IfPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/instructions.py#L55)      | cit_if          | `if (...) { ... } else { ... }` |
| [ForPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/instructions.py#L100)    | cit_for         | `for (...) { ... }`             |
| [WhilePat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/instructions.py#L144)  | cit_while       | `while (...) { ... }`           |
| [DoPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/instructions.py#L165)     | cit_do          | `do { ... } while (...)`        |
| TODO: SwitchPat                                                                                      | cit_switch      | `switch (...) { ... }`          |
| TODO: BreakPat                                                                                       | cit_break       | `break;`                        |
| TODO: ContinuePat                                                                                    | cit_continue    | `continue;`                     |
| [RetPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/instructions.py#L125)    | cit_ret         | `return;`                       |
| [GotoPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/instructions.py#L186)   | cit_goto        | `goto XXX;`                     |
| TODO: AsmPat                                                                                         | cit_asm         | `__asm { ... }`                 |
| [ExprInsPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/instructions.py#L38) | cit_expr        | `expression;`                   |
| [AnyPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/abstracts.py#L8)         | -               | `matches any ast-node`          |
| [OrPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/abstracts.py#L24)         | -               | `matches if one of provided patterns is matches`       |
| [RemovePat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/abstracts.py#L123)    | -               | `remove ast node if it matches provided patterns` |
| [BindItemPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/abstracts.py#L65)   | -               | `save ast-node in context if it matches to provided pattern`|
| [VarBindPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/abstracts.py#L85)    | -               | `save var in context if node is matched to provided pattern` |
| [DeepExprPat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/abstracts.py#L104)  | -               | `save ast-node in context if its matched to provided pattern somewhere inside of subtree` |
