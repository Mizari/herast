import idaapi

cexpr_op2str = dict(idaapi.cexpr_t.op_to_typename)
cinsn_op2str = dict(idaapi.cinsn_t.op_to_typename)
op2str = {}
op2str.update(cexpr_op2str)
op2str.update(cinsn_op2str)


binary_expressions_ops = [
	idaapi.cot_comma, idaapi.cot_asg, idaapi.cot_asgbor, idaapi.cot_asgxor, idaapi.cot_asgband,
	idaapi.cot_asgadd, idaapi.cot_asgsub, idaapi.cot_asgmul, idaapi.cot_asgsshr, idaapi.cot_asgushr,
	idaapi.cot_asgshl, idaapi.cot_asgsdiv, idaapi.cot_asgudiv, idaapi.cot_asgsmod, idaapi.cot_asgumod,
	idaapi.cot_lor, idaapi.cot_land, idaapi.cot_bor, idaapi.cot_xor, idaapi.cot_band, idaapi.cot_eq,
	idaapi.cot_ne, idaapi.cot_sge, idaapi.cot_uge, idaapi.cot_sle, idaapi.cot_ule, idaapi.cot_sgt,
	idaapi.cot_ugt, idaapi.cot_slt, idaapi.cot_ult, idaapi.cot_sshr, idaapi.cot_ushr, idaapi.cot_shl,
	idaapi.cot_add, idaapi.cot_sub, idaapi.cot_mul, idaapi.cot_sdiv, idaapi.cot_udiv, idaapi.cot_smod,
	idaapi.cot_umod, idaapi.cot_fadd, idaapi.cot_fsub, idaapi.cot_fmul, idaapi.cot_fdiv, idaapi.cot_idx
]

unary_expressions_ops = [
	idaapi.cot_fneg, idaapi.cot_neg, idaapi.cot_cast, idaapi.cot_lnot, idaapi.cot_bnot, idaapi.cot_ptr,
	idaapi.cot_ref, idaapi.cot_postinc, idaapi.cot_postdec, idaapi.cot_preinc, idaapi.cot_predec, idaapi.cot_sizeof,
	idaapi.cot_memref, idaapi.cot_memptr,
]

str2op = {v:k for k, v in op2str.items()}


# [NOTE]: Actual for 7.6
class HR_EVENT:
	HXE_FLOWCHART               = 0
	HXE_STKPNTS                 = 1
	HXE_PROLOG                  = 2
	HXE_MICROCODE               = 3
	HXE_PREOPTIMIZED            = 4
	HXE_LOCOPT                  = 5
	HXE_PREALLOC                = 6
	HXE_GLBOPT                  = 7
	HXE_STRUCTURAL              = 8
	HXE_MATURITY                = 9
	HXE_INTERR                  = 10
	HXE_COMBINE                 = 11
	HXE_PRINT_FUNC              = 12
	HXE_FUNC_PRINTED            = 13
	HXE_RESOLVE_STKADDRS        = 14
	HXE_OPEN_PSEUDOCODE         = 100
	HXE_SWITCH_PSEUDOCODE       = 101
	HXE_REFRESH_PSEUDOCODE      = 102
	HXE_CLOSE_PSEUDOCODE        = 103
	HXE_KEYBOARD                = 104
	HXE_RIGHT_CLICK             = 105
	HXE_DOUBLE_CLICK            = 106
	HXE_CURPOS                  = 107
	HXE_CREATE_HINT             = 108
	HXE_TEXT_READY              = 109
	HXE_POPULATING_POPUP        = 110
	LXE_LVAR_NAME_CHANGED       = 111
	LXE_LVAR_TYPE_CHANGED       = 112
	LXE_LVAR_CMT_CHANGED        = 113
	LXE_LVAR_MAPPING_CHANGED    = 114
	HXE_CMT_CHANGED             = 115

# [NOTE]: Actual for 7.6
class CMAT_LEVEL:
	ZERO    = 0
	BUILT   = 1
	TRANS1  = 2
	NICE    = 3
	TRANS2  = 4
	CPA     = 5
	TRANS3  = 6
	CASTED  = 7
	FINAL   = 8