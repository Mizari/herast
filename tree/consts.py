import idaapi

# [NOTE]: Actual for 7.6
op2str = {
    0: 'cot_empty', 1: 'cot_comma', 2: 'cot_asg', 
    3: 'cot_asgbor', 4: 'cot_asgxor', 5: 'cot_asgband', 
    6: 'cot_asgadd', 7: 'cot_asgsub', 8: 'cot_asgmul', 
    9: 'cot_asgsshr', 10: 'cot_asgushr', 11: 'cot_asgshl',
    12: 'cot_asgsdiv', 13: 'cot_asgudiv', 14: 'cot_asgsmod',
    15: 'cot_asgumod', 16: 'cot_tern', 17: 'cot_lor',
    18: 'cot_land', 19: 'cot_bor', 20: 'cot_xor',
    21: 'cot_band', 22: 'cot_eq', 23: 'cot_ne',
    24: 'cot_sge', 25: 'cot_uge', 26: 'cot_sle',
    27: 'cot_ule', 28: 'cot_sgt', 29: 'cot_ugt',
    30: 'cot_slt', 31: 'cot_ult', 32: 'cot_sshr',
    33: 'cot_ushr', 34: 'cot_shl', 35: 'cot_add',
    36: 'cot_sub', 37: 'cot_mul', 38: 'cot_sdiv', 
    39: 'cot_udiv', 40: 'cot_smod', 41: 'cot_umod', 
    42: 'cot_fadd', 43: 'cot_fsub', 44: 'cot_fmul', 
    45: 'cot_fdiv', 46: 'cot_fneg', 47: 'cot_neg', 
    48: 'cot_cast', 49: 'cot_lnot', 50: 'cot_bnot', 
    51: 'cot_ptr', 52: 'cot_ref', 53: 'cot_postinc', 
    54: 'cot_postdec', 55: 'cot_preinc', 56: 'cot_predec', 
    57: 'cot_call', 58: 'cot_idx', 59: 'cot_memref', 
    60: 'cot_memptr', 61: 'cot_num', 62: 'cot_fnum', 
    63: 'cot_str', 64: 'cot_obj', 65: 'cot_var', 
    66: 'cot_insn', 67: 'cot_sizeof', 68: 'cot_helper', 
    69: 'cot_type', 70: 'cit_empty', 71: 'cit_block', 
    72: 'cit_expr', 73: 'cit_if', 74: 'cit_for', 
    75: 'cit_while', 76: 'cit_do', 77: 'cit_switch', 
    78: 'cit_break', 80: 'cit_return', 81: 'cit_goto', 82: 'cit_asm'
}

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
     idaapi.cot_ref, idaapi.cot_postinc, idaapi.cot_postdec, idaapi.cot_preinc, idaapi.cot_predec, idaapi.sizeof
]

# [NOTE]: Actual for 7.6
str2op = {
	'cot_empty': 0, 'cot_comma': 1, 'cot_asg': 2, 'cot_asgbor': 3, 'cot_asgxor': 4, 'cot_asgband': 5,
	'cot_asgadd': 6, 'cot_asgsub': 7, 'cot_asgmul': 8, 'cot_asgsshr': 9, 'cot_asgushr': 10,
	'cot_asgshl': 11, 'cot_asgsdiv': 12, 'cot_asgudiv': 13, 'cot_asgsmod': 14, 'cot_asgumod': 15,
	'cot_tern': 16, 'cot_lor': 17, 'cot_land': 18, 'cot_bor': 19, 'cot_xor': 20, 'cot_band': 21,
	'cot_eq': 22, 'cot_ne': 23, 'cot_sge': 24, 'cot_uge': 25, 'cot_sle': 26, 'cot_ule': 27,
	'cot_sgt': 28, 'cot_ugt': 29, 'cot_slt': 30, 'cot_ult': 31, 'cot_sshr': 32, 'cot_ushr': 33,
	'cot_shl': 34, 'cot_add': 35, 'cot_sub': 36, 'cot_mul': 37, 'cot_sdiv': 38, 'cot_udiv': 39,
	'cot_smod': 40, 'cot_umod': 41, 'cot_fadd': 42, 'cot_fsub': 43, 'cot_fmul': 44, 'cot_fdiv': 45,
	'cot_fneg': 46, 'cot_neg': 47, 'cot_cast': 48, 'cot_lnot': 49, 'cot_bnot': 50, 'cot_ptr': 51,
	'cot_ref': 52, 'cot_postinc': 53, 'cot_postdec': 54, 'cot_preinc': 55, 'cot_predec': 56,
	'cot_call': 57, 'cot_idx': 58, 'cot_memref': 59, 'cot_memptr': 60, 'cot_num': 61, 'cot_fnum': 62,
	'cot_str': 63, 'cot_obj': 64, 'cot_var': 65, 'cot_insn': 66, 'cot_sizeof': 67, 'cot_helper': 68,
	'cot_type': 69, 'cit_empty': 70, 'cit_block': 71, 'cit_expr': 72, 'cit_if': 73, 'cit_for': 74,
	'cit_while': 75, 'cit_do': 76, 'cit_switch': 77, 'cit_break': 78, 'cit_return': 80, 'cit_goto': 81, 'cit_asm': 82
}


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