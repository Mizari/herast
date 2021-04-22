import idaapi
import logging, sys
import autologging

logging.basicConfig(level=autologging.TRACE, stream=sys.stdout,format="[%(levelname)s] %(name)s:%(funcName)s:%(message)s")




DEBUG_PRINT_ENABLED = True
def debug_print(*args):
    if DEBUG_PRINT_ENABLED:
        print("[DEBUG]", *args)

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


@autologging.traced("__assert", exclude=True)
class TreeProcessor:

    def __init__(self, cfunc):
        self.function_tree = cfunc
        self.context = None

        self.op2func = {
            # str2op['cot_insn']: self._process_cinsn, # guess this will never happen at this level of analysis, so there is no need in handler of cinsn
            str2op['cit_expr']: self._process_cexpr,

            str2op['cit_return']: self._process_creturn,
            str2op['cit_block']: self._process_cblock,
            str2op['cit_if']: self._process_cif,
            str2op['cit_while']: self._process_cwhile,
            str2op['cit_do']: self._process_cdo,
            str2op['cit_for']: self._process_cfor,
            str2op['cit_goto']: self._process_cgoto,
            str2op['cit_asm']: self._process_casm
        }
        
    
    def __assert(self, cond, msg=""):
        assert cond, "%s: %s" % (self.__class__.__name__, msg)

    def traverse_function_tree(self):
        function_body = self.function_tree.body

        self.__assert(isinstance(function_body, idaapi.cinsn_t), "Function body is not cinsn_t")
        self.__assert(isinstance(function_body.cblock, idaapi.cblock_t), "Function body must be a cblock_t")

        # print(function_body.cblock)

        self._process_cblock(function_body.cblock)
    

    def _process_cblock(self, cblock):
        # [NOTE] cblock is just an array of cinsn_t (qlist<cinsn_t>)
        for ins in cblock:
            # self._process_cinsn(ins)
            self.op2func[ins.op](ins)

    def _process_cexpr(self, cinsn):
        cexpr = cinsn.cexpr

        debug_print("Expression: %s" % cexpr)

    def _process_cinsn(self, cinsn):
        union = ["cblock", "cexpr", "cif", "cfor", "cwhile", "cdo", "cswitch", "creturn", "cgoto", "casm"]
        for possible_type in union:
            attr = getattr(cinsn, possible_type)
            if attr is not None:
                debug_print(attr, op2str[cinsn.op])
                return attr


    def _process_creturn(self, cinsn):
        # [NOTE] as i understand, creturn just a cexpr_t nested inside of creturn_t
        creturn = cinsn.creturn

        debug_print("return: %s", creturn.expr)
        return creturn.expr


    def _process_cif(self, cinsn):
        # [NOTE] cif has ithen<cinsn_t>, ielse<cinsn_t> and expr<cexpr_t>
        cif = cinsn.cif

        debug_print(cif)
        debug_print('if condition: %s' % cif)
        debug_print('if then branch: %s' % cif.ithen)
        debug_print('if else branch: %s' % cif.ielse)

    
    def _process_cfor(self, cinsn):
        cfor = cinsn.cfor
        pass

    def _process_cwhile(self, cinsn):
        cwhile = cinsn.cwhile
        pass

    def _process_cdo(self, cinsn):
        cdo = cinsn.cdo
        pass

    def _process_cswitch(self, cinsn):
        cswitch = cinsn.cswitch
        pass

    def _process_cgoto(self, cinsn):
        cgoto = cinsn.cgoto
        pass

    def _process_casm(self, cinsn):
        casm = cinsn.casm
        pass