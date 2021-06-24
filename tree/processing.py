from __future__ import print_function
import idaapi

idaapi.require('tree.consts')

from tree.consts import binary_expressions_ops, unary_expressions_ops, op2str, str2op


DEBUG_PRINT_ENABLED = False
def debug_print(*args, **kwargs):
    message = None
    try:
        message = kwargs['message']
    except KeyError:
        message = 'DEBUG'
    
    if DEBUG_PRINT_ENABLED:
        _args = args
        print("[%s]" % message, *_args)


def trace_method(method):
    import functools

    @functools.wraps(method)
    def method_wrapper(*args, **kwargs):
        insn = args[1]
        debug_print('%s   CALL: %s(%#x)' % (method.__name__, insn, insn.ea), message='TRACE')
        result = method(*args, **kwargs)
        debug_print('%s RETURN: %s' % (method.__name__, result), message='TRACE')

        return result
    return method_wrapper


class TreeProcessor:

    def __init__(self, cfunc, matcher):
        self.function_tree = cfunc
        self.matcher = matcher
        self.need_expression_traversal = matcher.has_deep_expressions()

        self.op2func = {i:self.__stub for i in range(100)}

        self.op2func.update({
            idaapi.cit_expr: self._process_cexpr,
            idaapi.cit_empty: self.__stub,
            idaapi.cit_break: self.__stub,
            idaapi.cit_return: self._process_creturn,
            idaapi.cit_block: self._process_cblock,
            idaapi.cit_if: self._process_cif,
            idaapi.cit_switch: self._process_cswitch,
            idaapi.cit_while: self._process_cwhile,
            idaapi.cit_do: self._process_cdo,
            idaapi.cit_for: self._process_cfor,
            idaapi.cit_goto: self.__stub,
            idaapi.cit_asm: self.__stub
        })

        for i in unary_expressions_ops:
            self.op2func[i] = self._process_unary_expr

        for i in binary_expressions_ops:
            self.op2func[i] = self._process_binary_expr

        self.op2func.update({
            idaapi.cot_call: self._process_call_expr
        })
    
    def __assert(self, cond, msg=""):
        assert cond, "%s: %s" % (self.__class__.__name__, msg)

    def process_function(self) -> None:
        function_body = self.function_tree.body

        self.__assert(isinstance(function_body, idaapi.cinsn_t), "Function body is not cinsn_t")
        self.__assert(isinstance(function_body.cblock, idaapi.cblock_t), "Function body must be a cblock_t")

        self._process_cblock(function_body)

    def __stub(*args, **kwargs) -> None:
        pass

    @trace_method
    def _process_cblock(self, cinsn) -> None:
        # [NOTE] cblock is just an array of cinsn_t (qlist<cinsn_t>)
        cblock = cinsn.cblock
        self.matcher.check_patterns(cinsn)

        try:
            for ins in cblock:
                self.op2func[ins.op](ins)

        except KeyError:
            raise KeyError("Handler for %s is not setted" % op2str[ins.op])

    @trace_method
    def _process_cexpr(self, cinsn) -> None:
        # This is kinda tricky, cuz sometimes we calling process_cexpr w/ cinsn_t and sometimes w/ cexpr_t
        # but as cexpr_t also has cexpr member, so it works
        cexpr = cinsn.cexpr
        self.matcher.check_patterns(cinsn)

        if self.need_expression_traversal:
            self.op2func[cexpr.op](cexpr)


    @trace_method
    def _process_creturn(self, cinsn) -> None:
        # [NOTE] as i understand, creturn just a cexpr_t nested inside of creturn_t
        creturn = cinsn.creturn
        self.matcher.check_patterns(cinsn)


        self._process_cexpr(creturn.expr)


    @trace_method
    def _process_cif(self, cinsn) -> None:
        # [NOTE] cif has ithen<cinsn_t>, ielse<cinsn_t> and expr<cexpr_t>
        cif = cinsn.cif
        self.matcher.check_patterns(cinsn)

        self._process_cexpr(cif.expr)

        if cif.ithen is not None:
            self.op2func[cif.ithen.op](cif.ithen)
        
        if cif.ielse is not None:
            self.op2func[cif.ielse.op](cif.ielse)


    @trace_method
    def _process_cfor(self, cinsn) -> None:
        # [NOTE]: cfor has init<cexpr_t>, expr<cexpr_t>, step<cexpr_t>, body<cinsn_t>(inherited from cloop_t)
        cfor = cinsn.cfor
        self.matcher.check_patterns(cinsn)
        

        if cfor.init is not None:
            self._process_cexpr(cfor.init)

        if cfor.expr is not None:
            self._process_cexpr(cfor.expr)

        if cfor.step is not None:
            self._process_cexpr(cfor.step)

        if cfor.body is not None:
            self.op2func[cfor.body.op](cfor.body)


    @trace_method
    def _process_cwhile(self, cinsn) -> None:
        # [NOTE]: cwhile has body<cinsn_t>(inherited from cloop_t), expr<cexpr_t>
        cwhile = cinsn.cwhile
        self.matcher.check_patterns(cinsn)
        
        self._process_cexpr(cwhile.expr)

        if cwhile.body is not None:
            self.op2func[cwhile.body.op](cwhile.body)


    @trace_method
    def _process_cdo(self, cinsn) -> None:
        # [NOTE]: cdo has body<cinsn_t>(inherited from cloop_t), expr<cexpr_t>
        cdo = cinsn.cdo
        self.matcher.check_patterns(cinsn)

        self._process_cexpr(cdo.expr)

        if cdo.body is not None:
            self.op2func[cdo.body.op](cdo.body)


    @trace_method
    def _process_cswitch(self, cinsn) -> None:
        # [NOTE]: cswitch has expr<cexpr_t> and cases<qvector<ccase_t>>
        # [NOTE]: ccase_t is just a cinsn_t which also has values<uint64vec_t>
        cswitch = cinsn.cswitch
        self.matcher.check_patterns(cinsn)
        
        self._process_cexpr(cswitch.expr)
        
        for c in cswitch.cases:
            self.op2func[c.op](c)


    @trace_method
    def _process_cgoto(self, cinsn) -> None:
        # [NOTE]: cgoto is just label_num, citem pointed by this label can be founded by cfunc_t.find_label(label_num)
        cgoto = cinsn.cgoto
        self.matcher.check_patterns(cinsn)


    @trace_method
    def _process_casm(self, cinsn) -> None:
        # [NOTE]: idfk, there is no normal way to interact with inline-assembly in HR
        casm = cinsn.casm
        self.matcher.check_patterns(cinsn)


    @trace_method
    def _process_unary_expr(self, expr) -> None:
        self.matcher.check_patterns(expr)
        
        self.op2func[expr.x.op](expr.x)


    @trace_method
    def _process_binary_expr(self, expr) -> None:
        self.matcher.check_patterns(expr)

        self.op2func[expr.x.op](expr.x)
        self.op2func[expr.y.op](expr.y)


    @trace_method
    def _process_call_expr(self, expr) -> None:
        self.matcher.check_patterns(expr)