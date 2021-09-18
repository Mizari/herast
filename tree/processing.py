from __future__ import print_function
import idaapi
import functools

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
    @functools.wraps(method)
    def method_wrapper(*args, **kwargs):
        self = args[0]
        insn = args[1]
        debug_print('%s   CALL: %s(%#x)' % (method.__name__, insn, insn.ea), message='TRACE_%d' % id(self))
        result = method(*args, **kwargs)
        debug_print('%s RETURN: %s' % (method.__name__, result), message='TRACE_%d' % id(self))

        return result
    return method_wrapper


class TreeProcessor:

    def __init__(self, tree_root, matcher, need_expression_traversal=False):
        self.tree_root = tree_root
        self.matcher = matcher
        self.need_expression_traversal = need_expression_traversal
        self.should_revisit_parent = False
        
        debug_print('has_deep_expressions = %s' % self.need_expression_traversal)

        self.op2func = {i:self.__stub for i in range(100)}

        self.op2func.update({
            idaapi.cit_expr: self._process_cexpr,
            idaapi.cit_empty: self.__stub,
            idaapi.cit_break: self.__stub,
            idaapi.cit_continue: self.__stub,
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
    
    @classmethod
    def from_cfunc(cls, cfunc, *args, **kwargs):
        assert isinstance(cfunc.body, idaapi.cinsn_t), "Function body is not cinsn_t"
        assert isinstance(cfunc.body.cblock, idaapi.cblock_t), "Function body must be a cblock_t"

        return cls(cfunc.body, *args, **kwargs)

    def _assert(self, cond, msg=""):
        assert cond, "%s: %s" % (self.__class__.__name__, msg)

    @staticmethod
    def __revert_check(func):
        @functools.wraps(func)
        def func_wrapper(self, *args, **kwargs):
                if self.should_revisit_parent:
                    return
                else:
                    func(self, *args, **kwargs)
                    while self.should_revisit_parent:
                        self.should_revisit_parent = False
                        func(self, *args, **kwargs)

        return func_wrapper
    revert_check = __revert_check.__func__

    @revert_check
    def process_tree(self) -> None:
        self.check_patterns(self.tree_root)
        self.op2func[self.tree_root.op](self.tree_root)

    def __stub(*args, **kwargs) -> None:
        pass

    def check_patterns(self, item):
        if not self.should_revisit_parent:
            self.should_revisit_parent = self.matcher.check_patterns(item)

    @revert_check
    @trace_method
    def _process_cblock(self, cinsn) -> None:
        # [NOTE] cblock is just an array of cinsn_t (qlist<cinsn_t>)
        cblock = cinsn.cblock
        # [TODO]: make traversal with adjustments like reverting to parent (or mb root) node to reanalyze subtree
        try:
            for ins in cblock:
                self.check_patterns(ins)
                if self.should_revisit_parent:
                    break
                
                self.op2func[ins.op](ins)

        except KeyError:
            raise KeyError("Handler for %s is not setted" % op2str[ins.op])

    @revert_check
    @trace_method
    def _process_cexpr(self, cinsn) -> None:
        # This is kinda tricky, cuz sometimes we calling process_cexpr with cinsn_t and sometimes with cexpr_t
        # but as cexpr_t also has cexpr member, so it works
        cexpr = cinsn.cexpr

        if self.need_expression_traversal:
            self.check_patterns(cexpr)
            self.op2func[cexpr.op](cexpr)


    @revert_check
    @trace_method
    def _process_creturn(self, cinsn) -> None:
        # [NOTE] as i understand, creturn just a cexpr_t nested inside of creturn_t
        creturn = cinsn.creturn

        if self.need_expression_traversal:
            self.check_patterns(creturn.expr)
            self.op2func[creturn.expr.op](creturn.expr)


    @revert_check
    @trace_method
    def _process_cif(self, cinsn) -> None:
        # [NOTE] cif has ithen<cinsn_t>, ielse<cinsn_t> and expr<cexpr_t>
        cif = cinsn.cif

        if self.need_expression_traversal:
            self.check_patterns(cif.expr)
            self.op2func[cif.expr.op](cif.expr)

        self.check_patterns(cif.ithen)
        self.op2func[cif.ithen.op](cif.ithen)
        
        if cif.ielse is not None:
            self.check_patterns(cif.ielse)
            self.op2func[cif.ielse.op](cif.ielse)


    @revert_check
    @trace_method
    def _process_cfor(self, cinsn) -> None:
        # [NOTE]: cfor has init<cexpr_t>, expr<cexpr_t>, step<cexpr_t>, body<cinsn_t>(inherited from cloop_t)
        cfor = cinsn.cfor
        
        if cfor.init is not None:
            if self.need_expression_traversal:
                self.check_patterns(cfor.init)
                self.op2func[cfor.init.op](cfor.init)

        if cfor.expr is not None:
            if self.need_expression_traversal:
                self.check_patterns(cfor.expr)
                self.op2func[cfor.expr.op](cfor.expr)

        if cfor.step is not None:
            if self.need_expression_traversal:
                self.check_patterns(cfor.step)
                self.op2func[cfor.step.op](cfor.step)

        if cfor.body is not None:
            self.check_patterns(cfor.body)
            self.op2func[cfor.body.op](cfor.body)


    @revert_check
    @trace_method
    def _process_cwhile(self, cinsn) -> None:
        # [NOTE]: cwhile has body<cinsn_t>(inherited from cloop_t), expr<cexpr_t>
        cwhile = cinsn.cwhile
        
        if self.need_expression_traversal:
            self.check_patterns(cwhile.expr)
            self.op2func[cwhile.expr.op](cwhile.expr)

        if cwhile.body is not None:
            self.check_patterns(cwhile.body)
            self.op2func[cwhile.body.op](cwhile.body)


    @revert_check
    @trace_method
    def _process_cdo(self, cinsn) -> None:
        # [NOTE]: cdo has body<cinsn_t>(inherited from cloop_t), expr<cexpr_t>
        cdo = cinsn.cdo

        if self.need_expression_traversal:
            self.check_patterns(cinsn)
            self.op2func[cdo.expr.op](cdo.expr)

        if cdo.body is not None:
            self.check_patterns(cdo.body)
            self.op2func[cdo.body.op](cdo.body)


    @revert_check
    @trace_method
    def _process_cswitch(self, cinsn) -> None:
        # [NOTE]: cswitch has expr<cexpr_t> and cases<qvector<ccase_t>>
        # [NOTE]: ccase_t is just a cinsn_t which also has values<uint64vec_t>
        cswitch = cinsn.cswitch
        
        if self.need_expression_traversal:
            self.check_patterns(cswitch.expr)
            self.op2func[cswitch.expr.op](cswitch.expr)
        
        for c in cswitch.cases:
            self.check_patterns(c)
            self.op2func[c.op](c)


    @revert_check
    @trace_method
    def _process_cgoto(self, cinsn) -> None:
        # [NOTE]: cgoto is just label_num, citem pointed by this label can be founded by cfunc_t.find_label(label_num)
        cgoto = cinsn.cgoto
        

    @revert_check
    @trace_method
    def _process_casm(self, cinsn) -> None:
        # [NOTE]: idfk, there is no normal way to interact with inline-assembly in HR
        casm = cinsn.casm


    @revert_check
    @trace_method
    def _process_unary_expr(self, expr) -> None:
        self.check_patterns(expr.x)
        self.op2func[expr.x.op](expr.x)


    @revert_check
    @trace_method
    def _process_binary_expr(self, expr) -> None:
        self.check_patterns(expr.x)
        self.op2func[expr.x.op](expr.x)

        self.check_patterns(expr.y)
        self.op2func[expr.y.op](expr.y)


    @revert_check
    @trace_method
    def _process_call_expr(self, expr) -> None:
        calling_expr = expr.x
        args = expr.a

        self.check_patterns(calling_expr)
        self.op2func[calling_expr.op](calling_expr)

        for arg in args:
            self.check_patterns(arg)
            if self.should_revisit_parent:
                break

            self.op2func[arg.op](arg)
