import idaapi

idaapi.require('tree.patterns.abstracts')
idaapi.require('tree.patterns.expressions')
idaapi.require('tree.patterns.instructions')
idaapi.require('tree.utils')

from tree.patterns.abstracts import *
from tree.patterns.expressions import CallExprPat, AsgExprPat, ObjPat
from tree.patterns.instructions import ExInsPat, IfInsPat, BlockPat

from tree.utils import *

pattern = IfInsPat(
                    BindExpr('if_expr', AnyPat()),
                    BlockPat(
                        SeqPat([
                            ExInsPat(
                                AsgExprPat(
                                    AnyPat(),
                                    SkipCasts(CallExprPat(ObjPat(name='__cxa_allocate_exception'), ignore_arguments=True))
                            )),
                            ExInsPat(
                                SkipCasts(CallExprPat(AnyPat(), ignore_arguments=True))
                            ),
                            ExInsPat(
                                SkipCasts(CallExprPat(ObjPat(name='__cxa_throw'), ignore_arguments=True))
                            )
                        ])
                    )
                )

def handler(item, ctx):
    # print("%#x" % item.ea)

    tmp = ctx['if_expr']
    if_expr = idaapi.cexpr_t()
    if_expr.cleanup()
    # print(type(tmp), type(if_expr))
    # tmp.swap(if_expr)

    if_expr = tmp

    arglist = idaapi.carglist_t()

    arg1 = idaapi.carg_t()
    arg1.assign(if_expr)
    # arg1.op = if_expr.op
    # arg1.ea = if_expr.ea
    # arg1.cexpr = if_expr.cexpr
    # arg1.type = idaapi.get_unk_type(8)

    arglist.push_back(arg1)

    helper = idaapi.call_helper(idaapi.get_unk_type(8), arglist, "__throw_if")
    insn = idaapi.cinsn_t()
    insn.ea = item.ea
    insn.op = idaapi.cit_expr
    insn.cexpr = helper
    insn.thisown = False
    insn.label_num = item.label_num

    # item.cleanup()

    idaapi.qswap(item, insn)

    return True
