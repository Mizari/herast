import idaapi

idaapi.require('tree.patterns.abstracts')
idaapi.require('tree.patterns.expressions')
idaapi.require('tree.patterns.instructions')
idaapi.require('tree.utils')

from tree.patterns.abstracts import *
from tree.patterns.expressions import CallExprPat, HelperExprPat, ObjPat
from tree.patterns.instructions import ExInsPat

from tree.utils import *

# test_pattern = CallExprPat(AnyPat(), AnyPat())
# test_pattern = ExInsPat(AnyPat())
# test_pattern = ExInsPat(DeepExpr(CallExprPat(AnyPat(), ignore_arguments=True)))


test_pattern = ExInsPat(CallExprPat(ObjPat(name='_objc_release'), ignore_arguments=True))

def test_handler(item, ctx):
    try:
        # print(item.x.helper)
        # calling_func_addr, calling_func_name = resolve_calling_function_from_node(item)
        # print("[FOUND]: %#x -> %s" % (item.ea, calling_func_name))
        print("[FOUND]: %#x" % item.ea)
        remove_instruction_from_ast(item, ctx.current_function)

        return True
        # print('[FOUND]: %#x' % item.ea)
    except Exception as e:
        print('Got an exception due handling: %s' % e)

    return False


__exported = [
        (test_pattern, test_handler)
]
