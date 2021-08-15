import idaapi

idaapi.require('tree.patterns.abstracts')
idaapi.require('tree.patterns.expressions')
idaapi.require('tree.patterns.instructions')
idaapi.require('tree.utils')

from tree.patterns.abstracts import *
from tree.patterns.expressions import CallExprPat, HelperExprPat, ObjPat
from tree.patterns.instructions import ExInsPat

from tree.utils import *

test_pattern = CallExprPat(AnyPat(), AnyPat())


def test_handler(item, ctx):
    try:
        # print(item.x.helper)
        calling_func_addr, calling_func_name = resolve_calling_function_from_node(item)
        
        print("[FOUND]: %#x -> %s" % (item.ea, calling_func_name))
        # remove_instruction_from_ast(item, ctx.data['current_function'])

        # print('[FOUND]: %#x' % item.ea)
    except NotImplementedError:
        pass