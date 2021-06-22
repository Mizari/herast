import idaapi

idaapi.require('tree.patterns.abstracts')
idaapi.require('tree.patterns.expressions')
idaapi.require('tree.utils')

from tree.patterns.abstracts import *
from tree.patterns.expressions import CallExprPat

from tree.utils import *

# test_pattern = IfInsPat(else_branch=AnyPat(may_be_none=False))
test_pattern = CallExprPat(AnyPat(), AnyPat())

def test_handler(item):
    calling_func = get_obj_from_call_node(item)
    func_name = resolve_obj_symbol(calling_func) or 'NOT_RESOLVED'
    
    print("[FOUND]: %#x -> %s" % (item.ea, func_name))