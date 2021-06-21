import idaapi

from tree.patterns.abstracts import *
from tree.patterns.expressions import CallExprPat

# test_pattern = IfInsPat(else_branch=AnyPat(may_be_none=False))
test_pattern = CallExprPat(AnyPat(), AnyPat())

def test_handler(item):
    calling_func = item.x
    func_name = str()

    if calling_func.op == idaapi.cot_obj:
        # func_name = calling_func.
        pass
    
    print("[FOUND]: %#x -> %s" % func_name)