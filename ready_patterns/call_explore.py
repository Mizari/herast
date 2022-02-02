import idaapi

from tree.patterns.abstracts import *
from tree.patterns.expressions import CallExprPat
from tree.patterns.instructions import ExInsPat

from tree.utils import *


test_pattern = ExInsPat(CallExprPat('_objc_release', ignore_arguments=True))

def test_handler(item, ctx):
	print("[FOUND]: %#x" % item.ea)
	ctx.modify_instr(item, None)
	return False


__exported = [
		(test_pattern, test_handler)
]
