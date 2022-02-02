import idaapi

from tree.patterns.abstracts import *
from tree.patterns.expressions import ObjPat
from tree.patterns.instructions import ExInsPat

from tree.utils import *


pattern = ExInsPat(DeepExpr(BindExpr('xref_me', ObjPat())))

def handler(item, ctx):
	obj = ctx.get_expr('xref_me')
	if obj.obj_ea >= 0 and obj.obj_ea <= 0x100000:
		idaapi.add_dref(obj.ea, obj.obj_ea, idaapi.dr_O)

	return False



__exported = [
	(pattern, handler)
]