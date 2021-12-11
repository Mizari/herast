import idaapi

idaapi.require('tree.patterns.abstracts')
idaapi.require('tree.patterns.expressions')
idaapi.require('tree.patterns.instructions')
idaapi.require('tree.utils')

from tree.patterns.abstracts import *
from tree.patterns.expressions import CallExprPat, AsgExprPat, ObjPat, AsgExprPat, AsgxorExprPat
from tree.patterns.instructions import ExInsPat, IfInsPat, BlockPat, ForInsPat

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