import idaapi

from herast.tree.patterns.abstracts import *
from herast.tree.patterns.expressions import ObjPat
from herast.tree.patterns.instructions import ExInsPat

from herast.schemes.single_pattern_schemes import SPScheme


class DrefingScheme(SPScheme):
	def on_matched_item(self, item, ctx: PatternContext):
		obj = ctx.get_expr('xref_me')
		if obj.obj_ea >= 0 and obj.obj_ea <= 0x100000:
			idaapi.add_dref(obj.ea, obj.obj_ea, idaapi.dr_O)
		return False


pattern = ExInsPat(DeepExpr(BindItem('xref_me', ObjPat())))
__exported = [
	DrefingScheme("drefing", pattern)
]