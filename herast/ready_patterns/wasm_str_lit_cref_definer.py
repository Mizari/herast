import idaapi
from herapi import *


class DrefingScheme(SPScheme):
	def on_matched_item(self, item, ctx: PatternContext):
		obj = ctx.get_expr('xref_me')
		if obj.obj_ea >= 0 and obj.obj_ea <= 0x100000:
			idaapi.add_dref(obj.ea, obj.obj_ea, idaapi.dr_O)
		return False


pattern = ExInsPat(DeepExpr(BindItem('xref_me', ObjPat())))
add_passive_scheme(DrefingScheme("drefing", pattern))