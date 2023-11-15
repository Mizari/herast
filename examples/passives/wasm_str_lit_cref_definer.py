import idaapi
from herapi import *


class DrefingScheme(Scheme):
	def on_matched_item(self, item, ctx: ASTContext):
		obj = ctx.get_expr('xref_me')
		if obj.obj_ea >= 0 and obj.obj_ea <= 0x100000:
			idaapi.add_dref(obj.ea, obj.obj_ea, idaapi.dr_O)
		return False


pattern = ExprInsPat(DeepExprPat(BindItemPat('xref_me', ObjPat())))
register_storage_scheme("drefing", DrefingScheme(pattern))