from __future__ import annotations

import idaapi
from herapi import *


class DrefingScheme(Scheme):
	def __init__(self, pattern):
		super().__init__(pattern, scheme_type=Scheme.SchemeType.READONLY)

	def on_matched_item(self, item, ctx: MatchContext) -> ASTPatch|None:
		obj = ctx.get_item('xref_me')
		if obj.obj_ea >= 0 and obj.obj_ea <= 0x100000:
			idaapi.add_dref(obj.ea, obj.obj_ea, idaapi.dr_O)
		return None


pattern = ExprInsPat(DeepExprPat(ObjPat(), bind_name="xref_me"))
register_storage_scheme("drefing", DrefingScheme(pattern))