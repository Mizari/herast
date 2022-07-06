from herapi import *

pattern = IfPat(
	VarBind("error_var"),
	ExprInsPat(BindItem("logic_expr")),
	ExprInsPat(AsgPat(VarBind("error_var"), BindItem("logic_expr")))
)

class ReplacingScheme(SPScheme):
	def on_matched_item(self, item, ctx: PatternContext):
		error_var = ctx.get_var("error_var")
		if error_var is None:
			return False

		logic_expr = ctx.get_expr("logic_expr")
		if logic_expr is None:
			return False

		new_item = make_call_helper_instr("__propagate_error", error_var, logic_expr)
		ctx.modify_instr(item, new_item)
		return False

scheme = ReplacingScheme("propagate_error", pattern)

register_storage_scheme(scheme)