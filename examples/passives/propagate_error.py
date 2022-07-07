from herapi import *


class ReplacingScheme(SPScheme):
	def __init__(self, name, pattern):
		pattern = IfPat(
			VarBind("error_var"),
			ExprInsPat(BindItem("logic_expr")),
			AsgInsnPat(VarBind("error_var"), BindItem("logic_expr"))
		)
		name = "propagate_erro"
		super().__init__(name, pattern)

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

register_storage_scheme(ReplacingScheme())