from herapi import *


class ReplacingScheme(Scheme):
	def __init__(self):
		"""
		pattern of form:
		if (error_var) {
			some_logic_expr;
		}
		else {
			error_var = some_logic_expr;
		}
		pattern checks that some_logic_exprs are equal via BindItem calls
		"""
		pattern = IfPat(
			VarPat(bind_name="error_var"),
			ExprInsPat(AnyPat(bind_name="logic_expr")),
			AsgInsnPat(VarPat(bind_name="error_var"), AnyPat(bind_name="logic_expr"))
		)
		super().__init__(pattern)

	def on_matched_item(self, item, ctx: MatchContext):
		error_var = ctx.get_var("error_var")
		if error_var is None:
			return False

		logic_expr = ctx.get_item("logic_expr")
		if logic_expr is None:
			return False

		new_item = make_call_helper_instr("__propagate_error", error_var, logic_expr)
		ctx.modify_instr(item, new_item)
		return False

register_storage_scheme("propagate_error", ReplacingScheme())