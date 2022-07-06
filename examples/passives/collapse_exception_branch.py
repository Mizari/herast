import idaapi
from herapi import *


class ExceptionBody(BasePattern):
	op = idaapi.cit_block
	def __init__(self, first_call, excstr_getter, last_call):
		self.first_call = first_call
		self.last_call = last_call
		self.excstr_getter = excstr_getter

	@BasePattern.parent_check
	def check(self, item, ctx):
		block = item.cblock

		if len(block) < 3:
			return False

		if not self.first_call.check(block[0], ctx):
			return False
		if not self.last_call.check(block[len(block) - 1], ctx):
			return False

		for i in range(1, len(block) - 2):
			if block[i].op != idaapi.cit_expr:
				return False

		for i in range(1, len(block) - 2):
			if self.excstr_getter.check(block[i], ctx):
				break

		return True

first_call_pattern    = AsgInsnPat(AnyPat(), CallPat("__cxa_allocate_exception"))
excstr_getter_pattern = AsgInsnPat(AnyPat(), CallPat(AnyPat(), AnyPat(), SkipCasts(BindItem("exception_str", AnyPat()))))
last_call_pattern = ExprInsPat(CallPat('__cxa_throw'))

pattern = IfPat(
	BindItem("if_expr"),
	ExceptionBody(first_call_pattern, excstr_getter_pattern, last_call_pattern)
)

class ExceptionCollapserScheme(SPScheme):
	def on_matched_item(self, item, ctx: PatternContext) -> bool:
		helper_args = []

		if_expr = ctx.get_expr("if_expr")
		if if_expr is not None:
			arg1 = idaapi.carg_t()
			arg1.assign(if_expr)
			helper_args.append(arg1)

		exception_str = ctx.get_expr("exception_str")
		if exception_str is not None:
			if exception_str.op == idaapi.cot_obj:
				arg2 = idaapi.carg_t()
				arg2.assign(exception_str)
				helper_args.append(arg2)

		new_item = make_call_helper_instr("__throw_if", *helper_args)

		ctx.modify_instr(item, new_item)

		return False

register_storage_scheme(ExceptionCollapserScheme("exception_collapser", pattern))