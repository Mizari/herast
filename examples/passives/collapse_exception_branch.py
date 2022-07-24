import idaapi
from herapi import *


class ExceptionBody(BasePat):
	"""
		Exception body checks the very first and the very last instructions.
		Then it will try to find instruction with exception string.
	"""
	def __init__(self, first_call, excstr_getter, last_call, **kwargs):
		self.first_call = first_call
		self.last_call = last_call
		self.excstr_getter = excstr_getter
		super().__init__(check_op=idaapi.cit_block, **kwargs)

	@BasePat.parent_check
	def check(self, item, ctx):
		block = item.cblock

		if len(block) < 3:
			return False

		if not self.first_call.check(block[0], ctx):
			b0 = block[0]
			if b0.op == idaapi.cit_if: return False
			c = b0.cexpr
			if c.y.op != idaapi.cot_call: return False
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


class ExceptionCollapserScheme(Scheme):
	def __init__(self):
		"""
			pattern looks like this:
				if (if_expr) {
					... = __cxa_allocate_exception();
					...
					... = some_function(..., "exception string");
					...
					__cxa_throw();
				}
		"""
		pattern = IfPat(
			AnyPat(),
			ExceptionBody(
				AsgInsnPat(AnyPat(), CallPat("__cxa_allocate_exception", ignore_arguments=True)),
				AsgInsnPat(AnyPat(), CallPat(AnyPat(), AnyPat(), BindItemPat("exception_str", ObjPat()))),
				CallInsnPat('__cxa_throw', ignore_arguments=True),
			),
			should_wrap_in_block=False,
		)

		name = "exception_collapser"
		super().__init__(name, pattern)

	def on_matched_item(self, item, ctx: PatternContext) -> bool:
		"""
			on match will try to construct from found item and binded expressions
			__throw_if(if_expr, "exception string")
		"""

		if_condition = item.cif.expr
		exception_str = ctx.get_expr("exception_str")
		if exception_str is None:
			new_item = make_call_helper_instr("__throw_if", if_condition)
		else:
			new_item = make_call_helper_instr("__throw_if", if_condition, exception_str)
		ctx.modify_instr(item, new_item)

		return False

register_storage_scheme(ExceptionCollapserScheme())