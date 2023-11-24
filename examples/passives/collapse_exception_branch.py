from __future__ import annotations
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

	@BasePat.base_check
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
				AsgInsnPat(AnyPat(), CallPat(AnyPat(), AnyPat(), ObjPat(bind_name="exception_str"))),
				CallInsnPat('__cxa_throw', ignore_arguments=True),
			),
			should_wrap_in_block=False,
		)

		super().__init__(pattern)

	def on_matched_item(self, item, ctx: MatchContext) -> ASTPatch|None:
		"""
			on match will try to construct from found item and binded expressions
			__throw_if(if_expr, "exception string")
		"""

		if_condition = item.cif.expr
		exception_str = ctx.get_item("exception_str")
		if exception_str is None:
			new_item = make_call_helper_instr("__throw_if", if_condition)
		else:
			new_item = make_call_helper_instr("__throw_if", if_condition, exception_str)
		return ASTPatch.replace_item(item, new_item)

register_storage_scheme("exception_collapser", ExceptionCollapserScheme())