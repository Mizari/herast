import idaapi

from tree.patterns.abstracts import *
from tree.patterns.expressions import CallExprPat, AsgExprPat, ObjPat
from tree.patterns.instructions import ExInsPat, IfInsPat, BlockPat

from tree.utils import *

def make_call_expr(fname=None):
	if fname is None:
		obj_pat = AnyPat()
	else:
		obj_pat = ObjPat(name=fname)
	return SkipCasts(CallExprPat(obj_pat, ignore_arguments=True))

first_call_pattern = ExInsPat(
							AsgExprPat(
								AnyPat(),
								make_call_expr("__cxa_allocate_exception")
							)
						)

excstr_getter_pattern = ExInsPat(
	AsgExprPat(
		AnyPat(),
		CallExprPat(AnyPat(), AnyPat(), SkipCasts(BindExpr("exception_str", AnyPat())))
	)
)
last_call_pattern = ExInsPat(make_call_expr('__cxa_throw'))

class ExceptionBody(AbstractPattern):
	op = idaapi.cit_block
	def __init__(self, first_call, excstr_getter, last_call):
		self.first_call = first_call
		self.last_call = last_call
		self.excstr_getter = excstr_getter

	@AbstractPattern.initial_check
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

pattern = IfInsPat(
	BindExpr("if_expr"),
	ExceptionBody(first_call_pattern, excstr_getter_pattern, last_call_pattern)
)

def handler(item, ctx):
	arglist = idaapi.carglist_t()
	if_expr = ctx.get_expr("if_expr")
	if if_expr is not None:
		arg1 = idaapi.carg_t()
		arg1.assign(if_expr)
		arglist.push_back(arg1)

	exception_str = ctx.get_expr("exception_str")
	arg2 = None
	if exception_str is not None:
		if exception_str.op == idaapi.cot_obj:
			arg2 = idaapi.carg_t()
			arg2.assign(exception_str)

	if arg2 is not None:
		arglist.push_back(arg2)

	helper = idaapi.call_helper(idaapi.get_unk_type(8), arglist, "__throw_if")
	new_item = idaapi.cinsn_t()
	new_item.ea = item.ea
	new_item.op = idaapi.cit_expr
	new_item.cexpr = helper
	new_item.thisown = False
	new_item.label_num = item.label_num

	ctx.modify_instr(item, new_item)

	return False

__exported = [
	(pattern, handler),
]