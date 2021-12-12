import idaapi

idaapi.require('tree.patterns.abstracts')
idaapi.require('tree.patterns.expressions')
idaapi.require('tree.patterns.instructions')
idaapi.require('tree.utils')

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

last_call_pattern = ExInsPat(make_call_expr('__cxa_throw'))

def make_sequence_pattern(n_additional_instrs):
	pats = [ExInsPat()] * n_additional_instrs
	pats = [first_call_pattern] + pats + [last_call_pattern]
	return SeqPat(pats)

def make_collapse_exception_pattern(n_additional_instrs=1):
	sequence_pattern = make_sequence_pattern(n_additional_instrs)
	return IfInsPat(BindExpr('if_expr', AnyPat()), BlockPat(sequence_pattern))

def handler(item, ctx):
	# print("%#x" % item.ea)

	tmp = ctx.get_expr('if_expr')
	if_expr = idaapi.cexpr_t()
	if_expr.cleanup()
	# print(type(tmp), type(if_expr))
	# tmp.swap(if_expr)

	if_expr = tmp

	arglist = idaapi.carglist_t()

	arg1 = idaapi.carg_t()
	arg1.assign(if_expr)
	# arg1.op = if_expr.op
	# arg1.ea = if_expr.ea
	# arg1.cexpr = if_expr.cexpr
	# arg1.type = idaapi.get_unk_type(8)

	arglist.push_back(arg1)

	helper = idaapi.call_helper(idaapi.get_unk_type(8), arglist, "__throw_if")
	insn = idaapi.cinsn_t()
	insn.ea = item.ea
	insn.op = idaapi.cit_expr
	insn.cexpr = helper
	insn.thisown = False
	insn.label_num = item.label_num

	# item.cleanup()

	idaapi.qswap(item, insn)

	return True


__exported = [
	(make_collapse_exception_pattern(1), handler),
	(make_collapse_exception_pattern(7), handler),
	(make_collapse_exception_pattern(8), handler),
	(make_collapse_exception_pattern(9), handler),
]