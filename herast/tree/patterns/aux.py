import idaapi

import herast.tree.consts as consts
from herast.tree.patterns.base_pattern import BasePattern
from herast.tree.pattern_context import PatternContext
from herast.tree.patterns.expressions import ObjPat

# sequence of instructions
class SeqPat(BasePattern):
	op = -1

	def __init__(self, *pats, skip_missing=True):
		self.skip_missing = skip_missing

		if len(pats) == 1 and isinstance(pats[0], list):
			pats = pats[0]

		for p in pats:
			if p.op < 0:
				continue
			if consts.cexpr_op2str.get(p.op, None) is not None:
				print("[*] WARNING: SeqPat expects instructions, not expression")

		self.seq = tuple(pats)
		self.length = len(pats)

	def check(self, instruction, ctx: PatternContext) -> bool:
		parent = ctx.get_parent_block(instruction)
		if parent is None:
			return False

		container = parent.cinsn.cblock
		start_from = container.index(instruction)
		if start_from + self.length > len(container):
			return False

		if not self.skip_missing and len(container) != self.length + start_from:
			return False

		for i in range(self.length):
			if not self.seq[i].check(container[start_from + i], ctx):
				return False
		return True

	@property
	def children(self):
		return tuple(self.pats)

class MultiObject(BasePattern):
	def __init__(self, *objects):
		self.objects = [ObjPat(o) for o in objects]
 
	def check(self, item, ctx: PatternContext) -> bool:
		if item.op != idaapi.cot_obj:
			return False

		for o in self.objects:
			if o.check(item):
				return True
		return False


class IntPat(BasePattern):
	def __init__(self, value=None):
		self.value = value

	def check(self, item, ctx: PatternContext) -> bool:
		if item.op not in (idaapi.cot_num, idaapi.cot_obj):
			return False

		if self.value is None:
			return True

		if item.op == idaapi.cot_num:
			check_value = item.n._value
		else:
			check_value = item.obj_ea
		return self.value == check_value