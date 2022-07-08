import idaapi

from herast.tree.patterns.base_pattern import BasePat
from herast.tree.pattern_context import PatternContext
from herast.tree.patterns.expressions import ObjPat, AsgPat
from herast.tree.patterns.instructions import ExprInsPat

class SeqPat(BasePat):
	"""Pattern for matching sequence of instructions inside Block Pattern aka curly braces."""
	def __init__(self, *pats, skip_missing=True, **kwargs):
		"""
		:param pats: instructions patterns
		:param skip_missing: whether should skip missing instructions or patterns for them
		"""
		super().__init__(**kwargs)
		self.skip_missing = skip_missing

		if len(pats) == 1 and isinstance(pats[0], list):
			pats = pats[0]

		import herast.tree.consts as consts
		for p in pats:
			if p.op < 0:
				continue
			if consts.cexpr_op2str.get(p.op, None) is not None:
				print("[*] WARNING: SeqPat expects instructions, not expression")

		self.seq = tuple(pats)
		self.length = len(pats)

	@BasePat.parent_check
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

class MultiObjectPat(BasePat):
	"""Pattern for expression, that is allowed to be one of multiple objects"""
	def __init__(self, *objects, **kwargs):
		super().__init__(**kwargs)
		self.objects = [ObjPat(o) for o in objects]
 
	@BasePat.parent_check
	def check(self, item, ctx: PatternContext) -> bool:
		if item.op != idaapi.cot_obj:
			return False

		for o in self.objects:
			if o.check(item):
				return True
		return False


class IntPat(BasePat):
	"""Pattern for expression, that could be interpreted as integer."""
	def __init__(self, value=None, **kwargs):
		super().__init__(**kwargs)
		self.value = value

	@BasePat.parent_check
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


class StringPat(BasePat):
	"""Pattern for expression that could be interpreted as string."""
	def __init__(self, str_value=None, minlen=5, **kwargs):
		super().__init__(**kwargs)
		self.str_value = str_value
		self.minlen = minlen

	@BasePat.parent_check
	def check(self, item, ctx: PatternContext) -> bool:
		if item.op != idaapi.cot_obj:
			return False

		item.obj_ea
		name = item.print1(None)
		name = idaapi.tag_remove(name)
		name = idaapi.str2user(name)

		if self.str_value is None:
			return len(name) == self.minlen
		else:
			return self.str_value == name


class StructFieldAccessPat(BasePat):
	"""Pattern for structure field access either by pointer or by reference."""
	def __init__(self, struct_type=None, member_offset=None, **kwargs):
		super().__init__(**kwargs)
		self.struct_type = struct_type
		self.member_offset = member_offset

	@BasePat.parent_check
	def check(self, item, ctx: PatternContext) -> bool:
		if item.op != idaapi.cot_memptr or item.op != idaapi.cot_memref:
			return False

		stype = item.x.type
		stype = stype.get_pointed_object()
		if not stype.is_struct():
			return False

		if self.member_offset is not None and self.member_offset != item.m:
			return False

		if self.struct_type is None:
			return True

		if isinstance(self.struct_type, str) and self.struct_type == str(stype):
			return True

		return self.struct_type == stype

def CallInsnPat(calling_function, *arguments, ignore_arguments=False, skip_missing=False, **kwargs):
	"""Pseudopattern for quite popular operation of
	Expression Instruction with Call Expression
	"""
	return ExprInsPat(calling_function, *arguments, ignore_arguments=ignore_arguments, skip_missing=skip_missing)

def AsgInsnPat(x, y):
	"""Pseudopattern for quite popular operation of
	Expression Instruction with Assignment Expression
	"""
	return ExprInsPat(AsgPat(x, y))