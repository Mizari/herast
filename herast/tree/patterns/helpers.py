import idaapi

from herast.tree.patterns.base_pattern import BasePat
from herast.tree.match_context import MatchContext
from herast.tree.patterns.expressions import AsgPat, CallPat
from herast.tree.patterns.instructions import ExprInsPat


class IntPat(BasePat):
	"""Pattern for expression, that could be interpreted as integer."""
	def __init__(self, value=None, **kwargs):
		super().__init__(**kwargs)
		self.value = value

	@BasePat.base_check
	def check(self, item, ctx: MatchContext) -> bool:
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

	@BasePat.base_check
	def check(self, item, ctx: MatchContext) -> bool:
		if item.op == idaapi.cot_obj:
			item.obj_ea
			name = item.print1(None)
			name = idaapi.tag_remove(name)
			name = idaapi.str2user(name)
		elif item.op == idaapi.cot_str:
			name = item.string
		else:
			return False

		if self.str_value is None:
			return len(name) >= self.minlen
		else:
			return self.str_value == name


class StructFieldAccessPat(BasePat):
	"""Pattern for structure field access either by pointer or by reference."""
	def __init__(self, struct_type=None, member_offset=None, **kwargs):
		super().__init__(**kwargs)
		self.struct_type = struct_type
		self.member_offset = member_offset

	@BasePat.base_check
	def check(self, item, ctx: MatchContext) -> bool:
		if item.op != idaapi.cot_memptr and item.op != idaapi.cot_memref:
			return False

		stype = item.x.type
		if stype.is_ptr():
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

def CallInsnPat(*args, **kwargs):
	"""Pseudopattern for quite popular operation of
	Expression Instruction with Call Expression
	"""
	return ExprInsPat(CallPat(*args, **kwargs))

def AsgInsnPat(x, y, **kwargs):
	"""Pseudopattern for quite popular operation of
	Expression Instruction with Assignment Expression
	"""
	return ExprInsPat(AsgPat(x, y, **kwargs))