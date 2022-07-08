import idaapi

from herast.tree.patterns.base_pattern import BasePattern
from herast.tree.pattern_context import PatternContext


class ExpressionPat(BasePattern):
	"""Base class for expression items patterns."""
	op = None

	def __init__(self, debug=False, skip_casts=True, check_op=None):
		super().__init__(debug, skip_casts, check_op=self.op)

	@staticmethod
	def parent_check(func):
		func = BasePattern.parent_check(func)
		def __perform_parent_check(self, item, *args, **kwargs):
			return func(self, item, *args, **kwargs)
		return __perform_parent_check


class CallPat(ExpressionPat):
	"""Pattern for matching function calls."""
	op = idaapi.cot_call

	def __init__(self, calling_function, *arguments, ignore_arguments=False, skip_missing=False, **kwargs):
		"""
		:param calling_function:  what function is called. will try to make ObjPat from it
		:param arguments:         call arguments
		:param ignore_arguments:  whether or not should match arguments
		:param skip_missing:      skip missing either call arguments or patterns for call arguments
		"""
		super().__init__(**kwargs)
		if isinstance(calling_function, str):
			calling_function = ObjPat(calling_function)

		if isinstance(calling_function, int):
			calling_function = ObjPat(calling_function)

		self.calling_function = calling_function
		self.arguments = arguments
		self.ignore_arguments = ignore_arguments
		self.skip_missing = skip_missing

	@ExpressionPat.parent_check
	def check(self, expression, ctx: PatternContext) -> bool:
		if self.calling_function is not None and not self.calling_function.check(expression.x, ctx):
			return False

		if self.ignore_arguments:
			return True

		if len(self.arguments) != len(expression.a) and not self.skip_missing:
			return False

		min_l = min(len(self.arguments), len(expression.a))
		for arg_id in range(min_l):
			if not self.arguments[arg_id].check(expression.a[arg_id], ctx):
				return False

		return True

	@property
	def children(self):
		return (self.calling_function, *self.arguments)


class HelperPat(ExpressionPat):
	"""Pattern for matching helper objects."""
	op = idaapi.cot_helper

	def __init__(self, helper_name=None, **kwargs):
		super().__init__(**kwargs)
		self.helper_name = helper_name

	@ExpressionPat.parent_check
	def check(self, expression, ctx: PatternContext) -> bool:
		return self.helper_name == expression.helper if self.helper_name is not None else True

	@property
	def children(self):
		return ()


class NumPat(ExpressionPat):
	"""Pattern for matching numbers."""
	op = idaapi.cot_num

	def __init__(self, num=None, **kwargs):
		super().__init__(**kwargs)
		self.num = num

	@ExpressionPat.parent_check
	def check(self, expr, ctx: PatternContext) -> bool:
		if self.num is None:
			return True

		return self.num == expr.n._value


class ObjPat(ExpressionPat):
	"""Pattern for matching objects with addresses."""
	op = idaapi.cot_obj

	def __init__(self, obj_info=None, **kwargs):
		"""
		:param obj_info: information for construction object. will try to get int address from it
		"""
		super().__init__(**kwargs)
		self.ea = None
		self.name = None

		if isinstance(obj_info, int):
			self.ea = obj_info
			if not idaapi.is_loaded(self.ea):
				print("[!] WARNING: object with address", hex(self.ea), "is not loaded. Will still try to match it")
			else:
				self.name = idaapi.get_name(self.ea)
				if self.name == '': self.name = None

		elif isinstance(obj_info, str):
			from herast.tree.utils import resolve_name_address
			self.name = obj_info
			ea = resolve_name_address(self.name)
			if ea == idaapi.BADADDR:
				print("[!] WARNING: object with name", self.name, "does not exist. Will still try to match it")
			else:
				self.ea = ea

		elif obj_info is None:
			# simply match idaapi.cot_obj
			pass

		else:
			raise TypeError("Object info should be int|str|None")

	@ExpressionPat.parent_check
	def check(self, expression, ctx: PatternContext) -> bool:
		if self.ea is None and self.name is None:
			return True

		if self.ea is not None and self.ea == expression.obj_ea:
			return True

		if self.name is None:
			return False

		ea_name = idaapi.get_name(expression.obj_ea)
		if self.name == ea_name:
			return True

		demangled_ea_name = idaapi.demangle_name(ea_name, idaapi.MNG_NODEFINIT | idaapi.MNG_NORETTYPE)
		return demangled_ea_name == self.name


class RefPat(ExpressionPat):
	"""Pattern for matching references."""
	op = idaapi.cot_ref

	def __init__(self, referenced_object, **kwargs):
		super().__init__(**kwargs)
		self.referenced_object = referenced_object

	@ExpressionPat.parent_check
	def check(self, expression, ctx: PatternContext) -> bool:
		return self.referenced_object.check(expression.x, ctx)


class MemrefPat(ExpressionPat):
	"""Pattern for matching memory references."""
	op = idaapi.cot_memref

	def __init__(self, referenced_object, field, **kwargs):
		super().__init__(**kwargs)
		self.referenced_object = referenced_object
		self.field = field

	@ExpressionPat.parent_check
	def check(self, expression, ctx: PatternContext) -> bool:
		return self.referenced_object.check(expression.x, ctx) and \
			self.field.check(expression.m, ctx)


class MemptrPat(ExpressionPat):
	"""Pattern for matching memory pointers."""
	op = idaapi.cot_memptr

	def __init__(self, pointed_object, field, **kwargs):
		super().__init__(**kwargs)
		self.pointed_object = pointed_object
		self.field = field

	@ExpressionPat.parent_check
	def check(self, expression, ctx: PatternContext) -> bool:
		return self.pointed_object.check(expression.x, ctx) and \
			self.field.check(expression.m, ctx)


class TernaryPat(ExpressionPat):
	"""Pattern for C's ternary operator."""
	op = idaapi.cot_tern

	def __init__(self, condition, positive_expression, negative_expression, **kwargs):
		super().__init__(**kwargs)
		self.condition = condition
		self.positive_expression = positive_expression
		self.negative_expression = negative_expression
		
	@ExpressionPat.parent_check
	def check(self, expression, ctx: PatternContext) -> bool:
		return self.condition.check(expression.x, ctx) and \
			self.positive_expression.check(expression.y, ctx) and \
			self.negative_expression.check(expression.z, ctx)


class VarPat(ExpressionPat):
	"""Pattern for matching variables."""
	op = idaapi.cot_var

	def __init__(self, **kwargs):
		super().__init__(**kwargs)

	@ExpressionPat.parent_check
	def check(self, expression, ctx: PatternContext) -> bool:
		return True


class AbstractUnaryOpPattern(ExpressionPat):
	"""Abstract class for C's unary operators."""
	def __init__(self, operand, **kwargs):
		super().__init__(**kwargs)
		self.operand = operand

	@ExpressionPat.parent_check
	def check(self, expression, ctx: PatternContext) -> bool:
		return self.operand.check(expression.x, ctx)

	@property
	def children(self):
		return (self.operand, )


class AbstractBinaryOpPattern(ExpressionPat):
	"""Abstract class for C's binary operators."""
	def __init__(self, first_operand, second_operand, symmetric=False, **kwargs):
		super().__init__(**kwargs)
		self.first_operand = first_operand
		self.second_operand = second_operand
		self.symmetric = symmetric

	@ExpressionPat.parent_check
	def check(self, expression, ctx: PatternContext) -> bool:
		first_op_second = self.first_operand.check(expression.x, ctx) and self.second_operand.check(expression.y, ctx)
		if self.symmetric:
			second_op_first = self.first_operand.check(expression.y, ctx) and self.second_operand.check(expression.x, ctx)
			return first_op_second or second_op_first
		else:
			return first_op_second

	@property
	def children(self):
		return (self.first_operand, self.second_operand)


class AsgPat(ExpressionPat):
	"""Class for assignment expression."""

	op = idaapi.cot_asg
	def __init__(self, lhs, rhs, **kwargs):
		super().__init__(**kwargs)
		self.lhs = lhs
		self.rhs = rhs

	@ExpressionPat.parent_check
	def check(self, item, ctx: PatternContext) -> bool:
		if not self.lhs.check(item.x, ctx):
			return False
		return self.rhs.check(item.y, ctx)


def __generate_expression_patterns():
	import sys
	module = sys.modules[__name__]
	from herast.tree.consts import binary_expressions_ops, unary_expressions_ops, op2str

	for op in unary_expressions_ops:
		name = '%sPat' % op2str[op].replace('cot_', '').capitalize()
		vars(module)[name] = type(name, (AbstractUnaryOpPattern,), {'op': op})

	for op in binary_expressions_ops:
		# skip assignment, because it is explicitly defined for easier coding
		if op == idaapi.cot_asg: continue
		name = '%sPat' % op2str[op].replace('cot_', '').capitalize()
		vars(module)[name] = type(name, (AbstractBinaryOpPattern,), {'op': op})
__generate_expression_patterns()