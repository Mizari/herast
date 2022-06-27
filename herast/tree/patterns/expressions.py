import idaapi

from herast.tree.patterns.abstracts import AnyPat, AbstractPattern
from herast.tree.consts import binary_expressions_ops, unary_expressions_ops, op2str
from herast.tree.utils import resolve_name_address
from herast.tree.pattern_context import PatternContext


class CallExprPat(AbstractPattern):
	op = idaapi.cot_call

	def __init__(self, calling_function, *arguments, ignore_arguments=False, skip_missing=False):
		if isinstance(calling_function, str):
			calling_function = ObjPat(calling_function)

		if isinstance(calling_function, int):
			calling_function = ObjPat(calling_function)

		if calling_function is None:
			calling_function = AnyPat()

		self.calling_function = calling_function
		self.arguments = arguments
		self.ignore_arguments = ignore_arguments
		self.skip_missing = skip_missing

	@AbstractPattern.initial_check
	def check(self, expression, ctx: PatternContext) -> bool:
		if not self.calling_function.check(expression.x, ctx):
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


class HelperExprPat(AbstractPattern):
	op = idaapi.cot_helper

	def __init__(self, helper_name=None):
		self.helper_name = helper_name
	
	@AbstractPattern.initial_check
	def check(self, expression, ctx: PatternContext) -> bool:
		return self.helper_name == expression.helper if self.helper_name is not None else True

	@property
	def children(self):
		return ()


class NumPat(AbstractPattern):
	op = idaapi.cot_num
	def __init__(self, num=None):
		self.num = num

	@AbstractPattern.initial_check
	def check(self, expr, ctx: PatternContext) -> bool:
		if self.num is None:
			return True

		return self.num == expr.n._value


class ObjPat(AbstractPattern):
	op = idaapi.cot_obj

	def __init__(self, obj_info=None):
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

	@AbstractPattern.initial_check
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


class RefPat(AbstractPattern):
	op = idaapi.cot_ref

	def __init__(self, referenced_object):
		self.referenced_object = referenced_object

	@AbstractPattern.initial_check
	def check(self, expression, ctx: PatternContext) -> bool:
		return self.referenced_object.check(expression.x, ctx)


class MemrefExprPat(AbstractPattern):
	op = idaapi.cot_memref

	def __init__(self, referenced_object, field):
		self.referenced_object = referenced_object
		self.field = field

	@AbstractPattern.initial_check
	def check(self, expression, ctx: PatternContext) -> bool:
		return self.referenced_object.check(expression.x, ctx) and \
			self.field.check(expression.m, ctx)


class MemptrExprPat(AbstractPattern):
	op = idaapi.cot_memptr

	def __init__(self, pointed_object, field):
		self.pointed_object = pointed_object
		self.field = field

	@AbstractPattern.initial_check
	def check(self, expression, ctx: PatternContext) -> bool:
		return self.pointed_object.check(expression.x, ctx) and \
			self.field.check(expression.m, ctx)


class TernaryExprPat(AbstractPattern):
	op = idaapi.cot_tern

	def __init__(self, condition, positive_expression, negative_expression):
		self.condition = condition
		self.positive_expression = positive_expression
		self.negative_expression = negative_expression
		
	@AbstractPattern.initial_check
	def check(self, expression, ctx: PatternContext) -> bool:
		return self.condition.check(expression.x, ctx) and \
			self.positive_expression.check(expression.y, ctx) and \
			self.negative_expression.check(expression.z, ctx)


class VarExprPat(AbstractPattern):
	op = idaapi.cot_var

	def __init__(self):
		pass

	@AbstractPattern.initial_check
	def check(self, expression, ctx: PatternContext) -> bool:
		return True


class AbstractUnaryOpPattern(AbstractPattern):
	op = None

	def __init__(self, operand):
		self.operand = operand

	@AbstractPattern.initial_check
	def check(self, expression, ctx: PatternContext) -> bool:
		return self.operand.check(expression.x, ctx)

	@property
	def children(self):
		return (self.operand, )


class AbstractBinaryOpPattern(AbstractPattern):
	op = None

	def __init__(self, first_operand, second_operand, symmetric=False):
		self.first_operand = first_operand
		self.second_operand = second_operand
		self.symmetric = symmetric

	@AbstractPattern.initial_check
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


import sys
module = sys.modules[__name__]

for op in unary_expressions_ops:
	name = '%sExprPat' % op2str[op].replace('cot_', '').capitalize()
	vars(module)[name] = type(name, (AbstractUnaryOpPattern,), {'op': op})

for op in binary_expressions_ops:
	name = '%sExprPat' % op2str[op].replace('cot_', '').capitalize()
	vars(module)[name] = type(name, (AbstractBinaryOpPattern,), {'op': op})