import idaapi

from tree.patterns.abstracts import AnyPat, AbstractPattern, SeqPat
from tree.consts import binary_expressions_ops, unary_expressions_ops, op2str
from tree.utils import resolve_name_address


class CallExprPat(AbstractPattern):
	op = idaapi.cot_call

	def __init__(self, calling_function, *arguments, ignore_arguments=False, skip_missing=False):
		self.calling_function = calling_function
		self.arguments = arguments
		self.ignore_arguments = ignore_arguments
		self.skip_missing = skip_missing

	@AbstractPattern.initial_check
	def check(self, expression, ctx) -> bool:
		if not self.calling_function.check(expression.x, ctx):
			return False

		if not self.ignore_arguments:
			if len(self.arguments) != len(expression.a) and not self.skip_missing:
				return False

			return all((pat.check(arg, ctx) for pat, arg in zip(self.arguments, expression.a)))

		return True

	@property
	def children(self):
		return (self.calling_function, *self.arguments)


class HelperExprPat(AbstractPattern):
	op = idaapi.cot_helper

	def __init__(self, helper_name=None):
		self.helper_name = helper_name
	
	@AbstractPattern.initial_check
	def check(self, expression, ctx) -> bool:
		return self.helper_name == expression.helper if self.helper_name is not None else True

	@property
	def children(self):
		return ()


class ObjPat(AbstractPattern):
	op = idaapi.cot_obj

	def __init__(self, name=None, ea=None):
		self.ea = ea
		self.name = name
		if ea is None and name is not None:
			self.ea = resolve_name_address(name)

	@AbstractPattern.initial_check
	def check(self, expression, ctx) -> bool:
		if self.ea is None:
			return True
		
		if self.ea == expression.obj_ea:
			return True

		ea_name = idaapi.get_name(self.ea)
		if self.name == ea_name:
			return True

		demangled_ea_name = idaapi.demangle_name(ea_name, idaapi.MNG_NODEFINIT | idaapi.MNG_NORETTYPE)
		return demangled_ea_name == self.name


class MemrefExprPat(AbstractPattern):
	op = idaapi.cot_memref

	def __init__(self, referenced_object, field):
		self.referenced_object = referenced_object
		self.field = field

	# [TODO]: field is actually just an int, but consider about creating a primitives for Integers, Strings and other literals
	@AbstractPattern.initial_check
	def check(self, expression, ctx) -> bool:
		return self.referenced_object.check(expression.x, ctx) and \
			self.field.check(expression.m, ctx)


class MemptrExprPat(AbstractPattern):
	op = idaapi.cot_memptr

	def __init__(self, pointed_object, field):
		self.pointed_object = pointed_object
		self.field = field

	# [TODO]: we can access ptrsize of memptr, it may be useful to check
	# [NOTE]: field is actually just an int, but consider about creating a primitives for Integers, Strings and other literals
	@AbstractPattern.initial_check
	def check(self, expression, ctx) -> bool:
		return self.pointed_object.check(expression.x, ctx) and \
			self.field.check(expression.m, ctx)


class TernaryExprPat(AbstractPattern):
	op = idaapi.cot_tern

	def __init__(self, condition, positive_expression, negative_expression):
		self.condition = condition
		self.positive_expression = positive_expression
		self.negative_expression = negative_expression
		
	@AbstractPattern.initial_check
	def check(self, expression, ctx):
		return self.condition.check(expression.x, ctx) and \
			self.positive_expression.check(expression.y, ctx) and \
			self.negative_expression.check(expression.z, ctx)


class VarExprPat(AbstractPattern):
	op = idaapi.cot_var

	def __init__(self):
		pass

	@AbstractPattern.initial_check
	def check(self, expression, ctx) -> bool:
		return True


class AbstractUnaryOpPattern(AbstractPattern):
	op = None

	def __init__(self, operand):
		self.operand = operand

	@AbstractPattern.initial_check
	def check(self, expression, ctx) -> bool:
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
	def check(self, expression, ctx) -> bool:
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

# [TODO]: name-overwriting check
for op in unary_expressions_ops:
	name = '%sExprPat' % op2str[op].replace('cot_', '').capitalize()
	vars(module)[name] = type(name, (AbstractUnaryOpPattern,), {'op': op})

for op in binary_expressions_ops:
	name = '%sExprPat' % op2str[op].replace('cot_', '').capitalize()
	vars(module)[name] = type(name, (AbstractBinaryOpPattern,), {'op': op})