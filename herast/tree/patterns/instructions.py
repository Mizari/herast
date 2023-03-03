import idaapi
import typing
from .abstracts import AnyPat
from herast.tree.patterns.base_pattern import BasePat
from herast.tree.pattern_context import PatternContext


class InstructionPat(BasePat):
	"""Base pattern for instructions patterns."""
	def __init__(self, check_op=None, **kwargs):
		super().__init__(check_op=self.op, **kwargs)


class BlockPat(InstructionPat):
	"""Pattern for block instruction aka curly braces."""
	op = idaapi.cit_block

	def __init__(self, *patterns: BasePat, **kwargs):
		super().__init__(**kwargs)
		self.sequence = patterns

	@InstructionPat.parent_check
	def check(self, instruction, ctx: PatternContext) -> bool:
		block = instruction.cblock
		if len(block) != len(self.sequence):
			return False

		for i, pat in enumerate(self.sequence):
			if not pat.check(block[i], ctx):
				return False
		return True

	@property
	def children(self):
		return (self.sequence, )       


class ExprInsPat(InstructionPat):
	"""Pattern for expression instruction aka ...;"""
	op = idaapi.cit_expr

	def __init__(self, expr=None, **kwargs):
		super().__init__(**kwargs)
		self.expr = expr or AnyPat()

	@InstructionPat.parent_check
	def check(self, instruction, ctx: PatternContext) -> bool:
		return self.expr.check(instruction.cexpr, ctx)

	@property
	def children(self):
		return (self.expr, )


class IfPat(InstructionPat):
	"""Pattern for if instruction."""
	op = idaapi.cit_if

	def __init__(self, condition=None, then_branch=None, else_branch=None, should_wrap_in_block=True, **kwargs):
		"""
		:param condition: if condition
		:param then_branch: if then block
		:param else_bran: if else block
		:param should_wrap_in_block: whether should wrap then and else branches in BlockPat
		"""
		super().__init__(**kwargs)
		def wrap_pattern(pat):
			if pat is None:
				return AnyPat()

			if not should_wrap_in_block or isinstance(pat, AnyPat):
				return pat

			if pat.op == idaapi.cit_block:
				return pat

			return BlockPat(pat)

		self.condition   = condition
		self.then_branch = wrap_pattern(then_branch)
		self.else_branch = wrap_pattern(else_branch)

	@InstructionPat.parent_check
	def check(self, instruction, ctx: PatternContext) -> bool:
		cif = instruction.cif

		rv = self.condition.check(cif.expr, ctx)
		if not rv: return False

		rv = self.then_branch.check(cif.ithen, ctx)
		if not rv: return False

		return self.else_branch.check(cif.ielse, ctx)

	@property
	def children(self):
		return (self.expr, self.body)


class ForPat(InstructionPat):
	"""Pattern for for cycle instruction."""
	op = idaapi.cit_for

	def __init__(self, init=None, expr=None, step=None, body=None, **kwargs):
		super().__init__(**kwargs)
		self.init = init or AnyPat()
		self.expr = expr or AnyPat()
		self.step = step or AnyPat()
		self.body = body or AnyPat()

	@InstructionPat.parent_check
	def check(self, instruction, ctx: PatternContext) -> bool:
		cfor = instruction.cfor

		return self.init.check(cfor.init, ctx) and \
			self.expr.check(cfor.expr, ctx) and \
			self.step.check(cfor.step, ctx) and \
			self.body.check(cfor.body, ctx)

	@property
	def children(self):
		return (self.init, self.expr, self.step, self.body)


class RetPat(InstructionPat):
	"""Pattern for return instruction."""
	op = idaapi.cit_return

	def __init__(self, expr=None, **kwargs):
		super().__init__(**kwargs)
		self.expr = expr or AnyPat()

	@InstructionPat.parent_check
	def check(self, instruction, ctx: PatternContext) -> bool:
		creturn = instruction.creturn

		return self.expr.check(creturn.expr, ctx)

	@property
	def children(self):
		return (self.expr, )


class WhilePat(InstructionPat):
	"""Pattern for while cycle instruction."""
	op = idaapi.cit_while

	def __init__(self, expr=None, body=None, **kwargs):
		super().__init__(**kwargs)
		self.expr = expr or AnyPat()
		self.body = body or AnyPat()

	@InstructionPat.parent_check
	def check(self, instruction, ctx: PatternContext) -> bool:
		cwhile = instruction.cwhile

		return self.expr.check(cwhile.expr, ctx) and \
			self.body.check(cwhile.body, ctx)

	@property
	def children(self):
		return (self.expr, self.body)


class DoPat(InstructionPat):
	"""Pattern for do while cycle instruction."""
	op = idaapi.cit_do

	def __init__(self, expr=None, body=None, **kwargs):
		super().__init__(**kwargs)
		self.expr = expr or AnyPat()
		self.body = body or AnyPat()

	@InstructionPat.parent_check
	def check(self, instruction, ctx: PatternContext) -> bool:
		cdo = instruction.cdo

		return self.body.check(cdo.body, ctx) and \
			self.expr.check(cdo.expr, ctx) 

	@property
	def children(self):
		return (self.expr, self.body)


class GotoPat(InstructionPat):
	"""Pattern for goto instruction."""
	op = idaapi.cit_goto

	def __init__(self, **kwargs):
		super().__init__(**kwargs)

	@InstructionPat.parent_check
	def check(self, item, ctx: PatternContext) -> bool:
		return True