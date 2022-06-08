import idaapi
from .abstracts import AnyPat, AbstractPattern, SeqPat


class BlockPat(AbstractPattern):
	op = idaapi.cit_block

	def __init__(self, seq=None, skip_missing=False):
		self.sequence = seq or AnyPat()

		# backwards compatibility, will be removed later
		if isinstance(seq, SeqPat):
			seq.skip_missing = skip_missing

	@AbstractPattern.initial_check
	def check(self, instruction, ctx) -> bool:
		block = instruction.cblock
		return self.sequence.check(block[0], ctx)

	@property
	def children(self):
		return (self.sequence, )       


class ExInsPat(AbstractPattern):
	op = idaapi.cit_expr

	def __init__(self, expr=None):
		self.expr = expr or AnyPat()

	@AbstractPattern.initial_check
	def check(self, instruction, ctx) -> bool:
		return self.expr.check(instruction.cexpr, ctx)

	@property
	def children(self):
		return (self.expr, )


class IfInsPat(AbstractPattern):
	op = idaapi.cit_if

	def __init__(self, condition=None, then_branch=None, else_branch=None, should_wrap_in_block=True):
		def wrap_pattern(pat):
			if pat is None:
				return AnyPat()

			if not should_wrap_in_block:
				return pat

			if pat.op == idaapi.cit_block:
				return pat

			return BlockPat(pat)

		self.condition   = wrap_pattern(condition)
		self.then_branch = wrap_pattern(then_branch)
		self.else_branch = wrap_pattern(else_branch)

	@AbstractPattern.initial_check
	def check(self, instruction, ctx) -> bool:
		cif = instruction.cif

		rv = self.condition.check(cif.expr, ctx)
		if not rv: return False

		rv = self.then_branch.check(cif.ithen, ctx)
		if not rv: return False

		return self.else_branch.check(cif.ielse, ctx)

	@property
	def children(self):
		return (self.expr, self.body)


class ForInsPat(AbstractPattern):
	op = idaapi.cit_for

	def __init__(self, init=None, expr=None, step=None, body=None):
		self.init = init or AnyPat()
		self.expr = expr or AnyPat()
		self.step = step or AnyPat()
		self.body = body or AnyPat()


	@AbstractPattern.initial_check
	def check(self, instruction, ctx) -> bool:
		cfor = instruction.cfor

		return self.init.check(cfor.init, ctx) and \
			self.expr.check(cfor.expr, ctx) and \
			self.step.check(cfor.step, ctx) and \
			self.body.check(cfor.body, ctx)

	@property
	def children(self):
		return (self.init, self.expr, self.step, self.body)


class RetInsPat(AbstractPattern):
	op = idaapi.cit_return

	def __init__(self, expr=None):
		self.expr = expr or AnyPat()

	@AbstractPattern.initial_check
	def check(self, instruction, ctx) -> bool:
		creturn = instruction.creturn

		return self.expr.check(creturn.expr, ctx)

	@property
	def children(self):
		return (self.expr, )


class WhileInsPat(AbstractPattern):
	op = idaapi.cit_while

	def __init__(self, expr=None, body=None):
		self.expr = expr or AnyPat()
		self.body = body or AnyPat()

	@AbstractPattern.initial_check
	def check(self, instruction, ctx) -> bool:
		cwhile = instruction.cwhile

		return self.expr.check(cwhile.expr, ctx) and \
			self.body.check(cwhile.body, ctx)

	@property
	def children(self):
		return (self.expr, self.body)


class DoInsPat(AbstractPattern):
	op = idaapi.cit_do

	def __init__(self, expr=None, body=None):
		self.expr = expr or AnyPat()
		self.body = body or AnyPat()

	@AbstractPattern.initial_check
	def check(self, instruction, ctx) -> bool:
		cdo = instruction.cdo

		return self.body.check(cdo.body, ctx) and \
			self.expr.check(cdo.expr, ctx) 

	@property
	def children(self):
		return (self.expr, self.body)


class GotoPat(AbstractPattern):
	op = idaapi.cit_goto
	def __init__(self):
		return

	@AbstractPattern.initial_check
	def check(self, item, ctx):
		return True