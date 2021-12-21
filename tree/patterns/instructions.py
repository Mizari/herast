import idaapi
from .abstracts import AnyPat, AbstractPattern, SeqPat

# [TODO]: consider about merging somehow cit_cdo and cit_cwhile patterns


# block:    
# if:       Done
# while:    Done
# do:       Done
# for:      Done
# switch:   
# return:   Done
# goto:     nope
# asm:      nope


# [TODO]: consider of using SeqPat implicitly and providing to ctor just *args or iterable (list, tuple) of patterns
class BlockPat(AbstractPattern):
	op = idaapi.cit_block

	def __init__(self, seq=None, skip_missing=False):
		self.sequence = seq or AnyPat()
		self.skip_missing = skip_missing

	@AbstractPattern.initial_check
	def check(self, instruction, ctx) -> bool:
		if isinstance(self.sequence, SeqPat) and not self.skip_missing and len(instruction.cblock) != self.sequence.length:
			return False

		block = instruction.cblock
		# hexrays allows deleting single instruction from block (yeah, weird, I know)
		if len(block) == 0:
			return False

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

	def __init__(self, condition=None, then_branch=None, else_branch=None):
		self.condition   = condition   or AnyPat()
		self.then_branch = then_branch or AnyPat()
		self.else_branch = else_branch or AnyPat()

	@AbstractPattern.initial_check
	def check(self, instruction, ctx) -> bool:
		cif = instruction.cif

		return self.condition.check(cif.expr, ctx) and \
			self.then_branch.check(cif.ithen, ctx) and \
			self.else_branch.check(cif.ielse, ctx)

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