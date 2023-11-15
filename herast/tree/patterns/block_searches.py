import idaapi

from herast.tree.patterns.instructions import InstructionPat
from herast.tree.pattern_context import ASTContext


class SeqPat(InstructionPat):
	op = idaapi.cit_block

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
			if p.op is not None and consts.cinsn_op2str.get(p.op) is None:
				print("[*] WARNING: SeqPat expects instructions, not expression")

		self.seq = tuple(pats)
		self.length = len(pats)

	@InstructionPat.instr_check
	def check(self, instruction, ctx: ASTContext) -> bool:
		container = instruction.cblock
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
		return tuple(self.seq)

