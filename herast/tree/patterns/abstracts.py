
from herast.tree.patterns.base_pattern import BasePat
from herast.tree.match_context import MatchContext
from herast.tree.processing import TreeProcessor


class AnyPat(BasePat):
	"""Pattern that always successfully matches"""
	def __init__(self, may_be_none=True, **kwargs):
		"""
		:param may_be_none: whether item is allowed to be None
		"""
		super().__init__(**kwargs)
		self.may_be_none = may_be_none

	def check(self, item, ctx: MatchContext) -> bool:
		return item is not None or self.may_be_none

	@property
	def children(self):
		return ()

class OrPat(BasePat):
	"""Logical or pattern."""
	def __init__(self, *pats: BasePat, **kwargs):
		super().__init__(**kwargs)
		if len(pats) <= 1:
			print("[*] WARNING: OrPat expects at least two patterns")
		self.pats = tuple(pats)

	@BasePat.base_check
	def check(self, item, ctx: MatchContext) -> bool:
		for p in self.pats:
			if p.check(item, ctx):
				return True
		
		return False

	@property
	def children(self):
		return self.pats

class AndPat(BasePat):
	"""Logical and pattern."""
	def __init__(self, *pats: BasePat, **kwargs):
		super().__init__(**kwargs)
		if len(pats) <= 1:
			print("[*] WARNING: one or less patterns to AndPat is useless")
		self.pats = tuple(pats)

	@BasePat.base_check
	def check(self, item, ctx: MatchContext) -> bool:
		for p in self.pats:
			if not p.check(item, ctx):
				return False

		return True

	@property
	def children(self):
		return self.pats


class DeepExprPat(BasePat):
	"""Find pattern somewhere inside an item and save it in context if 
	bind_name is provided."""
	def __init__(self, pat: BasePat, **kwargs):
		super().__init__(**kwargs)
		self.pat = pat

	@BasePat.base_check
	def check(self, expr, ctx: MatchContext) -> bool:
		tree_proc = TreeProcessor()
		for item in tree_proc.iterate_subitems(expr):
			if not self.pat.check(item, ctx):
				continue
			if self.bind_name is not None:
				ctx.bind_item(self.bind_name, item)
			return True
		return False