import idaapi
import typing

from herast.tree.patterns.base_pattern import BasePat
from herast.tree.pattern_context import PatternContext


class AnyPat(BasePat):
	"""Pattern that always successfully matches"""
	def __init__(self, may_be_none=True, **kwargs):
		"""
		:param may_be_none: whether item is allowed to be None
		"""
		super().__init__(**kwargs)
		self.may_be_none = may_be_none

	def check(self, item, ctx: PatternContext) -> bool:
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
	def check(self, item, ctx: PatternContext) -> bool:
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
	def check(self, item, ctx: PatternContext) -> bool:
		for p in self.pats:
			if not p.check(item, ctx):
				return False

		return True

	@property
	def children(self):
		return self.pats


class BindItemPat(BasePat):
	"""Save item in context after successful matching. If item with given
	name already exists in context, then checks their equality"""
	def __init__(self, name: str, pat: typing.Optional[BasePat] = None, **kwargs):
		super().__init__(**kwargs)
		self.pat = pat or AnyPat()
		self.name = name

	@BasePat.base_check
	def check(self, item, ctx: PatternContext) -> bool:
		if self.pat.check(item, ctx):
			current_expr = ctx.get_expr(self.name)
			if current_expr is None:
				ctx.save_expr(self.name, item)
				return True
			else:
				return item.equal_effect(current_expr)
		return False


class VarBindPat(BasePat):
	"""Save variable in context after successful matching. If variable with
	given name already exists in context, then checks their indexes"""
	def __init__(self, name: str, **kwargs):
		super().__init__(**kwargs)
		self.name = name

	@BasePat.base_check
	def check(self, expr, ctx: PatternContext) -> bool:
		if expr.op != idaapi.cot_var:
			return False

		if ctx.has_var(self.name):
			return ctx.get_var(self.name).v.idx == expr.v.idx
		else:
			ctx.save_var(self.name, expr)
			return True


class DeepExprPat(BasePat):
	"""Find pattern somewhere inside an item and save it in context if 
	bind_name is provided."""
	def __init__(self, pat: BasePat, bind_name=None, **kwargs):
		super().__init__(**kwargs)
		self.pat = pat
		self.bind_name = bind_name

	@BasePat.base_check
	def check(self, expr, ctx: PatternContext) -> bool:
		for item in ctx.tree_proc.iterate_subitems(expr):
			if not self.pat.check(item, ctx):
				continue
			if self.bind_name is not None:
				ctx.save_expr(self.bind_name, item)
			return True
		return False


class RemovePat(BasePat):
	"""Pattern, that will queue item removal after successful matching."""
	def __init__(self, pat: BasePat, **kwargs):
		super().__init__(**kwargs)
		self.pat = pat

	@BasePat.base_check
	def check(self, item, ctx: PatternContext) -> bool:
		if not self.pat.check(item, ctx):
			return False

		ctx.modify_instr(item, None)
		return True