from __future__ import annotations
from herast.tree.ast_iteration import iterate_all_subitems, IterationBreak
from herast.tree.ast_patch import ASTPatch
from herast.tree.ast_context import ASTContext


class ASTIterator:
	def __init__(self, ast):
		self.ast = ast
		self.cor = iterate_all_subitems(self.ast)

	def get_next(self):
		try:
			return self.cor.__next__()
		except StopIteration:
			return None

	def break_iteration(self, itbreak:IterationBreak):
		if itbreak is IterationBreak.ROOT:
			self.cor = iterate_all_subitems(self.ast)
		else:
			raise ValueError("Not implemented")

	def iterate_subitems(self):
		while (sub := self.get_next()) is not None:
			yield sub

	def apply_patch(self, ast_patch:ASTPatch, ast_ctx:ASTContext) -> IterationBreak|None:
		return ast_patch.do_patch(ast_ctx)