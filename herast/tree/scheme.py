from __future__ import annotations

from herast.tree.match_context import MatchContext
from herast.tree.patterns.base_pattern import BasePat
from herast.tree.ast_patch import ASTPatch


class Scheme:
	"""Class with logic on what to do with successfully found patterns in AST"""
	def __init__(self, *patterns: BasePat, is_readonly=False):
		"""Scheme initialization

		:param patterns: AST patterns
		"""
		self.patterns = patterns
		self.is_readonly = is_readonly

	def on_matched_item(self, item, ctx: MatchContext) -> ASTPatch|None:
		"""Callback for successful match of scheme's patterns on item.
		Generally contains logic with AST modification or some information collection

		:param item: AST item
		:param ctx: matching context
		:return: how to patch AST
		"""
		return None

	def on_tree_iteration_start(self):
		"""Callback for the start of AST iteration. Generally contains state initialization and state clear.
		"""
		return

	def on_tree_iteration_end(self):
		"""Callback for the end of AST iteration. Generally contains code for collected information processing
		"""
		return