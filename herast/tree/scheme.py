from __future__ import annotations

from enum import Enum
from herast.tree.match_context import MatchContext
from herast.tree.patterns.base_pattern import BasePat
from herast.tree.ast_patch import ASTPatch


class Scheme:
	class SchemeType(Enum):
		GENERIC  = 0
		READONLY = 1
		SINGULAR = 2

	"""Class with logic on what to do with successfully found patterns in AST"""
	def __init__(self, *patterns: BasePat, scheme_type=SchemeType.GENERIC):
		"""Scheme initialization

		:param patterns: AST patterns
		:param scheme_type:
			generic means items are independent of each other,
			readonly means scheme does no AST patching,
			singular means there is some interdependency between matched items
		"""
		self.patterns = patterns
		self.stype = scheme_type

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