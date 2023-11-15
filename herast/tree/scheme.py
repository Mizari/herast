from herast.tree.pattern_context import PatternContext
from herast.tree.patterns.base_pattern import BasePat


class Scheme:
	"""Class with logic on what to do with successfully found patterns in AST"""
	def __init__(self, *patterns: BasePat, is_readonly=False):
		"""Scheme initialization

		:param patterns: AST patterns
		"""
		self.patterns = patterns
		self.is_readonly = is_readonly

	def on_matched_item(self, item, ctx: PatternContext) -> bool:
		"""Callback for successful match of scheme's patterns on item.
		Generally contains logic with AST modification or some information collection

		:param item: AST item
		:param ctx: matching context
		:return: bool is AST modified?
		"""
		return False

	def on_tree_iteration_start(self, ctx: PatternContext):
		"""Callback for the start of AST iteration. Generally contains state initialization and state clear.

		:param ctx: AST context
		"""
		return

	def on_tree_iteration_end(self, ctx: PatternContext):
		"""Callback for the end of AST iteration. Generally contains code for collected information processing

		:param ctx: AST context
		"""
		return