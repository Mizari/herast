from herast.schemes.base_scheme import Scheme
from herast.tree.pattern_context import PatternContext


class SPScheme(Scheme):
	"""A scheme with a single pattern."""
	def __init__(self, name: str, pattern):
		self.pattern = pattern
		super().__init__(name)

	def on_new_item(self, item, ctx: PatternContext):
		return self.pattern.check(item, ctx)

	def get_patterns(self):
		return [self.pattern]


class ItemRemovalScheme(SPScheme):
	"""A scheme with a single pattern, that will give command to remove all found items."""
	def __init__(self, name: str, pattern):
		super().__init__(name, pattern)

	def on_matched_item(self, item, ctx: PatternContext) -> bool:
		ctx.modify_instr(item, None)
		return False