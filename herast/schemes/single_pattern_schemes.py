from herast.schemes.base_scheme import Scheme
from herast.tree.pattern_context import PatternContext


class SPScheme(Scheme):
	def __init__(self, name, pattern):
		self.pattern = pattern
		super().__init__(name)

	def on_new_item(self, item, ctx: PatternContext):
		return self.pattern.check(item, ctx)

	def get_patterns(self):
		return [self.pattern]


class ItemRemovalScheme(SPScheme):
	def __init__(self, name, pattern):
		super().__init__(name, pattern)

	def on_matched_item(self, item, ctx: PatternContext):
		ctx.modify_instr(item, None)
		return False