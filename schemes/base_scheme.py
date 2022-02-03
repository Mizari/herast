from tree.pattern_context import PatternContext

class Scheme:
	def __init__(self, name):
		self.name = name

	def on_new_item(self, item, ctx: PatternContext):
		return

	def on_matched_item(self, item, ctx: PatternContext):
		return False

	def on_tree_iteration_start(self, ctx: PatternContext):
		return False

	def on_tree_iteration_end(self, ctx: PatternContext):
		return False