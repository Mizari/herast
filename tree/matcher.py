import idaapi

from tree.patterns.abstracts import BindExpr, VarBind
from tree.pattern_context import PatternContext
import tree.utils as utils


class Matcher:
	def __init__(self):
		self.patterns = list()

	def check_patterns(self, tree_processor, item) -> bool:
		ctx = PatternContext(tree_processor)

		for pattern, handler in self.patterns:
			try:
				ctx.cleanup()
			except Exception as e:
				print('[!] Got an exception during context cleanup: %s' % e)
				continue

			try:
				if not pattern.check(item, ctx):
					continue
			except Exception as e:
				print('[!] Got an exception during pattern matching: %s' % e)
				continue

			try:
				is_tree_modified = False
				if handler is not None:
					is_tree_modified = handler(item, ctx)
				if not isinstance(is_tree_modified, bool):
					raise Exception("Handler return invalid return type, should be bool")

				if is_tree_modified:
					return True
			except Exception as e:
				print('[!] Got an exception during pattern handling: %s' % e)
				continue

			try:
				self.finalize(ctx)
			except Exception as e:
				print('[!] Got an exception during context finalizing: %s' % e)
				continue

			if tree_processor.is_tree_modified:
				return True

		return False

	def finalize(self, ctx):
		tree_proc = ctx.tree_proc
		for modified_instr in ctx.modified_instrs():
			item = modified_instr.item
			new_item = modified_instr.new_item

			if new_item is None:
				tree_proc.remove_item(item)
			else:
				tree_proc.replace_item(item, new_item)

	def insert_pattern(self, pat, handler):
		self.patterns.append((pat, handler))

	def expressions_traversal_is_needed(self):
		abstract_expression_patterns = (VarBind, BindExpr)
		for p, _, in self.patterns:
			if p.op >= 0 and p.op < idaapi.cit_empty or isinstance(p, abstract_expression_patterns):
				return True

		return False