import idaapi

from tree.patterns.abstracts import BindExpr, ItemsCollector, LabeledInstruction, VarBind
from tree.patterns.instructions import GotoPat
from tree.pattern_context import PatternContext
import tree.utils as utils


class Matcher:
	def __init__(self, processed_function):
		self.function = processed_function
		self.patterns = list()
		self.gotos_collector = ItemsCollector(GotoPat(), self.function)
		self.labels_collector = ItemsCollector(LabeledInstruction(), self.function)

	def check_patterns(self, item) -> bool:
		for pattern, handler, ctx in self.patterns:
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
				is_tree_modified = handler(item, ctx)
				if not isinstance(is_tree_modified, bool):
					raise Exception("Handler return invalid return type, should be bool")

				if is_tree_modified:
					return True
			except Exception as e:
				print('[!] Got an exception during pattern handling: %s' % e)
				continue

			try:
				is_tree_modified = self.finalize(ctx)
			except Exception as e:
				print('[!] Got an exception during context finalizing: %s' % e)
				continue

			if is_tree_modified:
				return True

		return False

	def finalize(self, ctx):
		tree_changed = False
		for modified_instr in ctx.modified_instrs():
			item = modified_instr.item
			new_item = modified_instr.new_item

			if new_item is None:
				rv = self.remove_item(ctx, item)
			else:
				rv = self.replace_item(ctx, item, new_item)
			if rv: tree_changed = True

		return tree_changed

	def remove_item(self, ctx, removed_item):
		gotos = self.gotos_collector.collect_items(removed_item)
		if len(gotos) > 0:
			print("[!] failed removing item with gotos in it")
			return False

		labels = self.labels_collector.collect_items(removed_item)
		if len(labels) > 0:
			print("[!] failed removing item with labels in it")
			return False

		parent = ctx.get_parent_block(removed_item)
		if parent is None:
			print("[*] Failed to remove item from tree, because no parent is found", removed_item.opname)
			return False

		rv = utils.remove_instruction_from_ast(removed_item, parent.cinsn)
		if rv:
			return True
		else:
			print("[*] Failed to remove item from tree")
			return False

	def replace_item(self, ctx, item, new_item):
		gotos = self.gotos_collector.collect_items(item)
		if len(gotos) > 0:
			print("[!] failed replacing item with gotos in it")
			return False

		labels = self.labels_collector.collect_items(item)
		if len(labels) > 0:
			print("[!] failed replacing item with labels in it")
			return False

		if new_item.ea == idaapi.BADADDR and item.ea != idaapi.BADADDR:
			new_item.ea = item.ea

		if new_item.label_num == -1 and item.label_num != -1:
			new_item.label_num = item.label_num

		try:
			idaapi.qswap(item, new_item)
			return True
		except Exception as e:
			print("[!] Got an exception during ctree instr replacing")
			return False

	def insert_pattern(self, pat, handler):
		ctx = PatternContext(self.function)
		self.patterns.append((pat, handler, ctx))

	def expressions_traversal_is_needed(self):
		abstract_expression_patterns = (VarBind, BindExpr)
		for p, _, _ in self.patterns:
			if p.op >= 0 and p.op < idaapi.cit_empty or isinstance(p, abstract_expression_patterns):
				return True

		return False