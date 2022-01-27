import idaapi

from tree.patterns.abstracts import BindExpr, ItemsCollector, LabeledInstruction, VarBind
from tree.patterns.instructions import GotoPat
from tree.pattern_context import PatternContext
import tree.utils as utils


class Matcher:
	def __init__(self):
		self.patterns = list()
		self.gotos_collector = None
		self.labels_collector = None

	def check_patterns(self, tree_processor, item) -> bool:
		self.gotos_collector = ItemsCollector(GotoPat())
		self.labels_collector = ItemsCollector(LabeledInstruction())
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
				is_tree_modified = self.finalize(ctx)
			except Exception as e:
				print('[!] Got an exception during context finalizing: %s' % e)
				continue

			if is_tree_modified:
				return True

		return False

	def finalize(self, ctx):
		tree_changed = False
		tree_proc = ctx.tree_proc
		for modified_instr in ctx.modified_instrs():
			item = modified_instr.item
			new_item = modified_instr.new_item

			if new_item is None:
				rv = self.remove_item(tree_proc, item)
			else:
				rv = self.replace_item(tree_proc, item, new_item)
			if rv: tree_changed = True

		return tree_changed

	def remove_item(self, tree_proc, removed_item):
		gotos = self.gotos_collector.collect_items(tree_proc, removed_item)
		if len(gotos) > 0:
			print("[!] failed removing item with gotos in it")
			return False

		parent = tree_proc.get_parent_block(removed_item)
		if parent is None:
			print("[*] Failed to remove item from tree, because no parent is found", removed_item.opname)
			return False

		labels = self.labels_collector.collect_items(tree_proc, removed_item)
		if len(labels) == 1 and labels[0] == removed_item:
			next_item = utils.get_following_instr(parent, removed_item)
			if next_item is None:
				print("[!] failed2removing item with labels in it", next_item)
				return False
			else:
				next_item.label_num = removed_item.label_num
				removed_item.label_num = -1

		elif len(labels) > 0:
			print("[!] failed removing item with labels in it")
			return False

		rv = utils.remove_instruction_from_ast(removed_item, parent.cinsn)
		if rv:
			return True
		else:
			print("[*] Failed to remove item from tree")
			return False

	def replace_item(self, tree_proc, item, new_item):
		gotos = self.gotos_collector.collect_items(tree_proc, item)
		if len(gotos) > 0:
			print("[!] failed replacing item with gotos in it")
			return False

		labels = self.labels_collector.collect_items(tree_proc, item)
		if len(labels) > 1:
			print("[!] failed replacing item with labels in it", labels, item)
			return False
		elif len(labels) == 1 and labels[0] != item:
			print("[!] failed replacing item with labels in it")
			return False

		if new_item.ea == idaapi.BADADDR and item.ea != idaapi.BADADDR:
			new_item.ea = item.ea

		if new_item.label_num == -1 and item.label_num != -1:
			new_item.label_num = item.label_num
			item.label_num = -1

		try:
			idaapi.qswap(item, new_item)
			return True
		except Exception as e:
			print("[!] Got an exception during ctree instr replacing")
			return False

	def insert_pattern(self, pat, handler):
		self.patterns.append((pat, handler))

	def expressions_traversal_is_needed(self):
		abstract_expression_patterns = (VarBind, BindExpr)
		for p, _, in self.patterns:
			if p.op >= 0 and p.op < idaapi.cit_empty or isinstance(p, abstract_expression_patterns):
				return True

		return False