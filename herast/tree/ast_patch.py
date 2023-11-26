from __future__ import annotations
import idaapi
import herast.tree.utils as utils
from herast.tree.processing import collect_gotos, collect_labels, IterationBreak
from herast.tree.ast_context import ASTContext


class ASTPatch:
	def __init__(self, item, new_item):
		self.item = item
		self.new_item = new_item

	@classmethod
	def remove_item(cls, item):
		return cls(item, None)

	@classmethod
	def replace_item(cls, item, new_item):
		return cls(item, new_item)

	def apply_patch(self, ast_ctx:ASTContext) -> IterationBreak|None:
		if self.new_item is None:
			return self._remove_item(self.item, ast_ctx)
		else:
			return self._replace_item(self.item, self.new_item, ast_ctx)

	def is_removal_possible(self, item, ctx:ASTContext) -> bool:
		gotos = collect_gotos(item)
		if len(gotos) > 0:
			print("[!] failed removing item with gotos in it")
			return False

		parent = ctx.get_parent_block(item)
		if parent is None:
			print("[*] Failed to remove item from tree, because no parent is found", item.opname)
			return False

		labels = collect_labels(item)
		if len(labels) == 1 and labels[0] == item:
			next_item = utils.get_following_instr(parent, item)
			if next_item is None:
				print("[!] failed2removing item with labels in it", next_item)
				return False

		elif len(labels) > 0:
			print("[!] failed removing item with labels in it")
			return False

		return True

	def _remove_item(self, item, ctx:ASTContext) -> IterationBreak|None:
		if not self.is_removal_possible(item, ctx):
			return None

		parent = ctx.get_parent_block(item)
		saved_lbl = item.label_num
		item.label_num = -1
		rv = utils.remove_instruction_from_ast(item, parent.cinsn) # type: ignore
		if not rv:
			item.label_num = saved_lbl
			print(f"[*] Failed to remove item {item.opname} from tree at {hex(item.ea)}")
			return None

		next_item = utils.get_following_instr(parent, item)
		if next_item is not None:
			next_item.label_num = saved_lbl
		return IterationBreak.ROOT

	def is_replacing_possible(self, item) -> bool:
		gotos = collect_gotos(item)
		if len(gotos) > 0:
			print("[!] failed replacing item with gotos in it")
			return False

		labels = collect_labels(item)
		if len(labels) > 1:
			print("[!] failed replacing item with labels in it", labels, item)
			return False

		if len(labels) == 1 and labels[0] != item:
			print("[!] failed replacing item with labels in it")
			return False

		return True

	def _replace_item(self, item, new_item, ctx:ASTContext) -> IterationBreak|None:
		if item.is_expr and new_item.is_expr:
			item.replace_by(new_item)
			return IterationBreak.ROOT

		if not self.is_replacing_possible(item):
			return None

		if new_item.ea == idaapi.BADADDR and item.ea != idaapi.BADADDR:
			new_item.ea = item.ea

		if new_item.label_num == -1 and item.label_num != -1:
			new_item.label_num = item.label_num

		try:
			idaapi.qswap(item, new_item)
			return IterationBreak.ROOT
		except Exception as e:
			print("[!] Got an exception during ctree instr replacing", e)
			return None