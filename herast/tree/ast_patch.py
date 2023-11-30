from __future__ import annotations
from enum import Enum
import idaapi
import herast.tree.utils as utils
from herast.tree.ast_iteration import collect_gotos, collect_labels
from herast.tree.ast_context import ASTContext


def is_removal_possible(item:idaapi.cinsn_t, ctx:ASTContext) -> bool:
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

def remove_instr(item:idaapi.cinsn_t, ctx:ASTContext) -> bool:
	if not is_removal_possible(item, ctx):
		return False

	parent = ctx.get_parent_block(item)
	saved_lbl = item.label_num
	item.label_num = -1
	rv = utils.remove_instruction_from_ast(item, parent.cinsn) # type: ignore
	if not rv:
		item.label_num = saved_lbl
		print(f"[*] Failed to remove item {item.opname} from tree at {hex(item.ea)}")
		return False

	next_item = utils.get_following_instr(parent, item)
	if next_item is not None:
		next_item.label_num = saved_lbl
	return True

def is_replacing_possible(item:idaapi.cinsn_t) -> bool:
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

def replace_expr(expr:idaapi.cexpr_t, new_expr:idaapi.cexpr_t, ctx:ASTContext) -> bool:
	new_expr = idaapi.cexpr_t(new_expr)
	expr.replace_by(new_expr)
	return True

def replace_instr(item, new_item:idaapi.cinsn_t, ctx:ASTContext) -> bool:
	if not is_replacing_possible(item):
		return False

	if new_item.ea == idaapi.BADADDR and item.ea != idaapi.BADADDR:
		new_item.ea = item.ea

	if new_item.label_num == -1 and item.label_num != -1:
		new_item.label_num = item.label_num

	try:
		new_item = idaapi.cinsn_t(new_item)
		idaapi.qswap(item, new_item)
		return True
	except Exception as e:
		print("[!] Got an exception during ctree instr replacing", e)
		return False


class ASTPatch:
	class PatchType(Enum):
		SCHEME_MODIFIED = 0
		REMOVE_INSTR    = 1
		REPLACE_INSTR   = 2
		REPLACE_EXPR    = 3

	def __init__(self, patch_type:PatchType, item=None, new_item=None):
		self.ptype = patch_type
		self.item = item
		self.new_item = new_item

	@classmethod
	def remove_instr(cls, item:idaapi.cinsn_t):
		assert not item.is_expr()
		return cls(cls.PatchType.REMOVE_INSTR, item)

	@classmethod
	def replace_instr(cls, item:idaapi.cinsn_t, new_item:idaapi.cinsn_t):
		assert not item.is_expr()
		assert not new_item.is_expr()
		return cls(cls.PatchType.REPLACE_INSTR, item, new_item)

	@classmethod
	def replace_expr(cls, expr:idaapi.cexpr_t, new_expr:idaapi.cexpr_t):
		assert expr.is_expr()
		assert new_expr.is_expr()
		return cls(cls.PatchType.REPLACE_EXPR, expr, new_expr)

	@classmethod
	def scheme_modified(cls):
		return cls(cls.PatchType.SCHEME_MODIFIED)

	def do_patch(self, ast_ctx:ASTContext) -> bool:
		if self.ptype == self.PatchType.REMOVE_INSTR:
			return remove_instr(self.item, ast_ctx)
		elif self.ptype == self.PatchType.REPLACE_INSTR:
			return replace_instr(self.item, self.new_item, ast_ctx)
		elif self.ptype == self.PatchType.REPLACE_EXPR:
			return replace_expr(self.item, self.new_item, ast_ctx)
		elif self.ptype == self.PatchType.SCHEME_MODIFIED:
			return False
		else:
			raise TypeError("This patch type is not implemented")