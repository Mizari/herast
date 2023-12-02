from __future__ import annotations
from enum import Enum
from collections import defaultdict
import idaapi
import herast.tree.utils as utils
from herast.tree.ast_iteration import collect_gotos, collect_labels
from herast.tree.ast_context import ASTContext


def __replace_instr(item:idaapi.cinsn_t, new_item:idaapi.cinsn_t) -> bool:
	new_item = idaapi.cinsn_t(new_item)
	try:
		idaapi.qswap(item, new_item)
		return True
	except Exception as e:
		print("[!] Got an exception during ctree instr replacing", e)
		return False

def remove_instr(item:idaapi.cinsn_t, ctx:ASTContext) -> bool:
	parent = ctx.get_parent_block(item)
	if parent is None:
		print("[*] Failed to remove item from tree, because no parent is found", item.opname)
		return False

	removed_gotos = collect_gotos(item)
	count = defaultdict(int)
	for g in removed_gotos:
		count[g.label_num] += 1

	unused_labels = []
	for lnum, c in count.items():
		if len(ctx.label2gotos[lnum]) == c:
			unused_labels.append(lnum)

	removed_labels = collect_labels(item)
	for u in unused_labels:
		try:
			removed_labels.remove(u)
		except ValueError:
			pass

	if len(removed_labels) > 0:
		print(f"[!] failed to remove item {item.opname} with labels in it")
		return False

	rv = utils.remove_instruction_from_ast(item, parent.cinsn)
	if not rv:
		print(f"[*] failed to remove item {item.opname} from tree at {hex(item.ea)}")

	if len(unused_labels) != 0 and rv:
		ctx.is_modified = True
		ctx.cfunc.remove_unused_labels()

	return rv

def replace_instr(item, new_item:idaapi.cinsn_t, ctx:ASTContext) -> bool:
	removed_gotos = collect_gotos(item)
	count = defaultdict(int)
	for g in removed_gotos:
		count[g.label_num] += 1

	unused_labels = []
	for lnum, c in count.items():
		if len(ctx.label2gotos[lnum]) == c:
			unused_labels.append(lnum)

	removed_labels = collect_labels(item)
	for u in unused_labels:
		try:
			removed_labels.remove(u)
		except ValueError:
			pass

	if new_item.ea == idaapi.BADADDR and item.ea != idaapi.BADADDR:
		new_item.ea = item.ea

	if new_item.label_num == -1 and item.label_num != -1:
		new_item.label_num = item.label_num

	if new_item.label_num not in (-1, item.label_num):
		print(f"[!] failed to replace item {item.opname} with new label")
		return False

	if len(removed_labels) > 1:
		print(f"[!] failed to replace item {item.opname} with labels in it")
		return False

	if len(removed_labels) == 1 and removed_labels[0] != item and new_item.label_num not in (item.label_num, -1):
		print(f"[!] failed to replace item {item.opname} with labels in it")
		return False

	rv = __replace_instr(item, new_item)

	if rv and new_item.op == idaapi.cit_goto:
		ctx.is_modified = True
	if rv and new_item.label_num != item.label_num:
		ctx.is_modified = True
	if rv and len(unused_labels) != 0:
		ctx.is_modified = True
		ctx.cfunc.remove_unused_labels()
	return rv

def replace_expr(expr:idaapi.cexpr_t, new_expr:idaapi.cexpr_t, ctx:ASTContext) -> bool:
	new_expr = idaapi.cexpr_t(new_expr)
	expr.replace_by(new_expr)
	return True


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