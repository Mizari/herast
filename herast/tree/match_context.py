from __future__ import annotations

import idaapi
import typing

if typing.TYPE_CHECKING:
	from herast.tree.patterns.base_pattern import BasePat

from herast.tree.ast_context import ASTContext
from herast.tree.ast_patch import ASTPatch


class MatchContext(ASTContext):
	def __init__(self, cfunc:idaapi.cfunc_t, pattern:BasePat):
		super().__init__(cfunc)
		self.pattern = pattern
		self.binded_items : dict[str, idaapi.cexpr_t] = dict()
		self.ast_patches : list = []

	def get_item(self, name: str):
		return self.binded_items.get(name, None)

	def bind_item(self, name: str, item) -> bool:
		current_item = self.get_item(name)
		if current_item is None:
			self.binded_items[name] = item
			return True

		if current_item.op == idaapi.cot_var:
			if item.op != idaapi.cot_var:
				return False
			return current_item.v.idx == item.v.idx

		return item.equal_effect(current_item)

	def has_item(self, name: str):
		return self.binded_items.get(name, None) is not None

	def add_patch(self, item, new_item):
		"""Modify instruction. Changes AST, so restarting matching follows.
		
		:param item: AST item
		:param new_item: new AST item, if None, then its just removed
		"""
		self.ast_patches.append(ASTPatch(item, new_item))

	def modified_instrs(self):
		for itm in self.ast_patches:
			yield itm