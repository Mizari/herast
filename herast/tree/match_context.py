from __future__ import annotations

import idaapi
import typing

if typing.TYPE_CHECKING:
	from herast.tree.patterns.base_pattern import BasePat

from herast.tree.ast_context import ASTContext


class InstrModification:
	def __init__(self, item, new_item):
		self.item = item
		self.new_item = new_item


class MatchContext(ASTContext):
	def __init__(self, cfunc:idaapi.cfunc_t, pattern:BasePat):
		super().__init__(cfunc)
		self.expressions : dict[str, idaapi.cexpr_t] = dict()
		self.instrs_to_modify : list = []

	def get_expr(self, name: str):
		return self.expressions.get(name, None)

	def save_expr(self, name: str, item) -> bool:
		current_item = self.get_expr(name)
		if current_item is None:
			self.expressions[name] = item
			return True

		if current_item.op == idaapi.cot_var:
			if item.op != idaapi.cot_var:
				return False
			return current_item.v.idx == item.v.idx

		return item.equal_effect(current_item)

	def has_expr(self, name: str):
		return self.expressions.get(name, None) is not None

	def modify_instr(self, item, new_item):
		"""Modify instruction. Changes AST, so restarting matching follows.
		
		:param item: AST item
		:param new_item: new AST item, if None, then its just removed
		"""
		self.instrs_to_modify.append(InstrModification(item, new_item))

	def modified_instrs(self):
		for itm in self.instrs_to_modify:
			yield itm