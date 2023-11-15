from __future__ import annotations
import idaapi
from herast.tree.processing import TreeProcessor

class InstrModification:
	def __init__(self, item, new_item):
		self.item = item
		self.new_item = new_item

class PatternContext:
	"""AST context, contains additional logic for information,
	not presented in AST. Also has some code for modifying AST in the
	process of AST matching.
	"""
	def __init__(self, tree_proc: TreeProcessor):
		self.tree_proc = tree_proc
		self.expressions : dict[str, idaapi.cexpr_t] = dict()
		self.variables : dict = dict()
		self.instrs_to_modify : list = []

	def get_func_ea(self):
		"""Get address of matched function."""
		return self.tree_proc.cfunc.entry_ea

	def get_func_name(self):
		return idaapi.get_name(self.get_func_ea())

	def get_var(self, name: str):
		return self.variables.get(name, None)

	def save_var(self, name: str, lvar_expr):
		self.variables[name] = lvar_expr

	def has_var(self, name: str):
		return self.variables.get(name, None) is not None

	def get_expr(self, name: str):
		return self.expressions.get(name, None)

	def save_expr(self, name: str, expression):
		self.expressions[name] = expression

	def has_expr(self, name: str):
		return self.expressions.get(name, None) is not None

	def cleanup(self):
		self.variables.clear()
		self.expressions.clear()
		self.instrs_to_modify.clear()

	def modify_instr(self, item, new_item):
		"""Modify instruction. Changes AST, so restarting matching follows.
		
		:param item: AST item
		:param new_item: new AST item, if None, then its just removed
		"""
		self.instrs_to_modify.append(InstrModification(item, new_item))

	def modified_instrs(self):
		for itm in self.instrs_to_modify:
			yield itm