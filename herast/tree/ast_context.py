from __future__ import annotations
import idaapi


class ASTContext:
	"""AST context, contains additional logic for information,
	not presented in AST. Also has some code for modifying AST in the
	process of AST matching.
	"""
	def __init__(self, cfunc:idaapi.cfunc_t):
		self.cfunc = cfunc

	@property
	def func_addr(self):
		return self.cfunc.entry_ea

	@property
	def func_name(self):
		return idaapi.get_name(self.func_addr)

	def get_parent_block(self, item):
		parent = self.cfunc.body.find_parent_of(item)
		if parent is None or parent.op != idaapi.cit_block:
			return None
		return parent