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

	def get_func_name(self):
		return idaapi.get_name(self.func_addr)