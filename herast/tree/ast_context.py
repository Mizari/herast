import idaapi

from herast.tree.ast_iteration import collect_gotos, collect_labels


class ASTContext:
	"""AST context, contains additional logic for information,
	not presented in AST. Also has some code for modifying AST in the
	process of AST matching.
	"""
	def __init__(self, cfunc:idaapi.cfunc_t):
		self.cfunc = cfunc

		self.label2gotos = {}
		self.label2instr = {}
		gotos = collect_gotos(self.cfunc.body)
		labels = collect_labels(self.cfunc.body)
		for l in labels:
			self.label2gotos[l.label_num] = []
			self.label2instr[l.label_num] = l

		for g in gotos:
			self.label2gotos[g.label_num] = g

		# TODO label names, var names

	@property
	def func_addr(self):
		return self.cfunc.entry_ea

	@property
	def root(self):
		return self.cfunc.body

	@property
	def func_name(self):
		return idaapi.get_name(self.func_addr)

	def get_parent_block(self, item):
		parent = self.cfunc.body.find_parent_of(item)
		if parent is None or parent.op != idaapi.cit_block:
			return None
		return parent