import idaapi
from herast.tree.ast_iteration import get_children


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

	def get_full_path(self, item):
		parent = self.cfunc.body.find_parent_of(item)
		if parent is None:
			return [(item, -1)]

		parent = parent.to_specific_type
		parent_children = get_children(parent)
		for child_idx, c in enumerate(parent_children):
			if c == item:
				break
		else:
			raise ValueError()

		path = self.get_full_path(parent)
		if len(path) != 0:
			path[-1] = (path[-1][0], child_idx)
		path.append((item, -1))
		return path