from __future__ import annotations
from herast.tree.ast_iteration import IterationBreak, get_children
from herast.tree.ast_patch import ASTPatch
from herast.tree.ast_context import ASTContext


def build_path(ast):
	path = []
	while len(children := get_children(ast)) != 0:
		path.append((ast,0))
		ast = children[0]
	path.append((ast, -1))
	return path


class ASTIterator:
	def __init__(self, root):
		self.root = root
		self.path = build_path(root)

	def is_iteration_ended(self) -> bool:
		return len(self.path) == 0

	def is_iteration_started(self) -> bool:
		if len(self.path) == 0:
			return False

		# check that AST path is all left-sided
		# except for the last node, that is supposed to be a leaf
		if any(child_idx != 0 for (_, child_idx) in self.path[:-1]):
			return False

		# check that the last node is a leaf
		last_item, child_idx = self.path[-1]
		if len(get_children(last_item)) != 0 or child_idx > 0:
			return False
		return True

	def get_next(self):
		if len(self.path) == 0:
			return None

		current_item, child_idx = self.path.pop()
		# -1 means no need to iterate children or that there are no children
		if child_idx == -1:
			return current_item

		children = get_children(current_item)
		# iteration is finished for all children
		if len(children) == child_idx + 1:
			return current_item

		self.path.append((current_item, child_idx+1))
		child = children[child_idx+1]
		self.path += build_path(child)
		return self.get_next()

	def break_iteration(self, itbreak:IterationBreak):
		if itbreak is IterationBreak.ROOT:
			self.path = build_path(self.root)
		else:
			raise ValueError("Not implemented")

	def apply_patch(self, ast_patch:ASTPatch, ast_ctx:ASTContext) -> IterationBreak:
		itbreak = ast_patch.do_patch(ast_ctx)
		self.break_iteration(itbreak)
		return itbreak