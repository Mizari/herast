from __future__ import annotations
import idaapi
from herast.tree.ast_iteration import get_children
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

	def get_current(self) -> idaapi.citem_t | None:
		if len(self.path) == 0:
			return None

		return self.path[-1][0]

	def pop_current(self) -> idaapi.citem_t | None:
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
		return self.pop_current()

	def apply_patch(self, ast_patch:ASTPatch, ast_ctx:ASTContext):
		# restart from root, if user modified AST in scheme callback
		if ast_patch.ptype == ast_patch.PatchType.SCHEME_MODIFIED:
			self.path = build_path(self.root)
			return

		# if iteration ended, then cant decide about reiteration
		# just do the pathch
		if len(self.path) == 0:
			print("[!] WARNING: patching AST, that is already finished iteration")
			is_patch_applied = ast_patch.do_patch(ast_ctx)

		# check that patch is applied to correct AST with the same root
		elif self.path[0][0] != ast_ctx.root:
			print("[!] WARNING: patching AST, that has different root")
			is_patch_applied = ast_patch.do_patch(ast_ctx)

		# current iteration item is either under patch item or on different path
		elif len(full_path := ast_ctx.get_full_path(ast_patch.item)) < len(self.path):
			is_patch_applied = ast_patch.do_patch(ast_ctx)

		else:
			is_patch_applied = ast_patch.do_patch(ast_ctx)

		if is_patch_applied:
			self.path = build_path(self.root)