from __future__ import annotations
import idaapi
from enum import Enum
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


class RelativePosition(Enum):
	PARENT     = 0
	BEHIND = 1
	AHEAD     = 2
	CURRENT = 3


class ASTProcessor:
	"""
	ASTProcessor iterates tree left-to-right and children first

	example1: A->B->C tree will yield C,B,A 
	example2: A<-B->C tree will yield A,C,B
	"""

	def __init__(self, root):
		self.root = root
		self.path = []
		self.restart_iteration()

	def get_item_path(self, item):
		parent = self.root.find_parent_of(item)
		if parent is None:
			return [(item, -1)]

		parent = parent.to_specific_type
		parent_children = get_children(parent)
		for child_idx, c in enumerate(parent_children):
			if c == item:
				break
		else:
			raise ValueError()

		path = self.get_item_path(parent)
		if len(path) != 0:
			path[-1] = (path[-1][0], child_idx)
		path.append((item, -1))
		return path

	def restart_iteration(self):
		self.path = build_path(self.root)

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
		return self.get_current()

	def get_relative_position(self, item_path, ast_ctx:ASTContext) -> RelativePosition:
		item = item_path[-1][0]
		if item == self.get_current():
			return RelativePosition.CURRENT

		for (_, pidx), (_, fidx) in zip(self.path, item_path):
			if pidx < fidx:
				relpos = RelativePosition.BEHIND
				break
			elif pidx > fidx:
				relpos = RelativePosition.AHEAD
				break
			else:
				continue
		else:
			if len(item_path) == len(self.path):
				relpos = RelativePosition.CURRENT
			elif len(item_path) < len(self.path):
				relpos = RelativePosition.PARENT
			else:
				relpos = RelativePosition.BEHIND
		return relpos

	def apply_patch(self, ast_patch:ASTPatch, ast_ctx:ASTContext) -> bool:
		# restart from root, if user modified AST in scheme callback
		# assuming that user only gives us scheme patch, when it actually happened
		if ast_patch.ptype is ast_patch.PatchType.SCHEME_MODIFIED:
			self.restart_iteration()
			return True

		# sanity check, None is only for scheme callbacks
		assert ast_patch.item is not None

		# if iteration ended, then cant decide about reiteration
		# just do the patch
		if len(self.path) == 0:
			print("[!] WARNING: patching AST, that already finished iteration")
			return ast_patch.do_patch(ast_ctx)

		item_path = self.get_item_path(ast_patch.item)
		if len(item_path) == 0:
			print("[!] WARNING: patching AST with items, that dont match")
			rv = ast_patch.do_patch(ast_ctx)
			self.restart_iteration()
			return rv

		if not ast_patch.do_patch(ast_ctx):
			return False

		# if context is changed, then reiterate from scratch
		if ast_ctx.is_modified:
			ast_ctx.rebuild()
			ast_ctx.is_modified = False
			self.restart_iteration()
			return True

		relpos = self.get_relative_position(item_path, ast_ctx)
		# if item is yet to be iterated, then nothing needs to change
		if relpos is RelativePosition.AHEAD:
			return True

		# otherwise current/parent/behind is modified/removed
		# that means that it is already iterated over
		# thus reiteration (aka rebuilding self.path) is needed

		# if instruction is removed
		if ast_patch.new_item is None:
			# popping deleted instruction
			item_path.pop()

			# higher than deleted instruction comes its parent block
			parent_block, child_idx = item_path[-1]

			children = get_children(parent_block)[child_idx]

			# if removed instr is not last, then traverse next
			if len(children) != child_idx:
				child = children[child_idx]
				item_path += build_path(child)

			# if removed instr is last, then next goes iteration over its
			# parent block, just update it in path
			else:
				item_path[-1] = (parent_block, -1)

			self.path = item_path

		# if item is replaced with new item
		elif ast_patch.new_item is not None:
			item_path.pop()
			self.path = item_path + build_path(ast_patch.new_item)

		return True