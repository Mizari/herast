import idaapi

from tree.patterns.abstracts import BindExpr, VarBind
import tree.utils as utils


class Matcher:
	def __init__(self, processed_function):
		self.function = processed_function
		self.patterns = list()

	def check_patterns(self, item) -> bool:
		for pattern, handler, ctx in self.patterns:
			try:
				ctx.cleanup()
			except Exception as e:
				print('[!] Got an exception during context cleanup: %s' % e)
				continue

			try:
				if not pattern.check(item, ctx):
					continue
			except Exception as e:
				print('[!] Got an exception during pattern matching: %s' % e)
				continue

			try:
				is_tree_modified = handler(item, ctx)
				if not isinstance(is_tree_modified, bool):
					raise Exception("Handler return invalid return type, should be bool")

				if is_tree_modified:
					return True
			except Exception as e:
				print('[!] Got an exception during pattern handling: %s' % e)
				continue

			try:
				is_tree_modified = self.finalize(ctx)
			except Exception as e:
				print('[!] Got an exception during context finalizing: %s' % e)
				continue

			if is_tree_modified:
				return True

		return False

	def finalize(self, ctx):
		tree_changed = False
		for modified_instr in ctx.modified_instrs():
			item = modified_instr.item
			new_item = modified_instr.new_item

			if new_item is None:
				rv = self.remove_item(ctx, item)
			else:
				rv = self.replace_item(ctx, item, new_item)
			if rv: tree_changed = True

		return tree_changed

	def remove_item(self, ctx, removed_item):
		parent = ctx.get_parent_block(removed_item)
		if parent is None:
			print("[*] Failed to remove item from tree, because no parent is found", removed_item.opname)
			return False

		rv = utils.remove_instruction_from_ast(removed_item, parent.cinsn)
		if rv:
			return True
		else:
			print("[*] Failed to remove item from tree")
			return False

	def replace_item(self, ctx, item, new_item):
		try:
			idaapi.qswap(item, new_item)
			return True
		except Exception as e:
			print("[!] Got an exception during ctree instr replacing")
			return False

	def insert_pattern(self, pat, handler):
		ctx = SavedContext(self.function)
		self.patterns.append((pat, handler, ctx))

	def expressions_traversal_is_needed(self):
		abstract_expression_patterns = (VarBind, BindExpr)
		for p, _, _ in self.patterns:
			if p.op >= 0 and p.op < idaapi.cit_empty or isinstance(p, abstract_expression_patterns):
				return True

		return False

class InstrModification:
	def __init__(self, item, new_item):
		self.item = item
		self.new_item = new_item

class SavedContext:
	def __init__(self, current_function):
		self.current_function = current_function
		self.expressions = dict()
		self.variables = dict()
		self.instrs_to_modify = []

	def get_var(self, name):
		return self.variables.get(name, None)

	def save_var(self, name, local_variable_index):
		self.variables[name] = SavedVariable(local_variable_index)

	def has_var(self, name):
		return self.variables.get(name, None) is not None

	def get_expr(self, name):
		return self.expressions.get(name, None)

	def save_expr(self, name, expression):
		self.expressions[name] = expression

	def has_expr(self, name):
		return self.expressions.get(name, None) is not None

	def cleanup(self):
		self.variables.clear()
		self.expressions.clear()
		self.instrs_to_modify.clear()

	def modify_instr(self, item, new_item):
		self.instrs_to_modify.append(InstrModification(item, new_item))

	def modified_instrs(self):
		for itm in self.instrs_to_modify:
			yield itm

	def get_parent_block(self, item):
		parent = self.current_function.body.find_parent_of(item)
		if parent is None or parent.op != idaapi.cit_block:
			return None
		return parent

class SavedVariable:
	def __init__(self, idx):
		self.idx = idx