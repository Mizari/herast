import idaapi

class InstrModification:
	def __init__(self, item, new_item, is_forced=False):
		self.item = item
		self.new_item = new_item
		self.is_forced = is_forced

class SavedVariable:
	def __init__(self, idx):
		self.idx = idx

class PatternContext:
	def __init__(self, tree_proc):
		self.tree_proc = tree_proc
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

	def modify_instr(self, item, new_item, is_forced=False):
		self.instrs_to_modify.append(InstrModification(item, new_item, is_forced=is_forced))

	def modified_instrs(self):
		for itm in self.instrs_to_modify:
			yield itm

	def get_parent_block(self, item):
		return self.tree_proc.get_parent_block(item)