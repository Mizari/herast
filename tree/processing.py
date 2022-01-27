from __future__ import print_function
import idaapi

import tree.utils as utils
from tree.consts import binary_expressions_ops, unary_expressions_ops


# handler, that maps item_op to children_items_getter
op2func = {}
op2func.update({
	idaapi.cit_expr:     lambda x: [x.cexpr],
	idaapi.cit_return:   lambda x: [x.creturn.expr],
	idaapi.cit_block:    lambda x: [i for i in x.cblock],
	idaapi.cit_if:       lambda x: [x.cif.ithen, x.cif.ielse, x.cif.expr],
	idaapi.cit_switch:   lambda x: [i for i in x.cswitch.cases] + [x.cswitch.expr],
	idaapi.cit_while:    lambda x: [x.cwhile.body, x.cwhile.expr],
	idaapi.cit_do:       lambda x: [x.cdo.body, x.cdo.expr],
	idaapi.cit_for:      lambda x: [x.cfor.body, x.cfor.init, x.cfor.expr, x.cfor.init],
	idaapi.cot_call:     lambda x: [i for i in x.a] + [x.x],
})

for i in unary_expressions_ops:
	op2func[i] = lambda x: [x.x]

for i in binary_expressions_ops:
	op2func[i] = lambda x: [x.x, x.y]

def get_children(item):
	handler = op2func.get(item.op, None)
	if handler is None:
		return []
	children = handler(item)
	return list(filter(None, children))

def iterate_all_subitems(item):
	unprocessed_items = [item]
	while len(unprocessed_items) != 0:
		current_item = unprocessed_items.pop(0)
		yield current_item
		unprocessed_items += get_children(current_item)

def iterate_all_subinstrs(instr):
	unprocessed_items = [instr]
	while len(unprocessed_items) != 0:
		current_item = unprocessed_items.pop(0)
		yield current_item
		children = get_children(current_item)
		children = [c for c in children if not c.is_expr()]
		unprocessed_items += children

class TreeModificationContext:
	def __init__(self, tree_proc, item):
		self.tree_proc = tree_proc
		self.item = item
		self.labels = None
		self.gotos = None
		self.next_item = None
		self.parent = None
	
	def get_gotos(self):
		if self.gotos is None:
			self.gotos = self.tree_proc.collect_gotos(self.item)
		return self.gotos

	def get_labels(self):
		if self.labels is None:
			self.labels = self.tree_proc.collect_labels(self.item)
		return self.labels

	def get_next_item(self):
		if self.next_item is None:
			parent = self.get_parent()
			if parent is not None:
				self.next_item = utils.get_following_instr(parent, self.item)
		return self.next_item

	def get_parent(self):
		if self.parent is None:
			self.parent = self.tree_proc.get_parent_block(self.item)
		return self.parent

class TreeProcessor:
	def __init__(self, cfunc):
		self.cfunc = cfunc
		self.is_tree_modified = False

	def process(self, tree_root, callback, iterator):
		if self.is_tree_modified:
			return

		self.is_tree_modified = True # just to enter into while loop
		while self.is_tree_modified:
			self.is_tree_modified = False
			for subitem in iterator(tree_root):
				is_tree_modified = callback(self, subitem)
				if is_tree_modified:
					self.is_tree_modified = True

				# goto outer loop to iterate from start again
				if self.is_tree_modified:
					break

	def process_all_items(self, tree_root, callback):
		return self.process(tree_root, callback, iterate_all_subitems)

	def process_all_instrs(self, tree_root, callback):
		return self.process(tree_root, callback, iterate_all_subinstrs)

	def get_parent_block(self, item):
		parent = self.cfunc.body.find_parent_of(item)
		if parent is None or parent.op != idaapi.cit_block:
			return None
		return parent

	def collect_gotos(self, haystack):
		gotos = []
		for potential_goto in iterate_all_subinstrs(haystack):
			if potential_goto.op == idaapi.cit_goto:
				gotos.append(potential_goto)

		return gotos

	def collect_labels(self, haystack):
		labels = []
		for potential_label in iterate_all_subinstrs(haystack):
			if potential_label.label_num != -1:
				labels.append(potential_label)

		return labels

	def is_removal_possible(self, tmc):
		item = tmc.item
		gotos = tmc.get_gotos()
		if len(gotos) > 0:
			print("[!] failed removing item with gotos in it")
			return False

		parent = tmc.get_parent()
		if parent is None:
			print("[*] Failed to remove item from tree, because no parent is found", item.opname)
			return False

		labels = tmc.get_labels()
		if len(labels) == 1 and labels[0] == item:
			next_item = tmc.get_next_item()
			if next_item is None:
				print("[!] failed2removing item with labels in it", next_item)
				return False

		elif len(labels) > 0:
			print("[!] failed removing item with labels in it")
			return False

		return True

	def remove_item(self, item, is_forced=False):
		tmc = TreeModificationContext(self, item)
		if not is_forced and not self.is_removal_possible(tmc):
			return

		parent = tmc.get_parent()
		saved_lbl = item.label_num
		item.label_num = -1
		rv = utils.remove_instruction_from_ast(item, parent.cinsn)
		if not rv:
			item.label_num = saved_lbl
			print("[*] Failed to remove item from tree")
			return

		self.is_tree_modified = True

		next_item = tmc.get_next_item()
		if next_item is not None:
			next_item.label_num = saved_lbl
	
	def is_replacing_possible(self, tmc):
		item = tmc.item
		gotos = tmc.get_gotos()
		if len(gotos) > 0:
			print("[!] failed replacing item with gotos in it")
			return False

		labels = tmc.get_labels()
		if len(labels) > 1:
			print("[!] failed replacing item with labels in it", labels, item)
			return False

		if len(labels) == 1 and labels[0] != item:
			print("[!] failed replacing item with labels in it")
			return False

		return True

	def replace_item(self, item, new_item, is_forced=False):
		tmc = TreeModificationContext(self, item)

		if not is_forced and not self.is_replacing_possible(tmc):
			return

		if new_item.ea == idaapi.BADADDR and item.ea != idaapi.BADADDR:
			new_item.ea = item.ea

		if new_item.label_num == -1 and item.label_num != -1:
			new_item.label_num = item.label_num

		try:
			idaapi.qswap(item, new_item)
			self.is_tree_modified = True
		except Exception as e:
			print("[!] Got an exception during ctree instr replacing")