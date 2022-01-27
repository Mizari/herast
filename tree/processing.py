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

class TreeProcessor:
	def __init__(self, cfunc):
		self.cfunc = cfunc
		self.is_tree_modified = False

	def process_tree(self, tree_root, callback, need_expression_traversal=False):
		iterate_from_start = True
		while iterate_from_start:
			iterate_from_start = False
			for subitem in iterate_all_subitems(tree_root):
				if not need_expression_traversal and subitem.is_expr():
					continue

				is_tree_modified = callback(self, subitem)

				# goto outer loop to iterate from start again
				if is_tree_modified:
					iterate_from_start = True
					break

	def get_parent_block(self, item):
		parent = self.cfunc.body.find_parent_of(item)
		if parent is None or parent.op != idaapi.cit_block:
			return None
		return parent

	def collect_gotos(self, haystack):
		gotos = []
		def process_item(tree_proc, potential_goto):
			if potential_goto.op == idaapi.cit_goto:
				gotos.append(potential_goto)
			return False

		self.process_tree(haystack, process_item, need_expression_traversal=True)
		return gotos

	def collect_labels(self, haystack):
		labels = []
		def process_item(tree_proc, potential_label):
			if potential_label.label_num != -1:
				labels.append(potential_label)
			return False

		self.process_tree(haystack, process_item)
		return labels

	def remove_item(self, item):
		gotos = self.collect_gotos(item)
		if len(gotos) > 0:
			print("[!] failed removing item with gotos in it")
			return False

		parent = self.get_parent_block(item)
		if parent is None:
			print("[*] Failed to remove item from tree, because no parent is found", item.opname)
			return False

		labels = self.collect_labels(item)
		if len(labels) == 1 and labels[0] == item:
			next_item = utils.get_following_instr(parent, item)
			if next_item is None:
				print("[!] failed2removing item with labels in it", next_item)
				return False
			else:
				next_item.label_num = item.label_num
				item.label_num = -1

		elif len(labels) > 0:
			print("[!] failed removing item with labels in it")
			return False

		rv = utils.remove_instruction_from_ast(item, parent.cinsn)
		if rv:
			return True
		else:
			print("[*] Failed to remove item from tree")
			return False

	def replace_item(self, item, new_item):
		gotos = self.collect_gotos(item)
		if len(gotos) > 0:
			print("[!] failed replacing item with gotos in it")
			return False

		labels = self.collect_labels(item)
		if len(labels) > 1:
			print("[!] failed replacing item with labels in it", labels, item)
			return False
		elif len(labels) == 1 and labels[0] != item:
			print("[!] failed replacing item with labels in it")
			return False

		if new_item.ea == idaapi.BADADDR and item.ea != idaapi.BADADDR:
			new_item.ea = item.ea

		if new_item.label_num == -1 and item.label_num != -1:
			new_item.label_num = item.label_num
			item.label_num = -1

		try:
			idaapi.qswap(item, new_item)
			return True
		except Exception as e:
			print("[!] Got an exception during ctree instr replacing")
			return False