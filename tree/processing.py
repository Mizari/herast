from __future__ import print_function
import idaapi
import functools

from tree.consts import binary_expressions_ops, unary_expressions_ops, op2str, str2op


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