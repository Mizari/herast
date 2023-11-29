from __future__ import annotations
from enum import Enum
import idaapi

from herast.tree.consts import binary_expressions_ops, unary_expressions_ops


# handler, that maps item_op to children_items_getter
op2func = {
	idaapi.cit_expr:     lambda x: [x.cexpr],
	idaapi.cit_return:   lambda x: [x.creturn.expr],
	idaapi.cit_block:    lambda x: [i for i in x.cblock],
	idaapi.cit_if:       lambda x: [x.cif.ithen, x.cif.ielse, x.cif.expr],
	idaapi.cit_switch:   lambda x: [i for i in x.cswitch.cases] + [x.cswitch.expr],
	idaapi.cit_while:    lambda x: [x.cwhile.body, x.cwhile.expr],
	idaapi.cit_do:       lambda x: [x.cdo.body, x.cdo.expr],
	idaapi.cit_for:      lambda x: [x.cfor.body, x.cfor.init, x.cfor.expr, x.cfor.step],
	idaapi.cot_call:     lambda x: [i for i in x.a] + [x.x],
}

for i in unary_expressions_ops:
	op2func[i] = lambda x: [x.x]

for i in binary_expressions_ops:
	op2func[i] = lambda x: [x.x, x.y]

op2func[idaapi.cot_tern] = lambda x: [x.x, x.y, x.z]

def get_children(item):
	if (handler := op2func.get(item.op, None)) is None:
		return []

	return [c for c in handler(item) if c is not None]

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

def collect_gotos(haystack):
	gotos = []
	for potential_goto in iterate_all_subinstrs(haystack):
		if potential_goto.op == idaapi.cit_goto:
			gotos.append(potential_goto)

	return gotos

def collect_labels(haystack):
	labels = []
	for potential_label in iterate_all_subinstrs(haystack):
		if potential_label.label_num != -1:
			labels.append(potential_label)

	return labels


class IterationBreak(Enum):
	NONE = 0
	ROOT = 1