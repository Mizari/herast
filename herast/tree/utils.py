from __future__ import annotations
import idaapi
import idc
import idautils


def get_func_calls_to(fea:int) -> list[int]:
	rv = filter(None, [get_func_start(x.frm) for x in idautils.XrefsTo(fea)])
	rv = filter(lambda x: x != idaapi.BADADDR, rv)
	return list(rv)

def get_func_start(addr:int) -> int:
	func = idaapi.get_func(addr)
	if func is None:
		return idaapi.BADADDR
	return func.start_ea

def is_func_start(addr:int) -> bool:
	return addr == get_func_start(addr)

def get_cfunc(func_ea:int) -> idaapi.cfunc_t|None:
	try:
		cfunc = idaapi.decompile(func_ea)
	except idaapi.DecompilationFailure:
		print("Error: failed to decompile function {}".format(hex(func_ea)))
		return None

	if cfunc is None:
		print("Error: failed to decompile function {}".format(hex(func_ea)))
	return cfunc

def get_following_instr(parent_block, item):
	container = parent_block.cinsn.cblock
	item_idx = container.index(item)
	if item_idx is None:
		return None
	if item_idx == len(container) - 1:
		return None
	return container[item_idx + 1]

def resolve_name_address(name:str) -> int:
	return idc.get_name_ea_simple(name)

def remove_instruction_from_ast(unwanted_ins, parent):
	assert type(unwanted_ins) is idaapi.cinsn_t, "Removing item must be an instruction (cinsn_t)"

	block = None
	if type(parent) is idaapi.cinsn_t and parent.op == idaapi.cit_block:
		block = parent.cblock

	elif type(parent) is idaapi.cfuncptr_t or type(parent) is idaapi.cfunc_t:
		ins = parent.body.find_parent_of(unwanted_ins).cinsn
		assert type(ins) is idaapi.cinsn_t and ins.op == idaapi.cit_block, "block is not cinsn_t or op != idaapi.cit_block"
		block = ins.cblock

	else:
		raise TypeError("Parent must be cfuncptr_t or cblock_t")

	if unwanted_ins.contains_label():
		return False

	if len(block) <= 1:
		return False

	try:
		return block.remove(unwanted_ins)
	except Exception as e:
		print('Got an exception %s while trying to remove instruction from block' % e)
		return False

def make_cblock(instructions):
	block = idaapi.cblock_t()
	for i in instructions:
		block.push_back(i)
	return block

def make_block_insn(instructions, address, label_num=-1):
	block = None
	if type(instructions) is idaapi.cblock_t:
		block = instructions
	elif type(instructions) is list or type(instructions) is tuple:
		block = make_cblock(instructions)
	else:
		raise TypeError("Trying to make cblock instruicton neither of cblock_t or list|tuple")

	insn = idaapi.cinsn_t()
	insn.ea = address
	insn.op = idaapi.cit_block
	insn.cblock = block
	insn.label_num = label_num
	insn.thisown = False

	return insn

def make_if_instr(cond, ithen, ielse=None):
	cif = idaapi.cif_t()
	cif.expr = cond
	cif.ithen = ithen
	cif.ielse = ielse
	instr = idaapi.cinsn_t()
	instr.op = idaapi.cit_if
	instr.cif = cif
	instr.label_num = -1
	return instr

def make_cast(x):
	new_obj = idaapi.cexpr_t()
	new_obj.op = idaapi.cot_cast
	new_obj.x = x
	return new_obj

def make_obj(obj_ea):
	new_obj = idaapi.cexpr_t()
	new_obj.op = idaapi.cot_obj
	new_obj.obj_ea = obj_ea
	return new_obj

def make_expr_instr(expr):
	new_item = idaapi.cinsn_t()
	new_item.op = idaapi.cit_expr
	new_item.cexpr = expr
	new_item.thisown = False
	return new_item

def make_arglist(*args):
	arglist = idaapi.carglist_t()
	for arg in args:
		if arg is None:
			print("[!] Warning: argument is None, skipping")
			continue

		if isinstance(arg, idaapi.carg_t):
			arglist.push_back(arg)
		else:
			narg = idaapi.carg_t()
			narg.assign(arg)
			arglist.push_back(narg)
	return arglist

def make_call(call, *args):
	call_expr = idaapi.cexpr_t()
	call_expr.op = idaapi.cot_call
	call_expr.x = call
	call_expr.a = make_arglist(*args)
	return call_expr

def make_call_helper_expr(name, *args, retval=None):
	if retval is None:
		retval = idaapi.get_unk_type(8)

	arglist = make_arglist(*args)
	return idaapi.call_helper(retval, arglist, name)

def make_call_helper_instr(name, *args):
	return make_expr_instr(make_call_helper_expr(name, *args))

def strip_casts(expr):
	import idaapi
	if expr.op == idaapi.cot_cast:
		return expr.x
	return expr